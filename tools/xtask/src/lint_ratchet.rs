//! The S1.3 lint ratchet: counts that may fall but never rise.
//!
//! Two sources feed one baseline, `tooling/lint-ratchet.txt`:
//!
//! - host Clippy at warn level for `RATCHET_LINTS`, counted per package and
//!   lint, each finding once however many targets report it;
//! - a text count of `unsafe {` blocks without a `// SAFETY:` comment in the
//!   four preceding lines, for `SAFETY_TEXT_FILES`. Those files are
//!   `target_os = "none"` only, so host Clippy never sees them, and the target
//!   toolchain ships no Clippy.
//!
//! The gate fails when any count exceeds its baseline (a key absent from the
//! baseline has baseline zero), and names every count that fell so the
//! baseline can be tightened in the same change.

use super::*;

pub(super) const LINT_RATCHET_BASELINE: &str = "tooling/lint-ratchet.txt";
pub(super) const RATCHET_LINTS: [&str; 2] = [
    "clippy::wildcard_enum_match_arm",
    "clippy::undocumented_unsafe_blocks",
];
/// The text counter's key for one file.
pub(super) const SAFETY_TEXT_COUNTER: &str = "unsafe-block-without-safety-comment";
pub(super) const SAFETY_TEXT_FILES: [&str; 2] = [
    "kernel/src/arch/x86_64/mm/activation/primordial.rs",
    "kernel/src/arch/x86_64/syscall/live.rs",
];

/// `(scope, counter)`: a package and lint, or a file and the text counter.
pub(super) type RatchetKey = (String, String);

pub(super) fn run_lint_ratchet() -> io::Result<u8> {
    let workspace = workspace_root();
    let mut arguments = vec![
        "clippy",
        "--locked",
        "--workspace",
        "--all-targets",
        "--message-format=json",
        "--",
    ];
    for lint in RATCHET_LINTS {
        arguments.extend(["-W", lint]);
    }
    let output = Command::new("cargo")
        .current_dir(&workspace)
        .args(arguments)
        .stderr(Stdio::inherit())
        .output()?;
    if !output.status.success() {
        let mut stderr = io::stderr().lock();
        writeln!(stderr, "error: the lint ratchet's Clippy run failed")?;
        return Ok(output.status.code().unwrap_or(EXIT_NOT_IMPLEMENTED as i32) as u8);
    }
    let stream = String::from_utf8(output.stdout)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Clippy JSON is not UTF-8"))?;
    let mut current = count_clippy_findings(&stream)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    for file in SAFETY_TEXT_FILES {
        let source = fs::read_to_string(workspace.join(file))?;
        current.insert(
            (file.to_owned(), SAFETY_TEXT_COUNTER.to_owned()),
            count_unsafe_blocks_without_safety_comment(&source),
        );
    }
    let baseline_source = fs::read_to_string(workspace.join(LINT_RATCHET_BASELINE))?;
    let baseline = parse_ratchet_baseline(&baseline_source)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let comparison = compare_ratchet(&baseline, &current);
    let mut stderr = io::stderr().lock();
    for ((scope, counter), count) in &current {
        writeln!(stderr, "lint ratchet: {scope} {counter} {count}")?;
    }
    for ((scope, counter), (was, now)) in &comparison.lower {
        writeln!(
            stderr,
            "lint ratchet: {scope} {counter} fell from {was} to {now}; tighten {LINT_RATCHET_BASELINE}"
        )?;
    }
    if comparison.higher.is_empty() {
        return Ok(0);
    }
    for ((scope, counter), (was, now)) in &comparison.higher {
        writeln!(
            stderr,
            "error: lint ratchet: {scope} {counter} rose from {was} to {now}"
        )?;
    }
    Ok(EXIT_NOT_IMPLEMENTED)
}

#[derive(Debug, Default, Eq, PartialEq)]
pub(super) struct RatchetComparison {
    pub(super) higher: BTreeMap<RatchetKey, (usize, usize)>,
    pub(super) lower: BTreeMap<RatchetKey, (usize, usize)>,
}

pub(super) fn compare_ratchet(
    baseline: &BTreeMap<RatchetKey, usize>,
    current: &BTreeMap<RatchetKey, usize>,
) -> RatchetComparison {
    let mut comparison = RatchetComparison::default();
    let keys = baseline
        .keys()
        .chain(current.keys())
        .collect::<BTreeSet<_>>();
    for key in keys {
        let was = baseline.get(key).copied().unwrap_or(0);
        let now = current.get(key).copied().unwrap_or(0);
        if now > was {
            comparison.higher.insert(key.clone(), (was, now));
        } else if now < was {
            comparison.lower.insert(key.clone(), (was, now));
        }
    }
    comparison
}

/// Parses `<scope> <counter> <count>` lines; `#` starts a comment line.
pub(super) fn parse_ratchet_baseline(source: &str) -> Result<BTreeMap<RatchetKey, usize>, String> {
    let mut baseline = BTreeMap::new();
    for (index, line) in source.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let [scope, counter, count] = fields[..] else {
            return Err(format!(
                "{LINT_RATCHET_BASELINE}:{}: expected `<scope> <counter> <count>`",
                index + 1
            ));
        };
        let count = count.parse::<usize>().map_err(|_| {
            format!(
                "{LINT_RATCHET_BASELINE}:{}: count must be a decimal integer",
                index + 1
            )
        })?;
        if baseline
            .insert((scope.to_owned(), counter.to_owned()), count)
            .is_some()
        {
            return Err(format!(
                "{LINT_RATCHET_BASELINE}:{}: duplicate {scope} {counter}",
                index + 1
            ));
        }
    }
    Ok(baseline)
}

/// Counts `unsafe {` blocks with no `// SAFETY:` comment in the four lines
/// before the one that opens them (the S0 metric's rule).
pub(super) fn count_unsafe_blocks_without_safety_comment(source: &str) -> usize {
    let lines = source.lines().collect::<Vec<_>>();
    lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            let blocks = line.matches("unsafe {").count();
            let documented = lines[index.saturating_sub(4)..index]
                .iter()
                .any(|previous| previous.contains("// SAFETY:"));
            if documented { 0 } else { blocks }
        })
        .sum()
}

/// Counts `RATCHET_LINTS` findings in Cargo's JSON message stream per package,
/// each primary location once: `--all-targets` reports a library's findings
/// again for its test harness.
///
/// Refuses a stream without a successful `build-finished` message, so a parse
/// that silently matched nothing cannot read as a clean tree.
pub(super) fn count_clippy_findings(stream: &str) -> Result<BTreeMap<RatchetKey, usize>, String> {
    let mut counts = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut finished = false;
    for line in stream.lines().filter(|line| line.starts_with('{')) {
        let message = Json::parse(line)?;
        match message.get("reason").and_then(Json::as_str) {
            Some("build-finished") => {
                finished = message.get("success") == Some(&Json::Bool(true));
            }
            Some("compiler-message") => {}
            _ => continue,
        }
        let Some(diagnostic) = message.get("message") else {
            continue;
        };
        let Some(lint) = diagnostic
            .get("code")
            .and_then(|code| code.get("code"))
            .and_then(Json::as_str)
            .filter(|code| RATCHET_LINTS.contains(code))
        else {
            continue;
        };
        let package = message
            .get("package_id")
            .and_then(Json::as_str)
            .map(package_name)
            .ok_or("a compiler message has no package_id")?;
        let primary = diagnostic
            .get("spans")
            .and_then(Json::as_array)
            .and_then(|spans| {
                spans
                    .iter()
                    .find(|span| span.get("is_primary") == Some(&Json::Bool(true)))
            })
            .ok_or("a ratchet finding has no primary span")?;
        let location = (
            lint.to_owned(),
            primary
                .get("file_name")
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_owned(),
            primary.get("line_start").and_then(Json::as_number),
            primary.get("column_start").and_then(Json::as_number),
        );
        if seen.insert(location) {
            *counts.entry((package, lint.to_owned())).or_insert(0) += 1;
        }
    }
    if !finished {
        return Err("Clippy's JSON stream has no successful build-finished message".into());
    }
    Ok(counts)
}

/// The package name from a Cargo package ID in either the current
/// (`path+file:///...#name@version`) or the older (`name version (source)`)
/// form.
fn package_name(package_id: &str) -> String {
    match package_id.rsplit_once('#') {
        Some((_, name_version)) => name_version
            .split_once('@')
            .map_or(name_version, |(name, _)| name)
            .to_owned(),
        None => package_id
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned(),
    }
}

/// Just enough JSON to read Cargo's message stream without a dependency.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Json {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub(super) fn parse(text: &str) -> Result<Self, String> {
        let mut parser = JsonParser {
            bytes: text.as_bytes(),
            position: 0,
        };
        let value = parser.value(0)?;
        parser.whitespace();
        if parser.position != parser.bytes.len() {
            return Err("trailing characters after a JSON value".into());
        }
        Ok(value)
    }

    fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) | Self::Array(_) => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::Array(_) | Self::Object(_) => None,
        }
    }

    fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) | Self::Object(_) => {
                None
            }
        }
    }

    fn as_number(&self) -> Option<u64> {
        match self {
            Self::Number(value) if value.fract() == 0.0 && *value >= 0.0 => Some(*value as u64),
            Self::Null
            | Self::Bool(_)
            | Self::Number(_)
            | Self::String(_)
            | Self::Array(_)
            | Self::Object(_) => None,
        }
    }
}

const MAX_JSON_DEPTH: usize = 64;

struct JsonParser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl JsonParser<'_> {
    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.position += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.bytes.get(self.position) == Some(&byte) {
            self.position += 1;
            Ok(())
        } else {
            Err(format!(
                "expected `{}` at byte {}",
                byte as char, self.position
            ))
        }
    }

    fn literal(&mut self, word: &str, value: Json) -> Result<Json, String> {
        if self.bytes[self.position..].starts_with(word.as_bytes()) {
            self.position += word.len();
            Ok(value)
        } else {
            Err(format!("invalid literal at byte {}", self.position))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_JSON_DEPTH {
            return Err("JSON nests too deeply".into());
        }
        self.whitespace();
        match self.bytes.get(self.position) {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Json::String),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(format!("expected a JSON value at byte {}", self.position)),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut entries = Vec::new();
        self.whitespace();
        if self.bytes.get(self.position) == Some(&b'}') {
            self.position += 1;
            return Ok(Json::Object(entries));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            self.whitespace();
            self.expect(b':')?;
            entries.push((key, self.value(depth + 1)?));
            self.whitespace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    return Ok(Json::Object(entries));
                }
                _ => return Err(format!("unterminated object at byte {}", self.position)),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut values = Vec::new();
        self.whitespace();
        if self.bytes.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(Json::Array(values));
        }
        loop {
            values.push(self.value(depth + 1)?);
            self.whitespace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(Json::Array(values));
                }
                _ => return Err(format!("unterminated array at byte {}", self.position)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut value = Vec::new();
        loop {
            let Some(&byte) = self.bytes.get(self.position) else {
                return Err("unterminated string".into());
            };
            self.position += 1;
            match byte {
                b'"' => {
                    return String::from_utf8(value).map_err(|_| "string is not UTF-8".into());
                }
                b'\\' => {
                    let Some(&escape) = self.bytes.get(self.position) else {
                        return Err("unterminated escape".into());
                    };
                    self.position += 1;
                    match escape {
                        b'"' | b'\\' | b'/' => value.push(escape),
                        b'b' => value.push(0x08),
                        b'f' => value.push(0x0c),
                        b'n' => value.push(b'\n'),
                        b'r' => value.push(b'\r'),
                        b't' => value.push(b'\t'),
                        b'u' => {
                            let character = self.unicode_escape()?;
                            let mut buffer = [0; 4];
                            value.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                        }
                        _ => return Err(format!("invalid escape at byte {}", self.position)),
                    }
                }
                _ => value.push(byte),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self
            .bytes
            .get(self.position..self.position + 4)
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .and_then(|digits| u32::from_str_radix(digits, 16).ok())
            .ok_or_else(|| format!("invalid \\u escape at byte {}", self.position))?;
        self.position += 4;
        Ok(digits)
    }

    fn unicode_escape(&mut self) -> Result<char, String> {
        let first = self.hex4()?;
        let code = if (0xd800..0xdc00).contains(&first) {
            self.expect(b'\\')?;
            self.expect(b'u')?;
            let second = self.hex4()?;
            if !(0xdc00..0xe000).contains(&second) {
                return Err("unpaired surrogate in \\u escape".into());
            }
            0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
        } else {
            first
        };
        char::from_u32(code).ok_or_else(|| "invalid \\u escape".into())
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.position;
        while self
            .bytes
            .get(self.position)
            .is_some_and(|byte| matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'))
        {
            self.position += 1;
        }
        std::str::from_utf8(&self.bytes[start..self.position])
            .ok()
            .and_then(|number| number.parse().ok())
            .map(Json::Number)
            .ok_or_else(|| format!("invalid number at byte {start}"))
    }
}
