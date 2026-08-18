use super::*;

pub(super) fn parse_document(path: &Path, allowed_sections: &[&str]) -> Result<Document> {
    let input = fs::read_to_string(path)
        .map_err(|error| Error::new(format!("{}: {error}", path.display())))?;
    let mut top = Table {
        path: path.to_path_buf(),
        line: 1,
        values: BTreeMap::new(),
    };
    let mut arrays: BTreeMap<String, Vec<Table>> = BTreeMap::new();
    let mut current: Option<(String, usize)> = None;

    for (index, raw) in input.lines().enumerate() {
        let line = index + 1;
        let text = raw.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        if text.starts_with("[[") {
            if !text.ends_with("]]") || text.len() < 5 {
                return Err(Error::new(format!(
                    "{}:{line}: malformed array-table header",
                    path.display()
                )));
            }
            let name = &text[2..text.len() - 2];
            if !allowed_sections.contains(&name) {
                return Err(Error::new(format!(
                    "{}:{line}: unsupported section `[[{name}]]`",
                    path.display()
                )));
            }
            arrays.entry(name.to_owned()).or_default().push(Table {
                path: path.to_path_buf(),
                line,
                values: BTreeMap::new(),
            });
            current = Some((name.to_owned(), arrays[name].len() - 1));
            continue;
        }
        if text.starts_with('[') {
            return Err(Error::new(format!(
                "{}:{line}: ordinary TOML tables are unsupported",
                path.display()
            )));
        }
        let (key, raw_value) = text.split_once('=').ok_or_else(|| {
            Error::new(format!("{}:{line}: expected `key = value`", path.display()))
        })?;
        let key = key.trim();
        if !valid_key(key) {
            return Err(Error::new(format!(
                "{}:{line}: invalid key `{key}`",
                path.display()
            )));
        }
        let value = parse_scalar(path, line, raw_value.trim())?;
        let target = match &current {
            Some((section, table_index)) => &mut arrays.get_mut(section).unwrap()[*table_index],
            None => &mut top,
        };
        if target.values.insert(key.to_owned(), value).is_some() {
            return Err(Error::new(format!(
                "{}:{line}: duplicate key `{key}` in the same table",
                path.display()
            )));
        }
    }
    Ok(Document { top, arrays })
}

pub(super) fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

pub(super) fn parse_scalar(path: &Path, line: usize, value: &str) -> Result<Scalar> {
    if value.starts_with('"') {
        if value.len() < 2 || !value.ends_with('"') {
            return Err(Error::new(format!(
                "{}:{line}: unterminated quoted string",
                path.display()
            )));
        }
        let inner = &value[1..value.len() - 1];
        if inner.contains('"') || inner.contains('\\') {
            return Err(Error::new(format!(
                "{}:{line}: string escapes and embedded quotes are unsupported",
                path.display()
            )));
        }
        return Ok(Scalar::Text(inner.to_owned()));
    }
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        i128::from_str_radix(hex, 16)
    } else if let Some(hex) = value.strip_prefix("-0x") {
        i128::from_str_radix(hex, 16).map(|number| -number)
    } else {
        value.parse::<i128>()
    };
    parsed.map(Scalar::Integer).map_err(|_| {
        Error::new(format!(
            "{}:{line}: unsupported or malformed value `{value}`",
            path.display()
        ))
    })
}
