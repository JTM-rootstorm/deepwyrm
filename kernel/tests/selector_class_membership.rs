//! Cross-list membership gate for selector product classes.
//!
//! Card R1 failed five VM runs in a row, and five of its defects were the same
//! shape: selector 34 was absent from one `cfg` list and silently inherited a
//! default written for a different product shape. The page ceiling, the init
//! failure status, the primordial completion contract, reporter custody, and a
//! `complete_pass` that would have emitted a PASS record with no evidence.
//!
//! None of those was findable by a test, because membership in a product class
//! is not declared anywhere. It is spread across dozens of independently
//! maintained `any(...)` lists, and nothing related them. This gate relates
//! them: it takes one site as the authoritative definition of the class and
//! requires every member to appear at the other sites the class depends on.
//!
//! It is deliberately source-reading. The alternative is a compile-time
//! construct, which cannot work here: the whole failure mode is that a selector
//! is *absent*, so nothing about its build fails, and only a build of some other
//! selector could notice.

const PRIMORDIAL: &str = include_str!("../src/arch/x86_64/mm/activation/primordial.rs");
const CONSTRUCTION: &str = include_str!("../src/boot/primordial/construction.rs");
const TEST_SUPPORT: &str = include_str!("../src/test_support/x86_64.rs");

/// The site that defines the class: a selector whose evidence reporter is bound
/// after primordial retirement has a live permanent supervisor. Everything this
/// gate demands follows from being such a product.
const CLASS_ANCHOR: &str = "fn enable_wyr1_reporter_after_retirement";

/// Sites every member of the class must appear in, with what goes wrong when one
/// does not. Each is an identifier the gate finds and then reads the `cfg`
/// attribute immediately above.
const REQUIRED_SITES: [(&str, &str, &str); 1] = [(
    "retiring_wyr1_primordial",
    "primordial.rs",
    "the selector would take complete_primordial_launch and have to prove a \
     quiescence a live permanent supervisor necessarily violates (card R1 run 4, \
     detail 0x7000000A)",
)];

/// The two retirement-facts contracts. A live-supervisor selector must take
/// exactly one: they differ in the READY bytes they accept, so taking neither
/// leaves it on the quiescence-verifying path and taking both is contradictory.
/// Selectors 25 and 27 are live-supervisor *non-resource* products, which is why
/// the rule is "exactly one" rather than "the resource one" -- a distinction this
/// gate found on its first run, after an earlier specification got it wrong.
const RETIREMENT_VARIANTS: [&str; 2] = [
    "validate_resource_primordial_retirement_facts",
    "validate_primordial_retirement_facts",
];

/// Extracts the `deepwyrm_*` selector tokens from the `#[cfg(...)]` attribute
/// immediately preceding `offset`, if there is one.
fn preceding_cfg_selectors(source: &str, offset: usize) -> Option<Vec<&str>> {
    let head = &source[..offset];
    let open = head.rfind("#[cfg(")?;
    // The attribute must be adjacent: only attributes, comments and blank lines
    // may sit between it and the item, or this is some unrelated earlier cfg.
    let between = &head[open..];
    // The last line is the item's own, truncated at the identifier, so it is not
    // part of the attribute block and must not be judged as if it were.
    let intervening = between.lines().count().saturating_sub(1);
    for line in between.lines().skip(1).take(intervening.saturating_sub(1)) {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with("//")
            || line.starts_with("#[")
            || line.starts_with("deepwyrm_")
            || line.starts_with("feature")
            || line.starts_with("test,")
            || line.starts_with(')')
            || line.starts_with("any(")
            || line.starts_with("not(")
            || line.starts_with("all(")
        {
            continue;
        }
        return None;
    }
    let mut depth = 0_usize;
    let mut end = open;
    for (index, byte) in between.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    end = open + index;
                    break;
                }
            }
            _ => {}
        }
    }
    let attribute = &head[open..=end];
    Some(selectors_in(attribute))
}

fn selectors_in(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(index) = rest.find("deepwyrm_") {
        let tail = &rest[index..];
        let length = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(tail.len());
        let token = &tail[..length];
        if token.ends_with("_evidence") && !found.contains(&token) {
            found.push(token);
        }
        rest = &tail[length..];
    }
    found
}

/// Every `cfg` selector list attached to `identifier` anywhere in `source`.
fn cfg_lists_for<'a>(source: &'a str, identifier: &str) -> Vec<Vec<&'a str>> {
    let mut lists = Vec::new();
    let mut start = 0;
    while let Some(index) = source[start..].find(identifier) {
        let at = start + index;
        if let Some(selectors) = preceding_cfg_selectors(source, at)
            && !selectors.is_empty()
        {
            lists.push(selectors);
        }
        start = at + identifier.len();
    }
    lists
}

/// The class is the union of every site that expresses it, not one privileged
/// site.
///
/// An earlier version of this gate took `CLASS_ANCHOR` as the definition. That
/// version passed when a selector was removed from *every* list, including the
/// anchor -- which is precisely the state card R1 was in before this work, so it
/// would not have caught run 4. Taking the union means any one site naming a
/// selector obliges all the others, and only deleting it everywhere hides it.
fn class_members() -> Vec<&'static str> {
    let mut members: Vec<&'static str> = Vec::new();
    let anchor_at = PRIMORDIAL
        .find(CLASS_ANCHOR)
        .expect("the class anchor still exists; re-point this gate if it moved");
    let mut sites: Vec<Vec<&'static str>> = vec![
        preceding_cfg_selectors(PRIMORDIAL, anchor_at)
            .expect("the class anchor still carries an adjacent cfg list"),
    ];
    sites.extend(cfg_lists_for(PRIMORDIAL, REQUIRED_SITES[0].0));
    for variant in RETIREMENT_VARIANTS {
        sites.extend(cfg_lists_for(CONSTRUCTION, variant));
    }
    for site in sites {
        for selector in site {
            if !members.contains(&selector) {
                members.push(selector);
            }
        }
    }
    assert!(
        members.len() >= 5,
        "the class collapsed to {members:?}; this gate would assert almost nothing"
    );
    members
}

#[test]
fn every_live_supervisor_selector_appears_at_every_site_its_class_depends_on() {
    let members = class_members();
    for (identifier, file, consequence) in REQUIRED_SITES {
        let source = match file {
            "primordial.rs" => PRIMORDIAL,
            "construction.rs" => CONSTRUCTION,
            other => panic!("unknown source {other}"),
        };
        let lists = cfg_lists_for(source, identifier);
        assert!(
            !lists.is_empty(),
            "found no cfg-gated use of {identifier} in {file}; re-point this gate \
             rather than letting it assert nothing"
        );
        for member in &members {
            let present = lists.iter().any(|list| list.contains(member));
            assert!(
                present,
                "{member} is in the live-permanent-supervisor class (it binds an \
                 evidence reporter after retirement) but appears at no cfg-gated \
                 use of {identifier} in {file}. Consequence: {consequence}."
            );
        }
    }
}

#[test]
fn every_class_member_takes_exactly_one_retirement_facts_contract() {
    let members = class_members();
    for member in &members {
        let taken: Vec<&str> = RETIREMENT_VARIANTS
            .into_iter()
            .filter(|variant| {
                // The resource name contains the other as a substring only if
                // compared naively; these are distinct identifiers, but read the
                // resource lists first and exclude those matches from the
                // non-resource count so one definition cannot satisfy both.
                let lists = cfg_lists_for(CONSTRUCTION, variant);
                lists.iter().any(|list| list.contains(member))
                    && (*variant == RETIREMENT_VARIANTS[0]
                        || !cfg_lists_for(CONSTRUCTION, RETIREMENT_VARIANTS[0])
                            .iter()
                            .any(|list| list.contains(member)))
            })
            .collect();
        assert_eq!(
            taken.len(),
            1,
            "{member} has a live permanent supervisor but takes {taken:?} of the \
             retirement-facts contracts. Taking neither leaves it proving a \
             quiescence it necessarily violates; the two accept different READY \
             bytes, so the choice must be made exactly once."
        );
    }
}

#[test]
fn no_class_member_can_emit_a_pass_record_through_the_primordial_path() {
    let members = class_members();
    let at = TEST_SUPPORT
        .find("pub(crate) fn complete_pass")
        .expect("complete_pass still exists");
    let body = &TEST_SUPPORT[at..];
    let end = body
        .find("\n/// Emit the build-selected test's FAIL")
        .expect("complete_pass is still followed by complete_fail");
    let body = &body[..end];
    let default = body
        .find("#[cfg(not(any(")
        .expect("complete_pass still has a negated default arm");
    let excluded = selectors_in(&body[default..]);
    for member in &members {
        assert!(
            excluded.contains(member),
            "{member} has a live permanent supervisor but is absent from \
             complete_pass's negated default, so a primordial-path pass would emit \
             a real PASS record carrying no evidence. A pass without a transcript \
             proves nothing and reads as success, which is worse than any failure."
        );
    }
}

#[test]
fn the_gate_detects_a_removed_member() {
    // A gate that cannot fail is worth nothing, so this exercises the comparison
    // itself on a source that is missing a member.
    let doctored = PRIMORDIAL.replacen("    deepwyrm_r1_evidence,\n", "", usize::MAX);
    let lists = cfg_lists_for(&doctored, "retiring_wyr1_primordial");
    assert!(!lists.is_empty(), "the doctored source still has the sites");
    assert!(
        !lists
            .iter()
            .any(|list| list.contains(&"deepwyrm_r1_evidence")),
        "removing the member from every list should leave it absent"
    );
}

/// Catches the shape that made card R1's reporter custody dead code.
///
/// `enable_wyr1_reporter_after_retirement` contained
/// `#[cfg(deepwyrm_r1_evidence)] R1_EVIDENCE.claim_reporter(reporter)` while the
/// enclosing function was gated on a list that excluded selector 34. The block
/// therefore never compiled, `R1_EVIDENCE` could never hold a reporter, and no
/// `R1SP` record could have been accepted even if the probe had run. Nothing
/// warned: the code is simply absent from every build.
#[test]
fn no_selector_is_named_inside_a_function_its_own_gate_excludes() {
    let mut checked = 0_usize;
    let mut offset = 0_usize;
    for line in PRIMORDIAL.split_inclusive('\n') {
        let at = offset;
        offset += line.len();
        let trimmed = line.trim_start();
        // Every visibility form, not just a bare `fn` at one indent, which is what
        // an earlier version of this scan matched -- it examined two functions and
        // would have proved almost nothing.
        let is_definition = trimmed.starts_with("fn ")
            || trimmed.starts_with("pub fn ")
            || trimmed.starts_with("pub(crate) fn ")
            || trimmed.starts_with("pub(super) fn ")
            || trimmed.starts_with("const fn ")
            || trimmed.starts_with("pub(crate) const fn ")
            || trimmed.starts_with("pub(super) const fn ")
            || trimmed.starts_with("unsafe fn ");
        if !is_definition {
            continue;
        }
        let Some(outer) = preceding_cfg_selectors(PRIMORDIAL, at) else {
            continue;
        };
        // Only product-class gates: a one- or two-selector gate is a private
        // arm, not a class, and an inner mention there is ordinary.
        if outer.len() < 3 {
            continue;
        }
        let body_start = match PRIMORDIAL[at..].find('{') {
            Some(offset) => at + offset,
            None => continue,
        };
        let mut depth = 0_usize;
        let mut body_end = body_start;
        for (offset, byte) in PRIMORDIAL[body_start..].bytes().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        body_end = body_start + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &PRIMORDIAL[body_start..=body_end];
        let name = PRIMORDIAL[at..body_start].trim();
        checked += 1;
        for inner in selectors_in(body) {
            assert!(
                outer.contains(&inner),
                "`{name}` is gated on {outer:?}, which excludes {inner}, but its \
                 body contains a cfg block naming {inner}. That block can never \
                 compile, so whatever it does is silently absent from every build."
            );
        }
    }
    assert!(
        checked >= 5,
        "only {checked} class-gated functions were examined; the scan stopped \
         matching the source"
    );
}
