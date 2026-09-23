//! Slicing helpers for the kernel's in-crate source-text tests.
//!
//! A test that reads source text should bound what it reads to one function,
//! not to whatever happens to follow a marker comment or the next closing
//! brace at some indentation.

/// The body of the one function whose signature contains `signature`, from
/// its opening brace to the matching closing brace.
///
/// Panics if `signature` is absent or occurs more than once, so a renamed or
/// duplicated function fails the test instead of silently moving the slice.
/// Braces inside string or character literals are not special-cased; use it
/// on functions whose bodies have none.
pub(crate) fn fn_body<'a>(source: &'a str, signature: &str) -> &'a str {
    let mut starts = source.match_indices(signature).map(|(start, _)| start);
    let start = starts
        .next()
        .unwrap_or_else(|| panic!("missing `{signature}`"));
    assert!(
        starts.next().is_none(),
        "`{signature}` must name exactly one function"
    );
    let open = start
        + source[start..]
            .find('{')
            .unwrap_or_else(|| panic!("`{signature}` has no body"));
    let mut depth = 0_usize;
    for (offset, character) in source[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[open..=open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("`{signature}` has an unterminated body")
}

#[cfg(test)]
mod tests {
    use super::fn_body;

    #[test]
    fn a_body_ends_at_its_own_closing_brace() {
        let source = "fn a() {\n    if x {\n    }\n    y();\n}\nfn b() { z(); }\n";
        assert_eq!(
            fn_body(source, "fn a()"),
            "{\n    if x {\n    }\n    y();\n}"
        );
        assert_eq!(fn_body(source, "fn b()"), "{ z(); }");
    }

    #[test]
    #[should_panic(expected = "must name exactly one function")]
    fn an_ambiguous_signature_is_refused() {
        fn_body("fn a() {}\nfn a() {}\n", "fn a()");
    }
}
