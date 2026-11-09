/** Escapes `text` so it can be safely inserted into HTML, both as element content and inside
attribute values.
*/
pub fn escape_html(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#39;"),
            _ => result.push(c),
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    mod escape_html {
        use super::*;

        #[test]
        fn return_text_unchanged_when_nothing_needs_escaping() {
            assert_eq!(escape_html("Access denied"), "Access denied");
        }

        #[test]
        fn return_empty_string_when_text_is_empty() {
            assert_eq!(escape_html(""), "");
        }

        #[test]
        fn return_non_ascii_unchanged() {
            assert_eq!(escape_html("アニ ナビ"), "アニ ナビ");
        }

        #[test]
        fn return_entities_for_all_special_characters() {
            assert_eq!(escape_html("&<>\"'"), "&amp;&lt;&gt;&quot;&#39;");
        }

        #[test]
        fn return_escaped_ampersand_between_text() {
            assert_eq!(escape_html("a & b"), "a &amp; b");
        }

        #[test]
        fn return_escaped_entity_when_text_already_contains_one() {
            // Literal text "&lt;" must still display as "&lt;", so its ampersand is escaped too.
            assert_eq!(escape_html("&lt;"), "&amp;lt;");
        }

        #[test]
        fn return_inert_markup_when_text_contains_script_tag() {
            assert_eq!(
                escape_html("<script>alert('hi')</script>"),
                "&lt;script&gt;alert(&#39;hi&#39;)&lt;/script&gt;"
            );
        }
    }
}
