/** Formats a raw HTTP/1.1 response with an HTML `body`.

`status` is the status code followed by its reason phrase, e.g. `"200 OK"`.
*/
pub fn http_response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {}\r\n\
        Content-Type: text/html; charset=utf-8\r\n\
        Content-Length: {}\r\n\r\n\
        {}",
        status,
        body.len(),
        body
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    mod http_response {
        use super::*;

        #[test]
        fn return_full_response_with_status_headers_and_body() {
            assert_eq!(
                http_response("200 OK", "<p>Hi</p>"),
                "HTTP/1.1 200 OK\r\n\
            Content-Type: text/html; charset=utf-8\r\n\
            Content-Length: 9\r\n\r\n\
            <p>Hi</p>"
            );
        }

        #[test]
        fn return_status_line_with_given_status() {
            let response = http_response("400 Bad Request", "");

            assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        }

        #[test]
        fn return_zero_content_length_when_body_is_empty() {
            let response = http_response("200 OK", "");

            assert!(response.contains("Content-Length: 0\r\n"));
            assert!(response.ends_with("\r\n\r\n"));
        }

        #[test]
        fn return_content_length_in_bytes_when_body_is_non_ascii() {
            // 3 characters, but each is 3 bytes in UTF-8.
            let response = http_response("200 OK", "アニメ");

            assert!(response.contains("Content-Length: 9\r\n"));
        }
    }
}
