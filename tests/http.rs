use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Output},
    thread,
    time::Duration,
};

fn server(responses: Vec<String>) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for response in responses {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut data = Vec::new();
            let mut buf = [0; 1024];
            while !data.windows(4).any(|s| s == b"\r\n\r\n") {
                let n = socket.read(&mut buf).unwrap();
                assert!(n > 0);
                data.extend_from_slice(&buf[..n]);
            }
            requests.push(String::from_utf8(data).unwrap());
            socket.write_all(response.as_bytes()).unwrap();
        }
        requests
    });
    (url, handle)
}

fn response(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    )
}

fn run(url: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_url-inspect"))
        .args([url, "--csp", "--json", "--no-proxy", "--timeout", "3"])
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn preserves_separate_headers_meta_tags_and_redirect_hops() {
    let (url, handle) = server(vec![
        response(
            "302 Found",
            "Location: /final\r\nContent-Security-Policy: default-src 'none'\r\n",
            "",
        ),
        response(
            "200 OK",
            "Content-Type: text/html; charset=utf-8\r\nContent-Security-Policy: default-src 'self'\r\nContent-Security-Policy: object-src 'none'\r\nContent-Security-Policy-Report-Only: frame-src 'none'\r\n",
            "<head><meta http-equiv='Content-Security-Policy' content=\"frame-src https://*.example.com\"></head>",
        ),
    ]);
    let result = run(&url, &["--require-csp", "-H", "X-Probe: retained"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["hops"].as_array().unwrap().len(), 2);
    assert_eq!(value["hops"][1]["policies"].as_array().unwrap().len(), 4);
    assert_eq!(value["hops"][1]["policies"][2]["report_only"], true);
    assert_eq!(value["hops"][1]["policies"][3]["source"], "meta");
    assert!(
        handle
            .join()
            .unwrap()
            .iter()
            .all(|r| r.to_lowercase().contains("x-probe: retained"))
    );
}

#[test]
fn drops_authentication_headers_on_cross_origin_redirect() {
    let (destination, final_handle) = server(vec![response("200 OK", "", "")]);
    let (url, handle) = server(vec![response(
        "302 Found",
        &format!("Location: {destination}/\r\n"),
        "",
    )]);
    let result = run(&url, &["-H", "Authorization: Bearer test-token"]);
    assert!(result.status.success());
    assert!(
        handle.join().unwrap()[0]
            .to_lowercase()
            .contains("authorization: bearer test-token")
    );
    assert!(
        !final_handle.join().unwrap()[0]
            .to_lowercase()
            .contains("authorization:")
    );
}

#[test]
fn report_only_does_not_satisfy_require_csp() {
    let (url, handle) = server(vec![response(
        "200 OK",
        "Content-Security-Policy-Report-Only: default-src 'self'\r\n",
        "",
    )]);
    assert_eq!(run(&url, &["--require-csp"]).status.code(), Some(2));
    handle.join().unwrap();
}

#[test]
fn redirect_limit_and_no_follow_are_respected() {
    let redirect = response("302 Found", "Location: /next\r\n", "");
    let (url, handle) = server(vec![redirect.clone()]);
    let output = run(&url, &["--no-follow"]);
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["hops"][0]["status"], 302);
    handle.join().unwrap();
    let (url, handle) = server(vec![redirect]);
    let output = run(&url, &["--max-redirects", "0"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Exceeded 0 redirects"));
    handle.join().unwrap();
}

#[test]
fn error_page_headers_are_reported_with_a_warning() {
    let (url, handle) = server(vec![response(
        "403 Forbidden",
        "Content-Security-Policy: default-src 'none'\r\n",
        "",
    )]);
    let output = run(&url, &[]);
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["hops"][0]["status"], 403);
    assert!(!value["hops"][0]["warnings"].as_array().unwrap().is_empty());
    handle.join().unwrap();
}

#[test]
fn no_arguments_or_url_alone_displays_help_without_network() {
    for args in [vec![], vec!["http://127.0.0.1:1"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_url-inspect"))
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("Usage:"));
        assert!(help.contains("--csp"));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_url-inspect"))
        .arg("--csp")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn certificate_only_omits_csp_even_when_response_contains_it() {
    let (url, handle) = server(vec![response(
        "200 OK",
        "Content-Security-Policy: default-src 'none'\r\n",
        "",
    )]);
    let output = Command::new(env!("CARGO_BIN_EXE_url-inspect"))
        .args([&url, "--cert", "--json", "--no-proxy"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value["hops"][0].get("policies").is_none());
    handle.join().unwrap();
}

#[test]
fn forced_colour_is_visible_in_text_but_not_json() {
    let (url, handle) = server(vec![response(
        "200 OK",
        "Content-Security-Policy: default-src 'self'\r\n",
        "",
    )]);
    let output = Command::new(env!("CARGO_BIN_EXE_url-inspect"))
        .args([&url, "--csp", "--no-proxy", "--color", "always"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.contains(&0x1b));
    handle.join().unwrap();
    let (url, handle) = server(vec![response("200 OK", "", "")]);
    let output = run(&url, &["--color", "always"]);
    assert!(output.status.success());
    assert!(!output.stdout.contains(&0x1b));
    serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
    handle.join().unwrap();
}

#[test]
fn headers_mode_preserves_repeated_headers_and_reports_http_version() {
    let (url, handle) = server(vec![response(
        "200 OK",
        "Set-Cookie: first=1\r\nSet-Cookie: second=2\r\nX-Test: visible\r\n",
        "",
    )]);
    let output = Command::new(env!("CARGO_BIN_EXE_url-inspect"))
        .args([&url, "--headers", "--json", "--no-proxy"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let hop = &value["hops"][0];
    assert_eq!(hop["http_version"], "HTTP/1.1");
    assert!(
        hop["remote_address"]
            .as_str()
            .unwrap()
            .starts_with("127.0.0.1:")
    );
    assert!(hop.get("policies").is_none());
    let headers = hop["response_headers"].as_array().unwrap();
    let cookies: Vec<_> = headers
        .iter()
        .filter(|h| h["name"] == "set-cookie")
        .map(|h| h["value"].as_str().unwrap())
        .collect();
    assert_eq!(cookies, ["first=1", "second=2"]);
    assert!(headers.iter().any(|h| h["name"] == "content-length"));
    assert!(
        handle.join().unwrap()[0]
            .to_lowercase()
            .contains("accept-encoding: identity")
    );
}

#[test]
fn unexpected_encoded_body_does_not_hide_response_headers() {
    let (url, handle) = server(vec![response(
        "200 OK",
        "Content-Type: text/html\r\nContent-Encoding: gzip\r\n",
        "not actually gzip",
    )]);
    let output = run(&url, &["--headers"]);
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let hop = &value["hops"][0];
    assert!(
        hop["response_headers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["name"] == "content-encoding" && h["value"] == "gzip")
    );
    assert!(
        hop["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("HTML meta scan skipped"))
    );
    handle.join().unwrap();
}

#[test]
fn tls_mode_accepts_http_without_claiming_tls_negotiation() {
    let (url, handle) = server(vec![response("200 OK", "", "")]);
    let output = Command::new(env!("CARGO_BIN_EXE_url-inspect"))
        .args([&url, "--tls", "--json", "--no-proxy"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let hop = &value["hops"][0];
    assert!(hop.get("tls_probe").is_none());
    assert!(
        hop["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("HTTP has no TLS certificate"))
    );
    handle.join().unwrap();
}
