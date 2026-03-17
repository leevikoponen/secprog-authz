use hyper::{
    body::Bytes,
    header::{self, HeaderValue},
    http::{Response, StatusCode},
};

pub fn data(code: StatusCode, kind: HeaderValue, content: Bytes) -> Response<Bytes> {
    Response::builder()
        .status(code)
        .header(header::CONTENT_TYPE, kind)
        .body(content)
        .expect("response shouldn't have invalid fields")
}

pub fn status(code: StatusCode) -> Response<Bytes> {
    data(
        code,
        HeaderValue::from_static("text/plain"),
        code.canonical_reason()
            .map(str::as_bytes)
            .map(Bytes::from_static)
            .unwrap_or_default(),
    )
}
