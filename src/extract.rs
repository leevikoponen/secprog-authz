use http_body_util::{BodyExt as _, Collected, Limited};
use hyper::{
    body::Incoming,
    header::{self, HeaderValue},
    http::{Method, Request, StatusCode},
};

pub fn route(request: &Request<Incoming>) -> (&Method, &str) {
    let segment = request.uri().path().rsplit('/').next().unwrap_or_default();

    (request.method(), segment)
}

pub async fn data(
    request: &mut Request<Incoming>,
    limit: usize,
    expected: HeaderValue,
) -> Result<Box<[u8]>, StatusCode> {
    let length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .ok_or(StatusCode::LENGTH_REQUIRED)?
        .to_str()
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    if length == 0 {
        return Err(StatusCode::LENGTH_REQUIRED);
    }

    if length > limit {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let provided = request.headers().get(header::CONTENT_TYPE);
    if provided != Some(&expected) {
        Err(StatusCode::UNSUPPORTED_MEDIA_TYPE)?;
    }

    Limited::new(request.body_mut(), length)
        .collect()
        .await
        .map(Collected::to_bytes)
        .map(Vec::from)
        .map(Vec::into_boxed_slice)
        .ok()
        .ok_or(StatusCode::BAD_REQUEST)
}

pub fn bearer(request: &Request<Incoming>) -> Result<Box<[u8]>, StatusCode> {
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.as_bytes().strip_prefix(b"Bearer: "))
        .ok_or(StatusCode::UNAUTHORIZED)
        .map(Vec::from)
        .map(Vec::into_boxed_slice)
}
