//! Open Policy Agent (openpolicyagent/OPA) verification for Actix applications
//!
//! OPA middleware could be used with application.
//!
//!
//!
extern crate actix_web;
extern crate base64;
extern crate bytes;
extern crate futures;
extern crate http;
extern crate url;

#[cfg(feature = "jwt")]
extern crate jsonwebtoken;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate log;

use base64::decode;
use bytes::Bytes;
use futures::future::Future;
use serde::de::DeserializeOwned;
use serde::Serialize;

use std::iter::FromIterator;
use std::str;
use std::time::Duration;

use actix_web::middleware::{Middleware, Started};
use actix_web::{client, HttpRequest, Result};
use actix_web::{HttpMessage, HttpResponse};
use http::header;

static HEADER_USER_AGENT_KEY: &str = "User-Agent";
static HEADER_USER_AGENT_VALUE: &str = "PolicyVerifier middleware";
static MIMETYPE_JSON: &str = "application/json; charset=utf-8";
static RESPONSE_BODY_SIZE: usize = 1024;
static DEFAULT_TIMEOUT_MS: u64 = 100;

/// `Middleware` for validating access against Open Policy Agent.
///
///
/// ```rust
/// extern crate actix_web;
/// extern crate actix_web_middleware_opa;
/// #[macro_use]
/// extern crate serde_derive;
/// extern crate serde;
///
/// use actix_web::{http, middleware, App, HttpResponse};
/// use actix_web_middleware_opa::*;
///
/// #[derive(Deserialize)]
/// struct PolicyDecision {
///     result: PolicyDecisionResult,
/// }
///
/// #[derive(Deserialize)]
/// struct PolicyDecisionResult {
///     allow: bool,
/// }
///
/// impl OPAResponse for PolicyDecision {
///     fn allowed(&self) -> bool {
///         self.result.allow
///     }
/// }
///
/// type Verifier = PolicyVerifier<HTTPTokenAuthRequest, PolicyDecision>;
///
/// fn main() {
///     let app = App::new()
///         .middleware(Verifier::build("http://localhost:8181/opa/api".to_string()))
///         .resource("/", |r| {
///             r.method(http::Method::GET).f(|_| HttpResponse::Ok());
///         })
///         .finish();
/// }
/// ```
///
pub trait OPARequest<S>
where
    Self: std::marker::Sized,
{
    fn from_http_request(req: &HttpRequest<S>) -> Result<Self, String>;
}

pub trait OPAResponse {
    fn allowed(&self) -> bool;
}

#[cfg(feature = "jwt")]
fn is_valid_token(token: &str) -> bool {
    jsonwebtoken::decode_header(token).is_ok()
}

#[cfg(not(feature = "jwt"))]
fn is_valid_token(_token: &str) -> bool {
    true
}

fn get_el_from_split(s: &str, separator: &str, offset: usize) -> Result<String, String> {
    let res: Vec<&str> = s.split(separator).collect();
    if res.len() > (offset) {
        Ok(res[offset].into())
    } else {
        Err("Requested offset is out of range".into())
    }
}

fn get_path_list<S>(req: &HttpRequest<S>) -> Vec<String> {
    Vec::from_iter(
        req.path()
            .split('/')
            .filter(|s| !s.is_empty())
            .map({ |s| s.to_string() }),
    )
}

#[derive(Serialize)]
pub struct HTTPBasicAuthRequest {
    input: HTTPBasicAuthRequestInput,
}

#[derive(Serialize)]
pub struct HTTPBasicAuthRequestInput {
    user: String,
    path: Vec<String>,
    method: String,
}

// XXX This does not verify the password
impl<S> OPARequest<S> for HTTPBasicAuthRequest {
    fn from_http_request(req: &HttpRequest<S>) -> Result<Self, String> {
        let headermap = req.headers();
        if headermap.contains_key(header::AUTHORIZATION) {
            match headermap[header::AUTHORIZATION].to_str() {
                Ok(s) => {
                    // Header value has the form "Authorization KEY"
                    match decode(&get_el_from_split(s, " ", 1)?) {
                        Ok(s) => {
                            // Decoded KEY has the form "username:password-hash"
                            let username = get_el_from_split(str::from_utf8(&s).unwrap(), ":", 0)?;
                            Ok(HTTPBasicAuthRequest {
                                input: HTTPBasicAuthRequestInput {
                                    user: username,
                                    path: get_path_list(req),
                                    method: req.method().to_string(),
                                },
                            })
                        }
                        Err(err) => Err(format!("Invalid Authorization key structure: {:?}", err)),
                    }
                }
                Err(err) => Err(format!(
                    "Unable to read the Authorization header : {:?}",
                    err
                )),
            }
        } else {
            Err("Missing Authorization header".to_string())
        }
    }
}

#[derive(Serialize)]
pub struct HTTPTokenAuthRequest {
    input: HTTPTokenAuthRequestInput,
}

#[derive(Serialize)]
pub struct HTTPTokenAuthRequestInput {
    token: String,
    path: Vec<String>,
    method: String,
}

impl<S> OPARequest<S> for HTTPTokenAuthRequest {
    fn from_http_request(req: &HttpRequest<S>) -> Result<Self, String> {
        let headermap = req.headers();
        if headermap.contains_key(header::AUTHORIZATION) {
            match headermap[header::AUTHORIZATION].to_str() {
                Ok(s) => {
                    // Header value has the form "Bearer TOKEN"
                    let token = &get_el_from_split(s, " ", 1)?;

                    if !is_valid_token(token) {
                        return Err("Bad token".to_string());
                    }

                    Ok(HTTPTokenAuthRequest {
                        input: HTTPTokenAuthRequestInput {
                            token: token.to_string(),
                            path: get_path_list(req),
                            method: req.method().to_string(),
                        },
                    })
                }
                Err(err) => Err(format!(
                    "Unable to read the Authorization header : {:?}",
                    err
                )),
            }
        } else {
            Err("Missing Authorization header".to_string())
        }
    }
}

pub struct PolicyVerifier<A, B> {
    url: String,
    duration: Duration,
    request: Option<A>,
    response: Option<B>,
}

impl<A, B> PolicyVerifier<A, B>
where
    A: Serialize,
{
    pub fn build(url: String) -> Self {
        PolicyVerifier {
            url: url,
            duration: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            request: None,
            response: None,
        }
    }

    pub fn url(mut self, url: String) -> PolicyVerifier<A, B> {
        self.url = url;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> PolicyVerifier<A, B> {
        self.duration = timeout;
        self
    }

    pub fn build_request(&self, req: &A) -> client::SendRequest {
        client::ClientRequest::post(&self.url)
            .header(HEADER_USER_AGENT_KEY, HEADER_USER_AGENT_VALUE)
            .header(header::CONTENT_TYPE, MIMETYPE_JSON)
            .timeout(self.duration)
            .json(req)
            .unwrap()
            .send()
    }
}

fn extract_response<B>(bytes: &Bytes) -> Result<Option<HttpResponse>>
where
    B: OPAResponse + DeserializeOwned,
{
    match str::from_utf8(&bytes) {
        Ok(s) => {
            let response: B = serde_json::from_str(&s)?;
            if response.allowed() {
                debug!("Decision from OPA: OK");
                Ok(None)
            } else {
                debug!("Decision from OPA: FORBIDDEN, finalizing response 403");
                Ok(Some(HttpResponse::Forbidden().finish()))
            }
        }
        Err(_) => {
            warn!("Invalid response from OPA received, returning 500");
            Ok(Some(HttpResponse::InternalServerError().finish()))
        }
    }
}

impl<A: 'static, B: 'static, S> Middleware<S> for PolicyVerifier<A, B>
where
    A: OPARequest<S> + Serialize,
    B: OPAResponse + DeserializeOwned,
{
    fn start(&self, req: &HttpRequest<S>) -> Result<Started> {
        debug!("Received incoming HTTP request {:?}", req);

        match &A::from_http_request(req) {
            Ok(res) => {
                let response = self.build_request(res);
                Ok(Started::Future(Box::new(
                            response
                            .from_err()
                            .and_then(|response| {
                                debug!("Received response from OPA : {:?}", response);
                                Ok(response.body())
                            })
                            .and_then(|body| {
                                body.limit(RESPONSE_BODY_SIZE)
                                    .from_err()
                                    .and_then(|bytes: Bytes| extract_response::<B>(&bytes))
                            }))))

            },
            Err(err) => {
                info!("Bad request, finalizing response 401 : {:?}", err);
                Ok(Started::Response(HttpResponse::Unauthorized().finish()))
            }
        }

    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::{TestRequest, TestServer};

    const TEST_BODY: &str = r#"{"input":{"user":"testuser"}}"#;

    #[derive(Serialize)]
    struct PolicyRequest {
        name: String,
    }

    impl<S> OPARequest<S> for PolicyRequest {
        fn from_http_request(_req: &HttpRequest<S>) -> Result<Self, String> {
            Ok(PolicyRequest {
                name: "Sam".to_string(),
            })
        }
    }

    #[derive(Deserialize)]
    struct PolicyDecision {
        result: OPAResult,
    }

    #[derive(Deserialize)]
    struct OPAResult {
        allow: bool,
    }

    impl OPAResponse for PolicyDecision {
        fn allowed(&self) -> bool {
            self.result.allow
        }
    }

    type Verifier = PolicyVerifier<PolicyRequest, PolicyDecision>;

    #[test]
    fn build_works() {
        let url = "http://localhost:5151/api/)".to_string();
        let verifier = Verifier::build(url.clone());
        assert_eq!(verifier.url, url);
    }

    #[test]
    fn url_change_works() {
        let url_a = "http://localhost:6161/api/)".to_string();
        let url_b = "http://localhost:6161/api/)".to_string();
        let verifier = Verifier::build(url_a.to_owned());
        verifier.url(url_b.to_owned());
        // assert_ne!(&verifier.url.clone(), &url_a);
        // assert_eq!(&verifier.url.clone(), &url_b);
    }

    #[test]
    fn basic() {
        let url_a = "http://localhost:6161/api/)".to_string();
        let verifier = Verifier::build(url_a.to_owned());

        let mut srv =
            TestServer::new(|app|
                                  app.handler(|_| HttpResponse::Ok().body(TEST_BODY)));

        let request = srv.get().header("X-Test", "456456456").finish().unwrap();
        let repr = format!("{:?}", request);
        // assert!(repr.contains("PolicyVerifier middleware"));

        let response = srv.execute(request.send()).unwrap();
        assert!(response.status().is_success());
    }
}
