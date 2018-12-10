extern crate actix_web;
extern crate base64;
extern crate bytes;
extern crate futures;
extern crate url;
extern crate http;

#[cfg(feature="jwt")]
extern crate jsonwebtoken;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

use base64::decode;
use bytes::Bytes;
use futures::future::Future;
use serde::de::DeserializeOwned;
use serde::Serialize;

use std::iter::FromIterator;
use std::str;

use http::header;
use actix_web::middleware::{Middleware, Started};
use actix_web::{client, HttpRequest, Result};
use actix_web::{HttpMessage, HttpResponse};

static HEADER_USER_AGENT_KEY: &str = "User-Agent";
static HEADER_USER_AGENT_VALUE: &str = "PolicyVerifier middleware";
static MIMETYPE_JSON: &str = "application/json; charset=utf-8";
static RESPONSE_BODY_SIZE: usize = 1024;

pub trait OPARequest<S>
where
    Self: std::marker::Sized,
{
    fn from_http_request(req: &HttpRequest<S>) -> Result<Self, String>;
}

pub trait OPAResponse {
    fn allowed(&self) -> bool;
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
            .filter(|s| !s.is_empty() )
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

                    if cfg!(feature="jwt") {
                        if !jsonwebtoken::decode_header(token).is_ok() {
                            return Err("Bad token".to_string());
                        }
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
    request: Option<A>,
    response: Option<B>,
}

impl<A, B> PolicyVerifier<A, B> {
    pub fn build(url: String) -> Self {
        PolicyVerifier {
            url: url,
            request: None,
            response: None,
        }
    }

    pub fn url(mut self, url: String) -> PolicyVerifier<A, B> {
        self.url = url;
        self
    }
}

fn extract_response<B>(bytes: & Bytes) -> Result<Option<HttpResponse>>
where
    B: OPAResponse + DeserializeOwned,
{
    // println!("==== BODY ==== {:?}", bytes);
    match str::from_utf8(&bytes) {
        Ok(s) => {
            let response: B = serde_json::from_str(&s)?;
            if response.allowed() {
                println!("200 OK");
                Ok(Some(HttpResponse::Ok().finish()))
            } else {
                println!("403 FORBIDDEN");
                Ok(Some(HttpResponse::Forbidden().finish()))
            }
        }
        Err(_) => {
            println!("400");
            Ok(Some(HttpResponse::BadRequest().finish()))
        }
    }
}

impl<A: 'static, B: 'static, S> Middleware<S> for PolicyVerifier<A, B>
where
    A: OPARequest<S> + Serialize,
    B: OPAResponse + DeserializeOwned,
{
    fn start(&self, req: &HttpRequest<S>) -> Result<Started> {
        println!("Get request {:?}", req);

        let response = client::ClientRequest::post(&self.url)
            .header(HEADER_USER_AGENT_KEY, HEADER_USER_AGENT_VALUE)
            .header(header::CONTENT_TYPE, MIMETYPE_JSON)
            .json(A::from_http_request(req).unwrap())?
            .send();

        Ok(Started::Future(Box::new(
            response
                .from_err()
                .and_then(|response| {
                    println!("Response : {:?}", response);
                    Ok(response.body())
                })
                .and_then(|body| {
                    body.limit(RESPONSE_BODY_SIZE)
                        .from_err()
                        .and_then(|bytes: Bytes| { extract_response::<B>(&bytes) })
                }),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::{self, TestRequest};

    #[derive(Serialize)]
    struct PolicyRequest {
        name: String,
    }

    impl<S> OPARequest<S> for PolicyRequest {
        fn from_http_request(_req: &HttpRequest<S>) -> Result<Self, String> {
            Ok(PolicyRequest {
                name: "Sam".to_string()
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
        let verifier = Verifier::build(url_a.to_string().clone());
        verifier.url(url_b.to_string().clone());
        // assert_ne!(verifier.url, url_a);
        // assert_eq!(verifier.url, url_b);
    }

}
