# actix-web-middleware-opa

[![Build Status](https://travis-ci.org/michiel/actix-web-middleware-opa.svg?branch=master)](https://travis-ci.org/michiel/actix-web-middleware-opa)
[![Crates.io Status](http://meritbadge.herokuapp.com/actix-web-middleware-opa)](https://crates.io/crates/actix-web-middleware-opa)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/michiel/actix-web-middleware-opa/master/LICENSE)
[![Documentation](https://docs.rs/actix-web-middleware-opa/badge.svg)](https://docs.rs/actix-web-middleware-opa)

Open Policy Agent (openpolicyagent/OPA) middleware for actix-web applications.

This middleware performs a policy check against an Open Policy Agent instance for incoming HTTP requests.

Both the policy check request and response are generic.

## Flow

![Components](https://raw.githubusercontent.com/michiel/actix-web-middleware-opa/master/resource/opa-middleware-components.svg?sanitize=true)

## Example

Take the following request :

    curl -XGET -H 'Authorization: Bearer 123123123' http://localhost:8080/order/item/1

This will need to be translated to a JSON call to OPA :

```json
{
  "input" : {
    "token"  : "123123123",
    "method" : "GET",
    "path"   : ["order", "item", "1"]
  }
}
```

We represent this as two Rust structs which implement `Serialize`,

```rust
#[derive(Serialize)]
struct PolicyRequest {
    input: PolicyRequestInput,
}

#[derive(Serialize)]
struct PolicyRequestInput {
    token: String,
    method: String,
    path: Vec<String>,
}
```

The expected response is a JSON object :

```json
{
   "result" : {
      "allow" : true
   }
}
```

We represent this as two Rust structs which implement `Deserialize`,

```rust
#[derive(Deserialize)]
struct PolicyResponse {
    input: PolicyResponseResult,
}

#[derive(Deserialize)]
struct PolicyResponseResult {
    allow: bool,
}
```

Lastly we have to implement the `OPARequest<S>` trait so that 

```rust

    impl<S> OPARequest<S> for PolicyRequest {
        fn from_http_request(_req: &HttpRequest<S>) -> Result<Self, String> {
            // This needs to be constructured from _req
            Ok(PolicyRequest {
              input: PolicyRequestInput {
                token: "123".into(),
                method: "GET",
                path: vec!["order", "item", "1"],
              }
            })
        }
    }
```

```rust
    type VerifierMiddleware = PolicyVerifier<PolicyRequest, PolicyResponse>;
```

