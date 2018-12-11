# actix-web-middleware-opa

[![Build Status](https://travis-ci.org/michiel/actix-web-middleware-opa.svg?branch=master)](https://travis-ci.org/michiel/actix-web-middleware-opa)
[![Crates.io Status](http://meritbadge.herokuapp.com/actix-web-middleware-opa)](https://crates.io/crates/actix-web-middleware-opa)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/michiel/actix-web-middleware-opa/master/LICENSE)
[![Documentation](https://docs.rs/actix-web-middleware-opa/badge.svg)](https://docs.rs/actix-web-middleware-opa)

Open Policy Agent (openpolicyagent/OPA) middleware for actix-web applications.

This middleware performs a policy check against an Open Policy Agent instance for incoming HTTP requests.

Both the policy check request and response are generic.

## Flow

![Components](/resource/opa-middleware-components.svg?sanitize=true)

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



```json
{
   "result" : {
      "allow" : true
   }
}
```


```rust
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
    struct PolicyResponse {
        result: OPAResult,
    }

    #[derive(Deserialize)]
    struct OPAResult {
        allow: bool,
    }

    impl OPAResponse for PolicyResponse {
        fn allowed(&self) -> bool {
            self.result.allow
        }
    }

    type VerifierMiddleware = PolicyVerifier<PolicyRequest, PolicyResponse>;
```

