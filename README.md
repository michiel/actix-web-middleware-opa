# actix-web-middleware-opa

Open Policy Agent (openpolicyagent/OPA) middleware integration for actix-web
applications.

### Example request

```json
{
  "input" : {
    "token"  : "123123123",
    "method" : "GET",
    "path"   : ["order", "item", "1"]
  }
}
```

### Example response

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

    type VerifierMiddleware = PolicyVerifier<PolicyRequest, PolicyDecision>;
```

