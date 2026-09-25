# DEPRECATED: this SDK is retired

The VerifIP language SDKs were retired on **2026-09-25** and receive no
further releases or fixes. The last version is 0.2.0. It keeps working, but
it will not learn new response fields.

**Use the HTTPS API directly.** It is one header and one JSON request:

```bash
curl -H "Authorization: Bearer vip_your_api_key"   "https://verifip.hextner.com/v1/check?ip=185.220.101.1"
```

Copy-paste examples for curl, JavaScript, Python, Go, PHP, Java and Ruby, with
retries, timeouts and connection reuse, are in the VerifIP API guide under
"Integrating without an SDK". For typed models, generate a client from the
OpenAPI spec with openapi-generator.

This repository is archived and read-only.
