package envoy.authz

import input.attributes.request.http as http_request

import future.keywords.in

ca_cert = `-----BEGIN CERTIFICATE-----
MIIEDTCCAvWgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJVUzEP
MA0GA1UECgwGR29vZ2xlMRMwEQYDVQQLDApFbnRlcnByaXNlMRswGQYDVQQDDBJF
bnRlcnByaXNlIFJvb3QgQ0EwHhcNMjIwMTA5MjIwNTQzWhcNMzIwMTA5MjIwNTQz
WjBXMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGR29vZ2xlMRMwEQYDVQQLDApFbnRl
cnByaXNlMSIwIAYDVQQDDBlFbnRlcnByaXNlIFN1Ym9yZGluYXRlIENBMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzQESuYrJ5UvVzNl6K9HL2wIjKpi1
ZmUNNlDonwIG/8Oqppv8Ll55uK5LsQnPEPjiu6dxeO7LH/YMZDIZMYSn626QKS6c
BQ67WWHp2xvb4zXIpjnwLt6FX++ps8yZNwPnT6ykzUUdTgvDPHziscqv8iBiNJv0
zsmT9syZNfXyFMMQVPvIlE7hB45xjGGnJ5zHSWrIXz0ik4Jh7IBRhM4LM7ki7uVP
q6195cB63L9HHwRzfpaGbusptEymRbnjTYEru/xIHH71JRlBJKI6s5fx1iaAzOHw
4+bQOsvfc3lr5nsyDOPukvne3rLSUPkgSYLtlEvPewp35wHiXlDsEgMs7wIDAQAB
o4HqMIHnMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud
DgQWBBS3urACoee+NMbBBVxmeOW7U12hVDAfBgNVHSMEGDAWgBR8HFvoPrMzCZaS
Mth/RL/MjJOckjBFBggrBgEFBQcBAQQ5MDcwNQYIKwYBBQUHMAKGKWh0dHA6Ly9w
a2kuZXNvZGVtb2FwcDIuY29tL2NhL3Jvb3QtY2EuY2VyMDoGA1UdHwQzMDEwL6At
oCuGKWh0dHA6Ly9wa2kuZXNvZGVtb2FwcDIuY29tL2NhL3Jvb3QtY2EuY3JsMA0G
CSqGSIb3DQEBCwUAA4IBAQDCrrAwdeRQMovu00ws8I3reUIMEdtsFwLRShu0ggVh
GHMH1vGDpdRJoaSpCGdCcPv1IA0BkL6969df1GDUxQOWbiLajyQ5S6fVFgZ/yIbn
3SzMw7Dubig2i9xJo9laPpjjjM/gF6bBSxdhoLUKLFf0e82FCuAPXskeiW7Bc1XB
3ui4xgPNVz3THu8Ma9z/fTJRohrC8t1C/pab7TQpcQR6XkRrX5Sb/MM6TnFew7sD
5cuFT7o/DvbWT42/UP2nuNi591TIGYDJBCKBqnd0AH6Rz+VTyeRUVp4j21ExtzL0
JKmN1S+dmP5W6P1EV+ztEllKEV3N/e6r655wlDG/0y7G
-----END CERTIFICATE-----`

default allow = false

headers["x-ext-auth-allow"] := "yes"
headers["x-validated-by"] := "security-checkpoint"
headers["x-google-groups"] := concat(" ",external_data.upstream_body["groups"])
request_headers_to_remove := ["xfoo"]
response_headers_to_add["response-header-key-1"] :=  "resp_value_1"


status_code := 200 {
  is_in_security_group
} else = 401 {
  not is_in_security_group
} else = 403 {
  not is_in_security_group
}

body := "ok" { status_code == 200 }
body := "Authentication Failed" { status_code == 401 }
body := "Unauthorized Request" { status_code == 403 }

jwt_payload = _value {
    verified_jwt := input.attributes.metadataContext.filterMetadata["envoy.filters.http.jwt_authn"]["verified_jwt"]
    _value := {
        "role": verified_jwt["role"],
        "aud": verified_jwt["aud"],
        "sub": verified_jwt["sub"]
    }
}

external_data = {"upstream_status_code": upstream_status_code, "upstream_body": upstream_body} {
  r := http.send({"method": "POST", "url": "https://server.yourdomain.com:8443/authz", "body":  jwt_payload.sub, "timeout": "3s", "force_cache": true, "force_cache_duration_seconds": 1, "tls_ca_cert": ca_cert})
  upstream_status_code := r.status_code 
  upstream_body := r.body
}


allow  = response {
    is_in_security_group
    not prohibited_header
    jwt_payload.aud == "bar.bar"
    action_allowed
    response := {
      "allowed": true,
      "headers": headers,
      "response_headers_to_add": response_headers_to_add,
      "request_headers_to_remove": request_headers_to_remove,
      "body": body,
      "http_status": status_code
    }
}

is_in_security_group {
  external_data.upstream_status_code == 200
  some "securitygroup1@domain.com" in external_data.upstream_body["groups"] 
}

prohibited_header {
  http_request.headers.foo == "bar"
}

action_allowed {
  http_request.method == "GET"
  glob.match("/get*", [], http_request.path)
}

action_allowed {
  http_request.method == "POST"
  glob.match("/post*", [], http_request.path)
}