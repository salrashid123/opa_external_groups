package envoy.authz

import input.attributes.request.http as http_request

import future.keywords.in

ca_cert = `-----BEGIN CERTIFICATE-----
MIIDdjCCAl6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJVUzEP
MA0GA1UECgwGR29vZ2xlMRMwEQYDVQQLDApFbnRlcnByaXNlMRcwFQYDVQQDDA5T
aW5nbGUgUm9vdCBDQTAeFw0yMzEyMjcxNzM4MDJaFw0zMzEyMjYxNzM4MDJaMEwx
CzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZHb29nbGUxEzARBgNVBAsMCkVudGVycHJp
c2UxFzAVBgNVBAMMDlNpbmdsZSBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAvU5LpbBExIrggs/y4jACCJvDMYIpfEmRJKnr824u+JdRbbJU
vo7pGBjkJG9OnnyCw9EbCnzxb5A3Olwm/0orclPceiKP5asUE+lEvgNgOtDd5ZVh
QIRb5xkBX8aHXUf64gpuvZ17sYisj6OPl7dtVwOjbL97JR7wugnCR34K67jDn+eH
yaFLD3DKdQvus46jmpL2GGVa4DeM70i7zUU1hREZ3Njxb42l1+9IFZ8aR/oW3Xcp
aQZtHtkdT4Zh32u4kfFDtoDkZSBmkKrRTaY9OXyiGY4Wp2Gi8hhLEyXuG3I4uY88
UK3NiPrcCKVnjg+KyGaNE1Akwx+ox6lWf8MVPwIDAQABo2MwYTAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7PDqU1M/nyPcwQ4xEDcH
3t7nbvMwHwYDVR0jBBgwFoAU7PDqU1M/nyPcwQ4xEDcH3t7nbvMwDQYJKoZIhvcN
AQELBQADggEBAHeqVgMEOYb8yGmLwwKuh0Ppr2Zg/fDfmD7z8eq7jhpAzhjStCiT
5E0cFRSJI4UQf8/2N7RkyI5XZ0EuCA8Zh+Z6ikrmk5KWUycZISQ4xy9DZ76khTzk
sBDXFHZI6IHgunomxPMdumG9zZZOnfa25a1qecCJAakem1SVl277mReEf7agBaEL
QabI06QI9tb/bx6Uh9DDS9qKSqpCqGAsVSWxYryjVA7eSjYHeO0q7dDi2EVF805P
HD+lXVm/Xmb09ncbh5DAeJSqqBuDbQ/5gzJbGHgbmUZhZEZhgL3YPWrlb883xr8y
yaBu9JVO3gc1ry7VH51s+7RZ25C7uURDQJI=
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
  r := http.send({"method": "POST", "url": "https://server.domain.com:8443/authz", "body":  jwt_payload.sub, "timeout": "3s", "force_cache": true, "force_cache_duration_seconds": 1, "tls_ca_cert": ca_cert})
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