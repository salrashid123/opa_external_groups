package envoy.authz

import input.attributes.request.http as http_request

import future.keywords.in

jwks = `{
  "keys": [
    {
      "e": "AQAB",
      "kid": "DHFbpoIUqrY8t2zpA2qXfCmr5VO5ZEr4RzHU_-envvQ",
      "kty": "RSA",
      "n": "xAE7eB6qugXyCAG3yhh7pkDkT65pHymX-P7KfIupjf59vsdo91bSP9C8H07pSAGQO1MV_xFj9VswgsCg4R6otmg5PV2He95lZdHtOcU5DXIg_pbhLdKXbi66GlVeK6ABZOUW3WYtnNHD-91gVuoeJT_DwtGGcp4ignkgXfkiEm4sw-4sfb4qdt5oLbyVpmW6x9cfa7vs2WTfURiCrBoUqgBo_-4WTiULmmHSGZHOjzwa8WtrtOQGsAFjIbno85jp6MnGGGZPYZbDAa_b3y5u-YpW7ypZrvD8BgtKVjgtQgZhLAGezMt0ua3DRrWnKqTZ0BJ_EyxOGuHJrLsn00fnMQ"
    }
  ]
}`

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

token = {"valid": valid, "payload": payload} {
    [_, jwt] := split(http_request.headers.authorization, " ")
    valid := io.jwt.verify_rs256(jwt, jwks)
    [_, payload, _] := io.jwt.decode(jwt) 
    payload.iss == "foo.bar"
}

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


external_data = {"upstream_status_code": upstream_status_code, "upstream_body": upstream_body} {
  r := http.send({"method": "POST", "url": "https://server.domain.com:8443/authz", "body": token.payload.sub, "timeout": "3s", "force_cache": true, "force_cache_duration_seconds": 1, "tls_ca_cert": ca_cert})
  upstream_status_code := r.status_code 
  upstream_body := r.body
}


allow  = response {
    is_in_security_group
    not prohibited_header
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

is_token_valid {
  token.valid
  token.payload.aud == "bar.bar"
  token.payload.iat <= time.now_ns() < token.payload.exp
}

prohibited_header {
  http_request.headers.foo == "bar"
}

action_allowed {
  http_request.method == "GET"
  token.payload.role == "admin"
  glob.match("/get*", [], http_request.path)
}

action_allowed {
  http_request.method == "POST"
  token.payload.role == "admin"
  glob.match("/post*", [], http_request.path)
}