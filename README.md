## Authorization Control using OpenPolicy Agent and Google Groups

Tutorial to setup [OpenPolicy Agent](https://www.openpolicyagent.org/) where authorization decisions are based using the groups a Google CLoud Identity user is a direct or indirect member of.

Normally, OPA decisions use signals sent to it by the requestor and combines that with data it loads either using its [push or pull model](https://www.openpolicyagent.org/docs/latest/philosophy/#the-opa-document-model).  Basically it requires a system to populate its information that it uses to make authroization decisions. 

If you want to make a decision based on a user's google workspace/cloud identity groups, you could seed OPA with all the groups data...but you'll need to know about changes in membership and refresh OPA.   Thats the problem:  google cloud identity doesn't have any immediate, low latency way to 'get notified' of membership changes.  Sure you can use the [Group Audit Log Events](https://support.google.com/a/answer/6270454?hl=en) but that can take hours to update an event...you need these updates faster.

This sample uses OPA's [External Data: Pull Data during Evaluation](https://www.openpolicyagent.org/docs/latest/external-data/#option-5-pull-data-during-evaluation) mechanism to load the groups a user is a member of at runtime.

We're using Envoy as the frontend proxy that calls out to OPA for authorization decisions...however you can use the `OPA` and `Groups Lookup Server` for **any other service that integrates with OPA**...you just need a way to provide OPA's with the username to lookup...

Anyway, we'll use envoy and the [OPA-Envoy Plugin](https://www.openpolicyagent.org/docs/latest/envoy-introduction/)

![images/arch.png](images/arch.png)


The OPA plugin basically functions as a self contained `external_authorization server` for envoy and provides access decisions back to envoy.  OPA itself has authorization policies defined inside its own rego which means it is in exclusive control for the authorization decisions when it comes to group membership.

For more information about other options for external authorization Envoy, see

* [Envoy External Processing Filter](https://blog.salrashid.dev/articles/2021/envoy_ext_proc/)
* [Envoy External Authorization server (envoy.ext_authz) with OPA HelloWorld](https://blog.salrashid.dev/articles/2019/envoy_external_authz/)

---


Lets get started...for this demo, we will run everything locally...i know, OPA, envoy and whatnot usually works with kubernetes ...but this is my demo to show you the component interactions and integration.



### Setup

First edit `/etc/hosts` and add on some hosts to make life a bit easier...

```bash
127.0.0.1	grpc.domain.com envoy.domain.com server.domain.com redis.domain.com
```

I used my own CA for these certs...if you want you can generate your own here ([CA_scratchpad](https://github.com/salrashid123/ca_scratchpad))

To run this demo, you'll also need the following:  `golang`, `docker`, `python3`

Once you have that, get a copy of the Envoy binary (you can also use envoy+dockerimage but i find this easier...)

```bash
docker cp `docker create envoyproxy/envoy-dev:latest`:/usr/local/bin/envoy /tmp/envoy
```

This demo will use a JWT sent over by a client that will get validated by either Envoy or OPA, then using the embedded claims, issue an API call to an external groups server for group memebership info.  OPA uses the group membership to make the final decision.

There are two modes you can run OPA here...pick either A or B..it just depends on what you what to test:


#### A) Envoy JWT Validation

In ths mode, Envoy will first validate the JWT provided to it and hand off the decoded JWT to OPA as [Envoy Dynamic Metadata](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/data_sharing_between_filters).   Since envy will validate the JWT, all OPA has to do is parse and make the external call.

To use the mode, run

```bash
docker run -p 8181:8181 -p 9191:9191 \
   --net=host \
   -v `pwd`/opa_policy:/policy \
   -v `pwd`/opa_config:/config openpolicyagent/opa:latest-envoy run \
   --server --addr=localhost:8181 \
      --set=plugins.envoy_ext_authz_grpc.addr=:9191 \
      --set=plugins.envoy_ext_authz_grpc.enable-reflection=true \
      --set=plugins.envoy_ext_authz_grpc.path=envoy/authz/allow \
      --set=status.console=true \
      --set=decision_logs.console=true --log-level=debug --log-format json-pretty \
      --ignore=.* /policy/policy_jwt.rego
```

Then run envoy with JWT validation filter enabled

```bash
cd envoy/
/tmp//envoy -c envoy_jwt.yaml -l trace
```

#### B) OPA JWT Validation

In this mode, the JWT is not validated by envoy and is simply sent to OPA as-is. OPA loads the public certificate that issued the JWT and validates then extracts the claims.

To use the mode, run:

```bash
docker run -p 8181:8181 -p 9191:9191 \
   --net=host \
   -v `pwd`/opa_policy:/policy \
   -v `pwd`/opa_config:/config openpolicyagent/opa:latest-envoy run \
   --server --addr=localhost:8181 \
      --set=plugins.envoy_ext_authz_grpc.addr=:9191 \
      --set=plugins.envoy_ext_authz_grpc.enable-reflection=true \
      --set=plugins.envoy_ext_authz_grpc.path=envoy/authz/allow \
      --set=status.console=true \
      --set=decision_logs.console=true --log-level=debug --log-format json-pretty \
      --ignore=.* /policy/policy_passthrough.rego
```

And its corresponding envoy filter

```bash
cd envoy/
./envoy -c envoy_passthrough.yaml -l debug
```

#### Cache Options

Since we're loading data from an external source, it'd help if we could cache the data.  

There are again two options here which you ca use independently from the section above.

You can either have a global shared cache or a per-opa local cache


- `A) Global Redis server`

You can either run a common `Redis` Server which can hold (with a TTL) the various groups a user is a member of.

This cache is filled in at runtime so when a user's jwt is first presented, the groups server will lookup the user's groups and save it into Redis with an auto-expiring TTL.

If you want to suse this mode, run redis

```bash
docker run -ti --net=host -p 6379:6379  redis:latest
```

- `B) Local OPA Cache`

OPA usually loads data locally and uses that to make decisions and to the cache is determined by its pull or push scheme.

External HTTP datasources, however, allows you to define how long to cache the response.  To use this,  edit `*.rego` and set the value for (`"force_cache_duration_seconds"`):

```r
r := http.send({"method": "POST", "url": "https://server.domain.com:8443/authz", "body":  jwt_payload.sub, "timeout": "3s", "force_cache": true, "force_cache_duration_seconds": 1, "tls_ca_cert": ca_cert})
```

for more information, see [OPA External Pull Performance and Availability](https://www.openpolicyagent.org/docs/latest/external-data/#recommended-usage-highly-dynamic-or-large-sized-data)


#### Groups Lookup External Datasource

We're finally rady to start our external groups lookups server. 

The specific API that enables this mode is described here:

* [Search Transitive Group Membership using Google Cloud Identity](https://blog.salrashid.dev/articles/2022/search_group_membership/)


Its a lot to get setup and you as a reader probably dont' have the time or access to do this..

to help with that, i've faked the groups lookup server for local testing by defining a set of static users and groups they are members of:




```golang
	mocks               = map[string]groupsStruct{
		"alice@domain.com": {
			Groups: []string{"securitygroup1@domain.com", "group_of_groups_1@domain.com", "group8_10@domain.com", "group4_7@domain.com", "deniedgcs@domain.com", "all_users_group@domain.com"},
		},
		"bob@domain.com": {
			Groups: []string{"all_users_group@domain.com"},
		},
	}
```

so, lets start the server

```bash
## Start groups server
cd groups_server
go run server.go 
```


If you want to use redis, specify the `--useRedis` flag when starting the groups_server, the default is to use the fakes and no redis

```golang
  -tlsCert string
    	Public x509 (default "../certs/server.crt")
  -tlsKey string
    	Private Key (default "../certs/server.key")
  -useCloudIdentityAPI
    	Use mock Groups
  -useRedis
    	Use redis cache
```

You can test the local group server using the curl (this is what opa will be calling anyway)

```bash
$ curl -s --cacert certs/root-ca.crt  -X POST --resolve  server.domain.com:8081:127.0.0.1  --data "alice@domain.com" https://server.domain.com:8443/authz | jq '.'
{
  "groups": [
    "securitygroup1@domain.com",
    "group_of_groups_1@domain.com",
    "group8_10@domain.com",
    "group4_7@domain.com",
    "deniedgcs@domain.com",
    "all_users_group@domain.com"
  ]
}
```

#### Test Client

We're now ready to run the test client testing all this:

Fist we need a JWT...included in this repo is a handy script from istio i'm borrowing:

```bash
cd jwt_generator
export ADMIN_TOKEN=`python3 gen-jwt.py -iss foo.bar -aud bar.bar -sub alice@domain.com -claims role:admin -expire 100000 key.pem`
```

You can see the specifics of this JWT at [jwt.io](jwt.io)

```json
{
  "alg": "RS256",
  "kid": "DHFbpoIUqrY8t2zpA2qXfCmr5VO5ZEr4RzHU_-envvQ",
  "typ": "JWT"
}
{
  "aud": "bar.bar",
  "exp": 1653086822,
  "iat": 1652986822,
  "iss": "foo.bar",
  "role": "admin",
  "sub": "alice@domain.com"
}
```

Notice the `aud`, `iss` and `sub` fields...we will use these in the OPA policies.


Now use this token to call envoy

```bash
$ curl -s -H "Authorization: Bearer $ADMIN_TOKEN" --cacert certs/root-ca.crt  --resolve  envoy.domain.com:8081:127.0.0.1  -H "xfoo: bar" https://envoy.domain.com:8080/get

> GET /get HTTP/1.1
> Host: envoy.domain.com:8080
> User-Agent: curl/7.82.0
> Accept: */*
> Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IkRIRmJwb0lVcXJZOHQyenBBMnFYZkNtcjVWTzVaRXI0UnpIVV8tZW52dlEiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJiYXIuYmFyIiwiZXhwIjoxNjUzMDg2OTQ2LCJpYXQiOjE2NTI5ODY5NDYsImlzcyI6ImZvby5iYXIiLCJyb2xlIjoiYWRtaW4iLCJzdWIiOiJhbGljZUBkb21haW4uY29tIn0.GPqG0kke_Lhc3Ma3Cl0H592w_v5Szl7qUyih26ftor6DK0FPCUaD8YueK4eOezYu4j8DMfTz1t-m-oSUcNKA_B9W1FkQy4S2AxtcI2LeG3Ffd6q0Yf0LPokxe1E3lkeumsn_NAw3gvzLaRDqMtZmK-1Qe_o6msPWaiPXpIoSeRSRrDusNRClt30mLKtBQgrnHxtN6Tfg3MnRRd9vycOCvNtNjk0_oE9VsrkKyIiPkS96fLgz_lQ-US51pPcKC6ChMQRJnm0k3eQJPD6XnDUTFjrXCQDyUSfgD7oRwr8JyNGSCrzCthN0Q_UPeZFmLzJ1ab9kHKStAHR0neEbmecuSQ
> xfoo: bar

< HTTP/1.1 200 OK
< date: Thu, 19 May 2022 19:02:57 GMT
< content-type: application/json
< content-length: 569
< server: envoy
< access-control-allow-origin: *
< access-control-allow-credentials: true
< x-envoy-upstream-service-time: 23
< response-header-key-1: resp_value_1
< 
{
  "args": {}, 
  "headers": {
    "Accept": "*/*", 
    "Host": "envoy.domain.com", 
    "User-Agent": "curl/7.82.0", 
    "X-Amzn-Trace-Id": "Root=1-62869461-435c1d3b5cd1748d6fec7142", 
    "X-Envoy-Expected-Rq-Timeout-Ms": "15000", 
    "X-Ext-Auth-Allow": "yes", 
    "X-Google-Groups": "securitygroup1@domain.com group_of_groups_1@domain.com group8_10@domain.com group4_7@domain.com deniedgcs@domain.com all_users_group@domain.com", 
    "X-Validated-By": "security-checkpoint"
  }, 
  "origin": "72.83.67.174", 
  "url": "https://envoy.domain.com/get"
}
```

What your'e seeing is three parts:

1. request to envoy
2. response from envoy
3. the request from envoy that httpbin.org/get actually saw.

Our OPA rules stipulated that we should add the groups information to the output request

```
headers["x-ext-auth-allow"] := "yes"
headers["x-validated-by"] := "security-checkpoint"
headers["x-google-groups"] := concat(" ",external_data.upstream_body["groups"])
request_headers_to_remove := ["xfoo"]
response_headers_to_add["response-header-key-1"] :=  "resp_value_1"
```

and thats exactly what we see...the upstream service (httpbin in our case) will get to see the groups this user is a member of!


#### gRPC


Envoy is very `grpc-first`...it has really good grpc handling capabilities.  

OPA-Envoy plugin leverages all that to allow you to _inspect and make decisions_ based on the gRPC Probuf messages!

 (well, [in a limited way](https://www.openpolicyagent.org/docs/v0.27.1/envoy-introduction/#configuration): just unary requests w/o compression)

Anyway, i think its nice so lets see this in action:

For this we will need a grpc client and server, then envoy that uses grpc and an OPA rego that will parse out and decode the message

In our case the Message proto is trivial:

```proto
syntax = "proto3";
package echo;

service EchoServer {
  rpc SayHelloUnary (EchoRequest) returns (EchoReply) {}
}

message EchoRequest {
  string name = 1;
}

message EchoReply {
  string message = 1;
}
```

Start gRPC Server

```bash
cd grpc/
go run greeter_server/grpc_server.go --grpcport :50051 --tlsCert ../certs/grpc.crt --tlsKey ../certs/grpc.key
```

Start Envoy with grpc handlers:

```bash
envoy -c envoy_grpc.yaml -l trace
```

Start OPA with grpc decoding enabled (`--set=plugins.envoy_ext_authz_grpc.proto-descriptor=/proto/echo.proto.pb`)

```bash
docker run -p 8181:8181 -p 9191:9191 \
   --net=host \
   -v `pwd`/opa_policy:/policy \
   -v `pwd`/grpc/echo/echo.proto.pb:/proto/echo.proto.pb \
   -v `pwd`/opa_config:/config openpolicyagent/opa:latest-envoy run \
   --server --addr=localhost:8181 \
      --set=plugins.envoy_ext_authz_grpc.addr=:9191 \
      --set=plugins.envoy_ext_authz_grpc.enable-reflection=true \
      --set=plugins.envoy_ext_authz_grpc.proto-descriptor=/proto/echo.proto.pb \
      --set=plugins.envoy_ext_authz_grpc.path=envoy/authz/allow \
      --set=status.console=true \
      --set=decision_logs.console=true --log-level=debug --log-format json-pretty \
      --ignore=.* /policy/policy_jwt_grpc.rego
```

What this rego does is validates the JWT as in the examples above but it checks for some other stuff:

```r
allow_theeggman {
  http_request.method == "POST"
  glob.match("/echo.EchoServer/SayHelloUnary", [], http_request.path)
  input.parsed_body.name == "iamtheeggman"
}
```

this policy will only work if a specific endpoint is called **AND** if the client emits a gRPC _message_ of Type `EchoRequest` with the payload value of _iamtheeggman_ (yeah, see the command below)

```golang
	ctx = grpcMetadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+*authToken)
	ctx = grpcMetadata.AppendToOutgoingContext(ctx, "xfoo", "bar")
  r, err := c.SayHelloUnary(ctx, &echo.EchoRequest{Name: *payloadData})
```


Get an `ADMIN_TOKEN` using the pythons script above


Test gRPC client...remember to pass in `iamtheeggman` too!

```bash
echo $ADMIN_TOKEN

go run greeter_client/grpc_client.go \
   --host localhost:8080 --cacert ../certs/root-ca.crt \
   --servername envoy.domain.com -skipHealthCheck  \
   --payloadData=iamtheeggman \
   --authToken=$ADMIN_TOKEN 
```

now notice the OPA request it got for evaluation...specifically the `parsed_body`!  thats the decoded protobuf


```json
{
  "decision_id": "c2da69a1-b678-4df4-9055-e8edec379ab2",
  "input": {
    "attributes": {
      "destination": {
        "address": {
          "socketAddress": {
            "address": "127.0.0.1",
            "portValue": 8080
          }
        },
        "principal": "envoy.domain.com"
      },
      "metadataContext": {
        "filterMetadata": {
          "envoy.filters.http.jwt_authn": {
            "verified_jwt": {
              "aud": "bar.bar",
              "exp": 1653086946,
              "iat": 1652986946,
              "iss": "foo.bar",
              "role": "admin",
              "sub": "alice@domain.com"
            }
          }
        }
      },
      "request": {
        "http": {
          "headers": {
            ":authority": "envoy.domain.com",
            ":method": "POST",
            ":path": "/echo.EchoServer/SayHelloUnary",
            ":scheme": "https",
            "content-type": "application/grpc",
            "grpc-timeout": "997788u",
            "te": "trailers",
            "user-agent": "grpc-go/1.33.2",
            "x-envoy-auth-partial-body": "false",
            "x-forwarded-proto": "https",
            "x-request-id": "3a3ae89f-bc08-4216-a520-128c3cc0696d",
            "xfoo": "bar"
          },
          "host": "envoy.domain.com",
          "id": "13150880515659298070",
          "method": "POST",
          "path": "/echo.EchoServer/SayHelloUnary",
          "protocol": "HTTP/2",
          "rawBody": "AAAAAA4KDGlhbXRoZWVnZ21hbg==",
          "scheme": "https",
          "size": "19"
        },
        "time": "2022-05-19T19:14:04.177094Z"
      },
      "source": {
        "address": {
          "socketAddress": {
            "address": "127.0.0.1",
            "portValue": 36564
          }
        }
      }
    },
    "parsed_body": {
      "name": "iamtheeggman"
    },
    "parsed_path": [
      "echo.EchoServer",
      "SayHelloUnary"
    ],
    "parsed_query": {},
    "truncated_body": false,
    "version": {
      "encoding": "protojson",
      "ext_authz": "v3"
    }
  },
  "labels": {
    "id": "42c36cb1-8d64-43a4-b7cf-1c84faec0a45",
    "version": "0.40.0-envoy-1"
  },
  "level": "info",
  "metrics": {
    "timer_rego_builtin_http_send_ns": 3415355,
    "timer_rego_query_compile_ns": 80794,
    "timer_rego_query_eval_ns": 3847696,
    "timer_server_handler_ns": 4795661
  },
  "msg": "Decision Log",
  "path": "envoy/authz/allow",
  "result": {
    "allowed": true,
    "body": "ok",
    "headers": {
      "x-ext-auth-allow": "yes",
      "x-google-groups": "securitygroup1@domain.com group_of_groups_1@domain.com group8_10@domain.com group4_7@domain.com deniedgcs@domain.com all_users_group@domain.com",
      "x-validated-by": "security-checkpoint"
    },
    "http_status": 200,
    "request_headers_to_remove": [
      "xfoo"
    ],
    "response_headers_to_add": {
      "response-header-key-1": "resp_value_1"
    }
  },
  "time": "2022-05-19T19:14:04Z",
  "timestamp": "2022-05-19T19:14:04.183258064Z",
  "type": "openpolicyagent.org/decision_logs"
}
```