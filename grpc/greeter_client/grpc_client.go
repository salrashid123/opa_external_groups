package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"time"

	"github.com/salrashid123/go-grpc-bazel-docker/echo"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	grpcMetadata "google.golang.org/grpc/metadata"
)

var (
	address         = flag.String("host", "localhost:50051", "host:port of gRPC server")
	insecure        = flag.Bool("insecure", false, "connect without TLS")
	skipHealthCheck = flag.Bool("skipHealthCheck", false, "Skip Initial Healthcheck")
	tlsCACert       = flag.String("cacert", "../certs/tls-ca.crt", "tls CA Certificate")
	authToken       = flag.String("authToken", "../certs/grpc.key", "AuthTOken to send")
	serverName      = flag.String("servername", "grpc.yourdomain.com", "CACert for server")
	payloadData     = flag.String("payloadData", "iamtheeggman", "grpcMessage name")
)

const ()

func main() {
	flag.Parse()

	// Set up a connection to the server.
	var err error
	var conn *grpc.ClientConn
	if *insecure == true {
		conn, err = grpc.Dial(*address, grpc.WithInsecure())
	} else {

		var tlsCfg tls.Config
		rootCAs := x509.NewCertPool()
		pem, err := ioutil.ReadFile(*tlsCACert)
		if err != nil {
			log.Fatalf("failed to load root CA certificates  error=%v", err)
		}
		if !rootCAs.AppendCertsFromPEM(pem) {
			log.Fatalf("no root CA certs parsed from file ")
		}
		tlsCfg.RootCAs = rootCAs
		tlsCfg.ServerName = *serverName

		ce := credentials.NewTLS(&tlsCfg)
		conn, err = grpc.Dial(*address, grpc.WithTransportCredentials(ce))
	}
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	c := echo.NewEchoServerClient(conn)
	ctx := context.Background()
	ctx = grpcMetadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+*authToken)
	ctx = grpcMetadata.AppendToOutgoingContext(ctx, "xfoo", "bar")

	// how to perform healthcheck request manually:
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	if !*skipHealthCheck {
		resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{Service: "echo.EchoServer"})
		if err != nil {
			log.Fatalf("HealthCheck failed %+v", err)
		}

		if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			log.Fatalf("service not in serving state: ", resp.GetStatus().String())
		}
		log.Printf("RPC HealthChekStatus: %v\n", resp.GetStatus())
	}

	// ******** Unary Request
	r, err := c.SayHelloUnary(ctx, &echo.EchoRequest{Name: *payloadData})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Unary Request Response:  %s", r.Message)

}
