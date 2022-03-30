package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"tls-test/tls"
)

// Test certificate copied from the Go tls test cases.

var defaultCertPem = []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`)

var defaultKeyPem = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`)

func main() {
	var err error

	listenAddr := flag.String("listenAddr", ":3333", "Address to listen on.")
	certFile := flag.String("certFile", "", "PEM-encoded X509 certificate file to use.")
	keyFile := flag.String("keyFile", "", "PEM-encoded X509 key file to use.")
	flag.Parse()

	certPem := defaultCertPem
	keyPem := defaultKeyPem

	// Read key-pair files, if specified.
	if *certFile != "" {
		certPem, err = os.ReadFile(*certFile)
		if err != nil {
			log.Fatalf("Error reading certificate file %q: %v", *certFile, err)
		}
	}
	if *keyFile != "" {
		keyPem, err = os.ReadFile(*keyFile)
		if err != nil {
			log.Fatalf("Error reading key file %q: %v", *keyFile, err)
		}
	}

	// Parse keypair.
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		log.Fatalf("Error parsing PEM-encoded X509 key pair: %v", err)
	}

	// Set up TLS configuration. Disable TLS 1.3.
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MaxVersion:   tls.VersionTLS12,
	}

	l, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("Error listening on TCP port: %v", err)
	}
	tlsl := tls.NewListener(l, cfg)

	log.Printf("Listening on %s", *listenAddr)
	err = http.Serve(tlsl, http.NotFoundHandler())
	if err != nil {
		log.Fatalf("Error in http.Serve: %v", err)
	}
}
