// Command smokeclient verifies the container's first-boot credential over HTTPS.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func check(base, directory, password string) error {
	ca, err := os.ReadFile(filepath.Join(directory, "ca.crt"))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return errors.New("invalid CA export")
	}
	bundle, err := os.ReadFile(filepath.Join(directory, "administrator.p12"))
	if err != nil {
		return err
	}
	key, cert, chain, err := pkcs12.DecodeChain(bundle, password)
	if err != nil {
		return fmt.Errorf("decode P12: %w", err)
	}
	pair := tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
	for _, c := range chain {
		pair.Certificate = append(pair.Certificate, c.Raw)
	}
	client := func(certs []tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: certs}}, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	anonymous, authenticated := client(nil), client([]tls.Certificate{pair})
	defer anonymous.CloseIdleConnections()
	defer authenticated.CloseIdleConnections()
	for _, test := range []struct {
		client *http.Client
		path   string
		status int
	}{{anonymous, "/healthz", 200}, {anonymous, "/admin", 401}, {authenticated, "/admin", 200}} {
		response, err := test.client.Get(base + test.path)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if err != nil {
			return err
		}
		if response.StatusCode != test.status {
			return fmt.Errorf("%s returned %d, expected %d", test.path, response.StatusCode, test.status)
		}
		if test.status == 200 && test.path == "/admin" && !strings.Contains(string(body), "Wardstone") {
			return errors.New("admin UI missing")
		}
	}
	fmt.Println("HTTPS health=200; anonymous admin=401; P12-authenticated admin=200")
	return nil
}
func main() {
	base := flag.String("url", "https://wardstone-smoke:8443", "HTTPS origin")
	directory := flag.String("bootstrap", "/bootstrap", "P12 and CA export directory")
	flag.Parse()
	password, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr, "Read bootstrap password from stdin:", err)
		os.Exit(1)
	}
	if err = check(*base, *directory, strings.TrimSpace(password)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
