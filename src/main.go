package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type config struct{ DataDir, BootstrapDir, Issuer, Listen, TLSCert, TLSKey string }

func env(k, v string) string {
	if s := os.Getenv(k); s != "" {
		return s
	}
	return v
}
func main() {
	c := config{env("WARDSTONE_DATA_DIR", "/data"), env("WARDSTONE_BOOTSTRAP_DIR", "/bootstrap"), env("WARDSTONE_ISSUER", "https://localhost:8443"), env("WARDSTONE_LISTEN", ":8443"), os.Getenv("WARDSTONE_TLS_CERT"), os.Getenv("WARDSTONE_TLS_KEY")}
	if err := run(c); err != nil {
		log.Fatal(err)
	}
}
func run(c config) error {
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("WARDSTONE_ISSUER must be an HTTPS origin without a path")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("provide both WARDSTONE_TLS_CERT and WARDSTONE_TLS_KEY")
	}
	s, boot, err := openStore(c)
	if err != nil {
		return err
	}
	defer s.db.Close()
	// Emit immediately after persistence, including if later listener setup fails.
	if boot != nil {
		log.Printf("BOOTSTRAP administrator certificate: %s", boot.Path)
		log.Printf("BOOTSTRAP administrator P12 password: %s", boot.Password)
	}
	a, err := newApp(c, s)
	if err != nil {
		return err
	}
	pair := s.serverPair
	if c.TLSCert != "" {
		pair, err = tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			return err
		}
	}
	server := &http.Server{Addr: c.Listen, Handler: a.handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientCAs: s.pool(), ClientAuth: tls.VerifyClientCertIfGiven}}
	listener, err := tls.Listen("tcp", c.Listen, server.TLSConfig)
	if err != nil {
		return err
	}
	defer listener.Close()
	// The sole intentional credential log: the user-requested first-boot P12 password.
	log.Printf("Wardstone listening at %s; import the administrator P12 to open /admin", c.Issuer)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go s.maintain(ctx)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
