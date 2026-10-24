package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type store struct {
	db         *sql.DB
	ca         *x509.Certificate
	caKey      *ecdsa.PrivateKey
	signCert   *x509.Certificate
	signKey    *rsa.PrivateKey
	serverPair tls.Certificate
	cryptoKey  [32]byte
}
type bootstrap struct{ Path, Password string }
type user struct {
	ID       string
	Name     string
	Email    string
	Admin    bool
	Disabled bool
	Groups   []string
}
type application struct {
	ID         string
	Name       string
	Protocol   string
	Redirects  []string
	SecretHash string
	Metadata   string
	Groups     []string
}
type credential struct {
	Fingerprint, UserID, Expires string
	Revoked                      bool
}

const schema = `
PRAGMA foreign_keys=ON;
CREATE TABLE settings(key TEXT PRIMARY KEY,value BLOB NOT NULL);
CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,email TEXT NOT NULL,admin INTEGER NOT NULL DEFAULT 0,disabled INTEGER NOT NULL DEFAULT 0,groups_json TEXT NOT NULL DEFAULT '[]');
CREATE TABLE certificates(fingerprint TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),expires TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE apps(id TEXT PRIMARY KEY,name TEXT NOT NULL,protocol TEXT NOT NULL,redirects_json TEXT NOT NULL,secret_hash TEXT NOT NULL,metadata TEXT NOT NULL,groups_json TEXT NOT NULL);
CREATE TABLE auth_requests(id TEXT PRIMARY KEY,code TEXT UNIQUE,data BLOB NOT NULL,expires INTEGER NOT NULL,consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE tokens(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),client_id TEXT NOT NULL REFERENCES apps(id),scopes TEXT NOT NULL,expires INTEGER NOT NULL,cert_fingerprint TEXT NOT NULL);
CREATE TABLE saml_replays(id TEXT PRIMARY KEY,expires INTEGER NOT NULL);
PRAGMA user_version=1;
`

func randomString(n int) string { return base64.RawURLEncoding.EncodeToString(randomBytes(n)) }
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
func serial() *big.Int { return new(big.Int).SetBytes(randomBytes(20)) }
func fingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}
func secretHash(s string) string { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func encode(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func openStore(c config) (_ *store, boot *bootstrap, err error) {
	if err = os.MkdirAll(c.DataDir, 0700); err != nil {
		return nil, nil, err
	}
	path, err := filepath.Abs(filepath.Join(c.DataDir, "wardstone.db"))
	if err != nil {
		return nil, nil, err
	}
	if info, e := os.Lstat(path); e == nil && !info.Mode().IsRegular() {
		return nil, nil, errors.New("database must be a regular file, not a directory or symlink")
	}
	// O_EXCL distinguishes a truly absent database from an empty/corrupt existing one.
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	fresh := e == nil
	if e != nil && !errors.Is(e, os.ErrExist) {
		return nil, nil, e
	}
	if fresh {
		_ = f.Close()
	}
	uri := url.URL{Scheme: "file", Path: path}
	q := url.Values{"_pragma": {"foreign_keys(1)", "busy_timeout(5000)"}}
	uri.RawQuery = q.Encode()
	db, e := sql.Open("sqlite", uri.String())
	if e != nil {
		return nil, nil, e
	}
	db.SetMaxOpenConns(1)
	s := &store{db: db}
	defer func() {
		if err != nil {
			_ = db.Close()
			if fresh {
				_ = os.Remove(path)
				_ = os.Remove(path + "-journal")
			}
		}
	}()
	if fresh {
		boot, err = s.initialize(c)
		if err != nil {
			return nil, nil, fmt.Errorf("first-boot initialization: %w", err)
		}
	} else {
		var version int
		if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
			return nil, nil, err
		}
		if version != 1 {
			return nil, nil, errors.New("existing database is uninitialized or unsupported; refusing to bootstrap over it")
		}
	}
	if err = s.loadKeys(); err != nil {
		return nil, nil, err
	}
	return s, boot, nil
}

func (s *store) initialize(c config) (*bootstrap, error) {
	if err := os.MkdirAll(c.BootstrapDir, 0700); err != nil {
		return nil, err
	}
	bundlePath := filepath.Join(c.BootstrapDir, "administrator.p12")
	if _, err := os.Lstat(bundlePath); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("administrator.p12 already exists or is inaccessible; refusing to overwrite it")
	}
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caT := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Wardstone Client CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	ca, err := makeCertificate(caT, caT, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	s.ca = ca
	s.caKey = caKey
	signKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	signT := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Wardstone Federation Signing"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(5, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	// Federation keys are independent of the client CA and are never usable for client authentication.
	signCert, err := makeCertificate(signT, signT, &signKey.PublicKey, signKey)
	if err != nil {
		return nil, err
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	issuer, err := url.Parse(c.Issuer)
	if err != nil {
		return nil, err
	}
	serverT := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: issuer.Hostname()}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(issuer.Hostname()); ip != nil {
		serverT.IPAddresses = []net.IP{ip}
	} else {
		serverT.DNSNames = []string{issuer.Hostname()}
	}
	serverCert, err := makeCertificate(serverT, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	u := user{ID: uuid.NewString(), Name: "administrator", Admin: true, Groups: []string{"administrators"}}
	client, clientKey, err := s.clientCertificate(u)
	if err != nil {
		return nil, err
	}
	password := randomString(24)
	bundle, err := pkcs12.Modern.Encode(clientKey, client, []*x509.Certificate{ca}, password)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(schema); err != nil {
		return nil, err
	}
	caDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return nil, err
	}
	signDER, err := x509.MarshalPKCS8PrivateKey(signKey)
	if err != nil {
		return nil, err
	}
	serverDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return nil, err
	}
	values := map[string][]byte{"ca_cert": ca.Raw, "ca_key": caDER, "sign_cert": signCert.Raw, "sign_key": signDER, "server_cert": serverCert.Raw, "server_key": serverDER, "crypto_key": randomBytes(32)}
	for key, value := range values {
		if _, err = tx.Exec("INSERT INTO settings VALUES(?,?)", key, value); err != nil {
			return nil, err
		}
	}
	if _, err = tx.Exec("INSERT INTO users(id,name,email,admin,groups_json) VALUES(?,?,?,1,?)", u.ID, u.Name, "", encode(u.Groups)); err != nil {
		return nil, err
	}
	if _, err = tx.Exec("INSERT INTO certificates VALUES(?,?,?,0)", fingerprint(client), u.ID, client.NotAfter.Format(time.RFC3339)); err != nil {
		return nil, err
	}
	// Reserve the final bundle path without following symlinks or overwriting old credentials.
	out, err := os.OpenFile(bundlePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	published := false
	defer func() {
		out.Close()
		if !published {
			_ = os.Remove(bundlePath)
		}
	}()
	if _, err = out.Write(bundle); err != nil {
		return nil, err
	}
	if err = out.Sync(); err != nil {
		return nil, err
	}
	if err = out.Close(); err != nil {
		return nil, err
	}
	if err = writePublic(filepath.Join(c.BootstrapDir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	published = true
	return &bootstrap{bundlePath, password}, nil
}
func writePublic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".ca-*.crt")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Chmod(0644); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func makeCertificate(t, parent *x509.Certificate, pub, key any) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, t, parent, pub, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}
func (s *store) loadKeys() error {
	get := func(k string) ([]byte, error) {
		var b []byte
		err := s.db.QueryRow("SELECT value FROM settings WHERE key=?", k).Scan(&b)
		return b, err
	}
	raw, err := get("ca_cert")
	if err != nil {
		return err
	}
	s.ca, err = x509.ParseCertificate(raw)
	if err != nil {
		return err
	}
	raw, err = get("ca_key")
	if err != nil {
		return err
	}
	key, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return err
	}
	var ok bool
	s.caKey, ok = key.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("invalid CA key type")
	}
	raw, err = get("sign_cert")
	if err != nil {
		return err
	}
	s.signCert, err = x509.ParseCertificate(raw)
	if err != nil {
		return err
	}
	raw, err = get("sign_key")
	if err != nil {
		return err
	}
	key, err = x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return err
	}
	s.signKey, ok = key.(*rsa.PrivateKey)
	if !ok {
		return errors.New("invalid signing key type")
	}
	raw, err = get("crypto_key")
	if err != nil {
		return err
	}
	if len(raw) != 32 {
		return errors.New("invalid encryption key")
	}
	copy(s.cryptoKey[:], raw)
	cert, err := get("server_cert")
	if err != nil {
		return err
	}
	raw, err = get("server_key")
	if err != nil {
		return err
	}
	s.serverPair, err = tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
	return err
}
func (s *store) pool() *x509.CertPool { p := x509.NewCertPool(); p.AddCert(s.ca); return p }
func (s *store) clientCertificate(u user) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	now := time.Now().UTC()
	end := now.AddDate(1, 0, 0)
	if end.After(s.ca.NotAfter) {
		end = s.ca.NotAfter
	}
	if !end.After(now) {
		return nil, nil, errors.New("client CA has expired")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	uri := &url.URL{Scheme: "urn", Opaque: "wardstone:user:" + u.ID}
	t := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: u.Name}, URIs: []*url.URL{uri}, NotBefore: now.Add(-time.Minute), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	cert, err := makeCertificate(t, s.ca, &key.PublicKey, s.caKey)
	return cert, key, err
}
func scanUser(row interface{ Scan(...any) error }) (user, error) {
	var u user
	var g string
	err := row.Scan(&u.ID, &u.Name, &u.Email, &u.Admin, &u.Disabled, &g)
	if err == nil {
		err = json.Unmarshal([]byte(g), &u.Groups)
	}
	return u, err
}
func (s *store) getUser(id string) (user, error) {
	return scanUser(s.db.QueryRow("SELECT id,name,email,admin,disabled,groups_json FROM users WHERE id=?", id))
}
func (s *store) getApp(id string) (application, error) {
	var a application
	var r, g string
	err := s.db.QueryRow("SELECT id,name,protocol,redirects_json,secret_hash,metadata,groups_json FROM apps WHERE id=?", id).Scan(&a.ID, &a.Name, &a.Protocol, &r, &a.SecretHash, &a.Metadata, &g)
	if err == nil {
		err = json.Unmarshal([]byte(r), &a.Redirects)
	}
	if err == nil {
		err = json.Unmarshal([]byte(g), &a.Groups)
	}
	return a, err
}
func (s *store) allowed(uid, appID string) bool {
	u, err := s.getUser(uid)
	if err != nil || u.Disabled {
		return false
	}
	a, err := s.getApp(appID)
	if err != nil {
		return false
	}
	for _, ug := range u.Groups {
		for _, ag := range a.Groups {
			if ug == ag {
				return true
			}
		}
	}
	return false
}
func groups(text string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, g := range strings.Split(text, ",") {
		g = strings.TrimSpace(g)
		if g != "" && !seen[g] {
			out = append(out, g)
			seen[g] = true
		}
	}
	return out
}
func (s *store) maintain(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, table := range []string{"auth_requests", "tokens", "saml_replays"} {
				_, _ = s.db.ExecContext(ctx, "DELETE FROM "+table+" WHERE expires<?", time.Now().Unix())
			}
		}
	}
}
