package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	dsig "github.com/russellhaering/goxmldsig"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func testConfig(t *testing.T) config {
	t.Helper()
	root := t.TempDir()
	return config{DataDir: filepath.Join(root, "data"), BootstrapDir: filepath.Join(root, "bootstrap"), Issuer: "https://localhost:8443"}
}
func mustStore(t *testing.T, c config) (*store, *bootstrap) {
	t.Helper()
	s, b, err := openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.Close() })
	return s, b
}
func decodeBundle(t *testing.T, b []byte, password string) tls.Certificate {
	t.Helper()
	key, cert, chain, err := pkcs12.DecodeChain(b, password)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certs := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	for _, ca := range chain {
		certs = append(certs, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	}
	pair, err := tls.X509KeyPair(certs, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
	if err != nil {
		t.Fatal(err)
	}
	pair.Leaf = cert
	return pair
}
func TestBootstrapAndRestart(t *testing.T) {
	c := testConfig(t)
	s, b := mustStore(t, c)
	if b == nil || len(b.Password) < 32 {
		t.Fatal("missing random bootstrap password")
	}
	bundle, err := os.ReadFile(b.Path)
	if err != nil {
		t.Fatal(err)
	}
	pair := decodeBundle(t, bundle, b.Password)
	if _, _, _, err = pkcs12.DecodeChain(bundle, "wrong password"); err == nil {
		t.Fatal("unencrypted bundle")
	}
	if _, err = pair.Leaf.Verify(x509.VerifyOptions{Roots: s.pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if pair.Leaf.IsCA {
		t.Fatal("administrator is a CA")
	}
	for _, path := range []string{b.Path, filepath.Join(c.DataDir, "wardstone.db")} {
		info, e := os.Stat(path)
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("unsafe permissions for %s", path)
		}
	}
	before := fingerprint(s.ca)
	s.db.Close()
	s2, b2 := mustStore(t, c)
	if b2 != nil {
		t.Fatal("restart regenerated credentials")
	}
	if fingerprint(s2.ca) != before {
		t.Fatal("CA changed")
	}
	after, err := os.ReadFile(b.Path)
	if err != nil || !bytes.Equal(bundle, after) {
		t.Fatal("bundle changed on restart")
	}
	// Losing the output directory must not silently re-bootstrap an existing DB.
	if err = os.Remove(b.Path); err != nil {
		t.Fatal(err)
	}
	s2.db.Close()
	_, b3 := mustStore(t, c)
	if b3 != nil {
		t.Fatal("rebootstrap after lost bundle")
	}
}
func TestBootstrapFailsClosed(t *testing.T) {
	t.Run("empty existing DB", func(t *testing.T) {
		c := testConfig(t)
		os.MkdirAll(c.DataDir, 0700)
		os.WriteFile(filepath.Join(c.DataDir, "wardstone.db"), nil, 0600)
		if s, _, err := openStore(c); err == nil {
			s.db.Close()
			t.Fatal("bootstrapped over existing DB")
		}
	})
	t.Run("bundle collision", func(t *testing.T) {
		c := testConfig(t)
		os.MkdirAll(c.BootstrapDir, 0700)
		p := filepath.Join(c.BootstrapDir, "administrator.p12")
		os.WriteFile(p, []byte("preserve"), 0600)
		if s, _, err := openStore(c); err == nil {
			s.db.Close()
			t.Fatal("overwrote existing bundle")
		}
		data, _ := os.ReadFile(p)
		if string(data) != "preserve" {
			t.Fatal("bundle overwritten")
		}
		if _, err := os.Stat(filepath.Join(c.DataDir, "wardstone.db")); !os.IsNotExist(err) {
			t.Fatal("failed initialization left database")
		}
	})
	t.Run("public CA output failure", func(t *testing.T) {
		c := testConfig(t)
		os.MkdirAll(filepath.Join(c.BootstrapDir, "ca.crt"), 0700)
		if s, _, err := openStore(c); err == nil {
			s.db.Close()
			t.Fatal("expected output failure")
		}
		if _, err := os.Stat(filepath.Join(c.DataDir, "wardstone.db")); !os.IsNotExist(err) {
			t.Fatal("failed initialization left DB")
		}
		if _, err := os.Stat(filepath.Join(c.BootstrapDir, "administrator.p12")); !os.IsNotExist(err) {
			t.Fatal("failed initialization left bundle")
		}
	})
}

type fixture struct {
	t                 *testing.T
	s                 *store
	a                 *app
	server            *httptest.Server
	client, anonymous *http.Client
	admin             user
	cert              tls.Certificate
	csrf              string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	c := testConfig(t)
	c.Issuer = "https://" + srv.Listener.Addr().String()
	s, b := mustStore(t, c)
	a, err := newApp(c, s)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(b.Path)
	if err != nil {
		t.Fatal(err)
	}
	cert := decodeBundle(t, raw, b.Password)
	srv.Config.Handler = a.handler()
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{s.serverPair}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: s.pool()}
	srv.StartTLS()
	mk := func(certs []tls.Certificate) *http.Client {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.pool(), Certificates: certs}}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	}
	f := &fixture{t: t, s: s, a: a, server: srv, client: mk([]tls.Certificate{cert}), anonymous: mk(nil), cert: cert}
	f.admin, err = scanUser(s.db.QueryRow("SELECT id,name,email,admin,disabled,groups_json FROM users WHERE admin=1"))
	if err != nil {
		t.Fatal(err)
	}
	f.csrf = a.csrf(fingerprint(cert.Leaf))
	return f
}
func (f *fixture) request(client *http.Client, method, path string, form url.Values, auth bool) (int, []byte, http.Header) {
	f.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r, err := http.NewRequest(method, f.server.URL+path, body)
	if err != nil {
		f.t.Fatal(err)
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if auth {
		r.SetBasicAuth("test-client", strings.Repeat("s", 32))
	}
	res, err := client.Do(r)
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	return res.StatusCode, b, res.Header
}
func (f *fixture) post(action string, v url.Values) (int, []byte, http.Header) {
	f.t.Helper()
	v.Set("csrf", f.csrf)
	return f.request(f.client, "POST", "/admin/"+action, v, false)
}
func (f *fixture) addOIDC() {
	f.t.Helper()
	_, err := f.s.db.Exec("INSERT INTO apps VALUES(?,?,?,?,?,?,?)", "test-client", "Test app", "oidc", `["https://app.example/callback"]`, secretHash(strings.Repeat("s", 32)), "", `["administrators"]`)
	if err != nil {
		f.t.Fatal(err)
	}
}
func (f *fixture) code() (string, string) {
	f.t.Helper()
	verifier := randomString(32)
	hash := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {"test-client"}, "redirect_uri": {"https://app.example/callback"}, "response_type": {"code"}, "scope": {"openid profile groups"}, "state": {"test-state"}, "nonce": {"test-nonce"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}, "code_challenge_method": {"S256"}}
	code, b, h := f.request(f.client, "GET", "/authorize?"+q.Encode(), nil, false)
	if code != 302 {
		f.t.Fatalf("authorize status=%d body=%s", code, b)
	}
	for range 2 {
		location := h.Get("Location")
		u, err := url.Parse(location)
		if err != nil {
			f.t.Fatal(err)
		}
		code, b, h = f.request(f.client, "GET", u.RequestURI(), nil, false)
		if code != 302 {
			f.t.Fatalf("callback status=%d body=%s", code, b)
		}
	}
	location, err := url.Parse(h.Get("Location"))
	if err != nil {
		f.t.Fatal(err)
	}
	if location.Host != "app.example" || location.Query().Get("state") != "test-state" || location.Query().Get("code") == "" {
		f.t.Fatalf("invalid callback: %s", location)
	}
	return location.Query().Get("code"), verifier
}
func TestMTLSAndAdmin(t *testing.T) {
	f := newFixture(t)
	status, _, _ := f.request(f.anonymous, "GET", "/admin", nil, false)
	if status != 401 {
		t.Fatalf("anonymous admin=%d", status)
	}
	status, body, _ := f.request(f.client, "GET", "/admin", nil, false)
	if status != 200 || !bytes.Contains(body, []byte("Wardstone")) {
		t.Fatalf("admin=%d", status)
	}
	status, _, _ = f.request(f.client, "POST", "/admin/user", url.Values{"name": {"csrf-bypass"}}, false)
	if status != 403 {
		t.Fatal("CSRF accepted")
	}
	status, _, _ = f.post("user", url.Values{"name": {"Alice"}, "email": {"alice@example.com"}, "groups": {"staff, engineering"}})
	if status != 303 {
		t.Fatalf("create user=%d", status)
	}
	var uid string
	if err := f.s.db.QueryRow("SELECT id FROM users WHERE name='Alice'").Scan(&uid); err != nil {
		t.Fatal(err)
	}
	status, bundle, _ := f.post("certificate", url.Values{"id": {uid}, "password": {"a-long-test-password"}})
	if status != 200 {
		t.Fatalf("issue certificate=%d", status)
	}
	pair := decodeBundle(t, bundle, "a-long-test-password")
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.s.pool(), Certificates: []tls.Certificate{pair}}}
	defer tr.CloseIdleConnections()
	alice := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	status, _, _ = f.request(alice, "GET", "/admin", nil, false)
	if status != 403 {
		t.Fatalf("non-admin access=%d", status)
	}
	status, _, _ = f.post("revoke", url.Values{"fingerprint": {fingerprint(pair.Leaf)}})
	if status != 303 {
		t.Fatal("revoke failed")
	}
	status, _, _ = f.request(alice, "GET", "/", nil, false)
	if status != 401 {
		t.Fatalf("revoked cert reused connection=%d", status)
	}
	// A newly CA-signed but unregistered certificate must not authenticate.
	unregistered, key, err := f.s.clientCertificate(f.admin)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pkcs12.Modern.Encode(key, unregistered, []*x509.Certificate{f.s.ca}, "password")
	if err != nil {
		t.Fatal(err)
	}
	unknown := decodeBundle(t, raw, "password")
	tr2 := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.s.pool(), Certificates: []tls.Certificate{unknown}}}
	defer tr2.CloseIdleConnections()
	status, _, _ = f.request(&http.Client{Transport: tr2}, "GET", "/admin", nil, false)
	if status != 401 {
		t.Fatal("unregistered certificate accepted")
	}
}
func TestOIDCFlow(t *testing.T) {
	f := newFixture(t)
	f.addOIDC()
	status, body, _ := f.request(f.anonymous, "GET", "/.well-known/openid-configuration", nil, false)
	if status != 200 {
		t.Fatalf("discovery=%d %s", status, body)
	}
	code, verifier := f.code()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://app.example/callback"}, "code_verifier": {verifier}}
	status, body, _ = f.request(f.anonymous, "POST", "/oauth/token", form, true)
	if status != 200 {
		t.Fatalf("token=%d %s", status, body)
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokens); err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatal("missing tokens")
	}
	signed, err := jwt.ParseSigned(tokens.IDToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var claims jwt.Claims
	var extra struct {
		Nonce  string   `json:"nonce"`
		Groups []string `json:"groups"`
		AMR    []string `json:"amr"`
	}
	if err = signed.Claims(&f.s.signKey.PublicKey, &claims, &extra); err != nil {
		t.Fatal(err)
	}
	if err = claims.Validate(jwt.Expected{Issuer: f.server.URL, Subject: f.admin.ID, AnyAudience: jwt.Audience{"test-client"}, Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if extra.Nonce != "test-nonce" || len(extra.Groups) != 1 || len(extra.AMR) != 1 {
		t.Fatalf("wrong identity claims: %+v", extra)
	}
	r, _ := http.NewRequest("GET", f.server.URL+"/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	res, err := f.anonymous.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !bytes.Contains(data, []byte(f.admin.ID)) {
		t.Fatalf("userinfo=%d %s", res.StatusCode, data)
	}
	status, _, _ = f.request(f.anonymous, "POST", "/oauth/token", form, true)
	if status == 200 {
		t.Fatal("code replay accepted")
	}
	_, err = f.s.db.Exec("UPDATE apps SET groups_json='[]' WHERE id='test-client'")
	if err != nil {
		t.Fatal(err)
	}
	res, err = f.anonymous.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode == 200 {
		t.Fatal("token accepted after access removed")
	}
}
func TestOIDCRejectsInvalidPKCEAndConcurrentReplay(t *testing.T) {
	f := newFixture(t)
	f.addOIDC()
	code, verifier := f.code()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://app.example/callback"}, "code_verifier": {verifier}}
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for range 2 {
		wg.Go(func() { status, _, _ := f.request(f.anonymous, "POST", "/oauth/token", form, true); statuses <- status })
	}
	wg.Wait()
	close(statuses)
	success := 0
	for status := range statuses {
		if status == 200 {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("concurrent code redemption successes=%d", success)
	}
	code, _ = f.code()
	form.Set("code", code)
	form.Set("code_verifier", "incorrect-verifier")
	status, _, _ := f.request(f.anonymous, "POST", "/oauth/token", form, true)
	if status == 200 {
		t.Fatal("wrong PKCE accepted")
	}
}
func TestSAMLFlowAndReplay(t *testing.T) {
	f := newFixture(t)
	spURL, _ := url.Parse("https://sp.example/metadata")
	acs, _ := url.Parse("https://sp.example/acs")
	sp := &saml.ServiceProvider{EntityID: spURL.String(), MetadataURL: *spURL, AcsURL: *acs, IDPMetadata: f.a.saml.Metadata()}
	metadata, err := xml.Marshal(sp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	status, body, _ := f.post("app", url.Values{"name": {"SAML test"}, "protocol": {"saml"}, "metadata": {string(metadata)}, "groups": {"administrators"}})
	if status != 303 {
		t.Fatalf("register SAML=%d %s", status, body)
	}
	auth, err := sp.MakeAuthenticationRequest(f.server.URL+"/saml/sso", saml.HTTPPostBinding, saml.HTTPPostBinding)
	if err != nil {
		t.Fatal(err)
	}
	doc := auth.Element()
	xmlDoc := etree.NewDocument()
	xmlDoc.SetRoot(doc)
	raw, err := xmlDoc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(raw)}, "RelayState": {"return-state"}}
	status, body, _ = f.request(f.client, "POST", "/saml/sso", form, false)
	if status != 200 {
		t.Fatalf("saml=%d %s", status, body)
	}
	re := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)
	match := re.FindSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("no SAML response: %s", body)
	}
	encoded := html.UnescapeString(string(match[1]))
	response, _ := http.NewRequest("POST", acs.String(), strings.NewReader(url.Values{"SAMLResponse": {encoded}}.Encode()))
	response.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response.ParseForm()
	assertion, err := sp.ParseResponse(response, []string{auth.ID})
	if err != nil {
		t.Fatal(err)
	}
	if assertion.Subject.NameID.Value != f.admin.ID || assertion.AuthnStatements[0].AuthnContext.AuthnContextClassRef.Value != "urn:oasis:names:tc:SAML:2.0:ac:classes:X509" {
		t.Fatal("wrong SAML identity/authentication context")
	}
	status, _, _ = f.request(f.client, "POST", "/saml/sso", form, false)
	if status != 400 {
		t.Fatal("SAML replay accepted")
	}
	// AuthnRequestsSigned in registered metadata must be enforced.
	signed := true
	spMeta := sp.Metadata()
	spMeta.SPSSODescriptors[0].AuthnRequestsSigned = &signed
	metadata, err = xml.Marshal(spMeta)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.s.db.Exec("UPDATE apps SET metadata=? WHERE id=?", string(metadata), sp.EntityID)
	if err != nil {
		t.Fatal(err)
	}
	status, _, _ = f.request(f.client, "POST", "/saml/sso", form, false)
	if status != 400 {
		t.Fatal("missing required signature accepted")
	}
}
func TestSignedSAMLRequests(t *testing.T) {
	f := newFixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: serial(), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	cert, err := makeCertificate(tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	acs, _ := url.Parse("https://signed.example/acs")
	meta, _ := url.Parse("https://signed.example/metadata")
	sp := &saml.ServiceProvider{EntityID: meta.String(), MetadataURL: *meta, AcsURL: *acs, IDPMetadata: f.a.saml.Metadata(), Key: key, Certificate: cert, SignatureMethod: dsig.RSASHA256SignatureMethod}
	metadata, err := xml.Marshal(sp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	status, body, _ := f.post("app", url.Values{"name": {"signed SP"}, "protocol": {"saml"}, "metadata": {string(metadata)}, "groups": {"administrators"}})
	if status != 303 {
		t.Fatalf("register signed SP=%d %s", status, body)
	}
	for _, binding := range []string{saml.HTTPPostBinding, saml.HTTPRedirectBinding} {
		t.Run(binding, func(t *testing.T) {
			req, err := sp.MakeAuthenticationRequest(f.server.URL+"/saml/sso", binding, saml.HTTPPostBinding)
			if err != nil {
				t.Fatal(err)
			}
			var status int
			var body []byte
			if binding == saml.HTTPRedirectBinding {
				redirect, err := req.Redirect("state", sp)
				if err != nil {
					t.Fatal(err)
				}
				tampered := *redirect
				q := tampered.Query()
				q.Set("RelayState", "tampered")
				tampered.RawQuery = q.Encode()
				bad, _, _ := f.request(f.client, "GET", tampered.RequestURI(), nil, false)
				if bad != 400 {
					t.Fatalf("tampered redirect signature accepted: %d", bad)
				}
				status, body, _ = f.request(f.client, "GET", redirect.RequestURI(), nil, false)
			} else {
				doc := etree.NewDocument()
				doc.SetRoot(req.Element())
				doc.Root().CreateAttr("ProviderName", "tampered")
				raw, err := doc.WriteToBytes()
				if err != nil {
					t.Fatal(err)
				}
				bad, _, _ := f.request(f.client, "POST", "/saml/sso", url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(raw)}}, false)
				if bad != 400 {
					t.Fatalf("tampered XML signature accepted: %d", bad)
				}
				doc.Root().RemoveAttr("ProviderName")
				raw, err = doc.WriteToBytes()
				if err != nil {
					t.Fatal(err)
				}
				status, body, _ = f.request(f.client, "POST", "/saml/sso", url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(raw)}}, false)
			}
			if status != 200 {
				t.Fatalf("signed SAML=%d %s", status, body)
			}
		})
	}
}
func TestForeignCARejected(t *testing.T) {
	f := newFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: serial(), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	cert, err := makeCertificate(tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pkcs12.Modern.Encode(key, cert, nil, "password")
	if err != nil {
		t.Fatal(err)
	}
	pair := decodeBundle(t, raw, "password")
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.s.pool(), Certificates: []tls.Certificate{pair}}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	res, err := client.Get(f.server.URL + "/admin")
	if err == nil {
		res.Body.Close()
		if res.StatusCode < 400 {
			t.Fatal("foreign CA certificate accepted")
		}
	}
}

// Browsers derive form POST origins from the page's referrer policy. A
// no-referrer policy makes even same-origin form navigation send Origin: null.
func TestAdminFormOriginProtection(t *testing.T) {
	f := newFixture(t)
	status, _, headers := f.request(f.client, "GET", "/admin", nil, false)
	if status != http.StatusOK || headers.Get("Referrer-Policy") != "same-origin" {
		t.Fatalf("admin page status=%d referrer policy=%q; forms must retain their same-origin Origin", status, headers.Get("Referrer-Policy"))
	}
	for _, tc := range []struct {
		name, origin, site, token string
		want                      int
	}{
		{"same-origin", f.a.issuer, "same-origin", f.csrf, http.StatusSeeOther},
		{"foreign-origin", "https://attacker.example", "same-origin", f.csrf, http.StatusForbidden},
		{"opaque-origin", "null", "same-origin", f.csrf, http.StatusForbidden},
		{"cross-site", f.a.issuer, "cross-site", f.csrf, http.StatusForbidden},
		{"missing-token", f.a.issuer, "same-origin", "", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{"name": {tc.name}, "csrf": {tc.token}}
			req, err := http.NewRequest(http.MethodPost, f.server.URL+"/admin/user", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Sec-Fetch-Site", tc.site)
			res, err := f.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != tc.want {
				t.Fatalf("create user status=%d want=%d", res.StatusCode, tc.want)
			}
			var count int
			if err := f.s.db.QueryRow("SELECT COUNT(*) FROM users WHERE name=?", tc.name).Scan(&count); err != nil {
				t.Fatal(err)
			}
			wantCount := 0
			if tc.want == http.StatusSeeOther {
				wantCount = 1
			}
			if count != wantCount {
				t.Fatalf("created users=%d want=%d", count, wantCount)
			}
		})
	}
}
