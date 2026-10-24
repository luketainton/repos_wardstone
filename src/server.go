package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/google/uuid"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/zitadel/oidc/v3/pkg/op"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type app struct {
	s      *store
	issuer string
	oidc   *op.Provider
	saml   *saml.IdentityProvider
}

func newApp(c config, s *store) (*app, error) {
	a := &app{s: s, issuer: c.Issuer}
	var err error
	a.oidc, err = op.NewOpenIDProvider(c.Issuer, &op.Config{CryptoKey: s.cryptoKey, CryptoKeyId: "wardstone-v1", CodeMethodS256: true, DefaultLogoutRedirectURI: c.Issuer + "/"}, &oidcStore{s})
	if err != nil {
		return nil, err
	}
	metadata, _ := url.Parse(c.Issuer + "/saml/metadata")
	sso, _ := url.Parse(c.Issuer + "/saml/sso")
	a.saml = &saml.IdentityProvider{Key: s.signKey, Signer: s.signKey, Certificate: s.signCert, MetadataURL: *metadata, SSOURL: *sso, LoginURL: *sso, ServiceProviderProvider: a, SessionProvider: a, AssertionMaker: certificateAssertion{}, SignatureMethod: dsig.RSASHA256SignatureMethod, Logger: log.New(os.Stderr, "saml: ", log.LstdFlags)}
	return a, nil
}
func (a *app) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/admin", http.StatusFound) })
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := a.s.db.PingContext(r.Context()); err != nil {
			http.Error(w, "unhealthy", 503)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /ca.crt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.s.ca.Raw}))
	})
	mux.HandleFunc("GET /admin", a.admin)
	mux.HandleFunc("POST /admin/{action}", a.mutate)
	mux.HandleFunc("GET /login", a.login)
	mux.HandleFunc("GET /saml/metadata", a.saml.ServeMetadata)
	mux.HandleFunc("/saml/sso", a.serveSAML)
	mux.Handle("/", a.oidc)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Preserve Origin on same-origin form POSTs; no-referrer makes it null.
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		// Public protocol endpoints authenticate apps/tokens. Browser identity always requires mTLS.
		public := r.URL.Path == "/healthz" || r.URL.Path == "/ca.crt" || r.URL.Path == "/saml/metadata" || r.URL.Path == "/.well-known/openid-configuration" || r.URL.Path == a.oidc.KeysEndpoint().Relative() || r.URL.Path == a.oidc.TokenEndpoint().Relative() || r.URL.Path == a.oidc.UserinfoEndpoint().Relative() || r.URL.Path == a.oidc.IntrospectionEndpoint().Relative() || r.URL.Path == a.oidc.RevocationEndpoint().Relative()
		if !public {
			p, err := a.authenticate(r)
			if err != nil {
				http.Error(w, "A registered, active client certificate is required", http.StatusUnauthorized)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
			if strings.HasPrefix(r.URL.Path, "/admin") && !p.User.Admin {
				http.Error(w, "Administrator access required", 403)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func (a *app) authenticate(r *http.Request) (principal, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return principal{}, errors.New("unverified certificate")
	}
	fp := fingerprint(r.TLS.PeerCertificates[0])
	var uid string
	if err := a.s.db.QueryRow("SELECT user_id FROM certificates WHERE fingerprint=?", fp).Scan(&uid); err != nil || !a.s.certActive(fp, uid) {
		return principal{}, errors.New("unregistered or revoked certificate")
	}
	u, err := a.s.getUser(uid)
	return principal{u, fp}, err
}
func (a *app) csrf(fp string) string {
	h := hmac.New(sha256.New, a.s.cryptoKey[:])
	_, _ = h.Write([]byte("admin-csrf:" + fp))
	return hex.EncodeToString(h.Sum(nil))
}

type adminView struct {
	User         user
	CSRF         string
	Users        []user
	Apps         []application
	Certificates []credential
	Error        string
}

func (a *app) admin(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey{}).(principal)
	v := adminView{User: p.User, CSRF: a.csrf(p.Fingerprint)}
	rows, err := a.s.db.Query("SELECT id,name,email,admin,disabled,groups_json FROM users ORDER BY name")
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	for rows.Next() {
		u, e := scanUser(rows)
		if e != nil {
			rows.Close()
			http.Error(w, "Database error", 500)
			return
		}
		v.Users = append(v.Users, u)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	rows, err = a.s.db.Query("SELECT id FROM apps ORDER BY name")
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	for _, id := range ids {
		ap, e := a.s.getApp(id)
		if e != nil {
			http.Error(w, "Database error", 500)
			return
		}
		v.Apps = append(v.Apps, ap)
	}
	rows, err = a.s.db.Query("SELECT fingerprint,user_id,expires,revoked FROM certificates ORDER BY expires")
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	for rows.Next() {
		var c credential
		if err = rows.Scan(&c.Fingerprint, &c.UserID, &c.Expires, &c.Revoked); err != nil {
			break
		}
		v.Certificates = append(v.Certificates, c)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	if err = adminTemplate.Execute(w, v); err != nil {
		log.Printf("render admin: %v", err)
	}
}
func (a *app) mutate(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey{}).(principal)
	if r.Header.Get("Origin") != "" && r.Header.Get("Origin") != a.issuer || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		http.Error(w, "Cross-origin request denied", 403)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", 400)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(a.csrf(p.Fingerprint))) != 1 {
		http.Error(w, "Invalid CSRF token", 403)
		return
	}
	var err error
	switch r.PathValue("action") {
	case "user":
		name := strings.TrimSpace(r.PostForm.Get("name"))
		if name == "" || len(name) > 128 {
			http.Error(w, "Name is required (maximum 128 characters)", 400)
			return
		}
		_, err = a.s.db.Exec("INSERT INTO users(id,name,email,admin,groups_json) VALUES(?,?,?,?,?)", uuid.NewString(), name, strings.TrimSpace(r.PostForm.Get("email")), r.PostForm.Get("admin") == "on", encode(groups(r.PostForm.Get("groups"))))
	case "groups":
		_, err = a.s.db.Exec("UPDATE users SET groups_json=? WHERE id=?", encode(groups(r.PostForm.Get("groups"))), r.PostForm.Get("id"))
	case "disable":
		id := r.PostForm.Get("id")
		u, e := a.s.getUser(id)
		if e != nil {
			err = e
			break
		}
		if u.Admin {
			http.Error(w, "Administrator disabling is unavailable in this version; create a replacement and use certificate revocation", 400)
			return
		}
		_, err = a.s.db.Exec("UPDATE users SET disabled=1 WHERE id=?", id)
	case "certificate":
		u, e := a.s.getUser(r.PostForm.Get("id"))
		if e != nil || u.Disabled {
			http.Error(w, "Active user required", 400)
			return
		}
		password := r.PostForm.Get("password")
		if len(password) < 16 || len(password) > 256 {
			http.Error(w, "P12 password must contain 16–256 bytes", 400)
			return
		}
		cert, key, e := a.s.clientCertificate(u)
		if e != nil {
			err = e
			break
		}
		bundle, e := pkcs12.Modern.Encode(key, cert, []*x509.Certificate{a.s.ca}, password)
		if e != nil {
			err = e
			break
		}
		_, err = a.s.db.Exec("INSERT INTO certificates VALUES(?,?,?,0)", fingerprint(cert), u.ID, cert.NotAfter.Format(time.RFC3339))
		if err != nil {
			break
		}
		log.Printf("audit actor=%s action=certificate-issued user=%s", p.User.ID, u.ID)
		w.Header().Set("Content-Type", "application/x-pkcs12")
		w.Header().Set("Content-Disposition", `attachment; filename="wardstone-client.p12"`)
		_, _ = w.Write(bundle)
		return
	case "revoke":
		fp := r.PostForm.Get("fingerprint")
		if fp == p.Fingerprint {
			http.Error(w, "Cannot revoke the certificate currently administering Wardstone", 400)
			return
		}
		_, err = a.s.db.Exec("UPDATE certificates SET revoked=1 WHERE fingerprint=?", fp)
	case "app":
		ap := application{ID: uuid.NewString(), Name: strings.TrimSpace(r.PostForm.Get("name")), Protocol: r.PostForm.Get("protocol"), Groups: groups(r.PostForm.Get("groups")), Redirects: []string{}, Metadata: r.PostForm.Get("metadata")}
		if ap.Name == "" {
			http.Error(w, "Application name required", 400)
			return
		}
		if ap.Protocol == "oidc" {
			redirect := r.PostForm.Get("redirect")
			uri, e := url.Parse(redirect)
			if e != nil || uri.Scheme != "https" || uri.Host == "" || uri.User != nil || uri.Fragment != "" {
				http.Error(w, "A complete HTTPS redirect URI is required", 400)
				return
			}
			ap.Redirects = []string{redirect}
			password := r.PostForm.Get("secret")
			if len(password) < 32 {
				http.Error(w, "OIDC client secret must contain at least 32 bytes", 400)
				return
			}
			ap.SecretHash = secretHash(password)
		} else if ap.Protocol == "saml" {
			metadata, e := parseMetadata(ap.Metadata)
			if e != nil {
				http.Error(w, "Valid SP metadata with HTTPS ACS endpoints is required", 400)
				return
			}
			ap.ID = metadata.EntityID
		} else {
			http.Error(w, "Unsupported protocol", 400)
			return
		}
		_, err = a.s.db.Exec("INSERT INTO apps VALUES(?,?,?,?,?,?,?)", ap.ID, ap.Name, ap.Protocol, encode(ap.Redirects), ap.SecretHash, ap.Metadata, encode(ap.Groups))
	case "policy":
		_, err = a.s.db.Exec("UPDATE apps SET groups_json=? WHERE id=?", encode(groups(r.PostForm.Get("groups"))), r.PostForm.Get("id"))
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("admin operation failed action=%s", r.PathValue("action"))
		http.Error(w, "Operation failed; check for duplicate names/IDs and retry", 400)
		return
	}
	log.Printf("audit actor=%s action=%s", p.User.ID, r.PathValue("action"))
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
func parseMetadata(text string) (*saml.EntityDescriptor, error) {
	var m saml.EntityDescriptor
	if err := xml.Unmarshal([]byte(text), &m); err != nil {
		return nil, err
	}
	if m.EntityID == "" || len(m.SPSSODescriptors) == 0 {
		return nil, errors.New("missing SP descriptor")
	}
	for _, sp := range m.SPSSODescriptors {
		if len(sp.AssertionConsumerServices) == 0 {
			return nil, errors.New("missing ACS")
		}
		for _, ep := range sp.AssertionConsumerServices {
			u, err := url.Parse(ep.Location)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
				return nil, errors.New("invalid ACS URL")
			}
		}
	}
	return &m, nil
}
func (a *app) GetServiceProvider(r *http.Request, id string) (*saml.EntityDescriptor, error) {
	ap, err := a.s.getApp(id)
	if err != nil || ap.Protocol != "saml" {
		return nil, os.ErrNotExist
	}
	return parseMetadata(ap.Metadata)
}
func (a *app) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	p, ok := r.Context().Value(principalKey{}).(principal)
	if !ok || !a.s.allowed(p.User.ID, req.ServiceProviderMetadata.EntityID) {
		http.Error(w, "Access denied by application policy", 403)
		return nil
	}
	// The upstream library delegates replay protection to the application.
	if req.Request.ID == "" || req.Request.IssueInstant.After(time.Now().Add(time.Minute)) {
		http.Error(w, "Invalid SAML request ID or issue time", 400)
		return nil
	}
	now := time.Now().UTC()
	_, err := a.s.db.Exec("INSERT INTO saml_replays(id,expires) VALUES(?,?)", req.ServiceProviderMetadata.EntityID+"\x00"+req.Request.ID, now.Add(10*time.Minute).Unix())
	if err != nil {
		http.Error(w, "SAML request already used", 400)
		return nil
	}
	return &saml.Session{ID: randomString(24), Index: randomString(24), CreateTime: now, ExpireTime: now.Add(5 * time.Minute), NameID: p.User.ID, NameIDFormat: string(saml.PersistentNameIDFormat), SubjectID: p.User.ID, UserName: p.User.Name, UserEmail: p.User.Email, UserCommonName: p.User.Name, Groups: p.User.Groups}
}

type certificateAssertion struct{}

func (certificateAssertion) MakeAssertion(req *saml.IdpAuthnRequest, session *saml.Session) error {
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		return err
	}
	for i := range req.Assertion.AuthnStatements {
		req.Assertion.AuthnStatements[i].AuthnContext.AuthnContextClassRef = &saml.AuthnContextClassRef{Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"}
	}
	return nil
}
