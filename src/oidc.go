package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type oidcStore struct{ *store }

var _ op.Storage = (*oidcStore)(nil)

type authRequest struct {
	Request           oidc.AuthRequest
	ID, Subject, Cert string
	Created           time.Time
}

func (a *authRequest) GetID() string          { return a.ID }
func (a *authRequest) GetACR() string         { return "urn:wardstone:mtls" }
func (a *authRequest) GetAMR() []string       { return []string{"urn:wardstone:mtls"} }
func (a *authRequest) GetAudience() []string  { return []string{a.Request.ClientID} }
func (a *authRequest) GetAuthTime() time.Time { return a.Created }
func (a *authRequest) GetClientID() string    { return a.Request.ClientID }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.Request.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{Challenge: a.Request.CodeChallenge, Method: a.Request.CodeChallengeMethod}
}
func (a *authRequest) GetNonce() string                   { return a.Request.Nonce }
func (a *authRequest) GetRedirectURI() string             { return a.Request.RedirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType { return a.Request.ResponseType }
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return a.Request.ResponseMode }
func (a *authRequest) GetScopes() []string                { return a.Request.Scopes }
func (a *authRequest) GetState() string                   { return a.Request.State }
func (a *authRequest) GetSubject() string                 { return a.Subject }
func (a *authRequest) Done() bool                         { return a.Subject != "" }

type principalKey struct{}
type principal struct {
	User        user
	Fingerprint string
}

func (s *oidcStore) CreateAuthRequest(ctx context.Context, r *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	p, ok := ctx.Value(principalKey{}).(principal)
	if !ok || !s.allowed(p.User.ID, r.ClientID) {
		return nil, oidc.ErrAccessDenied()
	}
	if r.CodeChallenge == "" || r.CodeChallengeMethod != oidc.CodeChallengeMethodS256 {
		return nil, oidc.ErrInvalidRequest().WithDescription("PKCE S256 is required")
	}
	if slices.Contains(r.Prompt, oidc.PromptConsent) || len(r.ACRValues) > 0 {
		return nil, oidc.ErrInvalidRequest().WithDescription("interactive consent and requested ACR values are unsupported")
	}
	a := &authRequest{Request: *r, ID: randomString(24), Subject: p.User.ID, Cert: p.Fingerprint, Created: time.Now().UTC()}
	_, err := s.db.ExecContext(ctx, "INSERT INTO auth_requests(id,data,expires) VALUES(?,?,?)", a.ID, encode(a), time.Now().Add(5*time.Minute).Unix())
	return a, err
}
func (s *oidcStore) loadAuth(ctx context.Context, query, key string, consume bool) (op.AuthRequest, error) {
	var b []byte
	var err error
	if consume {
		err = s.db.QueryRowContext(ctx, "UPDATE auth_requests SET consumed=1 WHERE code=? AND consumed=0 AND expires>? RETURNING data", key, time.Now().Unix()).Scan(&b)
	} else {
		err = s.db.QueryRowContext(ctx, query, key, time.Now().Unix()).Scan(&b)
	}
	if err != nil {
		return nil, oidc.ErrInvalidGrant()
	}
	var a authRequest
	if err = json.Unmarshal(b, &a); err != nil {
		return nil, err
	}
	if !s.allowed(a.Subject, a.Request.ClientID) || !s.certActive(a.Cert, a.Subject) {
		return nil, oidc.ErrAccessDenied()
	}
	return &a, nil
}
func (s *oidcStore) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	req, err := s.loadAuth(ctx, "SELECT data FROM auth_requests WHERE id=? AND consumed=0 AND expires>?", id, false)
	if err != nil {
		return nil, err
	}
	p, ok := ctx.Value(principalKey{}).(principal)
	if !ok || p.User.ID != req.GetSubject() || p.Fingerprint != req.(*authRequest).Cert {
		return nil, oidc.ErrAccessDenied()
	}
	return req, nil
}
func (s *oidcStore) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	return s.loadAuth(ctx, "", code, true)
}
func (s *oidcStore) SaveAuthCode(ctx context.Context, id, code string) error {
	res, err := s.db.ExecContext(ctx, "UPDATE auth_requests SET code=? WHERE id=? AND code IS NULL AND consumed=0", code, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return errors.New("authorization request already used")
	}
	return nil
}
func (s *oidcStore) DeleteAuthRequest(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM auth_requests WHERE id=?", id)
	return err
}
func (s *oidcStore) CreateAccessToken(ctx context.Context, r op.TokenRequest) (string, time.Time, error) {
	a, ok := r.(*authRequest)
	if !ok || !s.allowed(a.Subject, a.Request.ClientID) || !s.certActive(a.Cert, a.Subject) {
		return "", time.Time{}, oidc.ErrAccessDenied()
	}
	id := randomString(32)
	expires := time.Now().Add(5 * time.Minute)
	_, err := s.db.ExecContext(ctx, "INSERT INTO tokens VALUES(?,?,?,?,?,?)", id, a.Subject, a.Request.ClientID, encode([]string(a.Request.Scopes)), expires.Unix(), a.Cert)
	return id, expires, err
}
func (s *oidcStore) CreateAccessAndRefreshTokens(context.Context, op.TokenRequest, string) (string, string, time.Time, error) {
	return "", "", time.Time{}, oidc.ErrUnsupportedGrantType()
}
func (s *oidcStore) TokenRequestByRefreshToken(context.Context, string) (op.RefreshTokenRequest, error) {
	return nil, op.ErrInvalidRefreshToken
}
func (s *oidcStore) GetRefreshTokenInfo(context.Context, string, string) (string, string, error) {
	return "", "", op.ErrInvalidRefreshToken
}
func (s *oidcStore) TerminateSession(ctx context.Context, uid, cid string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM tokens WHERE user_id=? AND client_id=?", uid, cid)
	return err
}
func (s *oidcStore) RevokeToken(ctx context.Context, id, uid, cid string) *oidc.Error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM tokens WHERE id=? AND client_id=?", id, cid); err != nil {
		return oidc.ErrServerError()
	}
	return nil
}

type signingKey struct{ s *store }

func (k signingKey) ID() string                                  { return fingerprint(k.s.signCert) }
func (k signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k signingKey) Key() any                                    { return k.s.signKey }

type publicKey struct{ signingKey }

func (k publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k publicKey) Use() string                        { return "sig" }
func (k publicKey) Key() any                           { return &k.s.signKey.PublicKey }
func (s *oidcStore) SigningKey(context.Context) (op.SigningKey, error) {
	return signingKey{s.store}, nil
}
func (s *oidcStore) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}
func (s *oidcStore) KeySet(context.Context) ([]op.Key, error) {
	return []op.Key{publicKey{signingKey{s.store}}}, nil
}

type oidcClient struct{ application }

func (c oidcClient) GetID() string                       { return c.ID }
func (c oidcClient) RedirectURIs() []string              { return c.Redirects }
func (c oidcClient) PostLogoutRedirectURIs() []string    { return nil }
func (c oidcClient) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }
func (c oidcClient) AuthMethod() oidc.AuthMethod         { return oidc.AuthMethodBasic }
func (c oidcClient) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c oidcClient) GrantTypes() []oidc.GrantType        { return []oidc.GrantType{oidc.GrantTypeCode} }
func (c oidcClient) LoginURL(id string) string           { return "/login?id=" + url.QueryEscape(id) }
func (c oidcClient) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeBearer }
func (c oidcClient) IDTokenLifetime() time.Duration      { return 5 * time.Minute }
func (c oidcClient) DevMode() bool                       { return false }
func (c oidcClient) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c oidcClient) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c oidcClient) IsScopeAllowed(scope string) bool     { return scope == "groups" }
func (c oidcClient) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c oidcClient) ClockSkew() time.Duration             { return 0 }
func (s *oidcStore) GetClientByClientID(ctx context.Context, id string) (op.Client, error) {
	a, err := s.getApp(id)
	if err != nil || a.Protocol != "oidc" {
		return nil, errors.New("unknown OIDC client")
	}
	return oidcClient{a}, nil
}
func (s *oidcStore) AuthorizeClientIDSecret(ctx context.Context, id, secret string) error {
	a, err := s.getApp(id)
	if err != nil || a.Protocol != "oidc" || subtle.ConstantTimeCompare([]byte(a.SecretHash), []byte(secretHash(secret))) != 1 {
		return errors.New("invalid client credentials")
	}
	return nil
}
func (s *oidcStore) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil
}
func (s *oidcStore) fill(info *oidc.UserInfo, uid, cid string, scopes []string) error {
	if !s.allowed(uid, cid) {
		return oidc.ErrAccessDenied()
	}
	u, err := s.getUser(uid)
	if err != nil {
		return err
	}
	info.Subject = u.ID
	if slices.Contains(scopes, "profile") {
		info.PreferredUsername = u.Name
		info.Name = u.Name
	}
	if slices.Contains(scopes, "email") {
		info.Email = u.Email
	}
	if slices.Contains(scopes, "groups") {
		info.AppendClaims("groups", u.Groups)
	}
	return nil
}
func (s *oidcStore) SetUserinfoFromRequest(ctx context.Context, info *oidc.UserInfo, r op.IDTokenRequest, scopes []string) error {
	return s.fill(info, r.GetSubject(), r.GetClientID(), scopes)
}
func (s *oidcStore) token(ctx context.Context, id, subject string) (string, []string, time.Time, error) {
	var uid, cid, scope, fp string
	var exp int64
	err := s.db.QueryRowContext(ctx, "SELECT user_id,client_id,scopes,expires,cert_fingerprint FROM tokens WHERE id=?", id).Scan(&uid, &cid, &scope, &exp, &fp)
	if err != nil || uid != subject || time.Now().Unix() >= exp || !s.allowed(uid, cid) || !s.certActive(fp, uid) {
		return "", nil, time.Time{}, errors.New("invalid token")
	}
	var scopes []string
	err = json.Unmarshal([]byte(scope), &scopes)
	return cid, scopes, time.Unix(exp, 0), err
}
func (s *oidcStore) SetUserinfoFromToken(ctx context.Context, info *oidc.UserInfo, id, subject, origin string) error {
	cid, scopes, _, err := s.token(ctx, id, subject)
	if err != nil {
		return err
	}
	if origin != "" {
		return errors.New("browser cross-origin userinfo is unsupported")
	}
	return s.fill(info, subject, cid, scopes)
}
func (s *oidcStore) SetIntrospectionFromToken(ctx context.Context, info *oidc.IntrospectionResponse, id, subject, cid string) error {
	client, scopes, expires, err := s.token(ctx, id, subject)
	if err != nil || client != cid {
		return errors.New("invalid token audience")
	}
	ui := new(oidc.UserInfo)
	if err = s.fill(ui, subject, cid, scopes); err != nil {
		return err
	}
	info.SetUserInfo(ui)
	info.ClientID = cid
	info.Scope = scopes
	info.Expiration = oidc.FromTime(expires)
	return nil
}
func (s *oidcStore) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}
func (s *oidcStore) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("JWT client authentication is unsupported")
}
func (s *oidcStore) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errors.New("JWT profile grant is unsupported")
}
func (s *oidcStore) Health(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *store) certActive(fp, uid string) bool {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM certificates c JOIN users u ON c.user_id=u.id WHERE c.fingerprint=? AND u.id=? AND c.revoked=0 AND u.disabled=0 AND c.expires>?", fp, uid, time.Now().UTC().Format(time.RFC3339)).Scan(&n)
	return err == nil && n == 1
}
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	p, ok := r.Context().Value(principalKey{}).(principal)
	if !ok {
		http.Error(w, "Client certificate required", 401)
		return
	}
	req, err := a.oidc.Storage().AuthRequestByID(r.Context(), r.URL.Query().Get("id"))
	if err != nil || req.GetSubject() != p.User.ID || req.(*authRequest).Cert != p.Fingerprint {
		http.Error(w, "Invalid authorization request", 403)
		return
	}
	http.Redirect(w, r, a.issuer+a.oidc.AuthorizationEndpoint().Relative()+"/callback?id="+url.QueryEscape(req.GetID()), http.StatusFound)
}
