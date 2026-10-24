package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

func (a *app) serveSAML(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "POST" {
		http.Error(w, "GET or POST required", 405)
		return
	}
	req, err := saml.NewIdpAuthnRequest(a.saml, r)
	if err != nil {
		http.Error(w, "Invalid SAML request", 400)
		return
	}
	if err = xml.Unmarshal(req.RequestBuffer, &req.Request); err != nil {
		http.Error(w, "Invalid SAML XML", 400)
		return
	}
	if req.Request.Issuer == nil || req.Request.Issuer.Value == "" {
		http.Error(w, "SAML issuer required", 400)
		return
	}
	if err = req.Validate(); err != nil {
		http.Error(w, "SAML request validation failed", 400)
		return
	}
	if err = verifySAMLRequest(req, r); err != nil {
		log.Printf("SAML signature validation: %v", err)
		http.Error(w, "SAML request signature validation failed", 400)
		return
	}
	if ac := req.Request.RequestedAuthnContext; ac != nil && (ac.AuthnContextClassRef != "urn:oasis:names:tc:SAML:2.0:ac:classes:X509" || (ac.Comparison != "" && ac.Comparison != "exact")) {
		http.Error(w, "Requested authentication context is unsupported", 400)
		return
	}
	session := a.GetSession(w, r, req)
	if session == nil {
		return
	}
	if err = a.saml.AssertionMaker.MakeAssertion(req, session); err != nil {
		http.Error(w, "Cannot create assertion", 500)
		return
	}
	if err = req.WriteResponse(w); err != nil {
		http.Error(w, "Cannot write assertion", 500)
	}
}
func verifySAMLRequest(req *saml.IdpAuthnRequest, r *http.Request) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(req.RequestBuffer); err != nil {
		return err
	}
	var sig *etree.Element
	for _, child := range doc.Root().ChildElements() {
		if child.Tag == "Signature" && child.NamespaceURI() == dsig.Namespace {
			if sig != nil {
				return errors.New("multiple signatures")
			}
			sig = child
		}
	}
	required := req.SPSSODescriptor.AuthnRequestsSigned != nil && *req.SPSSODescriptor.AuthnRequestsSigned
	certs := []*x509.Certificate{}
	for _, kd := range req.SPSSODescriptor.KeyDescriptors {
		if kd.Use != "" && kd.Use != "signing" {
			continue
		}
		for _, xc := range kd.KeyInfo.X509Data.X509Certificates {
			raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(xc.Data), ""))
			if err != nil {
				return err
			}
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return err
			}
			certs = append(certs, cert)
		}
	}
	if r.Method == "GET" {
		raw := map[string]string{}
		for _, part := range strings.Split(r.URL.RawQuery, "&") {
			k, v, _ := strings.Cut(part, "=")
			key, err := url.QueryUnescape(k)
			if err != nil {
				return err
			}
			if _, exists := raw[key]; exists {
				return errors.New("duplicate parameter")
			}
			raw[key] = v
		}
		if r.URL.Query().Get("Signature") == "" {
			if required || sig != nil {
				return errors.New("signature required")
			}
			return nil
		}
		if r.URL.Query().Get("SigAlg") != dsig.RSASHA256SignatureMethod {
			return errors.New("only RSA SHA256 redirect signatures are supported")
		}
		message := "SAMLRequest=" + raw["SAMLRequest"]
		if relay, ok := raw["RelayState"]; ok {
			message += "&RelayState=" + relay
		}
		message += "&SigAlg=" + raw["SigAlg"]
		signature, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("Signature"))
		if err != nil {
			return err
		}
		hash := sha256.Sum256([]byte(message))
		for _, cert := range certs {
			if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
				continue
			}
			if key, ok := cert.PublicKey.(*rsa.PublicKey); ok && rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature) == nil {
				return nil
			}
		}
		return errors.New("invalid redirect signature")
	}
	if sig == nil {
		if required {
			return errors.New("signature required")
		}
		return nil
	}
	// Restrict XML signature and digest algorithms before library verification.
	if err := checkXMLAlgorithms(sig); err != nil {
		return err
	}
	if len(certs) == 0 {
		return errors.New("no trusted SP signing certificate")
	}
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certs})
	validated, err := ctx.Validate(doc.Root())
	if err != nil {
		return err
	}
	if validated.SelectAttrValue("ID", "") != req.Request.ID {
		return errors.New("signed request ID mismatch")
	}
	return nil
}

func checkXMLAlgorithms(sig *etree.Element) error {
	for _, info := range sig.ChildElements() {
		if info.Tag != "SignedInfo" || info.NamespaceURI() != dsig.Namespace {
			continue
		}
		validMethod := false
		references := 0
		for _, child := range info.ChildElements() {
			if child.NamespaceURI() != dsig.Namespace {
				continue
			}
			if child.Tag == "SignatureMethod" {
				validMethod = child.SelectAttrValue("Algorithm", "") == dsig.RSASHA256SignatureMethod
			}
			if child.Tag == "Reference" {
				references++
				validDigest := false
				for _, digest := range child.ChildElements() {
					if digest.Tag == "DigestMethod" && digest.NamespaceURI() == dsig.Namespace {
						validDigest = digest.SelectAttrValue("Algorithm", "") == "http://www.w3.org/2001/04/xmlenc#sha256"
					}
				}
				if !validDigest {
					return errors.New("SHA256 digest required")
				}
			}
		}
		if validMethod && references == 1 {
			return nil
		}
		return errors.New("RSA SHA256 XML signature with one reference required")
	}
	return errors.New("missing XML SignedInfo")
}
