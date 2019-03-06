// Copyright 2018 Google Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/WICG/webpackage/go/signedexchange"
	"github.com/WICG/webpackage/go/signedexchange/version"
)

const defaultPayload = `<!DOCTYPE html>
<html>
  <head>
    <title>Hello SignedHTTPExchange</title>
  </head>
  <body>
    <div id="message">
      <h1>Hello SignedHTTPExchange</h1>
    </div>
  </body>
</html>
`

type exchangeParams struct {
	ver           version.Version
	contentUrl    string
	certUrl       string
	validityUrl   string
	pemCerts      []byte
	pemPrivateKey []byte
	contentType   string
	resHeader     http.Header
	payload       []byte
	date          time.Time
	rand          io.Reader
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

func createExchange(params *exchangeParams) (*signedexchange.Exchange, error) {
	certUrl, _ := url.Parse(params.certUrl)
	validityUrl, _ := url.Parse(params.validityUrl)
	certs, err := signedexchange.ParseCertificates(params.pemCerts)
	if err != nil {
		return nil, err
	}
	if certs == nil {
		return nil, errors.New("invalid certificate")
	}
	parsedPrivKey, _ := pem.Decode(params.pemPrivateKey)
	if parsedPrivKey == nil {
		return nil, errors.New("invalid private key")
	}
	privkey, err := signedexchange.ParsePrivateKey(parsedPrivKey.Bytes)
	if err != nil {
		return nil, err
	}
	if privkey == nil {
		return nil, errors.New("invalid private key")
	}
	reqHeader := http.Header{}
	params.resHeader.Add("content-type", params.contentType)

	e := signedexchange.NewExchange(params.ver, params.contentUrl, http.MethodGet, reqHeader, 200, params.resHeader, []byte(params.payload))

	if err := e.MiEncodePayload(4096); err != nil {
		return nil, err
	}

	s := &signedexchange.Signer{
		Date:        params.date,
		Expires:     params.date.Add(time.Hour * 24),
		Certs:       certs,
		CertUrl:     certUrl,
		ValidityUrl: validityUrl,
		PrivKey:     privkey,
		Rand:        params.rand,
	}
	if s == nil {
		return nil, errors.New("Failed to sign")
	}
	if err := e.AddSignatureHeader(s); err != nil {
		return nil, err
	}
	return e, nil
}

func getHeaderIntegrity(path string, payload []byte, contentType string, ver version.Version, host string) string {
	contentUrl := "https://" + demoDomainName + path
	reqHeader := http.Header{}
	resHeader := http.Header{}
	resHeader.Add("content-type", contentType)

	e := signedexchange.NewExchange(ver, contentUrl, http.MethodGet, reqHeader, 200, resHeader, []byte(payload))

	if err := e.MiEncodePayload(4096); err != nil {
		return ""
	}

	var headerBuf bytes.Buffer
	if err := e.DumpExchangeHeaders(&headerBuf); err != nil {
		return ""
	}
	sum := sha256.Sum256(headerBuf.Bytes())
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

func serveExchange(params *exchangeParams, q url.Values, w http.ResponseWriter) {
	e, err := createExchange(params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/signed-exchange;v=b3")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	e.Write(w)
}

func signedExchangeHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	params := &exchangeParams{
		ver:           version.Version1b3,
		contentUrl:    "https://" + demoDomainName + "/hello.html",
		certUrl:       "https://" + r.Host + certURLPath,
		validityUrl:   "https://" + demoDomainName + "/cert/null.validity.msg",
		pemCerts:      certPem,
		pemPrivateKey: certKey,
		contentType:   "text/html; charset=utf-8",
		resHeader:     http.Header{},
		payload:       []byte(defaultPayload),
		date:          time.Now().Add(-time.Second * 10),
		rand:          nil,
	}

	switch r.URL.Path {
	case "/sxg/hello.sxg":
		serveExchange(params, q, w)
	default:
		http.Error(w, "signedExchangeHandler", 404)
	}
}
