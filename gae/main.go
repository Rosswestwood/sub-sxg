package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/WICG/webpackage/go/signedexchange"
)

var (
	demoDomainName string

	certKeyFileName = "cert/cert.key"
	certPemFileName = "cert/cert.pem"

	certURLPath = "/cert/cert.cbor"

	prvKey      crypto.PrivateKey
	certs       []*x509.Certificate
	certMessage []byte

	amptestnocdn_payload   []byte
	v0js_payload           []byte
	nikko_320_jpg_payload  []byte
	nikko_640_jpg_payload  []byte
	nikko_320_webp_payload []byte
	nikko_640_webp_payload []byte
)

func init() {
	certKeyPem, _ := ioutil.ReadFile(certKeyFileName)
	decodedCertKey, _ := pem.Decode(certKeyPem)
	prvKey, _ = signedexchange.ParsePrivateKey(decodedCertKey.Bytes)

	certPem, _ := ioutil.ReadFile(certPemFileName)
	certs, _ = signedexchange.ParseCertificates(certPem)
	ocsp, _ := getOCSP(certs)
	certMessage, _ = createCertChainCBOR(certs, ocsp, nil)

	demoDomainName, _ = getSubjectCommonName(certPem)

	amptestnocdn_payload, _ = ioutil.ReadFile("contents/amptestnocdn.html")
	v0js_payload, _ = ioutil.ReadFile("contents/v0.js")
	nikko_320_jpg_payload, _ = ioutil.ReadFile("contents/nikko_320.jpg")
	nikko_640_jpg_payload, _ = ioutil.ReadFile("contents/nikko_640.jpg")
	nikko_320_webp_payload, _ = ioutil.ReadFile("contents/nikko_320.webp")
	nikko_640_webp_payload, _ = ioutil.ReadFile("contents/nikko_640.webp")

	log.Printf("demoDomainName: %s", demoDomainName)
	log.Printf("initialized")
}

func main() {
	http.HandleFunc("/cert/", certHandler)
	http.HandleFunc("/sxg/", signedExchangeHandler)
	http.HandleFunc("/", indexHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("Defaulting to port %s", port)
	}

	log.Printf("Listening on port %s", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	t := template.Must(template.ParseFiles("templates/index.html"))

	type Data struct {
		Host string
		SXGs []string
	}
	data := Data{
		Host: r.Host,
		SXGs: []string{
			"hello.sxg",
			"amptestnocdn.sxg",
			"amptestnocdn_js_preload.sxg",
			"amptestnocdn_js_img_preload.sxg",
			"amptestnocdn_js_img_vary_preload.sxg",
			"amptestnocdn_js_preload_error.sxg",
			"amptestnocdn_js_img_preload_error.sxg",
		},
	}

	if err := t.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
