package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var (
	certKeyFileName = "cert/cert.key"
	certPemFileName = "cert/cert.pem"
	certKey         []byte
	certPem         []byte
)

func init() {
	var err error
	certKey, err = ioutil.ReadFile(certKeyFileName)
	if err != nil {
		log.Fatal("Failed to load %s", certKeyFileName)
	}
	certPem, err = ioutil.ReadFile(certPemFileName)
	if err != nil {
		log.Fatal("Failed to load %s", certPemFileName)
	}
	log.Printf("initialized")
}

func main() {
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
	fmt.Fprint(w, "")
}
