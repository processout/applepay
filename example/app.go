package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/gin-gonic/gin"
	"github.com/processout/applepay"
)

var (
	ap *applepay.Merchant
)

func init() {
	var err error
	applepay.AppleRootCertificatePath = "AppleRootCA-G3.crt"
	ap, err = applepay.New(
		"merchant.com.processout.test",
		applepay.MerchantDisplayName("ProcessOut Development Store"),
		applepay.MerchantDomainName("applepay.processout.com"),
		applepay.MerchantCertificateLocation(
			"certs/cert-merchant.crt",
			"certs/cert-merchant-key.pem",
		),
		applepay.ProcessingCertificateLocation(
			"certs/cert-processing.crt",
			"certs/cert-processing-key.pem",
		),
	)
	if err != nil {
		panic(err)
	}
	log.Println("Apple Pay test app starting")
}

func main() {
	r := gin.Default()
	r.StaticFile("/", "./static/index.html")
	r.Static("/.well-known", "./static/.well-known")
	r.Static("/public", "./static")
	r.POST("/getApplePaySession", getApplePaySession)
	r.POST("/processApplePayResponse", processApplePayResponse)
	port := "8000"
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}
	r.Run("localhost:" + port)
}

func getApplePaySession(c *gin.Context) {
	r := &struct{ URL string }{}
	if err := c.BindJSON(r); err != nil {
		log.Println(err)
		c.Status(http.StatusBadRequest)
		return
	}

	payload, err := ap.Session(r.URL)
	if err != nil {
		log.Println(err)
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusOK)
	c.Header("Content-Type", "application/json")
	c.Writer.Write(payload)
}

func processApplePayResponse(c *gin.Context) {
	r := &applepay.Response{}
	if err := c.BindJSON(r); err != nil {
		log.Println(err)
		c.Status(http.StatusBadRequest)
		return
	}

	// Optional: select merchant credentials to use based on the hash of the
	// public key:
	// h, err := r.Token.PublicKeyHash()

	token, err := ap.DecryptResponse(r)
	if err != nil {
		log.Println(err)
		c.Status(http.StatusBadRequest)
		return
	}

	fmt.Println("Token received!")
	spew.Dump(token)
	// TODO: check price…
	c.Status(http.StatusOK)
}
