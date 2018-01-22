/*
Package applepay abstracts all the Apple Pay flow.

It support features such as RSA-encrypted tokens (used in China), elliptic curve-encrypted token, full signature verification and protection against replay attacks.

Sample usage:
 ap, err := applepay.New(
	 "com.processout.test",
	 applepay.MerchantDisplayName("ProcessOut Test Store"),
	 applepay.MerchantDomainName("store.processout.com"),
	 applepay.MerchantCertificateLocation("cert-merchant.crt", "cert-merchant-key.pem"),
	 applepay.ProcessingCertificateLocation("cert-processing.crt", "cert-processing-key.pem"),
 )

 // Create a new session
 sessionPayload, err := ap.Session("https://apple-pay-gateway.apple.com/paymentservices/startSession")

 // Decrypt a token
 token, err := ap.DecryptResponse(res)

A working example can be found in applepay/app.go. It requires a registered domain and valid certificates to work.
*/
package applepay
