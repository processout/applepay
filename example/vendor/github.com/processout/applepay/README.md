# applepay

[![GoDoc](https://godoc.org/github.com/processout/applepay?status.svg)](https://godoc.org/github.com/processout/applepay)

applepay is a Go package for processing Apple Pay transactions easily. It is aimed at merchants or PSPs that are looking to manage their own Apple Pay flow, as opposed to letting a third-party (such as Stripe) do it end-to-end. You will need a paid Apple Developer account to use this.

Note: we have included the Apple root CA in this repository. For production use-cases, you should always download the certificates directly from [Apple](https://www.apple.com/certificateauthority/).

## Running tests

```shell
go test
```

You may need to change your `PKG_CONFIG_PATH` to include OpenSSL. For example, on my Mac I use `PKG_CONFIG_PATH=$(brew --prefix openssl)/lib/pkgconfig go test`.

## Getting up and running with the example

Requirements:
- An account in the Apple Developer Program
- A recent version of Go (tested with v1.9.2)
- [`cfssl`](https://github.com/cloudflare/cfssl)
- OpenSSL/libssl-dev
- make

1. Log into your developer account. [In the developer console](https://developer.apple.com/account/ios/identifier/merchant), create a Merchant ID

1. Verify your domain by serving the `apple-developer-merchantid-domain-association` file at `https://yourdomain.com/.well-known/apple-developer-merchantid-domain-association` (the example app will do it for you if you put it in `example/static/.well-known`).
**Note**: Be careful to support one of the [supported cipher suites](https://developer.apple.com/reference/applepayjs#2166536) for HTTPS!

1. Edit the JSON files in the `certs/` directory of this repo with your merchant ID, your domain and your email address.

1. Generate a *Payment Processing Certificate* request by running `make cert-processing.certSigningRequest` in the `certs/` directory.

1. Upload the certificate request to the developer console. Select your merchant ID and click "Create Certificate" in the "Payment Processing Certificate" section

1. Download the signed certificate to `certs/cert-processing.cer`, run `make cert-processing.crt` to convert it to the proper format

1. Repeat steps 4-6 for the *Merchant Identity Certificate*, by running `make cert-merchant.certSigningRequest` and, with the certificate, `make cert-merchant.crt`

1. Move the directory `certs/` to `example/certs/`

1. Deploy the application under your domain. We have included a Dockerfile your your convenience; you should be able to run `docker build`, `docker push` and `docker run`.

1. Go to the running application and try to pay with Apple Pay. If you don't see an Apple Pay button, you are probably visiting from an unsupported browser or device. You will not be charged.

## Picking a Payment Service Provider (PSP) that supports Apple Pay

Some PSPs, such as Braintree or Stripe, will accept Apple Pay payments on your behalf. That means that you don't have to use this package and just need to verify your domain with them. If you really want to, you can probably use this package and pass the tokens that decrypt yourself. Check with your processor for more info on how to know how to do that.

Other payment services may not do the integration for you, but will let you pass Apple Pay-related values (such as the payment cryptogram). This package is made for you!

If you can't charge network tokens with your payment processor, unfortunately you will not be able to accept Apple Pay. Contact your provider for more details.