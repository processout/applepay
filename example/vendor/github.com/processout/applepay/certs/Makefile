cert-merchant.certSigningRequest:
	cfssl genkey cert-merchant.json | cfssljson -bare cert-merchant
	mv cert-merchant.csr cert-merchant.certSigningRequest

cert-merchant.crt: cert-merchant.cer
	openssl x509 -inform der -in cert-merchant.cer -out cert-merchant.crt

cert-processing.certSigningRequest:
	cfssl genkey cert-processing.json | cfssljson -bare cert-processing
	mv cert-processing.csr cert-processing.certSigningRequest

cert-processing.crt: cert-processing.cer
	openssl x509 -inform der -in cert-processing.cer -out cert-processing.crt

.PHONY: clean
clean:
	$(RM) *.certSigningRequest
	$(RM) *.cer
