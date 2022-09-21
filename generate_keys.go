package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main3() {
	// Generate a public/private key pair to use for this example.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publicKey := &privateKey.PublicKey

	private_bytes := x509.MarshalPKCS1PrivateKey(privateKey)
	private_key_pem := pem.EncodeToMemory(
		&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: private_bytes,
		},
	)
	err = os.WriteFile("./private.pem", private_key_pem, 0644)
	
	public_bytes := x509.MarshalPKCS1PublicKey(publicKey)
    public_key_pem := pem.EncodeToMemory(
		&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: public_bytes,
		},
	)
	err = os.WriteFile("./public.pem", public_key_pem, 0644)

	fmt.Println("Done");
}