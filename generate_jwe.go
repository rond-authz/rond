package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"gopkg.in/square/go-jose.v2"

	"github.com/rond-authz/rond/custom_builtins"
)

func main2() {
	private_bytes, err := os.ReadFile("./private.pem")
	if err != nil {
		panic(err)
	}
	public_bytes, err := os.ReadFile("./public.pem")
	if err != nil {
		panic(err)
	}

	private_block, _ := pem.Decode(private_bytes)
	public_block, _ := pem.Decode(public_bytes)

	_, err = x509.ParsePKCS1PrivateKey(private_block.Bytes)
	if err != nil {
		panic(err)
	}
	publicKey, err := x509.ParsePKCS1PublicKey(public_block.Bytes)
	if err != nil {
		panic(err)
	}


	// Instantiate an encrypter using RSA-OAEP with AES128-GCM. An error would
	// indicate that the selected algorithm(s) are not currently supported.
	
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP, Key: publicKey}, nil)
	if err != nil {
		panic(err)
	}

	o := custom_builtins.JWEStructure {
		Ftype: "INTERNAL",
		Tower: "C0",
		MemberOf: []string { "OMNPIPPO", "OMNPLUTO" },
	}
	s, err := json.Marshal(o)

	// Encrypt a sample plaintext. Calling the encrypter returns an encrypted
	// JWE object, which can then be serialized for output afterwards. An error
	// would indicate a problem in an underlying cryptographic primitive.
	var plaintext = s
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	// Serialize the encrypted object using the full serialization format.
	// Alternatively you can also use the compact format here by calling
	// object.CompactSerialize() instead.
	serialized, err := object.CompactSerialize()

	fmt.Println(serialized)

	/*
	// Parse the serialized, encrypted JWE object. An error would indicate that
	// the given input did not represent a valid message.
	object, err = jose.ParseEncrypted(serialized)
	if err != nil {
		panic(err)
	}

	// Now we can decrypt and get back our original plaintext. An error here
	// would indicate that the message failed to decrypt, e.g. because the auth
	// tag was broken or the message was tampered with.
	decrypted, err := object.Decrypt(privateKey)
	if err != nil {
		panic(err)
	}

	fmt.Printf(string(decrypted))
	*/
}