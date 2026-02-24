package main

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	jwtpq "github.com/salrashid123/golang-jwt-pqc"
)

var (
	keyid = "keyid_1"
)

func main() {

	pubKeyPEMBytes, err := os.ReadFile("certs/ml-dsa-44-public.pem")
	if err != nil {
		log.Fatalf("%v", err)
	}

	// or marshal it directly

	pubPEMblock, rest := pem.Decode(pubKeyPEMBytes)
	if len(rest) != 0 {
		log.Fatalf("%v", err)
	}

	var si jwtpq.SubjectPublicKeyInfo

	_, err = asn1.Unmarshal(pubPEMblock.Bytes, &si)
	if err != nil {
		log.Fatalf("%v", err)
	}

	r := jwtpq.SubjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: si.Algorithm.Algorithm,
		},
		PublicKey: asn1.BitString{
			Bytes: si.PublicKey.Bytes,
		},
	}

	// https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/
	pub64 := base64.URLEncoding.EncodeToString(r.PublicKey.Bytes)
	canonicalJSON := fmt.Sprintf("{\"kty\":\"AKP\",\"alg\":\"ML_DSA-44\",\"pub\":\"%s\"}", pub64)
	h := sha256.New()
	h.Write([]byte(canonicalJSON))
	keyid := base64.RawStdEncoding.EncodeToString(h.Sum(nil))
	fmt.Printf("urn:ietf:params:oauth:jwk-thumbprint:sha-256:%s\n", keyid)

	ks := &jwtpq.JSONWebKeySet{
		Keys: []jwtpq.JSONWebKey{{
			Kty: "AKP",
			Alg: "ML-DSA-44",
			Kid: keyid,
			Pub: r.PublicKey.Bytes,
		},
		},
	}

	jsonData, err := json.MarshalIndent(ks, "  ", "  ")
	if err != nil {
		log.Fatal("Error marshalling JSON:", err)
	}

	fmt.Println(string(jsonData))
}
