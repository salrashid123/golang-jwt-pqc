package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
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

	//ctx := context.Background()

	// privKeyPEMBytes, err := os.ReadFile("certs/ml-dsa-44-private.pem")
	// if err != nil {
	// 	log.Fatalf("%v", err)
	// }

	// pr, err := pki.UnmarshalPEMPrivateKey(privKeyPEMBytes)
	// if err != nil {
	// 	log.Fatalf("%v", err)
	// }

	pubKeyPEMBytes, err := os.ReadFile("certs/ml-dsa-44-public.pem")
	if err != nil {
		log.Fatalf("%v", err)
	}

	// read the key using circl
	// pu, err := pki.UnmarshalPEMPublicKey(pubKeyPEMBytes)
	// if err != nil {
	// 	log.Fatalf("%v", err)
	// }

	// pubin, err := pu.MarshalBinary()
	// if err != nil {
	// 	log.Fatalf("%v", err)
	// }

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

	ks := &jwtpq.JSONWebKeySet{
		Keys: []jwtpq.JSONWebKey{{
			Kty: "ML-DSA",
			Alg: "ML-DSA-44",
			Kid: keyid,
			Pub: r.PublicKey.Bytes,
		},
		},
	}

	// j, err := json.Marshal(ks)
	// if err != nil {
	// 	log.Fatalf("%v", err)
	// }

	jsonData, err := json.MarshalIndent(ks, "  ", "  ")
	if err != nil {
		log.Fatal("Error marshalling JSON:", err)
	}

	fmt.Println(string(jsonData))
}
