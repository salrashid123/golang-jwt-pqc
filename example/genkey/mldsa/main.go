package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"

	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

const ()

var ()

func main() {
	flag.Parse()

	ppu, ppr, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	puPem, err := pki.MarshalPEMPublicKey(ppu)
	if err != nil {
		panic(err)
	}

	prPem, err := pki.MarshalPEMPrivateKey(ppr)
	if err != nil {
		panic(err)
	}

	prDer, err := pki.MarshalPKIXPrivateKey(ppr)
	if err != nil {
		panic(err)
	}

	// the following ifyou wanted to construct they prviate key from scratch
	ML_DSA_44_OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}

	type PrivateKeyInfo struct {
		Version             int
		PrivateKeyAlgorithm pkix.AlgorithmIdentifier
		PrivateKey          []byte `asn1:""` // The actual key data, an OCTET STRING
	}

	p := PrivateKeyInfo{
		Version: 0,
		PrivateKeyAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: ML_DSA_44_OID,
		},
		PrivateKey: prDer,
	}
	// result, err := asn1.Marshal(p)
	// if err != nil {
	// 	panic(err)
	// }

	kemblock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: p.PrivateKey[2:], // remove the prefix
	}
	pemBytes := pem.EncodeToMemory(kemblock)

	fmt.Printf("Public : \n%s\n", puPem)
	fmt.Printf("Private  in seed-only format: \n%s\n", prPem)
	fmt.Printf("Private  in bare-seed format: \n%s\n", pemBytes)

	// data := []byte("foo")

	// sig, err := ppr.Sign(rand.Reader, data, crypto.Hash(0))
	// if err != nil {
	// 	panic(err)
	// }
	// log.Printf("Signature %s", base64.StdEncoding.EncodeToString(sig))

	// ok := mldsa44.Verify(ppu, data, nil, sig)
	// if !ok {
	// 	log.Printf("Error verifying")
	// }
}
