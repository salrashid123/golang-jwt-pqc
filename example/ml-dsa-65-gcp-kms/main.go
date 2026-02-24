package main

import (
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"log"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
	gcpkmssigner "github.com/salrashid123/golang-jwt-pqc/gcpkms"
)

/*
to use your must bootstrap application default credentials with access to the kms key

gcloud auth application-default login

export GOOGLE_APPLICATION_CREDENTIALS=/path/to/svc-account.json
*/

var (
	projectID = "core-eso"
	kmsURI    = flag.String("kmsURI", "projects/core-eso/locations/us-central1/keyRings/tkr1/cryptoKeys/mldsa1/cryptoKeyVersions/1", "kms key uri")
)

func main() {

	flag.Parse()

	ctx := context.Background()

	// load existing public/private keys

	// issue the jwt
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA65, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &gcpkmssigner.GCPKMS{
			KMSURI: *kmsURI,
		},
	})
	if err != nil {
		log.Fatalf("Unable to initialize signer: %v", err)
	}

	token.Header["kid"] = "keyid_4"
	token.Header["kty"] = "AKP"

	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		log.Fatalf("Error signing %v", err)
	}
	log.Printf("TOKEN: %s\n", tokenString)

	// // // verify with embedded publickey

	pubKeyPEMBytes, err := os.ReadFile("../example/certs/ml-dsa-65-public-gcpkms.pem")
	if err != nil {
		log.Fatalf("%v", err)
	}

	r, err := jwtsigner.GetSubjectPublicKeyInfoFromPEM(pubKeyPEMBytes)
	if err != nil {
		log.Fatalf("%v", err)
	}
	// pubPEMblock, rest := pem.Decode(pubKeyPEMBytes)
	// if len(rest) != 0 {
	// 	log.Fatalf("%v", err)
	// }

	// var si jwtsigner.SubjectPublicKeyInfo

	// _, err = asn1.Unmarshal(pubPEMblock.Bytes, &si)
	// if err != nil {
	// 	log.Fatalf("%v", err)
	// }

	// r := jwtsigner.SubjectPublicKeyInfo{
	// 	Algorithm: pkix.AlgorithmIdentifier{
	// 		Algorithm: si.Algorithm.Algorithm,
	// 	},
	// 	PublicKey: asn1.BitString{
	// 		Bytes: si.PublicKey.Bytes,
	// 	},
	// }

	// creds, err := google.FindDefaultCredentials(context.TODO())
	// if err != nil {
	// 	log.Fatalf("%v", err)
	// }
	verifierctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &gcpkmssigner.GCPKMS{
			PublicKey: r,
			//Credentials: creds,
		},
	})
	if err != nil {
		log.Fatalf("Unable to initialize signer: %v", err)
	}
	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(verifierctx)
	if err != nil {
		log.Fatalf("could not get keyFunc: %v", err)
	}

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if vtoken.Valid {
		log.Println("verified with Signer PublicKey")
	}

	// //

	v, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

		var si jwtsigner.SubjectPublicKeyInfo

		pubPEMblock, rest := pem.Decode(pubKeyPEMBytes)
		if len(rest) != 0 {
			log.Fatalf("%v", err)
		}

		_, err = asn1.Unmarshal(pubPEMblock.Bytes, &si)
		if err != nil {
			log.Fatalf("%v", err)
		}

		r := jwtsigner.SubjectPublicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm: si.Algorithm.Algorithm,
			},
			PublicKey: asn1.BitString{
				Bytes: si.PublicKey.Bytes,
			},
		}

		return r, nil
	})
	if err != nil {
		log.Fatalf("Error parsing token %v", err)
	}
	if v.Valid {
		log.Println("verified with PubicKey")
	}

}
