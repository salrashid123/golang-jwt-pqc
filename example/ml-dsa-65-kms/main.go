package main

import (
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
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
)

func main() {

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
			PrivateKey: fmt.Sprintf("projects/%s/locations/us-central1/keyRings/tkr1/cryptoKeys/mldsa1/cryptoKeyVersions/1", projectID),
		},
	})
	if err != nil {
		log.Fatalf("Unable to initialize signer: %v", err)
	}

	token.Header["kid"] = "keyid_4"

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

	nkeyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{})
	if err != nil {
		log.Fatalf("Unable to initialize signer: %v", err)
	}
	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(nkeyctx, &jwtsigner.SignerConfig{
		Signer: &gcpkmssigner.GCPKMS{
			PublicKey: r,
		},
	})
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

	// use a JWK json as keyfunc

	vr, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kidInter, ok := token.Header["kid"]
		if !ok {
			return nil, fmt.Errorf("could not find kid in JWT header")
		}
		kid, ok := kidInter.(string)
		if !ok {
			return nil, fmt.Errorf("could not convert kid in JWT header to string")
		}

		// read from a file; you can read from a JWK url too
		jwkBytes, err := os.ReadFile("certs/jwk.json")
		if err != nil {
			return nil, fmt.Errorf("%w: error reading jwk", err)
		}

		// find the key by keyid
		var keyset jwtsigner.JSONWebKeySet
		if err := json.Unmarshal(jwkBytes, &keyset); err != nil {
			return nil, fmt.Errorf("%w: error Unmarshal keyset", err)
		}

		// unmarshal the binary forward
		for _, k := range keyset.Keys {
			if k.Kid == kid {
				switch k.Alg {
				case mldsa44.Scheme().Name():
					// pu, err := mldsa44.Scheme().UnmarshalBinaryPublicKey(k.Pub)
					// if err != nil {
					// 	return nil, fmt.Errorf("%w: error UnmarshalBinaryPublicKey ", err)
					// }
					// return pu, nil

					return jwtsigner.SubjectPublicKeyInfo{
						Algorithm: pkix.AlgorithmIdentifier{
							Algorithm: jwtsigner.ML_DSA_44_OID,
						},
						PublicKey: asn1.BitString{
							Bytes: k.Pub,
						},
					}, nil

				case mldsa65.Scheme().Name():
					return jwtsigner.SubjectPublicKeyInfo{
						Algorithm: pkix.AlgorithmIdentifier{
							Algorithm: jwtsigner.ML_DSA_65_OID,
						},
						PublicKey: asn1.BitString{
							Bytes: k.Pub,
						},
					}, nil
				default:
					return nil, fmt.Errorf("error unsupported key alg: %s", k.Alg)
				}
			}
		}
		return nil, fmt.Errorf("keyset not found for key %s", kid)
	})
	if err != nil {
		log.Fatalf("Error parsing token %v", err)
	}
	if vr.Valid {
		log.Println("verified with JWK KeyFunc URL")
	}

}
