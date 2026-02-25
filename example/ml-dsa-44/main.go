package main

import (
	"context"
	//"crypto/mldsa"

	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"filippo.io/mldsa"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	jwt "github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
	mldsasigner "github.com/salrashid123/golang-jwt-pqc/mldsa"
)

var ()

func main() {

	ctx := context.Background()

	// load existing public/private keys

	pubKeyPEMBytes, err := os.ReadFile("certs/ml-dsa-44-public.pem")
	if err != nil {
		log.Fatalf("%v", err)
	}

	publicKey, err := jwtsigner.GetSubjectPublicKeyInfoFromPEM(pubKeyPEMBytes)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// read the public key

	privKeyPEMBytes, err := os.ReadFile("certs/bare_seed/ml-dsa-44-private.pem")
	if err != nil {
		log.Fatalf("%v", err)
	}

	privateKey, err := jwtsigner.GetPrivateKeyInfoFromPEM(privKeyPEMBytes)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// create a JWT
	// note, i'm setting the algorithm statically here.
	//  if you want,  you can derive it from priS.PrivateKeyAlgorithm.Algorithm and then initialize the appropirate class
	fmt.Printf("Key Algorithm: %s\n", privateKey.PublicKey().Parameters().String())

	// issue the jwt
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA44, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &mldsasigner.MLDSA{
			PrivateKey: privateKey,
		},
	})
	if err != nil {
		log.Fatalf("Unable to initialize signer: %v", err)
	}

	token.Header["kid"] = "keyid_1"
	token.Header["kty"] = "AKP"

	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		log.Fatalf("Error signing %v", err)
	}
	log.Printf("TOKEN: %s\n", tokenString)

	// // // verify with  publickey

	verifierctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &mldsasigner.MLDSA{
			PublicKey: publicKey,
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

	// ***********************************************************************************
	// now verify the same thing with a keyfunc

	v, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		log.Fatalf("Error parsing token %v", err)
	}
	if v.Valid {
		log.Println("verified with PubicKey")
	}

	// ***********************************************************************************

	// finally verify with a JWK file
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
					e, err := mldsa.NewPublicKey(mldsa.MLDSA44(), k.Pub)
					if err != nil {
						return nil, err
					}
					return e, nil
				case mldsa65.Scheme().Name():
					e, err := mldsa.NewPublicKey(mldsa.MLDSA65(), k.Pub)
					if err != nil {
						return nil, err
					}
					return e, nil
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
