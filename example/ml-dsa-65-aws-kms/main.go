package main

import (
	"context"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	jwt "github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
	awskmssigner "github.com/salrashid123/golang-jwt-pqc/awskms"
)

/*
export AWS_ACCESS_KEY_ID=redacted
export AWS_SECRET_ACCESS_KEY=redacted
export AWS_REGION="us-east-2"
*/

var (
	keyID     = flag.String("keyID", "37aca4ea-3915-441f-b03d-d90bad1eb45a", "kms key id")
	awsRegion = flag.String("region", "us-east-2", "AWS Region")
)

func main() {

	flag.Parse()

	ctx := context.Background()

	// optional
	// // just print out the public key (save this as example/certs/ml-dsa-65-public-awskms.pem )
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	kmsClient := kms.NewFromConfig(cfg)

	pubOut, err := kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: keyID,
	})
	if err != nil {
		log.Fatalf("error getting publci key %v\n", err)
	}

	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubOut.PublicKey,
	}

	publicKeyPEM := pem.EncodeToMemory(&publicKeyBlock)

	fmt.Println(string(publicKeyPEM))

	/// end optional public key

	// issue the jwt
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA65, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &awskmssigner.AWSKMS{
			KeyID:  *keyID,
			Region: *awsRegion,
			//KMSClient: kmsClient,
		},
	})
	if err != nil {
		log.Fatalf("Unable to initialize signer: %v", err)
	}

	token.Header["kid"] = "keyid_5"
	token.Header["kty"] = "AKP"

	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		log.Fatalf("Error signing %v", err)
	}
	log.Printf("TOKEN: %s\n", tokenString)

	// // // verify with embedded publickey

	pubKeyPEMBytes, err := os.ReadFile("../example/certs/ml-dsa-65-public-awskms.pem")
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

	verifierctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &awskmssigner.AWSKMS{
			//PublicKey: r,
			KeyID:  *keyID,
			Region: *awsRegion,
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
		return r, nil
	})
	if err != nil {
		log.Fatalf("Error parsing token %v", err)
	}
	if v.Valid {
		log.Println("verified with PubicKey")
	}
}
