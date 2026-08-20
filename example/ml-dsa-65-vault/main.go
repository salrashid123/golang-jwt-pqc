package main

import (
	"context"
	"crypto/mldsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/vault/api"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
	mldsasigner "github.com/salrashid123/golang-jwt-pqc/mldsa"
	vaultsigner "github.com/salrashid123/golang-jwt-pqc/vault"
)

/*
export VAULT_TOKEN=hvs.CAESIMjAmW4cX_qit-BvEOAeAptS3gGQINYy0RDhWYKul3ZzGicKImh2cy5a--redacted
export VAULT_ADDR="https://vault-cluster-public-vault-22f2dfd2.6ac26e3a.z1.hashicorp.cloud:8200"
export VAULT_NAMESPACE="admin"
*/

var (
	vault_token = flag.String("vault_token", "hvs.CAESIFlBXnLygT9UdIVU92IitpBl_Ob4MsVgZbLrV3wcmn69GicKImh2cy5mRnbmh-redacted", "vault token")
	vault_addr  = flag.String("vault_addr", "https://vault-cluster-public-vault-c305537c.8639af5b.z1.hashicorp.cloud:8200", "vault address")
	namespace   = flag.String("namespace", "admin", "vault namespace")
	keyName     = flag.String("keyName", "my-sign-key", "name of the Key")
)

func main() {

	flag.Parse()

	ctx := context.Background()

	config := api.DefaultConfig()
	config.Address = *vault_addr

	vaultclient, err := api.NewClient(config)
	if err != nil {
		log.Fatalf("error initializing vault client: %w", err)
	}

	// Set the enterprise client token
	vaultclient.SetToken(*vault_token)
	vaultclient.SetNamespace(*namespace)
	if err != nil {
		log.Fatal(err)
	}

	// get the public key
	k, err := getPublicKey(vaultclient, fmt.Sprintf("transit/keys/%s", *keyName))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Got Public Key %s\n", k.Parameters())

	/// end optional public key

	// issue the jwt
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA65, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &vaultsigner.Vault{
			VaultClient: vaultclient,
			KeyName:     fmt.Sprintf("transit/sign/%s", *keyName),
			PublicKey:   k,
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

	// // // // verify with embedded publickey

	// verify with context
	verifierctxdirect, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &mldsasigner.MLDSA{
			PublicKey: k,
		},
	})
	if err != nil {
		log.Fatalf("Unable to initialize signer: %v", err)
	}
	keyFuncdirect, err := jwtsigner.SignerVerfiyKeyfunc(verifierctxdirect)
	if err != nil {
		log.Fatalf("could not get keyFunc: %v", err)
	}

	verifiedDirect, err := jwt.Parse(tokenString, keyFuncdirect)
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if verifiedDirect.Valid {
		log.Println("verified with Signer PublicKey")
	}

}

func getPublicKey(client *api.Client, path string) (*mldsa.PublicKey, error) {
	secret, err := client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	var pk *mldsa.PublicKey
	var keytype string
	if data, ok := secret.Data["keys"].(map[string]interface{}); ok {

		if k2, exists := data["1"].(map[string]interface{}); exists {

			if namestr, exists := k2["name"].(string); exists {
				keytype = namestr
			}
			fmt.Println(keytype)
			if pubKeyStr, exists := k2["public_key"].(string); exists {
				pkb, err := base64.StdEncoding.DecodeString(pubKeyStr)
				if err != nil {
					fmt.Printf("Error marshallling %v", err)
					return nil, err
				}

				pu := jwtsigner.SubjectPublicKeyInfo{
					Algorithm: pkix.AlgorithmIdentifier{
						Algorithm: jwtsigner.OidMLDSA65,
					},
					PublicKey: asn1.BitString{
						Bytes: pkb,
					},
				}

				publicDER, err := asn1.Marshal(pu)
				if err != nil {
					fmt.Printf("Error marshallling %v", err)
					return nil, err
				}

				if err := pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}); err != nil {
					fmt.Printf("Failed to write data: %s", err)
					return nil, err
				}

				pk, err = mldsa.NewPublicKey(mldsa.MLDSA65(), pkb)
				if err != nil {
					fmt.Printf("error signing %v", err)
					return nil, err
				}
			}

		} else {
			log.Fatalf("Public key version '1' not found in response")
		}
	} else {
		log.Fatalf("Invalid response format from Transit API")
	}

	return pk, nil
}
