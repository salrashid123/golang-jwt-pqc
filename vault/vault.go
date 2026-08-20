package vault

import (
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"crypto/mldsa"

	"github.com/hashicorp/vault/api"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
)

type Vault struct {
	jwtsigner.JWTSigner
	VaultClient *api.Client      // required
	KeyName     string           // transit/keys/my-signing-key
	PublicKey   *mldsa.PublicKey // needed for verify
}

func (s *Vault) Sign(signingString string, key interface{}) ([]byte, error) {
	var ctx context.Context
	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return nil, errors.New("golang-jwt-pqc: error loading conext for signing")
	}

	sctxo, ok := jwtsigner.SignerFromContext(ctx)
	if !ok {
		return nil, errors.New("golang-jwt-pqc: error getting SignerFromContext")
	}

	sctx, ok := sctxo.Signer.(*Vault)
	if !ok {
		return nil, errors.New("golang-jwt-pqc: error casting signer to AWSKMS")
	}

	if sctx.VaultClient == nil || sctx.KeyName == "" {
		return nil, errors.New("golang-jwt-pqc: both vault client and keyName must be set")
	}

	data := map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString([]byte(signingString)),
	}

	secret, err := s.VaultClient.Logical().Write(s.KeyName, data)
	if err != nil {
		return nil, fmt.Errorf("golang-jwt-pqc: failed to sign data: %v", err)
	}

	fullsignature, ok := secret.Data["signature"].(string)
	if !ok {
		return nil, fmt.Errorf("golang-jwt-pqc:signature not found in vault response")
	}

	if len(strings.Split(fullsignature, ":")) != 3 {
		return nil, fmt.Errorf("golang-jwt-pqc: vault signature has incorrect segments")
	}
	sig := strings.Split(fullsignature, ":")[2]

	sigB, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, fmt.Errorf("golang-jwt-pqc: error decoding signature %v", err)
	}

	return sigB, nil
}

func (k *Vault) GetPublicKey() (*mldsa.PublicKey, error) {

	if k.PublicKey == nil {

		secret, err := k.VaultClient.Logical().Read(k.KeyName)
		if err != nil {
			return nil, fmt.Errorf("failed reading public key: %w", err)
		}

		var pk *mldsa.PublicKey
		if data, ok := secret.Data["keys"].(map[string]interface{}); ok {
			if k2, exists := data["1"].(map[string]interface{}); exists {
				var keyType string
				if namestr, exists := k2["name"].(string); exists {
					keyType = namestr
				} else {
					return nil, errors.New("failed to read keytype")
				}

				if pubKeyStr, exists := k2["public_key"].(string); exists {
					pkb, err := base64.StdEncoding.DecodeString(pubKeyStr)
					if err != nil {
						return nil, fmt.Errorf("golang-jwt-pqc: Error marshallling public key %v", err)
					}

					var params mldsa.Parameters
					var mlAlgo asn1.ObjectIdentifier
					switch keyType {
					case "ml-dsa-44":
						params = mldsa.MLDSA44()
						mlAlgo = jwtsigner.OidMLDSA44
					case "ml-dsa-65":
						params = mldsa.MLDSA65()
						mlAlgo = jwtsigner.OidMLDSA65
					case "ml-dsa-87":
						params = mldsa.MLDSA87()
						mlAlgo = jwtsigner.OidMLDSA87
					default:
						return nil, fmt.Errorf("golang-jwt-pqc: unsupported key type %s", keyType)
					}
					pu := jwtsigner.SubjectPublicKeyInfo{
						Algorithm: pkix.AlgorithmIdentifier{
							Algorithm: mlAlgo,
						},
						PublicKey: asn1.BitString{
							Bytes: pkb,
						},
					}

					publicDER, err := asn1.Marshal(pu)
					if err != nil {
						return nil, fmt.Errorf("golang-jwt-pqc: error marshalling public key %v", err)
					}

					if err := pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}); err != nil {
						return nil, fmt.Errorf("golang-jwt-pqc: error encoding public key pem %v", err)
					}

					pk, err = mldsa.NewPublicKey(params, pkb)
					if err != nil {
						return nil, fmt.Errorf("golang-jwt-pqc: error encoding gettin MLDSA Public key %v", err)
					}
				}

			} else {
				return nil, errors.New("golang-jwt-pqc: Public key version '1' not found in response")
			}
		} else {
			return nil, errors.New("golang-jwt-pqc: Invalid response format from Transit API")
		}
		k.PublicKey = pk
	}
	return k.PublicKey, nil

}
