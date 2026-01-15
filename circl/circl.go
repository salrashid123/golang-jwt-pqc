package circl

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
)

type CIRCL struct {
	jwtsigner.JWTSigner
	PrivateKey sign.PrivateKey
	PublicKey  sign.PublicKey
}

func (s *CIRCL) Sign(signingString string, key interface{}) ([]byte, error) {
	var ctx context.Context
	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return nil, jwt.ErrInvalidKey
	}

	sctxo, ok := jwtsigner.SignerFromContext(ctx)
	if !ok {
		return nil, errors.New("golang-jwt-pqc: error loading signer from context")
	}

	sctx, ok := sctxo.Signer.(*CIRCL)
	if !ok {
		return nil, errors.New("golang-jwt-pqc: signer implementation is not CIRCL")
	}

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return nil, jwt.ErrInvalidKey
	}

	if sctx.PrivateKey == nil {
		return nil, errors.New("golang-jwt-pqc: private key must be specified for Sign")
	}
	signedBytes, err := sctx.PrivateKey.Sign(rand.Reader, []byte(signingString), crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	return signedBytes, nil
}

func (k *CIRCL) GetPublicKey() (jwtsigner.SubjectPublicKeyInfo, error) {
	pk, err := k.PublicKey.MarshalBinary()
	if err != nil {
		return jwtsigner.SubjectPublicKeyInfo{}, err
	}
	var oid asn1.ObjectIdentifier

	switch k.PublicKey.Scheme().Name() {
	case mldsa44.Scheme().Name():
		oid = jwtsigner.ML_DSA_44_OID
	case mldsa65.Scheme().Name():
		oid = jwtsigner.ML_DSA_65_OID
	case mldsa87.Scheme().Name():
		oid = jwtsigner.ML_DSA_87_OID
	default:
		return jwtsigner.SubjectPublicKeyInfo{}, fmt.Errorf("golang-jwt-pqc: unsupported scheme %v", k.PublicKey.Scheme().Name())
	}

	r := jwtsigner.SubjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		PublicKey: asn1.BitString{
			Bytes: pk,
		},
	}
	return r, nil
}

func GetCIRCLPrivateKeyFromBareSeed(in []byte) (sign.PrivateKey, error) {

	keyBlock, _ := pem.Decode(in)
	if keyBlock == nil {
		return nil, fmt.Errorf("Failed to find the PEM key block")
	}

	if keyBlock.Type == "ML-DSA-44 PRIVATE KEY" {
		return nil, fmt.Errorf("Please remove ML-DSA-44 PRIVATE KEY header and convert to bare-seed format")
	}

	if keyBlock.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("Please only provide PEM PRIVATE KEY in bare-seed format")
	}

	// unmarshall the private key into so we can just extract the 'seed`
	var rprkix jwtsigner.PrivateKeyInfo
	if rest, err := asn1.Unmarshal(keyBlock.Bytes, &rprkix); err != nil {
		return nil, fmt.Errorf("error unmarshalling private key %v\n", err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("error unmarshalling private key (res is not null)")
	}

	var pr sign.PrivateKey
	if rprkix.PrivateKeyAlgorithm.Algorithm.Equal(jwtsigner.ML_DSA_44_OID) {
		_, pr = mldsa44.NewKeyFromSeed((*[32]byte)(rprkix.PrivateKey))
	}

	if rprkix.PrivateKeyAlgorithm.Algorithm.Equal(jwtsigner.ML_DSA_65_OID) {
		_, pr = mldsa65.NewKeyFromSeed((*[32]byte)(rprkix.PrivateKey))
	}

	if rprkix.PrivateKeyAlgorithm.Algorithm.Equal(jwtsigner.ML_DSA_87_OID) {
		_, pr = mldsa87.NewKeyFromSeed((*[32]byte)(rprkix.PrivateKey))
	}
	return pr, nil

}
