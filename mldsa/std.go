package mldsa

import (
	"context"
	"crypto"

	//"crypto/mldsa"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	mldsa "filippo.io/mldsa"

	"github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
)

type MLDSA struct {
	jwtsigner.JWTSigner
	PrivateKey *mldsa.PrivateKey // required for sign
	PublicKey  *mldsa.PublicKey  // requried for verify
}

func (s *MLDSA) Sign(signingString string, key interface{}) ([]byte, error) {
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

	sctx, ok := sctxo.Signer.(*MLDSA)
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

func (k *MLDSA) GetPublicKey() (jwtsigner.SubjectPublicKeyInfo, error) {

	var oid asn1.ObjectIdentifier
	switch k.PublicKey.Parameters().String() {
	case mldsa.MLDSA44().String():
		oid = jwtsigner.OidMLDSA44
	case mldsa.MLDSA65().String():
		oid = jwtsigner.OidMLDSA65
	case mldsa.MLDSA87().String():
		oid = jwtsigner.OidMLDSA87
	default:
		return jwtsigner.SubjectPublicKeyInfo{}, fmt.Errorf("golang-jwt-pqc: unsupported scheme %v", k.PublicKey.Parameters().String())
	}

	r := jwtsigner.SubjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		PublicKey: asn1.BitString{
			Bytes: k.PublicKey.Bytes(),
		},
	}
	return r, nil
}
