package mldsa

import (
	"context"
	"crypto"

	//"crypto/mldsa"
	"crypto/rand"
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

func (k *MLDSA) GetPublicKey() (*mldsa.PublicKey, error) {

	if k.PublicKey == nil && k.PrivateKey == nil {
		return &mldsa.PublicKey{}, fmt.Errorf("golang-jwt-pqc: both public and private key cannot be null")
	}

	if k.PublicKey == nil && k.PrivateKey != nil {
		k.PublicKey = k.PrivateKey.PublicKey()
	}

	return k.PublicKey, nil
}
