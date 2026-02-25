package jwtpqc

import (
	"context"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	//"crypto/mldsa"
	mldsa "filippo.io/mldsa"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	MLDSA  = "ML-DSA"
	SLHDSA = "SLH-DSA"
)

// JWTSigner one of jwtpwc.MLDSA or jwtpqc.GCPKMS
type JWTSigner interface {
	jwt.SigningMethod
	GetPublicKey() (*mldsa.PublicKey, error)
}

type SignerConfig struct {
	Signer JWTSigner // JWTSigner one of jwtpwc.MLDSA or jwtpqc.GCPKMS
}

type SigningMethodPQ struct {
	alg    string
	family string
}

type signerConfigKey struct{}

var (
	SigningMethodMLDSA44 *SigningMethodPQ
	SigningMethodMLDSA65 *SigningMethodPQ
	SigningMethodMLDSA87 *SigningMethodPQ
)

func init() {
	// ML-DSA-44
	SigningMethodMLDSA44 = &SigningMethodPQ{
		"ML-DSA-44",
		MLDSA,
	}
	jwt.RegisterSigningMethod(SigningMethodMLDSA44.Alg(), func() jwt.SigningMethod {
		return SigningMethodMLDSA44
	})

	// ML-DSA-65
	SigningMethodMLDSA65 = &SigningMethodPQ{
		"ML-DSA-65",
		MLDSA,
	}
	jwt.RegisterSigningMethod(SigningMethodMLDSA65.Alg(), func() jwt.SigningMethod {
		return SigningMethodMLDSA65
	})

	// ML-DSA-87
	SigningMethodMLDSA87 = &SigningMethodPQ{
		"ML-DSA-87",
		MLDSA,
	}
	jwt.RegisterSigningMethod(SigningMethodMLDSA87.Alg(), func() jwt.SigningMethod {
		return SigningMethodMLDSA87
	})
}

func NewSignerContext(parent context.Context, val *SignerConfig) (context.Context, error) {
	return context.WithValue(parent, signerConfigKey{}, val), nil
}

func SignerFromContext(ctx context.Context) (*SignerConfig, bool) {
	val, ok := ctx.Value(signerConfigKey{}).(*SignerConfig)
	return val, ok
}

func SignerVerfiyKeyfunc(ctx context.Context) (jwt.Keyfunc, error) {
	sctxo, ok := SignerFromContext(ctx)
	if !ok {
		return nil, errors.New("golang-jwt-pqc: error getting signer context for verification")
	}
	return func(token *jwt.Token) (interface{}, error) {
		return sctxo.Signer.GetPublicKey()
	}, nil
}

func (s *SigningMethodPQ) Sign(signingString string, key interface{}) ([]byte, error) {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return nil, jwt.ErrInvalidKey
	}

	sctxo, ok := SignerFromContext(ctx)
	if !ok {
		return nil, errors.New("golang-jwt-pqc: error getting thumbprint; invalid context")
	}
	return sctxo.Signer.Sign(signingString, key)
}

func (s *SigningMethodPQ) Alg() string {
	return s.alg
}

func (s *SigningMethodPQ) Verify(signingString string, signature []byte, key interface{}) error {
	p, ok := key.(*mldsa.PublicKey)
	if !ok {
		return fmt.Errorf("golang-jwt-pqc: Error unsupported key %T", key)
	}
	return mldsa.Verify(p, []byte(signingString), signature, nil)
}

func (k *SignerConfig) PublicKey() (*mldsa.PublicKey, error) {
	return k.Signer.GetPublicKey()
}

func GetSubjectPublicKeyInfoFromPEM(in []byte) (*mldsa.PublicKey, error) {

	pubPEMblock, rest := pem.Decode(in)
	if len(rest) != 0 {
		return &mldsa.PublicKey{}, fmt.Errorf("trailing data found during pemDecode")
	}

	var si SubjectPublicKeyInfo

	_, err := asn1.Unmarshal(pubPEMblock.Bytes, &si)
	if err != nil {
		return &mldsa.PublicKey{}, fmt.Errorf("Error unmarshalling pem key %v", err)
	}
	var params *mldsa.Parameters
	if si.Algorithm.Algorithm.Equal(OidMLDSA44) {
		params = mldsa.MLDSA44()
	} else if si.Algorithm.Algorithm.Equal(OidMLDSA65) {
		params = mldsa.MLDSA65()
	} else if si.Algorithm.Algorithm.Equal(OidMLDSA87) {
		params = mldsa.MLDSA87()
	} else {
		return &mldsa.PublicKey{}, fmt.Errorf("unsupported algorithm %s\n", si.Algorithm.Algorithm)
	}
	s, err := mldsa.NewPublicKey(params, si.PublicKey.Bytes)
	if err != nil {
		return &mldsa.PublicKey{}, fmt.Errorf("Error recreating public key %v", err)
	}
	return s, nil

}

func GetPrivateKeyInfoFromPEM(in []byte) (*mldsa.PrivateKey, error) {

	pubPEMblock, rest := pem.Decode(in)
	if len(rest) != 0 {
		return &mldsa.PrivateKey{}, fmt.Errorf("trailing data found during pemDecode")
	}

	var si PrivateKeyInfo

	_, err := asn1.Unmarshal(pubPEMblock.Bytes, &si)
	if err != nil {
		return &mldsa.PrivateKey{}, fmt.Errorf("Error unmarshalling pem key %v", err)
	}

	var params *mldsa.Parameters

	if si.PrivateKeyAlgorithm.Algorithm.Equal(OidMLDSA44) {
		params = mldsa.MLDSA44()
	} else if si.PrivateKeyAlgorithm.Algorithm.Equal(OidMLDSA65) {
		params = mldsa.MLDSA65()
	} else if si.PrivateKeyAlgorithm.Algorithm.Equal(OidMLDSA87) {
		params = mldsa.MLDSA87()
	} else {
		return &mldsa.PrivateKey{}, fmt.Errorf("unsupported algorithm %s\n", si.PrivateKeyAlgorithm.Algorithm)
	}
	s, err := mldsa.NewPrivateKey(params, si.PrivateKey)
	if err != nil {
		return &mldsa.PrivateKey{}, fmt.Errorf("Error recreating private key %v", err)
	}
	return s, nil

}
