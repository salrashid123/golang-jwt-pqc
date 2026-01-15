package jwtpqc

import (
	"context"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	MLDSA  = "ML-DSA"
	SLHDSA = "SLH-DSA"
)

type JWTSigner interface {
	jwt.SigningMethod
	GetPublicKey() (SubjectPublicKeyInfo, error)
}

type SignerConfig struct {
	Signer JWTSigner
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
	errMissingConfig     = errors.New("signer: missing configuration in provided context")
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

func SignerVerfiyKeyfunc(ctx context.Context, config *SignerConfig) (jwt.Keyfunc, error) {
	return func(token *jwt.Token) (interface{}, error) {
		return config.Signer.GetPublicKey()
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
	switch k := key.(type) {
	case SubjectPublicKeyInfo:
		if k.Algorithm.Algorithm.Equal(ML_DSA_44_OID) {
			pub, err := mldsa44.Scheme().UnmarshalBinaryPublicKey(k.PublicKey.Bytes)
			if err != nil {
				return err
			}
			mpub, ok := pub.(*mldsa44.PublicKey)
			if !ok {
				return errors.New("golang-jwt-pqc: error casting mldsa publci key")
			}
			vok := mldsa44.Verify(mpub, []byte(signingString), nil, signature)
			if !vok {
				return errors.New("golang-jwt-pqc: Error verifying mldsa44 signature")
			}
		} else if k.Algorithm.Algorithm.Equal(ML_DSA_65_OID) {
			pub, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(k.PublicKey.Bytes)
			if err != nil {
				return err
			}
			mpub, ok := pub.(*mldsa65.PublicKey)
			if !ok {
				return errors.New("golang-jwt-pqc: error casting mldsa public key")
			}
			vok := mldsa65.Verify(mpub, []byte(signingString), nil, signature)
			if !vok {
				return errors.New("golang-jwt-pqc: Error verifying mldsa65 signature")
			}
		} else if k.Algorithm.Algorithm.Equal(ML_DSA_87_OID) {
			pub, err := mldsa87.Scheme().UnmarshalBinaryPublicKey(k.PublicKey.Bytes)
			if err != nil {
				return err
			}
			mpub, ok := pub.(*mldsa87.PublicKey)
			if !ok {
				return errors.New("golang-jwt-pqc: error casting mldsa public key")
			}
			vok := mldsa87.Verify(mpub, []byte(signingString), nil, signature)
			if !vok {
				return errors.New("golang-jwt-pqc: Error verifying mldsa87 signature")
			}
		} else {
			return fmt.Errorf("golang-jwt-pqc: Error unsupported scheme %v", k.Algorithm.Algorithm)
		}
		return nil
	default:
		return errors.New("golang-jwt-pqc: invalid key context")
	}
}

func (k *SignerConfig) GetPublicKey() (SubjectPublicKeyInfo, error) {
	return k.Signer.GetPublicKey()
}

func GetSubjectPublicKeyInfoFromPEM(in []byte) (SubjectPublicKeyInfo, error) {

	pubPEMblock, rest := pem.Decode(in)
	if len(rest) != 0 {
		return SubjectPublicKeyInfo{}, fmt.Errorf("trailing data found during pemDecode")
	}

	var si SubjectPublicKeyInfo

	_, err := asn1.Unmarshal(pubPEMblock.Bytes, &si)
	if err != nil {
		return SubjectPublicKeyInfo{}, fmt.Errorf("Error unmarshalling pem key %v", err)
	}

	if !(si.Algorithm.Algorithm.Equal(ML_DSA_44_OID) || si.Algorithm.Algorithm.Equal(ML_DSA_65_OID) || si.Algorithm.Algorithm.Equal(ML_DSA_87_OID)) {
		return SubjectPublicKeyInfo{}, fmt.Errorf("unsupported algorithm %s\n", si.Algorithm.Algorithm)
	}

	return si, nil

}

func GetSubjectPrivateKeyInfoFromPEM(in []byte) (PrivateKeyInfo, error) {

	pubPEMblock, rest := pem.Decode(in)
	if len(rest) != 0 {
		return PrivateKeyInfo{}, fmt.Errorf("trailing data found during pemDecode")
	}

	var si PrivateKeyInfo

	_, err := asn1.Unmarshal(pubPEMblock.Bytes, &si)
	if err != nil {
		return PrivateKeyInfo{}, fmt.Errorf("Error unmarshalling pem key %v", err)
	}

	if !(si.PrivateKeyAlgorithm.Algorithm.Equal(ML_DSA_44_OID) || si.PrivateKeyAlgorithm.Algorithm.Equal(ML_DSA_65_OID) || si.PrivateKeyAlgorithm.Algorithm.Equal(ML_DSA_87_OID)) {
		return PrivateKeyInfo{}, fmt.Errorf("unsupported algorithm %s\n", si.PrivateKeyAlgorithm.Algorithm)
	}

	return si, nil

}
