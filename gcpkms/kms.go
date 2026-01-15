package gcpkms

import (
	"context"
	"errors"
	"fmt"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
)

type GCPKMS struct {
	jwtsigner.JWTSigner
	PrivateKey string
	PublicKey  jwtsigner.SubjectPublicKeyInfo
}

func (s *GCPKMS) Sign(signingString string, key interface{}) ([]byte, error) {
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

	sctx, ok := sctxo.Signer.(*GCPKMS)
	if !ok {
		return nil, errors.New("golang-jwt-pqc: error casting signer to GCPKMS")
	}

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return nil, jwt.ErrInvalidKey
	}

	if sctx.PrivateKey == "" {
		return nil, errors.New("golang-jwt-pqc: rivate key must be specified for Sign")
	}

	kmsClient, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		panic(err)
	}
	defer kmsClient.Close()

	req := &kmspb.AsymmetricSignRequest{
		Name: sctx.PrivateKey,
		Data: []byte(signingString),
	}
	dresp, err := kmsClient.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("golang-jwt-pqc: error signing %v", err)
	}
	return dresp.Signature, nil
}

func (k *GCPKMS) GetPublicKey() (jwtsigner.SubjectPublicKeyInfo, error) {
	if k.PublicKey.Algorithm.Algorithm.Equal(jwtsigner.ML_DSA_44_OID) || k.PublicKey.Algorithm.Algorithm.Equal(jwtsigner.ML_DSA_65_OID) || k.PublicKey.Algorithm.Algorithm.Equal(jwtsigner.ML_DSA_87_OID) {
		return k.PublicKey, nil
	}
	return jwtsigner.SubjectPublicKeyInfo{}, fmt.Errorf("golang-jwt-pqc: unsupported scheme %v", k.PublicKey.Algorithm.Algorithm)
}
