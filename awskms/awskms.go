package awskms

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
)

type AWSKMS struct {
	jwtsigner.JWTSigner
	KeyID     string                         // required
	Region    string                         // required
	KMSClient *kms.Client                    // optional
	PublicKey jwtsigner.SubjectPublicKeyInfo // required for verify
}

func (s *AWSKMS) Sign(signingString string, key interface{}) ([]byte, error) {
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

	sctx, ok := sctxo.Signer.(*AWSKMS)
	if !ok {
		return nil, errors.New("golang-jwt-pqc: error casting signer to AWSKMS")
	}

	if sctx.KeyID == "" || sctx.Region == "" {
		return nil, errors.New("golang-jwt-pqc: both keyID and region must be set")
	}

	if s.KMSClient == nil {
		cfg, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("golang-jwt-pqc: unable to load SDK config, %v", err)
		}
		s.KMSClient = kms.NewFromConfig(cfg)
	}

	input := &kms.SignInput{
		KeyId:            &s.KeyID,
		Message:          []byte(signingString),
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecMlDsaShake256,
	}

	resp, err := s.KMSClient.Sign(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("golang-jwt-pqc: error signing %v\n", err)
	}

	return resp.Signature, nil
}

func (k *AWSKMS) GetPublicKey() (jwtsigner.SubjectPublicKeyInfo, error) {
	if k.PublicKey.Algorithm.Algorithm.Equal(jwtsigner.OidMLDSA44) || k.PublicKey.Algorithm.Algorithm.Equal(jwtsigner.OidMLDSA65) || k.PublicKey.Algorithm.Algorithm.Equal(jwtsigner.OidMLDSA87) {
		return k.PublicKey, nil
	}
	return jwtsigner.SubjectPublicKeyInfo{}, fmt.Errorf("golang-jwt-pqc: unsupported scheme %v", k.PublicKey.Algorithm.Algorithm)
}
