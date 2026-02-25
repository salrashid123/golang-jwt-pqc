package awskms

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"

	//"crypto/mldsa"

	"filippo.io/mldsa"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
)

type AWSKMS struct {
	jwtsigner.JWTSigner
	KeyID     string           // required
	Region    string           // required
	KMSClient *kms.Client      // optional
	PublicKey *mldsa.PublicKey // needed for verify
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

func (k *AWSKMS) GetPublicKey() (*mldsa.PublicKey, error) {

	if k.PublicKey == nil {

		if k.KeyID == "" || k.Region == "" {
			return nil, errors.New("golang-jwt-pqc: both keyID and region must be set")
		}

		if k.KMSClient == nil {
			cfg, err := config.LoadDefaultConfig(context.TODO())
			if err != nil {
				return nil, fmt.Errorf("golang-jwt-pqc: unable to load SDK config, %v", err)
			}
			k.KMSClient = kms.NewFromConfig(cfg)
		}

		input := &kms.GetPublicKeyInput{
			KeyId: &k.KeyID,
		}

		resp, err := k.KMSClient.GetPublicKey(context.Background(), input)
		if err != nil {
			return nil, fmt.Errorf("golang-jwt-pqc: error signing %v\n", err)
		}

		var params *mldsa.Parameters
		switch resp.KeySpec {
		case types.KeySpecMlDsa44:
			params = mldsa.MLDSA44()
		case types.KeySpecMlDsa65:
			params = mldsa.MLDSA65()
		case types.KeySpecMlDsa87:
			params = mldsa.MLDSA87()
		default:
			return nil, fmt.Errorf("golang-jwt-pqc: unsupported algorithm %s\n", resp.KeySpec)
		}

		var si jwtsigner.SubjectPublicKeyInfo
		_, err = asn1.Unmarshal(resp.PublicKey, &si)
		if err != nil {
			return nil, fmt.Errorf("golang-jwt-pqc: error unmarshalling public key %v", err)
		}
		s, err := mldsa.NewPublicKey(params, si.PublicKey.Bytes)
		if err != nil {
			return nil, fmt.Errorf("golang-jwt-pqc: Error recreating public key %v", err)
		}
		k.PublicKey = s
	}
	return k.PublicKey, nil

}
