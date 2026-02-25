package gcpkms

import (
	"context"
	"errors"
	"fmt"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"

	//"crypto/mldsa"
	"filippo.io/mldsa"
	"github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

type GCPKMS struct {
	jwtsigner.JWTSigner
	KMSURI      string              // needed to sign
	PublicKey   *mldsa.PublicKey    // needed for verify
	Credentials *google.Credentials // option, otherwise derived from application default credentials
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

	if sctx.KMSURI == "" {
		return nil, errors.New("golang-jwt-pqc: kmsuri must be specified for Sign")
	}

	var creds *google.Credentials
	if s.Credentials != nil {
		creds = s.Credentials
	} else {
		var err error
		creds, err = google.FindDefaultCredentials(ctx, cloudkms.DefaultAuthScopes()...)
		if err != nil {
			return nil, fmt.Errorf("golang-jwt-pqc: error getting default credentials %v", err)
		}
	}

	// rest
	//kmsClient, err := cloudkms.NewKeyManagementRESTClient(ctx, option.WithCredentials(creds))
	// grpc
	kmsClient, err := cloudkms.NewKeyManagementClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("golang-jwt-pqc: error creating gcp kms client %v", err)
	}
	defer kmsClient.Close()

	req := &kmspb.AsymmetricSignRequest{
		Name: sctx.KMSURI,
		Data: []byte(signingString),
	}
	dresp, err := kmsClient.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("golang-jwt-pqc: error signing %v", err)
	}

	return dresp.Signature, nil
}

func (k *GCPKMS) GetPublicKey() (*mldsa.PublicKey, error) {

	if k.PublicKey == nil {

		if k.KMSURI == "" {
			return nil, fmt.Errorf("golang-jwt-pqc: error deriving publicKey: either PublicKey or KMSURI must be set")
		}
		ctx := context.Background()
		var creds *google.Credentials
		if k.Credentials != nil {
			creds = k.Credentials
		} else {
			var err error
			creds, err = google.FindDefaultCredentials(ctx, cloudkms.DefaultAuthScopes()...)
			if err != nil {
				return nil, fmt.Errorf("golang-jwt-pqc: error getting default credentials %v", err)
			}
		}

		// rest
		//kmsClient, err := cloudkms.NewKeyManagementRESTClient(ctx, option.WithCredentials(creds))
		// grpc
		kmsClient, err := cloudkms.NewKeyManagementClient(ctx, option.WithCredentials(creds))
		if err != nil {
			return nil, fmt.Errorf("golang-jwt-pqc: error creating gcp kms client %v", err)
		}
		defer kmsClient.Close()

		pk, err := kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
			Name:            k.KMSURI,
			PublicKeyFormat: kmspb.PublicKey_NIST_PQC,
		})
		if err != nil {
			return nil, fmt.Errorf("golang-jwt-pqc: error getting public key %v", err)
		}

		var params *mldsa.Parameters
		switch pk.Algorithm {
		case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44:
			params = mldsa.MLDSA44()
		case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65:
			params = mldsa.MLDSA65()
		case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87:
			params = mldsa.MLDSA87()
		default:
			return nil, fmt.Errorf("golang-jwt-pqc: unsupported algorithm %s\n", pk.Algorithm)
		}
		s, err := mldsa.NewPublicKey(params, pk.PublicKey.Data)
		if err != nil {
			return nil, fmt.Errorf("golang-jwt-pqc: Error recreating public key %v", err)
		}
		k.PublicKey = s
	}
	return k.PublicKey, nil
}
