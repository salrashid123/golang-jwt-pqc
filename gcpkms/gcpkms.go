package gcpkms

import (
	"context"
	"errors"
	"fmt"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

type GCPKMS struct {
	jwtsigner.JWTSigner
	KMSURI      string                         // needed to sign
	PublicKey   jwtsigner.SubjectPublicKeyInfo // needed for verify
	Credentials *google.Credentials            // option, otherwise derived from application default credentials
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

func (k *GCPKMS) GetPublicKey() (jwtsigner.SubjectPublicKeyInfo, error) {
	if k.PublicKey.Algorithm.Algorithm.Equal(jwtsigner.OidMLDSA44) || k.PublicKey.Algorithm.Algorithm.Equal(jwtsigner.OidMLDSA65) || k.PublicKey.Algorithm.Algorithm.Equal(jwtsigner.OidMLDSA87) {
		return k.PublicKey, nil
	}
	return jwtsigner.SubjectPublicKeyInfo{}, fmt.Errorf("golang-jwt-pqc: unsupported scheme %v", k.PublicKey.Algorithm.Algorithm)
}
