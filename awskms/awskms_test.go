package awskms

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"

	"github.com/stretchr/testify/require"
)

const ()

var ()

func TestKMSDSA65(t *testing.T) {

	access_key_id := os.Getenv("CICD_AWS_ACCESS_KEY")
	access_secret_id := os.Getenv("CICD_AWS_ACCESS_SECRET")
	aws_region := os.Getenv("CICD_AWS_REGION")

	os.Setenv("AWS_ACCESS_KEY_ID", access_key_id)
	os.Setenv("AWS_SECRET_ACCESS_KEY", access_secret_id)
	os.Setenv("AWS_REGION", aws_region)

	keyID := "37aca4ea-3915-441f-b03d-d90bad1eb45a"
	region := aws_region

	// demo signer

	publicPEM, err := os.ReadFile("../example/certs/ml-dsa-65-public-awskms.pem")
	require.NoError(t, err)

	pu, err := jwtsigner.GetSubjectPublicKeyInfoFromPEM(publicPEM)
	require.NoError(t, err)

	ctx := context.Background()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA87, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &AWSKMS{
			KeyID:  keyID,
			Region: region,
		},
	})
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	verifierctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &AWSKMS{
			PublicKey: pu,
		},
	})
	require.NoError(t, err)

	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(verifierctx)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}
