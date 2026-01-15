package gcpkms

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"

	"github.com/stretchr/testify/require"
)

const ()

var ()

func TestKMSDSA65(t *testing.T) {

	saJSON := os.Getenv("CICD_SA_JSON")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cert.json")

	err := os.WriteFile(filePath, []byte(saJSON), 0644)
	require.NoError(t, err)

	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filePath)

	kmsURI := "projects/core-eso/locations/us-central1/keyRings/tkr1/cryptoKeys/mldsa1/cryptoKeyVersions/1"
	// demo signer

	publicPEM, err := os.ReadFile("../example/certs/ml-dsa-65-public-gcpkms.pem")
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
		Signer: &GCPKMS{
			PrivateKey: kmsURI,
		},
	})
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(context.Background(), &jwtsigner.SignerConfig{
		Signer: &GCPKMS{
			PublicKey: pu,
		},
	})
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}
