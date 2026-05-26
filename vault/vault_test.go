package vault

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/vault/api"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
	"github.com/stretchr/testify/require"
)

const ()

var ()

func TestVAULMLDSA65(t *testing.T) {

	vaultToken := os.Getenv("VAULT_TOKEN")
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultNamespace := os.Getenv("VAULT_NAMESPACE")
	keyName := os.Getenv("KEY_NAME")
	// os.Setenv("VAULT_TOKEN", vaultToken)
	// os.Setenv("VAULT_ADDR", vaultAddr)
	// os.Setenv("VAULT_NAMESPACE", vaultNamespace)

	config := api.DefaultConfig()
	config.Address = vaultAddr

	vaultclient, err := api.NewClient(config)
	require.NoError(t, err)

	// Set the enterprise client token
	vaultclient.SetToken(vaultToken)
	vaultclient.SetNamespace(vaultNamespace)
	require.NoError(t, err)

	// // demo signer

	publicPEM, err := os.ReadFile("../example/certs/ml-dsa-65-public-vault.pem")
	require.NoError(t, err)

	pu, err := jwtsigner.GetSubjectPublicKeyInfoFromPEM(publicPEM)
	require.NoError(t, err)

	ctx := context.Background()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA65, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &Vault{
			VaultClient: vaultclient,
			KeyName:     fmt.Sprintf("transit/sign/%s", keyName),
		},
	})
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	verifierctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &Vault{
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
