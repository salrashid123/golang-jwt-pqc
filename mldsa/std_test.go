package mldsa

import (
	"context"
	//"crypto/mldsa"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"testing"
	"time"

	mldsa "filippo.io/mldsa"

	"github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"

	"github.com/stretchr/testify/require"
)

const ()

var ()

func TestDSA44(t *testing.T) {

	// demo signer

	pubPEMBytes, err := os.ReadFile("../example/certs/ml-dsa-44-public.pem")
	require.NoError(t, err)

	pubPEMblock, _ := pem.Decode(pubPEMBytes)

	var pubF jwtsigner.SubjectPublicKeyInfo

	_, err = asn1.Unmarshal(pubPEMblock.Bytes, &pubF)
	require.NoError(t, err)

	pubFromFile, err := mldsa.NewPublicKey(mldsa.MLDSA44(), pubF.PublicKey.Bytes)
	require.NoError(t, err)

	privatePEM, err := os.ReadFile("../example/certs/bare_seed/ml-dsa-44-private.pem")
	require.NoError(t, err)

	rprkix, err := jwtsigner.GetPrivateKeyInfoFromPEM(privatePEM)
	require.NoError(t, err)

	pubFromPrivate := rprkix.PublicKey()

	require.True(t, pubFromPrivate.Equal(pubFromFile))

	ctx := context.Background()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA44, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &MLDSA{
			PrivateKey: rprkix,
		},
	})
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	verifierctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &MLDSA{
			PublicKey: pubFromPrivate,
		},
	})
	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(verifierctx)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}

func TestDSA65(t *testing.T) {
	pubPEMBytes, err := os.ReadFile("../example/certs/ml-dsa-65-public.pem")
	require.NoError(t, err)

	pubPEMblock, _ := pem.Decode(pubPEMBytes)

	var pubF jwtsigner.SubjectPublicKeyInfo

	_, err = asn1.Unmarshal(pubPEMblock.Bytes, &pubF)
	require.NoError(t, err)

	pubFromFile, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pubF.PublicKey.Bytes)
	require.NoError(t, err)

	privatePEM, err := os.ReadFile("../example/certs/bare_seed/ml-dsa-65-private.pem")
	require.NoError(t, err)

	rprkix, err := jwtsigner.GetPrivateKeyInfoFromPEM(privatePEM)
	require.NoError(t, err)

	pubFromPrivate := rprkix.PublicKey()

	require.True(t, pubFromPrivate.Equal(pubFromFile))

	ctx := context.Background()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA65, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &MLDSA{
			PrivateKey: rprkix,
		},
	})
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	verifierctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &MLDSA{
			PublicKey: pubFromPrivate,
		},
	})
	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(verifierctx)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)

}

func TestDSA87(t *testing.T) {

	pubPEMBytes, err := os.ReadFile("../example/certs/ml-dsa-87-public.pem")
	require.NoError(t, err)

	pubPEMblock, _ := pem.Decode(pubPEMBytes)

	var pubF jwtsigner.SubjectPublicKeyInfo

	_, err = asn1.Unmarshal(pubPEMblock.Bytes, &pubF)
	require.NoError(t, err)

	pubFromFile, err := mldsa.NewPublicKey(mldsa.MLDSA87(), pubF.PublicKey.Bytes)
	require.NoError(t, err)

	privatePEM, err := os.ReadFile("../example/certs/bare_seed/ml-dsa-87-private.pem")
	require.NoError(t, err)

	rprkix, err := jwtsigner.GetPrivateKeyInfoFromPEM(privatePEM)
	require.NoError(t, err)

	pubFromPrivate := rprkix.PublicKey()

	require.True(t, pubFromPrivate.Equal(pubFromFile))

	ctx := context.Background()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA65, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &MLDSA{
			PrivateKey: rprkix,
		},
	})
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	verifierctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &MLDSA{
			PublicKey: pubFromPrivate,
		},
	})
	require.NoError(t, err)

	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(verifierctx)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}
