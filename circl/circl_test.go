package circl

import (
	"context"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"

	"github.com/stretchr/testify/require"
)

const ()

var ()

func TestDSA44(t *testing.T) {

	// demo signer

	publicPEM, err := os.ReadFile("../example/certs/ml-dsa-44-public.pem")
	require.NoError(t, err)

	pu, err := pki.UnmarshalPEMPublicKey(publicPEM)
	require.NoError(t, err)

	privatePEM, err := os.ReadFile("../example/certs/bare_seed/ml-dsa-44-private.pem")
	require.NoError(t, err)

	rprkix, err := jwtsigner.GetSubjectPrivateKeyInfoFromPEM(privatePEM)
	require.NoError(t, err)
	// privPEMblock, _ := pem.Decode(privatePEM)
	// var rprkix jwtsigner.PrivateKeyInfo
	// _, err = asn1.Unmarshal(privPEMblock.Bytes, &rprkix)
	// require.NoError(t, err)

	// require.Equal(t, rprkix.PrivateKeyAlgorithm.Algorithm, jwtsigner.ML_DSA_44_OID)

	_, pr := mldsa44.NewKeyFromSeed((*[32]byte)(rprkix.PrivateKey))

	ctx := context.Background()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA87, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &CIRCL{
			PrivateKey: pr,
		},
	})
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(context.Background(), &jwtsigner.SignerConfig{
		Signer: &CIRCL{
			PublicKey: pu,
		},
	})
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}

func TestDSA65(t *testing.T) {

	// demo signer
	privatePEM, err := os.ReadFile("../example/certs/bare_seed/ml-dsa-65-private.pem")
	require.NoError(t, err)

	publicPEM, err := os.ReadFile("../example/certs/ml-dsa-65-public.pem")
	require.NoError(t, err)

	pu, err := pki.UnmarshalPEMPublicKey(publicPEM)
	require.NoError(t, err)

	privPEMblock, _ := pem.Decode(privatePEM)
	var rprkix jwtsigner.PrivateKeyInfo
	_, err = asn1.Unmarshal(privPEMblock.Bytes, &rprkix)
	require.NoError(t, err)

	var pr sign.PrivateKey
	require.Equal(t, rprkix.PrivateKeyAlgorithm.Algorithm, jwtsigner.ML_DSA_65_OID)

	_, pr = mldsa65.NewKeyFromSeed((*[32]byte)(rprkix.PrivateKey))

	ctx := context.Background()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA87, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &CIRCL{
			PrivateKey: pr,
		},
	})
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(context.Background(), &jwtsigner.SignerConfig{
		Signer: &CIRCL{
			PublicKey: pu,
		},
	})
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}

func TestDSA87(t *testing.T) {

	// demo signer
	privatePEM, err := os.ReadFile("../example/certs/bare_seed/ml-dsa-87-private.pem")
	require.NoError(t, err)

	publicPEM, err := os.ReadFile("../example/certs/ml-dsa-87-public.pem")
	require.NoError(t, err)

	pu, err := pki.UnmarshalPEMPublicKey(publicPEM)
	require.NoError(t, err)

	privPEMblock, _ := pem.Decode(privatePEM)
	var rprkix jwtsigner.PrivateKeyInfo
	_, err = asn1.Unmarshal(privPEMblock.Bytes, &rprkix)
	require.NoError(t, err)

	var pr sign.PrivateKey
	require.Equal(t, rprkix.PrivateKeyAlgorithm.Algorithm, jwtsigner.ML_DSA_87_OID)

	_, pr = mldsa87.NewKeyFromSeed((*[32]byte)(rprkix.PrivateKey))

	ctx := context.Background()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA87, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &CIRCL{
			PrivateKey: pr,
		},
	})
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(context.Background(), &jwtsigner.SignerConfig{
		Signer: &CIRCL{
			PublicKey: pu,
		},
	})
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}
