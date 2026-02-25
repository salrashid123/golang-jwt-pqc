package jwtpqc

import (
	"context"
	"os"
	"testing"

	"filippo.io/mldsa"
	"github.com/stretchr/testify/require"
)

const ()

var ()

func TestNewContext(t *testing.T) {
	// TODO: write test cases
	ctx := context.Background()
	_, err := NewSignerContext(ctx, &SignerConfig{})
	require.NoError(t, err)
}

func TestGetSubjectPublicKeyInfoFromPEM(t *testing.T) {
	pubKeyPEMBytes, err := os.ReadFile("example/certs/ml-dsa-65-public-gcpkms.pem")
	require.NoError(t, err)

	r, err := GetSubjectPublicKeyInfoFromPEM(pubKeyPEMBytes)
	require.NoError(t, err)

	require.Equal(t, r.Parameters(), mldsa.MLDSA65())
}

func TestGetSubjectPrivateKeyInfoFromPEM(t *testing.T) {
	pubKeyPEMBytes, err := os.ReadFile("example/certs/bare_seed/ml-dsa-65-private.pem")
	require.NoError(t, err)

	r, err := GetPrivateKeyInfoFromPEM(pubKeyPEMBytes)
	require.NoError(t, err)

	require.Equal(t, r.PublicKey().Parameters(), mldsa.MLDSA65())
}
