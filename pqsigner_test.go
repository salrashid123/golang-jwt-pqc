package jwtpqc

import (
	"context"
	"os"
	"testing"

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

	require.True(t, r.Algorithm.Algorithm.Equal(ML_DSA_65_OID))
}

func TestGetSubjectPrivateKeyInfoFromPEM(t *testing.T) {
	pubKeyPEMBytes, err := os.ReadFile("example/certs/bare_seed/ml-dsa-65-private.pem")
	require.NoError(t, err)

	r, err := GetSubjectPrivateKeyInfoFromPEM(pubKeyPEMBytes)
	require.NoError(t, err)

	require.True(t, r.PrivateKeyAlgorithm.Algorithm.Equal(ML_DSA_65_OID))
}
