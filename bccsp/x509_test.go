/*
Copyright IBM Corp. 2017 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0

*/

package bccsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func computeSKI(key *ecdsa.PublicKey) []byte {
	raw := elliptic.Marshal(key.Curve, key.X, key.Y)
	hash := sha256.Sum256(raw)
	return hash[:]
}

func TestValidateCANameConstraintsMitigation(t *testing.T) {
	// Prior to Go 1.15, if a signing certificate contains a name constraint, the
	// leaf certificate does not include a SAN, and the leaf common name looks
	// like a valid hostname, the certificate chain would fail to validate.
	// (This behavior may have been introduced with Go 1.10.)
	//
	// In Go 1.15, the behavior has changed and, by default, the same structure
	// will validate. This test asserts on the old behavior.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caKeyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	caTemplate := x509.Certificate{
		Subject:                     pkix.Name{CommonName: "TestCA"},
		SerialNumber:                big.NewInt(1),
		NotBefore:                   time.Now().Add(-1 * time.Hour),
		NotAfter:                    time.Now().Add(2 * time.Hour),
		ExcludedDNSDomains:          []string{"example.com"},
		PermittedDNSDomainsCritical: true,
		IsCA:                        true,
		BasicConstraintsValid:       true,
		KeyUsage:                    caKeyUsage,
		SubjectKeyId:                computeSKI(caKey.Public().(*ecdsa.PublicKey)),
	}
	caCertBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, caKey.Public(), caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caCertBytes)
	require.NoError(t, err)

	leafTemplate := x509.Certificate{
		Subject:      pkix.Name{CommonName: "localhost"},
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: computeSKI(leafKey.Public().(*ecdsa.PublicKey)),
	}
	leafCertBytes, err := x509.CreateCertificate(rand.Reader, &leafTemplate, ca, leafKey.Public(), caKey)
	require.NoError(t, err)

	t.Run("VerifyNameConstraintsSingleCert", func(t *testing.T) {
		for _, der := range [][]byte{caCertBytes, leafCertBytes} {
			cert, err := x509.ParseCertificate(der)
			require.NoError(t, err, "failed to parse certificate")

			err = VerifyLegacyNameConstraints([]*x509.Certificate{cert})
			require.NoError(t, err, "single certificate should not trigger legacy constraints")
		}
	})

	t.Run("VerifyNameConstraints", func(t *testing.T) {
		var certs []*x509.Certificate
		for _, der := range [][]byte{leafCertBytes, caCertBytes} {
			cert, err := x509.ParseCertificate(der)
			require.NoError(t, err, "failed to parse certificate")
			certs = append(certs, cert)
		}

		err = VerifyLegacyNameConstraints(certs)
		require.Error(t, err, "certificate chain should trigger legacy constraints")
		var cie x509.CertificateInvalidError
		require.True(t, errors.As(err, &cie))
		require.Equal(t, x509.NameConstraintsWithoutSANs, cie.Reason)
	})

	t.Run("VerifyNameConstraintsWithSAN", func(t *testing.T) {
		caCert, err := x509.ParseCertificate(caCertBytes)
		require.NoError(t, err)

		leafTemplate := leafTemplate
		leafTemplate.DNSNames = []string{"localhost"}

		leafCertBytes, err := x509.CreateCertificate(rand.Reader, &leafTemplate, caCert, leafKey.Public(), caKey)
		require.NoError(t, err)

		leafCert, err := x509.ParseCertificate(leafCertBytes)
		require.NoError(t, err)

		err = VerifyLegacyNameConstraints([]*x509.Certificate{leafCert, caCert})
		require.NoError(t, err, "signer with name constraints and leaf with SANs should be valid")
	})
}

func TestValidHostname(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"", false},
		{".", false},
		{"example.com", true},
		{"example.com.", true},
		{"*.example.com", true},
		{".example.com", false},
		{"host.*.example.com", false},
		{"localhost", true},
		{"-localhost", false},
		{"Not_Quite.example.com", true},
		{"weird:colon.example.com", true},
		{"1-2-3.example.com", true},
	}
	for _, tt := range tests {
		if tt.valid {
			require.True(t, validHostname(tt.name), "expected %s to be a valid hostname", tt.name)
		} else {
			require.False(t, validHostname(tt.name), "expected %s to be an invalid hostname", tt.name)
		}
	}
}
