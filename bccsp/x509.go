/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bccsp

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
)

var (
	oidExtensionSubjectAltName  = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}
)

// verifyLegacyNameConstraints exercises the name constraint validation rules
// that were part of the certificate verification process in Go 1.14.
//
// If a signing certificate contains a name constratint, the leaf certificate
// does not include SAN extensions, and the leaf's common name looks like a
// host name, the validation would fail with an x509.CertificateInvalidError
// and a rason of x509.NameConstraintsWithoutSANs.
func VerifyLegacyNameConstraints(chain []*x509.Certificate) error {
	if len(chain) < 2 {
		return nil
	}

	// Leaf certificates with SANs are fine.
	if oidInExtensions(oidExtensionSubjectAltName, chain[0].Extensions) {
		return nil
	}
	// Leaf certificates without a hostname in CN are fine.
	if !validHostname(chain[0].Subject.CommonName) {
		return nil
	}
	// If an intermediate or root have a name constraint, validation
	// would fail in Go 1.14.
	for _, c := range chain[1:] {
		if oidInExtensions(oidExtensionNameConstraints, c.Extensions) {
			return x509.CertificateInvalidError{Cert: chain[0], Reason: x509.NameConstraintsWithoutSANs}
		}
	}
	return nil
}

func oidInExtensions(oid asn1.ObjectIdentifier, exts []pkix.Extension) bool {
	for _, ext := range exts {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// validHostname reports whether host is a valid hostname that can be matched or
// matched against according to RFC 6125 2.2, with some leniency to accommodate
// legacy values.
//
// This implementation is sourced from the standard library.
func validHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")

	if len(host) == 0 {
		return false
	}

	for i, part := range strings.Split(host, ".") {
		if part == "" {
			// Empty label.
			return false
		}
		if i == 0 && part == "*" {
			// Only allow full left-most wildcards, as those are the only ones
			// we match, and matching literal '*' characters is probably never
			// the expected behavior.
			continue
		}
		for j, c := range part {
			if 'a' <= c && c <= 'z' {
				continue
			}
			if '0' <= c && c <= '9' {
				continue
			}
			if 'A' <= c && c <= 'Z' {
				continue
			}
			if c == '-' && j != 0 {
				continue
			}
			if c == '_' || c == ':' {
				// Not valid characters in hostnames, but commonly
				// found in deployments outside the WebPKI.
				continue
			}
			return false
		}
	}

	return true
}

type VerifyOptions struct {
	x509.VerifyOptions
}

func NewVerifyOptions() *VerifyOptions {
	data := x509.VerifyOptions{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}
	return &VerifyOptions{data}
}

type CRL struct {
	CRL []*pkix.CertificateList
}

func NewCRL(size int) *CRL {
	data := make([]*pkix.CertificateList, size)
	return &CRL{CRL: data}
}

func ParseCRL(bytes []byte) (*pkix.CertificateList, error) {
	return x509.ParseCRL(bytes)
}
