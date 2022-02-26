/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bccsp

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"hash"
	"math/big"
	"time"

	"github.com/pkg/errors"
)

type Cert interface {
	Key
	// *x509.Certificate.NotAfter
	NotAfter() time.Time

	// *x509.Certificate.Subject
	Subject() pkix.Name

	//*x509.Certificate.Raw
	Raw() []byte

	//*x509.Certificate.Issuer
	Issuer() pkix.Name

	//*x509.Certificate.SerialNumber
	SerialNumber() *big.Int

	Signature() []byte

	IsCA() bool

	Cert() *x509.Certificate

	Equal(*x509.Certificate) bool
}

// Key represents a cryptographic key
type Key interface {

	// Bytes converts this key to its byte representation,
	// if this operation is allowed.
	Bytes() ([]byte, error)

	// SKI returns the subject key identifier of this key.
	SKI() []byte

	// Symmetric returns true if this key is a symmetric key,
	// false is this key is asymmetric
	Symmetric() bool

	// Private returns true if this key is a private key,
	// false otherwise.
	Private() bool

	// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
	// This method returns an error in symmetric key schemes.
	PublicKey() (Key, error)
}

// KeyGenOpts contains options for key-generation with a CSP.
type KeyGenOpts interface {

	// Algorithm returns the key generation algorithm identifier (to be used).
	Algorithm() string

	// Ephemeral returns true if the key to generate has to be ephemeral,
	// false otherwise.
	Ephemeral() bool
}

// KeyDerivOpts contains options for key-derivation with a CSP.
type KeyDerivOpts interface {

	// Algorithm returns the key derivation algorithm identifier (to be used).
	Algorithm() string

	// Ephemeral returns true if the key to derived has to be ephemeral,
	// false otherwise.
	Ephemeral() bool
}

// KeyImportOpts contains options for importing the raw material of a key with a CSP.
type KeyImportOpts interface {

	// Algorithm returns the key importation algorithm identifier (to be used).
	Algorithm() string

	// Ephemeral returns true if the key generated has to be ephemeral,
	// false otherwise.
	Ephemeral() bool
}

// HashOpts contains options for hashing with a CSP.
type HashOpts interface {

	// Algorithm returns the hash algorithm identifier (to be used).
	Algorithm() string
}

// SignerOpts contains options for signing with a CSP.
type SignerOpts interface {
	crypto.SignerOpts
}

// EncrypterOpts contains options for encrypting with a CSP.
type EncrypterOpts interface{}

// DecrypterOpts contains options for decrypting with a CSP.
type DecrypterOpts interface{}

// BCCSP is the blockchain cryptographic service provider that offers
// the implementation of cryptographic standards and algorithms.
type BCCSP interface {

	// KeyGen generates a key using opts.
	KeyGen(opts KeyGenOpts) (k Key, err error)

	// KeyDeriv derives a key from k using opts.
	// The opts argument should be appropriate for the primitive used.
	KeyDeriv(k Key, opts KeyDerivOpts) (dk Key, err error)

	// KeyImport imports a key from its raw representation using opts.
	// The opts argument should be appropriate for the primitive used.
	KeyImport(raw interface{}, opts KeyImportOpts) (k Key, err error)

	CertImport(raw interface{}, opts KeyImportOpts) (cert Cert, err error)
	// GetKey returns the key this CSP associates to
	// the Subject Key Identifier ski.
	GetKey(ski []byte) (k Key, err error)

	// Hash hashes messages msg using options opts.
	// If opts is nil, the default hash function will be used.
	Hash(msg []byte, opts HashOpts) (hash []byte, err error)

	// GetHash returns and instance of hash.Hash using options opts.
	// If opts is nil, the default hash function will be returned.
	GetHash(opts HashOpts) (h hash.Hash, err error)

	// Sign signs digest using key k.
	// The opts argument should be appropriate for the algorithm used.
	//
	// Note that when a signature of a hash of a larger message is needed,
	// the caller is responsible for hashing the larger message and passing
	// the hash (as digest).
	Sign(k Key, digest []byte, opts SignerOpts) (signature []byte, err error)

	// Verify verifies signature against key k and digest
	// The opts argument should be appropriate for the algorithm used.
	Verify(k Key, signature, digest []byte, opts SignerOpts) (valid bool, err error)

	// Encrypt encrypts plaintext using key k.
	// The opts argument should be appropriate for the algorithm used.
	Encrypt(k Key, plaintext []byte, opts EncrypterOpts) (ciphertext []byte, err error)

	// Decrypt decrypts ciphertext using key k.
	// The opts argument should be appropriate for the algorithm used.
	Decrypt(k Key, ciphertext []byte, opts DecrypterOpts) (plaintext []byte, err error)
}

func GetCertFromPem(idBytes []byte) (*x509.Certificate, error) {
	if idBytes == nil {
		return nil, errors.New("getCertFromPem error: nil idBytes")
	}

	// Decode the pem bytes
	pemCert, _ := pem.Decode(idBytes)
	if pemCert == nil {
		return nil, errors.Errorf("getCertFromPem error: could not decode pem bytes [%v]", idBytes)
	}

	// get a cert
	var cert *x509.Certificate
	cert, err := x509.ParseCertificate(pemCert.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "getCertFromPem error: failed to parse x509 cert")
	}

	return cert, nil
}
