/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bccsp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
	"reflect"
	"time"

	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/pkg/errors"
)

type Cert interface {
	Key

	NotBefore() time.Time

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

func GetValidityOptsForCert(mspOption *VerifyOptions, cert *x509.Certificate) x509.VerifyOptions {
	// First copy the opts to override the CurrentTime field
	// in order to make the certificate passing the expiration test
	// independently from the real local current time.
	// This is a temporary workaround for FAB-3678

	var tempOpts x509.VerifyOptions
	tempOpts.Roots = mspOption.Roots
	tempOpts.DNSName = mspOption.DNSName
	tempOpts.Intermediates = mspOption.Intermediates
	tempOpts.KeyUsages = mspOption.KeyUsages
	tempOpts.CurrentTime = cert.NotBefore.Add(time.Second)

	return tempOpts
}

// sanitizeCert ensures that x509 certificates signed using ECDSA
// do have signatures in Low-S. If this is not the case, the certificate
// is regenerated to have a Low-S signature.
func SanitizeCert(mspOptions *VerifyOptions, cert *x509.Certificate) (*x509.Certificate, error) {
	if IsECDSASignedCert(cert) {
		// Lookup for a parent certificate to perform the sanitization
		var parentCert *x509.Certificate
		chain, err := GetUniqueValidationChain(cert, GetValidityOptsForCert(mspOptions, cert))
		if err != nil {
			return nil, err
		}

		// at this point, cert might be a root CA certificate
		// or an intermediate CA certificate
		if cert.IsCA && len(chain) == 1 {
			// cert is a root CA certificate
			parentCert = cert
		} else {
			parentCert = chain[1]
		}

		// Sanitize
		cert, err = SanitizeECDSASignedCert(cert, parentCert)
		if err != nil {
			return nil, err
		}
	}
	return cert, nil
}

func isIdentitySignedInCanonicalForm(sig []byte, mspID string, pemEncodedIdentity []byte) error {
	r, s, err := utils.UnmarshalECDSASignature(sig)
	if err != nil {
		return err
	}

	expectedSig, err := utils.MarshalECDSASignature(r, s)
	if err != nil {
		return err
	}

	if !bytes.Equal(expectedSig, sig) {
		return errors.Errorf("identity %s for MSP %s has a non canonical signature",
			string(pemEncodedIdentity), mspID)
	}

	return nil
}

func IsWellFormed(bytes []byte, mspID string) error {
	bl, rest := pem.Decode(bytes)
	if bl == nil {
		return errors.New("PEM decoding resulted in an empty block")
	}
	if len(rest) > 0 {
		return errors.Errorf("identity %s for MSP %s has trailing bytes", string(bytes), mspID)
	}

	// Important: This method looks very similar to getCertFromPem(idBytes []byte) (*x509.Certificate, error)
	// But we:
	// 1) Must ensure PEM block is of type CERTIFICATE or is empty
	// 2) Must not replace getCertFromPem with this method otherwise we will introduce
	//    a change in validation logic which will result in a chain fork.
	if bl.Type != "CERTIFICATE" && bl.Type != "" {
		return errors.Errorf("pem type is %s, should be 'CERTIFICATE' or missing", bl.Type)
	}
	cert, err := x509.ParseCertificate(bl.Bytes)
	if err != nil {
		return err
	}

	if !IsECDSASignedCert(cert) {
		return nil
	}

	return isIdentitySignedInCanonicalForm(cert.Signature, mspID, bytes)
}

func ValidateCertAgainstChain(cert *x509.Certificate, validationChain []*x509.Certificate, CRL *CRL) error {
	// here we know that the identity is valid; now we have to check whether it has been revoked

	// identify the SKI of the CA that signed this cert
	SKI, err := GetSubjectKeyIdentifierFromCert(validationChain[1])
	if err != nil {
		return errors.WithMessage(err, "could not obtain Subject Key Identifier for signer cert")
	}

	// check whether one of the CRLs we have has this cert's
	// SKI as its AuthorityKeyIdentifier
	for _, crl := range CRL.CRL {
		aki, err := getAuthorityKeyIdentifierFromCrl(crl)
		if err != nil {
			return errors.WithMessage(err, "could not obtain Authority Key Identifier for crl")
		}

		// check if the SKI of the cert that signed us matches the AKI of any of the CRLs
		if bytes.Equal(aki, SKI) {
			// we have a CRL, check whether the serial number is revoked
			for _, rc := range crl.TBSCertList.RevokedCertificates {
				if rc.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					// We have found a CRL whose AKI matches the SKI of
					// the CA (root or intermediate) that signed the
					// certificate that is under validation. As a
					// precaution, we verify that said CA is also the
					// signer of this CRL.
					err = validationChain[1].CheckCRLSignature(crl)
					if err != nil {
						// the CA cert that signed the certificate
						// that is under validation did not sign the
						// candidate CRL - skip
						//mspLogger.Warningf("Invalid signature over the identified CRL, error %+v", err)
						continue
					}

					// A CRL also includes a time of revocation so that
					// the CA can say "this cert is to be revoked starting
					// from this time"; however here we just assume that
					// revocation applies instantaneously from the time
					// the MSP config is committed and used so we will not
					// make use of that field
					return errors.New("The certificate has been revoked")
				}
			}
		}
	}

	return nil
}

// getSubjectKeyIdentifierFromCert returns the Subject Key Identifier for the supplied certificate
// Subject Key Identifier is an identifier of the public key of this certificate
func GetSubjectKeyIdentifierFromCert(cert *x509.Certificate) ([]byte, error) {
	var SKI []byte

	for _, ext := range cert.Extensions {
		// Subject Key Identifier is identified by the following ASN.1 tag
		// subjectKeyIdentifier (2 5 29 14) (see https://tools.ietf.org/html/rfc3280.html)
		if reflect.DeepEqual(ext.Id, asn1.ObjectIdentifier{2, 5, 29, 14}) {
			_, err := asn1.Unmarshal(ext.Value, &SKI)
			if err != nil {
				return nil, errors.Wrap(err, "failed to unmarshal Subject Key Identifier")
			}

			return SKI, nil
		}
	}

	return nil, errors.New("subjectKeyIdentifier not found in certificate")
}

/*
   This is the definition of the ASN.1 marshalling of AuthorityKeyIdentifier
   from https://www.ietf.org/rfc/rfc5280.txt

   AuthorityKeyIdentifier ::= SEQUENCE {
      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }

   KeyIdentifier ::= OCTET STRING

   CertificateSerialNumber  ::=  INTEGER

*/

type authorityKeyIdentifier struct {
	KeyIdentifier             []byte  `asn1:"optional,tag:0"`
	AuthorityCertIssuer       []byte  `asn1:"optional,tag:1"`
	AuthorityCertSerialNumber big.Int `asn1:"optional,tag:2"`
}

// getAuthorityKeyIdentifierFromCrl returns the Authority Key Identifier
// for the supplied CRL. The authority key identifier can be used to identify
// the public key corresponding to the private key which was used to sign the CRL.
func getAuthorityKeyIdentifierFromCrl(crl *pkix.CertificateList) ([]byte, error) {
	aki := authorityKeyIdentifier{}

	for _, ext := range crl.TBSCertList.Extensions {
		// Authority Key Identifier is identified by the following ASN.1 tag
		// authorityKeyIdentifier (2 5 29 35) (see https://tools.ietf.org/html/rfc3280.html)
		if reflect.DeepEqual(ext.Id, asn1.ObjectIdentifier{2, 5, 29, 35}) {
			_, err := asn1.Unmarshal(ext.Value, &aki)
			if err != nil {
				return nil, errors.Wrap(err, "failed to unmarshal AKI")
			}

			return aki.KeyIdentifier, nil
		}
	}

	return nil, errors.New("authorityKeyIdentifier not found in certificate")
}

func ValidateTLSCAIdentity(cert *x509.Certificate, opts *VerifyOptions, CRL *CRL) error {
	if !cert.IsCA {
		return errors.New("Only CA identities can be validated")
	}

	validationChain, err := GetUniqueValidationChain(cert, opts.VerifyOptions)
	if err != nil {
		return errors.WithMessage(err, "could not obtain certification chain")
	}
	if len(validationChain) == 1 {
		// validationChain[0] is the root CA certificate
		return nil
	}

	return ValidateCertAgainstChain(cert, validationChain, CRL)
}

func GetCertificationChainIdentifierFromChain(mspbccsp BCCSP, hashopt string, chain []*x509.Certificate) ([]byte, error) {
	// Hash the chain
	// Use the hash of the identity's certificate as id in the IdentityIdentifier
	hashOpt, err := GetHashOpt(hashopt)
	if err != nil {
		return nil, errors.WithMessage(err, "failed getting hash function options")
	}

	hf, err := mspbccsp.GetHash(hashOpt)
	if err != nil {
		return nil, errors.WithMessage(err, "failed getting hash function when computing certification chain identifier")
	}
	for i := 0; i < len(chain); i++ {
		hf.Write(chain[i].Raw)
	}
	return hf.Sum(nil), nil
}

func GetValidationChain(opts *VerifyOptions, certificationTreeInternalNodesMap map[string]bool, bccspCert Cert, isIntermediateChain bool) ([]*x509.Certificate, error) {
	/*if id == nil {
		return nil, errors.New("Invalid bccsp identity. Must be different from nil.")
	}*/

	// CAs cannot be directly used as identities..
	if bccspCert.IsCA() && !isIntermediateChain {
		return nil, errors.New("An X509 certificate with Basic Constraint: " +
			"Certificate Authority equals true cannot be used as an identity")
	}

	cert := bccspCert.Cert()
	if opts == nil {
		return nil, errors.New("the supplied identity has no verify options")
	}
	validationChain, err := GetUniqueValidationChain(cert, GetValidityOptsForCert(opts, cert))
	if err != nil {
		return nil, errors.WithMessage(err, "failed getting validation chain")
	}

	// we expect a chain of length at least 2
	if len(validationChain) < 2 {
		return nil, errors.Errorf("expected a chain of length at least 2, got %d", len(validationChain))
	}

	// check that the parent is a leaf of the certification tree
	// if validating an intermediate chain, the first certificate will the parent
	parentPosition := 1
	if isIntermediateChain {
		parentPosition = 0
	}
	if certificationTreeInternalNodesMap[string(validationChain[parentPosition].Raw)] {
		return nil, errors.Errorf("invalid validation chain. Parent certificate should be a leaf of the certification tree [%v]", cert.Raw)
	}
	return validationChain, nil
}

func CertifiersIdentifier(root bool, cert *x509.Certificate, mspbccsp BCCSP, opts *VerifyOptions, certificationTreeInternalNodesMap map[string]bool, IdentityIdentifierHashFunction string) ([]byte, error) {
	// 3. get the certification path for it
	var certifiersIdentifier []byte
	var err error
	var chain []*x509.Certificate
	if root {
		chain = []*x509.Certificate{cert}
	} else {
		bccsp_cert, _ := mspbccsp.CertImport(cert, &X509PublicKeyImportOpts{Temporary: true})

		chain, err = GetValidationChain(opts, certificationTreeInternalNodesMap, bccsp_cert, true)
		if err != nil {
			return nil, fmt.Errorf("Failed computing validation chain for [%v]. [%s]", cert, err)
		}
	}

	// 4. compute the hash of the certification path
	certifiersIdentifier, err = GetCertificationChainIdentifierFromChain(mspbccsp, IdentityIdentifierHashFunction, chain)
	if err != nil {
		return nil, fmt.Errorf("Failed computing Certifiers Identifier for [%v]. [%s]", cert.Raw, err)
	}
	return certifiersIdentifier, nil
}

func MakeCertificates(TlsRootCerts [][]byte, TlsIntermediateCerts [][]byte) (*VerifyOptions, []*x509.Certificate, [][]byte, [][]byte, error) {
	opts := NewVerifyOptions()

	tlsRootCerts := make([][]byte, len(TlsRootCerts))
	rootCerts := make([]*x509.Certificate, len(TlsRootCerts))
	for i, trustedCert := range TlsRootCerts {
		cert, err := GetCertFromPem(trustedCert)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		rootCerts[i] = cert
		tlsRootCerts[i] = trustedCert
		opts.Roots.AddCert(cert)
	}

	// make and fill the set of intermediate certs (if present)
	tlsIntermediateCerts := make([][]byte, len(TlsIntermediateCerts))
	intermediateCerts := make([]*x509.Certificate, len(TlsIntermediateCerts))
	for i, trustedCert := range TlsIntermediateCerts {
		cert, err := GetCertFromPem(trustedCert)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		intermediateCerts[i] = cert
		tlsIntermediateCerts[i] = trustedCert
		opts.Intermediates.AddCert(cert)
	}

	all_certificates := append(append([]*x509.Certificate{}, rootCerts...), intermediateCerts...)
	return opts, all_certificates, tlsRootCerts, tlsIntermediateCerts, nil
}
