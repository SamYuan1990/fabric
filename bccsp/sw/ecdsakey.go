/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/hyperledger/fabric/bccsp"
)

type ecdsaPrivateKey struct {
	privKey *ecdsa.PrivateKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *ecdsaPrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *ecdsaPrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(k.privKey.Curve, k.privKey.PublicKey.X, k.privKey.PublicKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *ecdsaPrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *ecdsaPrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *ecdsaPrivateKey) PublicKey() (bccsp.Key, error) {
	return &ecdsaPublicKey{&k.privKey.PublicKey}, nil
}

type ecdsaPublicKey struct {
	pubKey *ecdsa.PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *ecdsaPublicKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *ecdsaPublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *ecdsaPublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *ecdsaPublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *ecdsaPublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}

type ecdsaCert struct {
	cert x509.Certificate
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (cert *ecdsaCert) Bytes() ([]byte, error) {
	return cert.cert.Raw, nil
}

// SKI returns the subject key identifier of this key.
func (cert *ecdsaCert) SKI() []byte {
	if cert.cert.PublicKey == nil {
		return nil
	}

	// Marshall the public key
	// *ecdsa.PublicKey
	ecdsaPK, ok := cert.cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil
	}
	raw := elliptic.Marshal(ecdsaPK.Curve, ecdsaPK.X, ecdsaPK.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (cert *ecdsaCert) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (cert *ecdsaCert) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (cert *ecdsaCert) PublicKey() (bccsp.Key, error) {
	ecdsaPK, ok := cert.cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to ECDSA public key. Invalid raw material.")
	}
	return &ecdsaPublicKey{ecdsaPK}, nil
}

// *x509.Certificate.NotAfter
func (cert *ecdsaCert) NotAfter() time.Time {
	return cert.cert.NotAfter
}

// *x509.Certificate.Subject
func (cert *ecdsaCert) Subject() pkix.Name {
	return cert.cert.Subject
}

//*x509.Certificate.Raw
func (cert *ecdsaCert) Raw() []byte {
	return cert.cert.Raw
}

//*x509.Certificate.Issuer
func (cert *ecdsaCert) Issuer() pkix.Name {
	return cert.cert.Issuer
}

//*x509.Certificate.SerialNumber
func (cert *ecdsaCert) SerialNumber() *big.Int {
	return cert.cert.SerialNumber
}

func (cert *ecdsaCert) Signature() []byte {
	return cert.cert.Signature
}

func (cert *ecdsaCert) IsCA() bool {
	return cert.cert.IsCA
}

func (cert *ecdsaCert) Cert() *x509.Certificate {
	return &cert.cert
}

func (cert *ecdsaCert) Equal(c *x509.Certificate) bool {
	return cert.cert.Equal(c)
}
