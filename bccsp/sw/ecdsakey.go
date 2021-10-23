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
package sm2

// TWGC todo
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
)

<<<<<<< HEAD:bccsp/sw/ecdsakey.go
type ecdsaPrivateKey struct {
	privKey *ecdsa.PrivateKey
=======
type SM2PrivateKey struct {
	PrivKey *sm2.PrivateKey
>>>>>>> add package sm2 and starts with some test cases:bccsp/sm2/sm2key.go
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
<<<<<<< HEAD:bccsp/sw/ecdsakey.go
func (k *ecdsaPrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *ecdsaPrivateKey) SKI() []byte {
	if k.privKey == nil {
=======
func (k *SM2PrivateKey) Bytes() (raw []byte, err error) {
	return x509.MarshalECPrivateKey(k.PrivKey)
}

// SKI returns the subject key identifier of this key.
func (k *SM2PrivateKey) SKI() (ski []byte) {
	if k.PrivKey == nil {
>>>>>>> add package sm2 and starts with some test cases:bccsp/sm2/sm2key.go
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(k.PrivKey.Curve, k.PrivKey.PublicKey.X, k.PrivKey.PublicKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
<<<<<<< HEAD:bccsp/sw/ecdsakey.go
func (k *ecdsaPrivateKey) Symmetric() bool {
=======
func (k *SM2PrivateKey) Symmetric() bool {
>>>>>>> add package sm2 and starts with some test cases:bccsp/sm2/sm2key.go
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
<<<<<<< HEAD:bccsp/sw/ecdsakey.go
func (k *ecdsaPrivateKey) Private() bool {
=======
func (k *SM2PrivateKey) Private() bool {
>>>>>>> add package sm2 and starts with some test cases:bccsp/sm2/sm2key.go
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
<<<<<<< HEAD:bccsp/sw/ecdsakey.go
func (k *ecdsaPrivateKey) PublicKey() (bccsp.Key, error) {
	return &ecdsaPublicKey{&k.privKey.PublicKey}, nil
}

func (k *ecdsaPrivateKey) GetPrivKey() *ecdsa.PrivateKey {
	return k.privKey
}

type ecdsaPublicKey struct {
	pubKey *ecdsa.PublicKey
=======
func (k *SM2PrivateKey) PublicKey() (bccsp.Key, error) {
	return &SM2PublicKey{&k.PrivKey.PublicKey}, nil
}

func NewSm2PrivateKey(privKey *sm2.PrivateKey) *SM2PrivateKey {
	return &SM2PrivateKey{privKey}
}

type SM2PublicKey struct {
	PubKey *sm2.PublicKey
>>>>>>> add package sm2 and starts with some test cases:bccsp/sm2/sm2key.go
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
<<<<<<< HEAD:bccsp/sw/ecdsakey.go
func (k *ecdsaPublicKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.pubKey)
=======
func (k *SM2PublicKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.PubKey)
>>>>>>> add package sm2 and starts with some test cases:bccsp/sm2/sm2key.go
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
<<<<<<< HEAD:bccsp/sw/ecdsakey.go
func (k *ecdsaPublicKey) SKI() []byte {
	if k.pubKey == nil {
=======
func (k *SM2PublicKey) SKI() (ski []byte) {
	if k.PubKey == nil {
>>>>>>> add package sm2 and starts with some test cases:bccsp/sm2/sm2key.go
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(k.PubKey.Curve, k.PubKey.X, k.PubKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
<<<<<<< HEAD:bccsp/sw/ecdsakey.go
func (k *ecdsaPublicKey) Symmetric() bool {
=======
func (k *SM2PublicKey) Symmetric() bool {
>>>>>>> add package sm2 and starts with some test cases:bccsp/sm2/sm2key.go
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
<<<<<<< HEAD:bccsp/sw/ecdsakey.go
func (k *ecdsaPublicKey) Private() bool {
=======
func (k *SM2PublicKey) Private() bool {
>>>>>>> add package sm2 and starts with some test cases:bccsp/sm2/sm2key.go
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
<<<<<<< HEAD:bccsp/sw/ecdsakey.go
func (k *ecdsaPublicKey) PublicKey() (bccsp.Key, error) {
=======
func (k *SM2PublicKey) PublicKey() (bccsp.Key, error) {
>>>>>>> add package sm2 and starts with some test cases:bccsp/sm2/sm2key.go
	return k, nil
}

func (k *ecdsaPublicKey) GetPubKey() *ecdsa.PublicKey {
	return k.pubKey
}
