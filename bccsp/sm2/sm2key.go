/*
Copyright CETCS. 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
	SPDX-License-Identifier: Apache-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sm2

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/Hyperledger-TWGC/ccs-gm/x509"
	"github.com/hyperledger/fabric/bccsp"
)

type SM2PrivateKey struct {
	PrivKey *sm2.PrivateKey
}

type pkcs8Info struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

var oidNamedCurveSm2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case sm2.P256():
		return oidNamedCurveSm2, true
	}
	return nil, false
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *SM2PrivateKey) Bytes() (raw []byte, err error) {
	return x509.MarshalECPrivateKey(k.PrivKey)
}

// SKI returns the subject key identifier of this key.
func (k *SM2PrivateKey) SKI() (ski []byte) {
	if k.PrivKey == nil {
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
func (k *SM2PrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *SM2PrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *SM2PrivateKey) PublicKey() (bccsp.Key, error) {
	return &SM2PublicKey{&k.PrivKey.PublicKey}, nil
}

func (k *SM2PrivateKey) GetPrivKey() *sm2.PrivateKey {
	return k.PrivKey
}

func NewSm2PrivateKey(privKey *sm2.PrivateKey) *SM2PrivateKey {
	return &SM2PrivateKey{privKey}
}

type SM2PublicKey struct {
	PubKey *sm2.PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *SM2PublicKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.PubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *SM2PublicKey) SKI() (ski []byte) {
	if k.PubKey == nil {
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
func (k *SM2PublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *SM2PublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *SM2PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}

func (k *SM2PublicKey) GetPubKey() *sm2.PublicKey {
	return k.PubKey
}

func SM2publicKeyToEncryptedPEM(k interface{}, pwd []byte) ([]byte, error) {
	if k.(*sm2.PublicKey) == nil {
		return nil, errors.New("Invalid sm2 public key. It must be different from nil.")
	}
	raw, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, err
	}

	block, err := x509.EncryptPEMBlock(
		rand.Reader,
		"PUBLIC KEY",
		raw,
		pwd,
		x509.PEMCipherAES256)

	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(block), nil
}

func SM2PrivateKeyToDER(privateKey interface{}) ([]byte, error) {
	return x509.MarshalECPrivateKey(privateKey.(*sm2.PrivateKey))
}

func SM2privateKeyToPEM(k interface{}, pwd []byte) ([]byte, error) {
	if k.(*sm2.PrivateKey) == nil {
		return nil, errors.New("Invalid ecdsa private key. It must be different from nil.")
	}

	// get the oid for the curve
	oidNamedCurve, ok := oidFromNamedCurve(k.(*sm2.PrivateKey).Curve)
	if !ok {
		return nil, errors.New("unknown elliptic curve")
	}

	// based on https://golang.org/src/crypto/x509/sec1.go
	privateKeyBytes := k.(*sm2.PrivateKey).D.Bytes()
	paddedPrivateKey := make([]byte, (k.(*sm2.PrivateKey).Curve.Params().N.BitLen()+7)/8)
	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)
	// omit NamedCurveOID for compatibility as it's optional
	asn1Bytes, err := asn1.Marshal(ecPrivateKey{
		Version:    1,
		PrivateKey: paddedPrivateKey,
		PublicKey:  asn1.BitString{Bytes: elliptic.Marshal(k.(*sm2.PrivateKey).Curve, k.(*sm2.PrivateKey).X, k.(*sm2.PrivateKey).Y)},
	})

	if err != nil {
		return nil, fmt.Errorf("error marshaling SM2 key to asn1 [%s]", err)
	}

	var pkcs8Key pkcs8Info
	pkcs8Key.Version = 0
	pkcs8Key.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 2)
	pkcs8Key.PrivateKeyAlgorithm[0] = oidPublicKeyECDSA
	pkcs8Key.PrivateKeyAlgorithm[1] = oidNamedCurve
	pkcs8Key.PrivateKey = asn1Bytes

	pkcs8Bytes, err := asn1.Marshal(pkcs8Key)
	if err != nil {
		return nil, fmt.Errorf("error marshaling EC key to asn1 [%s]", err)
	}
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8Bytes,
		},
	), nil
}

func SM2privateKeyToEncryptedPEM(k interface{}, pwd []byte) ([]byte, error) {
	if k.(*sm2.PrivateKey) == nil {
		return nil, errors.New("Invalid sm2 private key. It must be different from nil.")
	}
	oid := oidNamedCurveSm2
	privateKeyBytes := k.(*sm2.PrivateKey).D.Bytes()
	paddedPrivateKey := make([]byte, (k.(*sm2.PrivateKey).Curve.Params().N.BitLen()+7)/8)
	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)
	raw, err := asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    paddedPrivateKey,
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(k.(*sm2.PrivateKey).Curve, k.(*sm2.PrivateKey).X, k.(*sm2.PrivateKey).Y)},
	})
	if err != nil {
		return nil, err
	}
	block, err := x509.EncryptPEMBlock(
		rand.Reader,
		"PRIVATE KEY",
		raw,
		pwd,
		x509.PEMCipherAES256)

	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(block), nil
}

func SM2publicKeyToPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	if publicKey.(*sm2.PublicKey) == nil {
		return nil, errors.New("Invalid ecdsa public key. It must be different from nil.")
	}
	PubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: PubASN1,
		},
	), nil
}

func derToSM2PrivateKey(der []byte) (key interface{}, err error) {

	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err = x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key.(type) {
		case *sm2.PrivateKey:
			return
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err = x509.ParseECPrivateKey(der); err == nil {
		return
	}

	return nil, errors.New("invalid key type. The DER must contain an ecdsa.PrivateKey")
}

func PemToPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding PEM. Block must be different from nil [% x]", raw)
	}

	// TODO: derive from header the type of the key

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("encrypted Key. Need a password")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("failed PEM decryption: [%s]", err)
		}

		key, err := derToSM2PrivateKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	cert, err := derToSM2PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

func NewSM2PubKey(k interface{}) bccsp.Key {
	return &SM2PublicKey{PubKey: k.(*sm2.PublicKey)}
}

func NewSM2PrivateKey(k interface{}) bccsp.Key {
	return &SM2PrivateKey{PrivKey: k.(*sm2.PrivateKey)}
}

func SM2PrivateKeyToInterface(k interface{}) interface{} {
	return k.(*SM2PrivateKey).GetPrivKey()
}

func SM2PublicKeyToInterface(k interface{}) interface{} {
	return k.(*SM2PublicKey).GetPubKey()
}
