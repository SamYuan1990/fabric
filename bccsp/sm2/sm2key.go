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
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	sm2utils "github.com/Hyperledger-TWGC/ccs-gm/utils"
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
	return sm2utils.PublicKeyToPEM(k.(*sm2.PublicKey), pwd)
}

func SM2PrivateKeyToDER(privateKey interface{}) ([]byte, error) {
	return x509.MarshalECPrivateKey(privateKey.(*sm2.PrivateKey))
}

func SM2privateKeyToPEM(k interface{}, pwd []byte) ([]byte, error) {
	return SM2privateKeyToEncryptedPEM(k, pwd)
}

func SM2privateKeyToEncryptedPEM(k interface{}, pwd []byte) ([]byte, error) {
	if k.(*sm2.PrivateKey) == nil {
		return nil, errors.New("Invalid ecdsa private key. It must be different from nil.")
	}
	return sm2utils.PrivateKeyToPEM(k.(*sm2.PrivateKey), pwd)
}

func SM2publicKeyToPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	return SM2publicKeyToEncryptedPEM(publicKey, pwd)
}

func PemToPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	return sm2utils.PEMtoPrivateKey(raw, pwd)
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
