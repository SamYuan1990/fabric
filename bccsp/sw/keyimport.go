/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/ecdsa"
	"crypto/rsa"

	"crypto/x509"
	"errors"
	"fmt"
	"reflect"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"

	gmx509 "github.com/Hyperledger-TWGC/ccs-gm/x509"
	"github.com/hyperledger/fabric/bccsp"
)

type aes256ImportKeyOptsKeyImporter struct{}

func (*aes256ImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if aesRaw == nil {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	if len(aesRaw) != 32 {
		return nil, fmt.Errorf("Invalid Key Length [%d]. Must be 32 bytes", len(aesRaw))
	}

	return &aesPrivateKey{aesRaw, false}, nil
}

type hmacImportKeyOptsKeyImporter struct{}

func (*hmacImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(aesRaw) == 0 {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	return &aesPrivateKey{aesRaw, false}, nil
}

type ecdsaPKIXPublicKeyImportOptsKeyImporter struct{}

func (*ecdsaPKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
	}

	ecdsaPK, ok := lowLevelKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to ECDSA public key. Invalid raw material.")
	}

	return &ecdsaPublicKey{ecdsaPK}, nil
}

type ecdsaPrivateKeyImportOptsKeyImporter struct{}

func (*ecdsaPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
	}

	ecdsaSK, ok := lowLevelKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to ECDSA private key. Invalid raw material.")
	}

	return &ecdsaPrivateKey{ecdsaSK}, nil
}

type ecdsaGoPublicKeyImportOptsKeyImporter struct{}

func (*ecdsaGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *ecdsa.PublicKey.")
	}

	return &ecdsaPublicKey{lowLevelKey}, nil
}

type x509PublicKeyImportOptsKeyImporter struct {
	bccsp *CSP
}

func (ki *x509PublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	var pk interface{}
	// TWGC todo
	// make this map as global variable
	var m2 map[reflect.Type]func(interface{}) interface{}
	m2 = make(map[reflect.Type]func(interface{}) interface{})
	validate := false
	m2[reflect.TypeOf(&gmx509.Certificate{})] = GMPublicKeyFromCert
	m2[reflect.TypeOf(&x509.Certificate{})] = ECDSAPublicKeyFromCert
	for k, v := range m2 {
		if k == reflect.TypeOf(raw) {
			validate = true
			pk = v(raw)
		}
	}
	if !validate {
		return nil, errors.New("Invalid raw material. Expected *x509.Certificate in ECDSA or GM")
	}

	// TWGC todo
	// make this map as global variable
	var m map[reflect.Type]func(ki *x509PublicKeyImportOptsKeyImporter, opts bccsp.KeyImportOpts, pk interface{}) (bccsp.Key, error)
	m = make(map[reflect.Type]func(ki *x509PublicKeyImportOptsKeyImporter, opts bccsp.KeyImportOpts, pk interface{}) (bccsp.Key, error))
	m[reflect.TypeOf(&ecdsa.PublicKey{})] = ECDSAPublicKeyImport
	m[reflect.TypeOf(&rsa.PublicKey{})] = RSAPublicKeyImport
	m[reflect.TypeOf(&sm2.PublicKey{})] = SM2PublicKeyImport
	for i, v := range m {
		if i == reflect.TypeOf(pk) {
			return v(ki, opts, pk)
		}
	}

	return nil, errors.New("Certificate's public key type not recognized. Supported keys: [ECDSA, RSA]")
}

func RSAPublicKeyImport(ki *x509PublicKeyImportOptsKeyImporter, opts bccsp.KeyImportOpts, pk interface{}) (bccsp.Key, error) {
	return &rsaPublicKey{pubKey: pk.(*rsa.PublicKey)}, nil
}

func ECDSAPublicKeyImport(ki *x509PublicKeyImportOptsKeyImporter, opts bccsp.KeyImportOpts, pk interface{}) (bccsp.Key, error) {
	return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{})].KeyImport(
		pk,
		&bccsp.ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
}

func SM2PublicKeyImport(ki *x509PublicKeyImportOptsKeyImporter, opts bccsp.KeyImportOpts, pk interface{}) (bccsp.Key, error) {
	return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.SM2GoPublicKeyImportOpts{})].KeyImport(
		pk.(*sm2.PublicKey), &bccsp.SM2GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
}

func ECDSAPublicKeyFromCert(raw interface{}) interface{} {
	return raw.(*x509.Certificate).PublicKey
}

func GMPublicKeyFromCert(raw interface{}) interface{} {
	return raw.(*gmx509.Certificate).PublicKey
}
