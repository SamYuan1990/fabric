/*
Copyright TWGC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sm2

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/Hyperledger-TWGC/ccs-gm/x509"
	"github.com/hyperledger/fabric/bccsp"
)

type SM2PKIXPublicKeyImportOptsKeyImporter struct{}

func (*SM2PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	//lowLevelKey, err := utils.DERToPublicKey(der)
	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to sm2 public key [%s]", err)
	}

	sm2PK, ok := lowLevelKey.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to sm2 public key. Invalid raw material.")
	}

	return &SM2PublicKey{sm2PK}, nil
}

type SM2PrivateKeyImportOptsKeyImporter struct{}

func (*SM2PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[sm2DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[sm2DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	//lowLevelKey, err := utils.DERToPrivateKey(der)
	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to sm2 public key [%s]", err)
	}

	sm2SK, ok := lowLevelKey.(*sm2.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to sm2 private key. Invalid raw material.")
	}

	return &SM2PrivateKey{sm2SK}, nil
}

type SM2GoPublicKeyImportOptsKeyImporter struct{}

func (*SM2GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *sm2.PublicKey.")
	}

	return &SM2PublicKey{lowLevelKey}, nil
}

func derToPrivateKey(der []byte) (key interface{}, err error) {

	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err = x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key.(type) {
		case *ecdsa.PrivateKey, *sm2.PrivateKey:
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

func derToPublicKey(raw []byte) (pub interface{}, err error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid DER. It must be different from nil")
	}

	key, err := x509.ParsePKIXPublicKey(raw)

	return key, err
}

func GMPublicKeyFromCert(raw interface{}) interface{} {
	return raw.(*x509.Certificate).PublicKey
}

func SM2PublicKeyImport(opts bccsp.KeyImportOpts) bccsp.KeyImportOpts {
	return &bccsp.SM2GoPublicKeyImportOpts{Temporary: opts.Ephemeral()}
}
