/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/ecdsa"
	"crypto/x509"
	"sync"

	"reflect"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/sm2"

	ccssm2 "github.com/Hyperledger-TWGC/ccs-gm/sm2"
	gmx509 "github.com/Hyperledger-TWGC/ccs-gm/x509"
)

//TWGC todo
//move this into bccsp/sw/new.go
var lock sync.Mutex

//for x509 import
var certImport map[reflect.Type]func(interface{}) interface{}
var keyImport map[reflect.Type]func(opt bccsp.KeyImportOpts) bccsp.KeyImportOpts

//publicKeyToEncryptedPEM
var puk2epem map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error)

//PrivateKeyToDER
var pri2der map[reflect.Type]func(interface{}) ([]byte, error)

//privateKeyToPEM
var pri2pem map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error)

//privateKeyToEncryptedPEM
var pri2epem map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error)

//publicKeyToPEM
var puk2pem map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error)

var PemToPrivateKeys []func(raw []byte, pwd []byte) (interface{}, error)

//new pk
var newpk map[reflect.Type]func(interface{}) bccsp.Key

//new pri key
var newprikey map[reflect.Type]func(interface{}) bccsp.Key

func InitMaps() {
	lock.Lock()
	defer lock.Unlock()
	// init
	// bccsp cert Import validation
	certImport = make(map[reflect.Type]func(interface{}) interface{})
	// bccsp cert key mapping
	keyImport = make(map[reflect.Type]func(opt bccsp.KeyImportOpts) bccsp.KeyImportOpts)

	//from key to file
	// PrivateKeyToDER
	pri2der = make(map[reflect.Type]func(interface{}) ([]byte, error))
	// privateKeyToPEM
	pri2pem = make(map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error))
	// privateKeyToEncryptedPEM
	pri2epem = make(map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error))

	// publicKeyToPEM
	puk2pem = make(map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error))
	// publicKeyToEncryptedPEM
	puk2epem = make(map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error))

	//file to key
	// PemToPrivateKey
	PemToPrivateKeys = make([]func(raw []byte, pwd []byte) (interface{}, error), 0)

	//new key function
	newpk = make(map[reflect.Type]func(interface{}) bccsp.Key)
	newprikey = make(map[reflect.Type]func(interface{}) bccsp.Key)

	//AddWrapper for ecdsa
	certImport[reflect.TypeOf(&x509.Certificate{})] = ECDSAPublicKeyFromCert
	keyImport[reflect.TypeOf(&ecdsa.PublicKey{})] = ECDSAPublicKeyImport
	puk2epem[reflect.TypeOf(&ecdsa.PublicKey{})] = ECDSApublicKeyToEncryptedPEM
	pri2der[reflect.TypeOf(&ecdsa.PrivateKey{})] = ECDSAPrivateKeyToDER
	pri2pem[reflect.TypeOf(&ecdsa.PrivateKey{})] = ECDSAprivateKeyToPEM
	pri2epem[reflect.TypeOf(&ecdsa.PrivateKey{})] = ECDSAprivateKeyToEncryptedPEM
	puk2pem[reflect.TypeOf(&ecdsa.PublicKey{})] = ECDSApublicKeyToPEM
	PemToPrivateKeys = append(PemToPrivateKeys, PemToPrivateKey)
	newpk[reflect.TypeOf(&ecdsa.PublicKey{})] = NewECDSAPubKey
	newprikey[reflect.TypeOf(&ecdsa.PrivateKey{})] = NewECDSAPrivateKey

	//AddWrapper for sm2
	certImport[reflect.TypeOf(&gmx509.Certificate{})] = sm2.GMPublicKeyFromCert
	keyImport[reflect.TypeOf(&ccssm2.PublicKey{})] = sm2.SM2PublicKeyImport
	puk2epem[reflect.TypeOf(&ccssm2.PublicKey{})] = sm2.SM2publicKeyToEncryptedPEM
	pri2der[reflect.TypeOf(&ccssm2.PrivateKey{})] = sm2.SM2PrivateKeyToDER
	pri2pem[reflect.TypeOf(&ccssm2.PrivateKey{})] = sm2.SM2privateKeyToPEM
	pri2epem[reflect.TypeOf(&ccssm2.PrivateKey{})] = sm2.SM2privateKeyToEncryptedPEM
	puk2pem[reflect.TypeOf(&ccssm2.PublicKey{})] = sm2.SM2publicKeyToPEM
	PemToPrivateKeys = append(PemToPrivateKeys, sm2.PemToPrivateKey)
	newpk[reflect.TypeOf(&ccssm2.PublicKey{})] = sm2.NewSM2PubKey
	newprikey[reflect.TypeOf(&ccssm2.PrivateKey{})] = sm2.NewSM2PrivateKey
}

func GetCertImportMap() map[reflect.Type]func(interface{}) interface{} {
	if certImport == nil {
		InitMaps()
	}
	return certImport
}

func GetKeyImportMap() map[reflect.Type]func(opt bccsp.KeyImportOpts) bccsp.KeyImportOpts {
	if keyImport == nil {
		InitMaps()
	}
	return keyImport
}

func Getpuk2epem() map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error) {
	if puk2epem == nil {
		InitMaps()
	}
	return puk2epem
}

func Getpri2der() map[reflect.Type]func(interface{}) ([]byte, error) {
	if pri2der == nil {
		InitMaps()
	}
	return pri2der
}

func Getpri2pem() map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error) {
	if pri2pem == nil {
		InitMaps()
	}
	return pri2pem
}

func Getpri2epem() map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error) {
	if pri2epem == nil {
		InitMaps()
	}
	return pri2epem
}

func Getpuk2pem() map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error) {
	if puk2pem == nil {
		InitMaps()
	}
	return puk2pem
}

func GetPemToPrivateKeys() []func(raw []byte, pwd []byte) (interface{}, error) {
	if PemToPrivateKeys == nil {
		InitMaps()
	}
	return PemToPrivateKeys
}

func GetNewpk() map[reflect.Type]func(interface{}) bccsp.Key {
	if newpk == nil {
		InitMaps()
	}
	return newpk
}

func GetNewprik() map[reflect.Type]func(interface{}) bccsp.Key {
	if newprikey == nil {
		InitMaps()
	}
	return newprikey
}
