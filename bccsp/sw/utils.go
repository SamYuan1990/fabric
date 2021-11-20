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

//to do a map and wrapper for derToPrivateKey

func InitMaps() {
	lock.Lock()
	defer lock.Unlock()
	// init
	// bccsp cert Import validation
	certImport = make(map[reflect.Type]func(interface{}) interface{})
	// bccsp cert key mapping
	keyImport = make(map[reflect.Type]func(opt bccsp.KeyImportOpts) bccsp.KeyImportOpts)
	// publicKeyToEncryptedPEM
	puk2epem = make(map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error))
	//PrivateKeyToDER
	pri2der = make(map[reflect.Type]func(interface{}) ([]byte, error))
	//privateKeyToPEM
	pri2pem = make(map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error))
	//privateKeyToEncryptedPEM
	pri2epem = make(map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error))
	//publicKeyToPEM
	puk2pem = make(map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error))

	//AddWrapper for ecdsa
	certImport[reflect.TypeOf(&x509.Certificate{})] = ECDSAPublicKeyFromCert
	keyImport[reflect.TypeOf(&ecdsa.PublicKey{})] = ECDSAPublicKeyImport
	puk2epem[reflect.TypeOf(&ecdsa.PublicKey{})] = ECDSApublicKeyToEncryptedPEM
	pri2der[reflect.TypeOf(&ecdsa.PrivateKey{})] = ECDSAPrivateKeyToDER
	pri2pem[reflect.TypeOf(&ecdsa.PrivateKey{})] = ECDSAprivateKeyToPEM
	pri2epem[reflect.TypeOf(&ecdsa.PrivateKey{})] = ECDSAprivateKeyToEncryptedPEM
	puk2pem[reflect.TypeOf(&ecdsa.PublicKey{})] = ECDSApublicKeyToPEM

	//AddWrapper for sm2
	certImport[reflect.TypeOf(&gmx509.Certificate{})] = sm2.GMPublicKeyFromCert
	keyImport[reflect.TypeOf(&ccssm2.PublicKey{})] = sm2.SM2PublicKeyImport
	puk2epem[reflect.TypeOf(&ccssm2.PublicKey{})] = sm2.SM2publicKeyToEncryptedPEM
	pri2der[reflect.TypeOf(&ccssm2.PrivateKey{})] = sm2.SM2PrivateKeyToDER
	pri2pem[reflect.TypeOf(&ccssm2.PrivateKey{})] = sm2.SM2privateKeyToPEM
	pri2epem[reflect.TypeOf(&ccssm2.PrivateKey{})] = sm2.SM2privateKeyToEncryptedPEM
	puk2pem[reflect.TypeOf(&ccssm2.PublicKey{})] = SM2publicKeyToPEM
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
