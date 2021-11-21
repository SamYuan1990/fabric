/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"reflect"
	"sync"

	"github.com/Hyperledger-TWGC/ccs-gm/sm3"

	ccssm2 "github.com/Hyperledger-TWGC/ccs-gm/sm2"
	gmx509 "github.com/Hyperledger-TWGC/ccs-gm/x509"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/sm2"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

// NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
// at security level 256, hash family SHA2 and using FolderBasedKeyStore as KeyStore.
func NewDefaultSecurityLevel(keyStorePath string) (bccsp.BCCSP, error) {
	ks := &fileBasedKeyStore{}
	if err := ks.Init(nil, keyStorePath, false); err != nil {
		return nil, errors.Wrapf(err, "Failed initializing key store at [%v]", keyStorePath)
	}

	return NewWithParams(256, "SHA2", ks)
}

// NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
// at security level 256, hash family SHA2 and using the passed KeyStore.
func NewDefaultSecurityLevelWithKeystore(keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	return NewWithParams(256, "SHA2", keyStore)
}

// NewWithParams returns a new instance of the software-based BCCSP
// set at the passed security level, hash family and KeyStore.
func NewWithParams(securityLevel int, hashFamily string, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// Init config
	conf := &config{}
	err := conf.setSecurityLevel(securityLevel, hashFamily)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing configuration at [%v,%v]", securityLevel, hashFamily)
	}

	swbccsp, err := New(keyStore)
	if err != nil {
		return nil, err
	}

	// Notice that errors are ignored here because some test will fail if one
	// of the following call fails.

	// Set the Encryptors
	swbccsp.AddWrapper(reflect.TypeOf(&aesPrivateKey{}), &aescbcpkcs7Encryptor{})

	// Set the Decryptors
	swbccsp.AddWrapper(reflect.TypeOf(&aesPrivateKey{}), &aescbcpkcs7Decryptor{})

	// Set the Signers
	swbccsp.AddWrapper(reflect.TypeOf(&ecdsaPrivateKey{}), &ecdsaSigner{})

	// Set the Verifiers
	swbccsp.AddWrapper(reflect.TypeOf(&ecdsaPrivateKey{}), &ecdsaPrivateKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&ecdsaPublicKey{}), &ecdsaPublicKeyKeyVerifier{})

	// Set the Hashers
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHAOpts{}), &hasher{hash: conf.hashFunction})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA256Opts{}), &hasher{hash: sha256.New})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA384Opts{}), &hasher{hash: sha512.New384})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA3_256Opts{}), &hasher{hash: sha3.New256})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA3_384Opts{}), &hasher{hash: sha3.New384})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM3Opts{}), &hasher{hash: sm3.New})

	// Set the key generators
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAKeyGenOpts{}), &ecdsaKeyGenerator{curve: conf.ellipticCurve})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAP256KeyGenOpts{}), &ecdsaKeyGenerator{curve: elliptic.P256()})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAP384KeyGenOpts{}), &ecdsaKeyGenerator{curve: elliptic.P384()})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.AESKeyGenOpts{}), &aesKeyGenerator{length: conf.aesBitLength})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.AES256KeyGenOpts{}), &aesKeyGenerator{length: 32})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.AES192KeyGenOpts{}), &aesKeyGenerator{length: 24})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.AES128KeyGenOpts{}), &aesKeyGenerator{length: 16})

	// Set the key deriver
	swbccsp.AddWrapper(reflect.TypeOf(&ecdsaPrivateKey{}), &ecdsaPrivateKeyKeyDeriver{})
	swbccsp.AddWrapper(reflect.TypeOf(&ecdsaPublicKey{}), &ecdsaPublicKeyKeyDeriver{})
	swbccsp.AddWrapper(reflect.TypeOf(&aesPrivateKey{}), &aesPrivateKeyKeyDeriver{conf: conf})

	// Set the key importers
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.AES256ImportKeyOpts{}), &aes256ImportKeyOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.HMACImportKeyOpts{}), &hmacImportKeyOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAPKIXPublicKeyImportOpts{}), &ecdsaPKIXPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAPrivateKeyImportOpts{}), &ecdsaPrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{}), &ecdsaGoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.X509PublicKeyImportOpts{}), &x509PublicKeyImportOptsKeyImporter{bccsp: swbccsp})

	// to do package gm
	swbccsp.AddWrapper(reflect.TypeOf(&sm2.SM2PrivateKey{}), &sm2.SM2Signer{})
	swbccsp.AddWrapper(reflect.TypeOf(&sm2.SM2PrivateKey{}), &sm2.SM2PrivateKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&sm2.SM2PublicKey{}), &sm2.SM2PublicKeyKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2KeyGenOpts{}), &sm2.SM2KeyGenerator{})
	swbccsp.AddWrapper(reflect.TypeOf(&sm2.SM2PrivateKey{}), &sm2.SM2PrivateKeyKeyDeriver{})
	swbccsp.AddWrapper(reflect.TypeOf(&sm2.SM2PublicKey{}), &sm2.SM2PublicKeyKeyDeriver{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2PKIXPublicKeyImportOpts{}), &sm2.SM2PKIXPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2PrivateKeyImportOpts{}), &sm2.SM2PrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2GoPublicKeyImportOpts{}), &sm2.SM2GoPublicKeyImportOptsKeyImporter{})
	InitCryptoProviders()

	return swbccsp, nil
}

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

var keyMap map[reflect.Type]func(k interface{}) interface{}

func InitCryptoProviders() {
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
	keyMap = make(map[reflect.Type]func(k interface{}) interface{})

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
	keyMap[reflect.TypeOf(&ecdsaPrivateKey{})] = ECDSAPrivateKeyToInterface
	keyMap[reflect.TypeOf(&ecdsaPublicKey{})] = ECDSAPublicKeyToInterface
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
	keyMap[reflect.TypeOf(&sm2.SM2PrivateKey{})] = sm2.SM2PrivateKeyToInterface
	keyMap[reflect.TypeOf(&sm2.SM2PublicKey{})] = sm2.SM2PublicKeyToInterface
}

func GetCertImportMap() map[reflect.Type]func(interface{}) interface{} {
	if len(certImport) == 0 {
		InitCryptoProviders()
	}
	return certImport
}

func GetKeyImportMap() map[reflect.Type]func(opt bccsp.KeyImportOpts) bccsp.KeyImportOpts {
	if len(keyImport) == 0 {
		InitCryptoProviders()
	}
	return keyImport
}

func Getpuk2epem() map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error) {
	if len(puk2epem) == 0 {
		InitCryptoProviders()
	}
	return puk2epem
}

func Getpri2der() map[reflect.Type]func(interface{}) ([]byte, error) {
	if len(pri2der) == 0 {
		InitCryptoProviders()
	}
	return pri2der
}

func Getpri2pem() map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error) {
	if len(pri2pem) == 0 {
		InitCryptoProviders()
	}
	return pri2pem
}

func Getpri2epem() map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error) {
	if len(pri2epem) == 0 {
		InitCryptoProviders()
	}
	return pri2epem
}

func Getpuk2pem() map[reflect.Type]func(k interface{}, pwd []byte) ([]byte, error) {
	if len(puk2pem) == 0 {
		InitCryptoProviders()
	}
	return puk2pem
}

func GetPemToPrivateKeys() []func(raw []byte, pwd []byte) (interface{}, error) {
	if len(PemToPrivateKeys) == 0 {
		InitCryptoProviders()
	}
	return PemToPrivateKeys
}

func GetNewpk() map[reflect.Type]func(interface{}) bccsp.Key {
	if len(newpk) == 0 {
		InitCryptoProviders()
	}
	return newpk
}

func GetNewprik() map[reflect.Type]func(interface{}) bccsp.Key {
	if len(newprikey) == 0 {
		InitCryptoProviders()
	}
	return newprikey
}

func GetKeyMap() map[reflect.Type]func(interface{}) interface{} {
	if len(keyMap) == 0 {
		InitCryptoProviders()
	}
	return keyMap
}

//privateKey.(*bccspsm2.SM2PrivateKey).GetPrivKey()
//privateKey.(*).GetPrivKey()
