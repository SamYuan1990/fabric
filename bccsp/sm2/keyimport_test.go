/*
Copyright TWGC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sm2_test

import (
	"crypto/rand"

	ccssm2 "github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/hyperledger/fabric/bccsp/sm2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Keyimport", func() {

	It("SM2PrivateKeyImportOptsKeyImporter", func() {
		ccssm2key, _ := ccssm2.GenerateKey(rand.Reader)
		instance := &sm2.SM2PrivateKeyImportOptsKeyImporter{}
		key_instance := sm2.NewSm2PrivateKey(ccssm2key)
		priv := key_instance.GetPrivKey()
		bytes, _ := sm2.SM2PrivateKeyToDER(priv)
		key, err := instance.KeyImport(bytes, nil)
		Expect(err).NotTo(HaveOccurred())

		testMsg := []byte("123456")

		SM2Signer := &sm2.SM2Signer{}
		signedData, _ := SM2Signer.Sign(key, testMsg, nil)
		SM2GoPublicKeyImportOptsKeyImporter := &sm2.SM2GoPublicKeyImportOptsKeyImporter{}
		SM2PublicKeyKeyVerifier := &sm2.SM2PublicKeyKeyVerifier{}
		pubkey := ccssm2key.Public()
		bccsppubk, _ := SM2GoPublicKeyImportOptsKeyImporter.KeyImport(pubkey, nil)
		ok, _ := SM2PublicKeyKeyVerifier.Verify(bccsppubk, signedData, testMsg, nil)
		Expect(ok).To(BeTrue())
	})
})
