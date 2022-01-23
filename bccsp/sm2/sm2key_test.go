/*
Copyright TWGC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sm2_test

import (
	"crypto/rand"
	"encoding/hex"

	ccssm2 "github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/hyperledger/fabric/bccsp/sm2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Sm2key", func() {
	Context("SM2PrivateKey", func() {

		It("usage", func() {
			ccssm2key, _ := ccssm2.GenerateKey(rand.Reader)
			instance := sm2.NewSM2PrivateKey(ccssm2key)
			Expect(instance).ToNot(BeNil())
			//Bytes
			_, err := instance.Bytes()
			Expect(err).NotTo(HaveOccurred())
			//SKI
			Expect(instance.SKI()).ToNot(BeNil())
			//Symmetric
			Expect(instance.Symmetric()).To(BeFalse())
			//Private
			Expect(instance.Private()).To(BeTrue())
			//PublicKey
			_, err = instance.PublicKey()
			Expect(err).NotTo(HaveOccurred())

			instance2 := sm2.NewSm2PrivateKey(ccssm2key)
			Expect(instance2).ToNot(BeNil())
			priv := instance2.GetPrivKey()
			Expect(priv).To(Equal(ccssm2key))
			Expect(instance2).To(Equal(instance))

			instance3 := sm2.SM2PrivateKeyToInterface(instance2)
			Expect(instance3).ToNot(BeNil())

			_, err = sm2.SM2PrivateKeyToDER(priv)
			Expect(err).NotTo(HaveOccurred())

			raw, err := sm2.SM2privateKeyToPEM(priv, nil)
			Expect(err).NotTo(HaveOccurred())
			raw2, err := sm2.SM2privateKeyToEncryptedPEM(priv, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(hex.EncodeToString(raw)).To(Equal(hex.EncodeToString(raw2)))
			key, err := sm2.PemToPrivateKey(raw2, nil)
			Expect(err).NotTo(HaveOccurred())
			testMsg := []byte("123456")
			signedData, _ := key.(*ccssm2.PrivateKey).Sign(rand.Reader, testMsg, nil)
			Expect(ccssm2key.Public().(*ccssm2.PublicKey).Verify(testMsg, signedData)).To(BeTrue())
		})
	})

	Context("SM2PublicKey", func() {

		It("usage", func() {
			ccssm2key, _ := ccssm2.GenerateKey(rand.Reader)
			pubkey := ccssm2key.Public()

			instance := sm2.NewSM2PubKey(pubkey)
			Expect(instance).ToNot(BeNil())
			//Bytes
			_, err := instance.Bytes()
			Expect(err).NotTo(HaveOccurred())
			//SKI
			Expect(instance.SKI()).ToNot(BeNil())
			//Symmetric
			Expect(instance.Symmetric()).To(BeFalse())
			//Private
			Expect(instance.Private()).To(BeFalse())
			//PublicKey
			k, err := instance.PublicKey()
			Expect(err).NotTo(HaveOccurred())
			Expect(k).To(Equal(instance))

			instance2 := sm2.SM2PublicKeyToInterface(k)
			Expect(instance2).ToNot(BeNil())

			var pwd []byte
			_, err = sm2.SM2publicKeyToEncryptedPEM(k.(*sm2.SM2PublicKey).GetPubKey(), pwd)
			Expect(err).NotTo(HaveOccurred())

			_, err = sm2.SM2publicKeyToPEM(k.(*sm2.SM2PublicKey).GetPubKey(), pwd)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
