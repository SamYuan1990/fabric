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

var _ = Describe("Sm2", func() {

	Context("Sign Verify", func() {
		ccssm2key, _ := ccssm2.GenerateKey(rand.Reader)
		pubkey := ccssm2key.Public()

		bccspprik := sm2.NewSM2PrivateKey(ccssm2key)
		bccsppubk := sm2.NewSM2PubKey(pubkey)

		SM2Signer := &sm2.SM2Signer{}
		SM2PrivateKeyVerifier := &sm2.SM2PrivateKeyVerifier{}
		SM2PublicKeyKeyVerifier := &sm2.SM2PublicKeyKeyVerifier{}

		testMsg := []byte("123456")

		signedData, _ := SM2Signer.Sign(bccspprik, testMsg, nil)
		ok, _ := SM2PrivateKeyVerifier.Verify(bccspprik, signedData, testMsg, nil)
		Expect(ok).To(BeTrue())
		ok, _ = SM2PublicKeyKeyVerifier.Verify(bccsppubk, signedData, testMsg, nil)
		Expect(ok).To(BeTrue())
	})

})
