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

var _ = Describe("Keyderiv", func() {
	//SM2PublicKeyKeyDeriver
	Context("KeyDeriv", func() {
		It("should success", func() {
			SM2PublicKeyKeyDeriver := &sm2.SM2PublicKeyKeyDeriver{}
			var opts *sm2.SM2ReRandKeyOpts
			ccssm2key, _ := ccssm2.GenerateKey(rand.Reader)
			opts = &sm2.SM2ReRandKeyOpts{}
			key, err := SM2PublicKeyKeyDeriver.KeyDeriv(sm2.NewSM2PubKey(&ccssm2key.PublicKey), opts)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(key).NotTo(BeNil())
		})

	})

	//SM2PrivateKeyKeyDeriver
	Context("KeyDeriv", func() {
		SM2PrivateKeyKeyDeriver := &sm2.SM2PrivateKeyKeyDeriver{}
		var opts *sm2.SM2ReRandKeyOpts
		opts = &sm2.SM2ReRandKeyOpts{}
		ccssm2key, _ := ccssm2.GenerateKey(rand.Reader)
		key, err := SM2PrivateKeyKeyDeriver.KeyDeriv(sm2.NewSM2PrivateKey(ccssm2key), opts)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(key).NotTo(BeNil())
	})
})
