/*
Copyright TWGC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sm2_test

import (
	"github.com/hyperledger/fabric/bccsp/sm2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Keygen", func() {
	Context("KeyGen", func() {
		It("should success", func() {
			SM2KeyGenerator := sm2.SM2KeyGenerator{}
			k, err := SM2KeyGenerator.KeyGen(&sm2.SM2KeyGenOpts{})
			Expect(err).NotTo(HaveOccurred())
			Expect(k).ToNot(BeNil())
		})
	})
})
