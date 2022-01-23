/*
Copyright TWGC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sm2_test

import (
	"github.com/Hyperledger-TWGC/ccs-gm/sm3"
	"github.com/hyperledger/fabric/bccsp/sm2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Sm3sig", func() {

	It("Should same with sm3 hash", func() {
		msg := []byte("Hello World")
		data, err := sm2.Hash(msg, &sm2.SM3SIGOpts{})
		Expect(err).NotTo(HaveOccurred())

		bench := sm3.New()
		bench.Write(msg)
		expectValue := bench.Sum(nil)
		Expect(data).To(Equal(expectValue))
	})

})
