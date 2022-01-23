/*
Copyright TWGC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sm2_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestSm2(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sm2 Suite")
}
