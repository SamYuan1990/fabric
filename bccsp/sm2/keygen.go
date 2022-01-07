/*
Copyright TWGC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sm2

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/hyperledger/fabric/bccsp"
)

type SM2KeyGenerator struct {
	curve elliptic.Curve
}

func (kg *SM2KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Failed generating sm2 key : [%s]", err)
	}

	return &SM2PrivateKey{privKey}, nil
}
