/*
Copyright TWGC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sm2

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/hyperledger/fabric/bccsp"
)

// TWGC todo
type SM2PublicKeyKeyDeriver struct{}

func (kd *SM2PublicKeyKeyDeriver) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	// Validate opts
	if opts == nil {
		return nil, errors.New("Invalid opts parameter. It must not be nil.")
	}

	sm2K := k.(*SM2PublicKey)

	switch opts.(type) {
	// Re-randomized an SM2 public key
	case *bccsp.SM2ReRandKeyOpts:
		reRandOpts := opts.(*bccsp.SM2ReRandKeyOpts)
		tempSK := &sm2.PublicKey{
			Curve: sm2K.GetPubKey().Curve,
			X:     new(big.Int),
			Y:     new(big.Int),
		}

		var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
		var one = new(big.Int).SetInt64(1)
		n := new(big.Int).Sub(sm2K.GetPubKey().Params().N, one)
		k.Mod(k, n)
		k.Add(k, one)

		// Compute temporary public key
		tempX, tempY := sm2K.GetPubKey().ScalarBaseMult(k.Bytes())
		tempSK.X, tempSK.Y = tempSK.Add(
			sm2K.GetPubKey().X, sm2K.GetPubKey().Y,
			tempX, tempY,
		)

		// Verify temporary public key is a valid point on the reference curve
		isOn := tempSK.Curve.IsOnCurve(tempSK.X, tempSK.Y)
		if !isOn {
			return nil, errors.New("Failed temporary public key IsOnCurve check.")
		}
		return &SM2PublicKey{tempSK}, nil
	default:
		return nil, fmt.Errorf("Unsupported 'KeyDerivOpts' provided [%v]", opts)
	}
}

// TWGC todo
type SM2PrivateKeyKeyDeriver struct{}

func (kd *SM2PrivateKeyKeyDeriver) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	// Validate opts
	if opts == nil {
		return nil, errors.New("Invalid opts parameter. It must not be nil.")
	}

	sm2K := k.(*SM2PrivateKey)

	switch opts.(type) {
	// Re-randomized an ECDSA private key
	case *bccsp.SM2ReRandKeyOpts:
		reRandOpts := opts.(*bccsp.SM2ReRandKeyOpts)
		tempSK := &sm2.PrivateKey{
			PublicKey: sm2.PublicKey{
				Curve: sm2K.PrivKey.Curve,
				X:     new(big.Int),
				Y:     new(big.Int),
			},
			D: new(big.Int),
		}

		var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
		var one = new(big.Int).SetInt64(1)
		n := new(big.Int).Sub(sm2K.PrivKey.Params().N, one)
		k.Mod(k, n)
		k.Add(k, one)

		tempSK.D.Add(sm2K.PrivKey.D, k)
		tempSK.D.Mod(tempSK.D, sm2K.PrivKey.PublicKey.Params().N)

		// Compute temporary public key
		tempX, tempY := sm2K.PrivKey.PublicKey.ScalarBaseMult(k.Bytes())
		tempSK.PublicKey.X, tempSK.PublicKey.Y =
			tempSK.PublicKey.Add(
				sm2K.PrivKey.PublicKey.X, sm2K.PrivKey.PublicKey.Y,
				tempX, tempY,
			)

		// Verify temporary public key is a valid point on the reference curve
		isOn := tempSK.Curve.IsOnCurve(tempSK.PublicKey.X, tempSK.PublicKey.Y)
		if !isOn {
			return nil, errors.New("Failed temporary public key IsOnCurve check.")
		}
		return &SM2PrivateKey{tempSK}, nil
	default:
		return nil, fmt.Errorf("Unsupported 'KeyDerivOpts' provided [%v]", opts)
	}
}
