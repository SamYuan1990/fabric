/*
Copyright CETCS. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	SPDX-License-Identifier: Apache-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sm2

import (
	"hash"

	"github.com/Hyperledger-TWGC/ccs-gm/sm3"
	"github.com/hyperledger/fabric/bccsp"
)

type SM3sig struct {
	sm3 hash.Hash
	msg []byte
}

func NewSM3Sig() hash.Hash {

	return &SM3sig{
		sm3: sm3.New(),
	}
}

func (d *SM3sig) Write(p []byte) (n int, err error) {
	return d.sm3.Write(p)
}

func (d *SM3sig) Sum(b []byte) []byte {
	return d.sm3.Sum(b)
}

func (d *SM3sig) Reset() {
	d.msg = d.msg[:0]
}

func (d *SM3sig) Size() int {
	return 0
}

func (d *SM3sig) BlockSize() int {
	return 0
}

func Hash(msg []byte, opts bccsp.HashOpts) (hash []byte, err error) {
	instance := NewSM3Sig()
	instance.Write(msg)
	return instance.Sum(nil), nil
}
