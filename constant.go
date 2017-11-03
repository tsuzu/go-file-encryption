// Copyright (c) 2017 Tsuzu
//
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

package fileencryption

const BlockSize = 128 / 8
const SaltSize = BlockSize / 2
const BufReadLength = BlockSize * 2048

var SaltPrefix = []byte("Salted__")
