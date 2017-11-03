// Copyright (c) 2017 Tsuzu
//
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

package fileencryption

import "errors"

var ErrIllegalPrefixOfEncrypted = errors.New("Illegal Prefix of Encrypted")
var ErrIllegalLengthOfkey = errors.New("Illegal length of key")
var ErrIllegalPadding = errors.New("Illegal Padding")
var ErrInsufficientData = errors.New("Insufficient Data")
