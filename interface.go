// Copyright (c) 2017 Tsuzu
//
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT
package fileencryption

import "io"

type CrytionStream interface {
	io.ReadWriteCloser
}
