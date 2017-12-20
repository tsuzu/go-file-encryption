// Copyright (c) 2017 Tsuzu
//
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

package fileencryption

import (
	"bytes"
	"io/ioutil"
	"math/rand"
	"reflect"
	"testing"
)

var Base = []byte("Hello, world!\n")
var AES256CBCEncrypted = []byte{0x53, 0x61, 0x6c, 0x74, 0x65, 0x64, 0x5f, 0x5f, 0xa1, 0xb6, 0xd8, 0x18, 0xf2, 0x5f, 0x92, 0x78, 0x75, 0xe6, 0x44, 0xe2, 0x9d, 0x84, 0x3, 0xc2, 0x33, 0x74, 0xc6, 0xd6, 0x15, 0x31, 0xea, 0x32}
var AES128CBCEncrypted = []byte{0x53, 0x61, 0x6c, 0x74, 0x65, 0x64, 0x5f, 0x5f, 0x4e, 0x24, 0xbe, 0x4, 0xdf, 0xc7, 0x7b, 0x41, 0x98, 0x97, 0xce, 0x90, 0xc, 0x22, 0xd2, 0x8e, 0xae, 0x18, 0x6, 0xdd, 0xc1, 0xab, 0xb8, 0xa0}

const Password = "password"

func testCBCDecryptionAESCBC(bit int, t *testing.T) {
	var baseData []byte

	if bit == 128 {
		baseData = AES128CBCEncrypted
	} else if bit == 256 {
		baseData = AES256CBCEncrypted
	}

	stream, err := NewCBCDecryptionStream(bit, Password, bytes.NewReader(baseData))

	if err != nil {
		t.Fatal("NewCBCDecryptionStream error: ", err)

		return
	}

	b, err := ioutil.ReadAll(stream)

	if err != nil {
		t.Fatal("Read error: ", err)

		return
	}

	if len(b) != len(Base) || string(b) != string(Base) {
		t.Fatal("Illegal result: ", Base, b, string(b))
	}
}

func TestCBCDecryptionAES256CBC(t *testing.T) {
	testCBCDecryptionAESCBC(256, t)
}

func TestCBCDecryptionAES128CBC(t *testing.T) {
	testCBCDecryptionAESCBC(128, t)
}

func testCBCEncryptionAESCBC(bit int, t *testing.T) {
	stream, err := NewCBCEncryptionStream(bit, Password, bytes.NewReader(Base))

	if err != nil {
		t.Fatal("NewCBCEncryptionStream error: ", err)

		return
	}

	b, err := ioutil.ReadAll(stream)

	if err != nil {
		t.Error("Read error: ", err)

		return
	}

	stream2, err := NewCBCDecryptionStream(bit, Password, bytes.NewReader(b))

	if err != nil {
		t.Fatal("NewCBCDecryptionStream error: ", err)

		return
	}

	b, err = ioutil.ReadAll(stream2)

	if err != nil {
		t.Fatal("Read error: ", err)

		return
	}

	if len(b) != len(Base) || string(b) != string(Base) {
		t.Fatal("Illegal result: ", Base, b, string(b))
	}
}

func TestCBCEncryptionAES256CBC(t *testing.T) {
	testCBCEncryptionAESCBC(256, t)
}

func TestCBCEncryptionAES128CBC(t *testing.T) {
	testCBCEncryptionAESCBC(128, t)
}

const BaseCharacters = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"

func benchmarkCBCEncryptionAESCBCRandom(bit, length int, b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		base := make([]byte, length)

		for i := range base {
			base[i] = BaseCharacters[rand.Intn(len(BaseCharacters))]
		}

		b.StartTimer()
		stream, err := NewCBCEncryptionStream(bit, Password, bytes.NewReader(base))

		if err != nil {
			b.Fatal("NewCBCEncryptionStream error: ", err)

			return
		}

		stream2, err := NewCBCDecryptionStream(bit, Password, stream)

		if err != nil {
			b.Fatal("NewCBCDecryptionStream error: ", err)

			return
		}

		buf, err := ioutil.ReadAll(stream2)

		b.StopTimer()

		if err != nil {
			b.Fatal("Read error: ", err)

			return
		}

		if !reflect.DeepEqual(base, buf) {
			b.Fatal("Illegal result", base[:10], buf[:10])
		}
	}
}

func BenchmarkCBCEncryptionAES256CBCRandom1M(b *testing.B) {
	benchmarkCBCEncryptionAESCBCRandom(256, 1*1024*1024, b)
}

func BenchmarkCBCEncryptionAES256CBCRandom10M(b *testing.B) {
	benchmarkCBCEncryptionAESCBCRandom(256, 10*1024*1024, b)
}

func BenchmarkCBCEncryptionAES256CBCRandom100M(b *testing.B) {
	benchmarkCBCEncryptionAESCBCRandom(256, 100*1024*1024, b)
}

func BenchmarkCBCEncryptionAES128CBCRandom1M(b *testing.B) {
	benchmarkCBCEncryptionAESCBCRandom(128, 1*1024*1024, b)
}

func BenchmarkCBCEncryptionAES128CBCRandom10M(b *testing.B) {
	benchmarkCBCEncryptionAESCBCRandom(128, 10*1024*1024, b)
}

func BenchmarkCBCEncryptionAES128CBCRandom100M(b *testing.B) {
	benchmarkCBCEncryptionAESCBCRandom(128, 100*1024*1024, b)
}
