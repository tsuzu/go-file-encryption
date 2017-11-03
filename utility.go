// Copyright (c) 2017 Tsuzu
//
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

package fileencryption

import "crypto/md5"
import "crypto/rand"

func ReadByteChannelForFixedSize(ch chan byte, length int) []byte {
	buf := make([]byte, length)

	if len(ch) < length {
		return nil
	}

	for i := 0; i < length; i++ {
		buf[i] = <-ch
	}

	return buf
}

func PBKDF1(password []byte, salt []byte) ([]byte, []byte) {
	key := md5.Sum(append(password, salt...))
	iv := md5.Sum(append(append(key[:], password...), salt...))

	return key[:], iv[:]
}

// [DEPRECETED] This is the same as OpenSSL's, but it is  insecure.
func CreateKeyIVForAES128(password string, salt []byte) ([]byte, []byte) {
	pass := []byte(password)

	return PBKDF1(pass, salt)
}

// [DEPRECETED] This is the same as OpenSSL's, but it is  insecure.
func CreateKeyIVForAES256(password string, salt []byte) ([]byte, []byte) {
	pass := []byte(password)
	former, latter := PBKDF1(pass, salt)
	key := append(former, latter...)
	iv := md5.Sum(append(append(latter, pass...), salt...))

	return key[:], iv[:]
}

func CreateSalt() ([]byte, error) {
	b := make([]byte, 8)

	// _ must be len(b)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

func SendByteArrayToChannel(b []byte, ch chan byte) {
	for i := range b {
		ch <- b[i]
	}
}
