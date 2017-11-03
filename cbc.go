// Copyright (c) 2017 Tsuzu
//
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT
package fileencryption

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"reflect"
)

type CBCDecryptionStream struct {
	Password  string
	Key       []byte
	IV        []byte
	Salt      []byte
	EOFFlag   bool
	keyLen    int
	blockMode cipher.BlockMode
	srcReader io.Reader
	srcBuf    []byte
	dstBuf    []byte
	extraBuf  []byte
	err       error
}

func (stream *CBCDecryptionStream) Read(b []byte) (retLength int, retError error) {
	if stream.err != nil {
		return 0, stream.err
	}

	retLength = 0
	if len(b) <= len(stream.extraBuf) {
		copy(b, stream.extraBuf[:len(b)])
		stream.extraBuf = stream.extraBuf[len(b):]

		return len(b), nil
	} else {
		copy(b, stream.extraBuf)

		b = b[len(stream.extraBuf):]
		retLength += len(stream.extraBuf)
	}

	for {
		if !stream.EOFFlag {
			dlen := (len(stream.dstBuf) - 1) / BlockSize * BlockSize

			if dlen != 0 {
				blen := (len(b) + BlockSize - 1) / BlockSize * BlockSize

				if blen <= dlen {
					copy(b, stream.dstBuf[:len(b)])
					stream.extraBuf = stream.dstBuf[len(b):blen]
					stream.dstBuf = stream.dstBuf[blen:]

					retLength += len(b)
				} else {
					copy(b, stream.dstBuf[:dlen])
					stream.extraBuf = nil
					stream.dstBuf = stream.dstBuf[dlen:]

					retLength += dlen
				}
			}
		} else {
			dlen := len(stream.dstBuf)
			blen := len(b)

			if blen <= dlen {
				copy(b, stream.dstBuf[:blen])
				stream.dstBuf = stream.dstBuf[blen:]
				stream.extraBuf = nil

				retLength += blen
			} else {
				copy(b, stream.dstBuf[:dlen])
				stream.dstBuf = stream.dstBuf[dlen:]

				retLength += dlen
				retError = io.EOF
			}
		}

		if retLength != 0 || retError == io.EOF {
			return
		}

		if len(stream.srcBuf) < BlockSize {
			buf := make([]byte, BufReadLength)
			n, err := stream.srcReader.Read(buf)

			stream.srcBuf = append(stream.srcBuf, buf[:n]...)

			if err != nil && err != io.EOF {
				stream.err = err
				retError = err

				return
			}

			if n == 0 && err == io.EOF {
				stream.EOFFlag = true
			}
		}

		if stream.Key == nil {
			if len(stream.srcBuf) < BlockSize {
				if stream.EOFFlag {
					stream.err = ErrInsufficientData
					retError = stream.err

					return
				}

				continue
			}
			stream.Salt = stream.srcBuf[:BlockSize]
			stream.srcBuf = stream.srcBuf[BlockSize:]

			if !reflect.DeepEqual(stream.Salt[:SaltSize], SaltPrefix) {
				stream.err = ErrIllegalPrefixOfEncrypted

				return 0, stream.err
			}
			stream.Salt = stream.Salt[SaltSize:]

			switch stream.keyLen {
			case 128:
				stream.Key, stream.IV = CreateKeyIVForAES128(stream.Password, stream.Salt)
			case 256:
				stream.Key, stream.IV = CreateKeyIVForAES256(stream.Password, stream.Salt)
			}

			block, err := aes.NewCipher(stream.Key)

			if err != nil {
				stream.err = err
				retError = err

				return
			}

			stream.blockMode = cipher.NewCBCDecrypter(block, stream.IV)
		} else {
			if BlockSize > len(stream.srcBuf) {
				if stream.EOFFlag {
					if len(stream.srcBuf) != 0 {
						stream.err = ErrInsufficientData
						retError = stream.err

						return
					}

					if len(stream.dstBuf) != 0 {
						lastIndex := len(stream.dstBuf) - 1
						for i := 1; i < int(stream.dstBuf[lastIndex]); i++ {
							if lastIndex-i < 0 || stream.dstBuf[lastIndex] != stream.dstBuf[lastIndex-i] {
								stream.err = ErrIllegalPadding
								retError = stream.err

								return
							}
						}

						stream.dstBuf = stream.dstBuf[:lastIndex-int(stream.dstBuf[lastIndex])+1]
					}
				}

				continue
			}

			size := len(stream.srcBuf) / BlockSize * BlockSize
			dst := make([]byte, size)

			stream.blockMode.CryptBlocks(dst, stream.srcBuf[:size])
			stream.srcBuf = stream.srcBuf[size:]

			if len(stream.dstBuf) == 0 {
				stream.dstBuf = dst
			} else {
				stream.dstBuf = append(stream.dstBuf, dst...)
			}
		}
	}
}

// keyLen only supports 128 or 256
func NewCBCDecryptionStream(keyLen int, password string, reader io.Reader) (*CBCDecryptionStream, error) {
	switch keyLen {
	case 128:
	case 256:
		// OK. Do nothing.
	default:
		return nil, ErrIllegalLengthOfkey
	}

	return &CBCDecryptionStream{
		Password:  password,
		Key:       nil,
		IV:        nil,
		keyLen:    keyLen,
		srcReader: reader,
	}, nil
}

type CBCEncryptionStream struct {
	Password  string
	Key       []byte
	IV        []byte
	Salt      []byte
	EOFFlag   bool
	keyLen    int
	blockMode cipher.BlockMode
	srcReader io.Reader
	srcBuf    []byte
	dstBuf    []byte
	err       error
}

func (stream *CBCEncryptionStream) Read(b []byte) (retLength int, retError error) {
	if stream.err != nil {
		return 0, stream.err
	}
	for {
		dlen := len(stream.dstBuf)
		blen := len(b)

		if blen <= dlen {
			copy(b, stream.dstBuf[:blen])
			stream.dstBuf = stream.dstBuf[blen:]

			retLength += blen
		} else {
			copy(b, stream.dstBuf[:dlen])
			stream.dstBuf = stream.dstBuf[dlen:]

			retLength += dlen
			if stream.EOFFlag {
				retError = io.EOF
			}
		}

		if retLength != 0 || retError == io.EOF {
			return
		}

		if len(stream.srcBuf) < BlockSize {
			buf := make([]byte, BufReadLength)
			n, err := stream.srcReader.Read(buf)

			stream.srcBuf = append(stream.srcBuf, buf[:n]...)

			if err != nil && err != io.EOF {
				stream.err = err
				retError = err

				return
			}

			if n == 0 && err == io.EOF {
				stream.EOFFlag = true
			}
		}

		if stream.Key == nil {
			var err error
			stream.Salt, err = CreateSalt()

			if err != nil {
				stream.err = err

				return 0, err
			}

			stream.dstBuf = append(SaltPrefix, stream.Salt...)

			switch stream.keyLen {
			case 128:
				stream.Key, stream.IV = CreateKeyIVForAES128(stream.Password, stream.Salt)
			case 256:
				stream.Key, stream.IV = CreateKeyIVForAES256(stream.Password, stream.Salt)
			}

			block, err := aes.NewCipher(stream.Key)

			if err != nil {
				stream.err = err

				return 0, err
			}

			stream.blockMode = cipher.NewCBCEncrypter(block, stream.IV)
		} else {
			if stream.EOFFlag {
				buf := make([]byte, (len(stream.srcBuf)/BlockSize+1)*BlockSize)

				copy(buf, stream.srcBuf)
				for i := len(stream.srcBuf); i < len(buf); i++ {
					buf[i] = byte(len(buf) - len(stream.srcBuf))
				}

				dst := make([]byte, len(buf))
				stream.blockMode.CryptBlocks(dst, buf)

				if len(stream.dstBuf) != 0 {
					stream.dstBuf = append(stream.dstBuf, dst...)
				} else {
					stream.dstBuf = dst
				}
			} else {
				size := len(stream.srcBuf) / BlockSize * BlockSize
				dst := make([]byte, size)

				stream.blockMode.CryptBlocks(dst, stream.srcBuf[:size])
				stream.srcBuf = stream.srcBuf[size:]

				if len(stream.dstBuf) == 0 {
					stream.dstBuf = dst
				} else {
					stream.dstBuf = append(stream.dstBuf, dst...)
				}
			}
		}
	}
}

// keyLen only supports 128 or 256
func NewCBCEncryptionStream(keyLen int, password string, reader io.Reader) (*CBCEncryptionStream, error) {
	switch keyLen {
	case 128:
	case 256:
		// OK. Do nothing.
	default:
		return nil, ErrIllegalLengthOfkey
	}

	return &CBCEncryptionStream{
		Password:  password,
		Key:       nil,
		IV:        nil,
		keyLen:    keyLen,
		srcReader: reader,
	}, nil
}
