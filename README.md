# Go-File-Encryption
[![Build Status](http://img.shields.io/travis/cs3238-tsuzu/popcon-sc/master.svg?style=flat-square)](https://travis-ci.org/cs3238-tsuzu/go-file-encryption)
[![license](https://img.shields.io/github/license/mashape/apistatus.svg?style=flat-square)](./LICENSE)


# Introduction
- A file encryption/decryption library that uses the same algorithm as OpenSSL's with IV and salt
- You can set key and IV manually instead of creating them from password and salt.

# !!!Caution!!!
- OpenSSL's key creation algorithm with password and salt is NOT secure.
- You should set key and IV manually or use some alternative algorithms.

# Examples
- Read cbc\_test.go

# License
- Under the MIT License
- Copyright (c) 2017 Tsuzu
