package reolink

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"fmt"
)

// Fixed XOR key used by BCEncrypt for control-plane XML
var bcKey = [8]byte{0x1F, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0xFF}
var aesIV = []byte("0123456789abcdef")

func decryptBC(encOffset uint32, buf []byte) []byte {
	if len(buf) == 0 {
		return buf
	}
	offsetByte := byte(encOffset)
	out := make([]byte, len(buf))
	for i, b := range buf {
		out[i] = b ^ bcKey[(int(offsetByte)+i)%8] ^ offsetByte
	}
	return out
}

func encryptBC(encOffset uint32, buf []byte) []byte {
	offsetByte := byte(encOffset)
	out := make([]byte, len(buf))
	for i, b := range buf {
		key := bcKey[(int(offsetByte)+i)%8]
		out[i] = b ^ key ^ offsetByte
	}
	return out
}

func encryptAES(key []byte, body []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, aesIV[:])
	ciphertext := make([]byte, len(body))
	stream.XORKeyStream(ciphertext, body)

	return ciphertext
}

func decryptAES(key []byte, encdat []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	stream := cipher.NewCFBDecrypter(block, aesIV[:])
	plaintext := make([]byte, len(encdat))
	stream.XORKeyStream(plaintext, encdat)

	return plaintext
}

// MD5 hash should be upper case and 31 characters long
func md5HexUpper(b []byte) string {
	sum := md5.Sum(b)
	return fmt.Sprintf("%X", sum[:])[:31]
}
