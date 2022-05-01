package md5Cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
)

func createHash(key string) string {

	hashes := md5.New()
	hashes.Write([]byte(key))

	return hex.EncodeToString(hashes.Sum(nil))
}

func EncryptData(data []byte, pass string) []byte {

	block, blkErr := aes.NewCipher([]byte(createHash(pass)))
	if blkErr != nil {

		panic(blkErr.Error())
	}

	galois, _err := cipher.NewGCM(block)

	if _err != nil {

		panic(_err.Error())
	}

	nonce := make([]byte, galois.NonceSize())
	if _, _err = io.ReadFull(rand.Reader, nonce); _err != nil {

		panic(_err.Error())
	}

	return galois.Seal(nonce, nonce, data, nil)
}

func DecryptData(data []byte, pass string) []byte {

	key := []byte(createHash(pass))
	block, _err := aes.NewCipher(key)

	if _err != nil {

		panic(_err.Error())
	}

	galois, _err := cipher.NewGCM(block)
	if _err != nil {

		panic(_err.Error())
	}

	nonceSize := galois.NonceSize()
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	text, err := galois.Open(nil, nonce, cipherText, nil)
	if err != nil {

		panic(err.Error())
	}

	return text
}
