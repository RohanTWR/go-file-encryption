package filecrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

// source = file
func Encrypt(source string, password []byte) {

	//check if source file exists or not, if not then throw an error
	if _, err := os.Stat(source); os.IsNotExist(err) {
		panic(err.Error())
	}

	plaintext, err := os.ReadFile(source)

	//handle error
	if err != nil {
		panic(err.Error())
	}

	//we need to use the password for some computation hence we will store it in a new var
	key := password

	//Step -3: create a nonce ( a slice of byte of length 12 [0,0,0,0....0])
	nonce := make([]byte, 12)

	//Step -4: Randomize the nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Step -5: pass password,nonce , iterations and algo to PasswordBasedKeyDerivationFunction
	//you get back a derived key
	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)

	//Step-6: get the block by passing through AES Cipher
	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}

	//Step-7 use newGCM inside cipher function to get aesgcm
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Step-8 use gcm.seal function which converts plain text to cipher text
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	//apend the 12 byte nonce to end of cipher text or encrypted file
	ciphertext = append(ciphertext, nonce...)

	//create a source file for encrypted data and write the data into it
	destinationFile, err := os.Create(source)
	if err != nil {
		panic(err.Error())
	}

	//Write the data
	_, err = io.Copy(destinationFile, bytes.NewReader(ciphertext))
	if err != nil {
		panic(err.Error())
	}

}

func Decrypt(source string, password []byte) {

	//check if source file exists or not, if not then throw an error
	if _, err := os.Stat(source); os.IsNotExist(err) {
		panic(err.Error())
	}

	ciphertext, err := os.ReadFile(source)

	//handle error
	if err != nil {
		panic(err.Error())
	}

	//we need to use the password for some computation hence we wil lstore it in a new var
	key := password

	// converting last 12 digits into nonce
	salt := ciphertext[len(ciphertext)-12:]
	str := hex.EncodeToString(salt)

	//use hex package to decode the string to get the nonce from the last 12 digits of the cipher
	nonce, err := hex.DecodeString(str)
	if err != nil {
		panic(err.Error())
	}

	// pass password,nonce , iterations and algo to PasswordBasedKeyDerivationFunction
	//you get back a derived key
	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)

	//get the block by passing through AES Cipher
	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}

	// use newGCM inside cipher function to get aesgcm
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//get back the plain text
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[:len(ciphertext)-12], nil)
	if err != nil {
		panic(err.Error())
	}

	//create a source file for encrypted data and write the data into it
	destinationFile, err := os.Create(source)
	if err != nil {
		panic(err.Error())
	}

	//write plain text to a new file
	_, err = io.Copy(destinationFile, bytes.NewReader(plaintext))
	if err != nil {
		panic(err.Error())
	}

}
