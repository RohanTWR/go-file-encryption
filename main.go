package main

import (
	"bytes"
	"fmt"
	"os"
	"syscall"

	"github.com/RohanTWR/go-file-encryption/filecrypt"
	"golang.org/x/term"
)

func main() {

	//we could have used cobra to print messages to CLI but we dont want to import a whole new package just for printing few messages
	if len(os.Args) < 2 {

		//if user does not know how to encrypt or decrypt then just print help in that scenario
		printHelp()
		os.Exit(0)
	}

	function := os.Args[1]

	switch function {
	case "help":
		printHelp()
	case "encrypt":
		encryptHandle()
	case "decrypt":
		decryptHandle()
	default:
		fmt.Println("Run encrypt to encrypt a file, decrypt to decrypt a file.")
		os.Exit(1)
	}
}

// function to tell user how to use this project
func printHelp() {
	fmt.Println("File encryption")
	fmt.Println("Simple file encrypter for yoru day-today needs.")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("")
	fmt.Println("\tgo run . encrypt /path/of/your/file")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("")
	fmt.Println("\t encrypt\tEncrypts a file given a password")
	fmt.Println("\t decrypt\tTries to decrypt a file using a password")
	fmt.Println("\t help\t\tDisplays help text")
	fmt.Println("")
}

func encryptHandle() {
	//Step-1: check if user has given us the file path
	if len(os.Args) < 3 {
		println("Missing the path to the file. For more info, run . help")
		os.Exit(0)
	}

	//step 2: take the file path and validate it
	filepath := os.Args[2]
	if !validateFile(filepath) {
		panic("File not found")
	}

	//step 3: make the user set a password and then return it to us and we store it in var password
	// The password is set by asking user to enter his choice of password twice and then validating if both the enetered passwords are same are not. If not same we ask the user to try again setting the password
	password := getPassword()

	//Step-4
	//Start encryption using our own created filecrypt package
	fmt.Println("\nEncrypting ...")

	//if password is incorrect will be taken care by encrpyt function
	filecrypt.Encrypt(filepath, password)
	fmt.Println("\n File successfully protected")

}

func decryptHandle() {

	//Step-1: check if user has given us the file path
	if len(os.Args) < 3 {
		println("Missing the path to the file. For more info, run . help")
		os.Exit(0)
	}

	//step 2: take the file path and validate it
	filepath := os.Args[2]
	if !validateFile(filepath) {
		panic("File not found")
	}

	//step 3: ask the user for the password he had set earlier while encrypting
	fmt.Print("Enter password")

	//	password, _ := term.ReadPassword(0)
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err.Error())
	}

	//step -4: Start decrypting the file
	fmt.Println("\nDecrypting ...")

	filecrypt.Decrypt(filepath, password)

	//if password is incorrect will be taken care by decrpyt function
	fmt.Println("\n File successfully decrypted")

}

// returns a password
func getPassword() []byte {

	fmt.Print("Enter password")

	//use terminal package to read the password into the password variable

	//password, _ := term.ReadPassword(0)
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err.Error())
	}

	//Also confirm the password not just ask it once
	fmt.Print("\nConfirm Password: ")

	//password2, _ := term.ReadPassword(0)
	password2, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err.Error())
	}
	//validate both obtained passwords if they are matching or not
	if !validatePassword(password, password2) {

		fmt.Print("\nPasswords do not match. Please try again\n ")

		//ask again
		return getPassword()
	}

	//if everything matches well just return the password
	return password

}

func validatePassword(password1 []byte, password2 []byte) bool {

	return bytes.Equal(password1, password2)
}

// returns a boolean
func validateFile(filepath string) bool {

	//combining obtaining error and checking if the error exists by IsNotExist function which returns true if there is an error obtained while trying to obtain file information for the given filepath
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return false
	}
	return true
}
