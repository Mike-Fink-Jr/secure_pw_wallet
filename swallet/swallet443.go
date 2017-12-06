////////////////////////////////////////////////////////////////////////////////
//
//  File           : swallet443.go
//  Description    : This is the implementaiton file for the swallet password
//                   wallet program program.  See assignment details.
//
//  Collaborators  : **TODO**: FILL ME IN
//  Last Modified  : **TODO**: FILL ME IN
//

// Package statement
package main

// Imports
import ( 
	"fmt"
	"os"
	"time"
	"strings"
	"math/rand"
	"github.com/pborman/getopt"
	"bufio"
	"golang.org/x/crypto/ssh/terminal"
	"strconv"
	"bytes"
	"crypto/sha1"
	"crypto/hmac"
	"encoding/base64"
	"crypto/aes"
	"crypto/cipher"
	// There will likely be several mode APIs you need
)

// Type definition  ** YOU WILL NEED TO ADD TO THESE **

// A single password
type walletEntry struct {
	entry []byte 	   // Should be exactly 32 bytes with zero right padding
	password []byte    // Should be exactly 32 bytes with zero right padding
	salt []byte        // Should be exactly 16 bytes 
	comment []byte     // Should be exactly 128 bytes with zero right padding
}

// The wallet as a whole
type wallet struct {
	filename string
	masterPassword []byte   // Should be exactly 32 bytes with zero right padding
	passwords []walletEntry
	generationNum int
}

// Global data
var usageText string = `USAGE: swallet443 [-h] [-v] <wallet-file> [create|add|del|show|chpw|reset|list]

where:
    -h - help mode (display this message)
    -v - enable verbose output

    <wallet-file> - wallet file to manage
    [create|add|del|show|chpw] - is a command to execute, where

     create - create a new wallet file
     add - adds a password to the wallet
     del - deletes a password from the wallet
     show - show a password in the wallet
     chpw - changes the password for an entry in the wallet
     reset - changes the password for the wallet
     list - list the entries in the wallet (without passwords)`

var verbose bool = true
var mod_entry int 

// You may want to create more global variables

//
// Functions
func encrypt(key []byte, plaintext []byte, salt []byte) []byte{
  	
  	block, _ := aes.NewCipher(key)

  	gcm, _ := cipher.NewGCMWithNonceSize(block, 16)
    
  	encryption := gcm.Seal(nil, salt, plaintext, nil)
    if verbose {
        fmt.Print("-Password encrypted\n")
    }
    return encryption
}

func decrypt(key []byte, ciphertext []byte, salt []byte) []byte{
  	// The key argument should be the AES key, either 16 or 32 bytes
  	// to select AES-128 or AES-256.
   	fmt.Print(len(salt))
  	block, _ := aes.NewCipher(key)

  	gcm, _ := cipher.NewGCMWithNonceSize(block, 16)

  	decryption, err := gcm.Open(nil, salt, ciphertext, nil)
  	if err != nil {
  		panic(err.Error())
  	}
  
    if verbose {
        fmt.Printf("-Password decrypted\n", decryption)
    }
    return decryption
}


func getPass(leng int) []byte{

	pw := []byte{}

	pw_match := false


	for !pw_match{
		fmt.Print("Enter new password \n")

		pass, _ := terminal.ReadPassword(0)
		if (len(pass) <= leng){
			fmt.Print("Enter new password again \n")
			pass2, _ := terminal.ReadPassword(0)
			if (bytes.Equal(pass,pass2)){
				pw_match = true
				if(verbose){
					fmt.Print("-passwords match \n")
				}
				return pass
			}else{
				fmt.Print("Passwords do not match, try again \n")
			}
		}else{
			fmt.Print("Password must be less than " + strconv.Itoa(leng) + " characters \n")
		}
	}
	return pw
 }





// Up to you to decide which functions you want to add

////////////////////////////////////////////////////////////////////////////////
//
// Function     : walletUsage
// Description  : This function prints out the wallet help
//
// Inputs       : none
// Outputs      : none

func walletUsage() {
	fmt.Fprintf(os.Stderr, "%s\n\n", usageText)
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : createWallet
// Description  : This function creates a wallet if it does not exist
//
// Inputs       : filename - the name of the wallet file
// Outputs      : the wallet if created, nil otherwise

func createWallet(filename string) *wallet {

	// Setup the wallet
	var myWallet wallet 
	myWallet.filename = filename
	myWallet.masterPassword = make([]byte, 32, 32) // You need to take it from here
	myWallet.generationNum = -1

	fmt.Print("Create master password: \n")
	mp := getPass(32)
 	
	copy(myWallet.masterPassword, mp)
	if (verbose){
		fmt.Print("-created wallet \n")
	}

	// Return the wall
	return &myWallet
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : loadWallet
// Description  : This function loads an existing wallet
//
// Inputs       : filename - the name of the wallet file
// Outputs      : the wallet if created, nil otherwise

func loadWallet(filename string) *wallet {

	if (verbose){
		fmt.Print("-Loading wallet from " + filename + "\n")
	}

	// Setup the wallet
	var myWallet wallet
	myWallet.filename = filename 
	// DO THE LOADING HERE
	f, err := os.Open(filename)
	if err != nil{
		fmt.Print("error could not open " + filename + "\n")
		return nil
	}

	defer f.Close()

	fmt.Print("Enter Password \n")
	pw, _ := terminal.ReadPassword(0)

	sc := bufio.NewScanner(f)
    sc.Scan()

    hmacLines := sc.Text() //all except last used for HMAC
    var entryLines []string //the middle lines
    lastLine :=""
    
    for sc.Scan(){
        hmacLines += lastLine + "\n"  //won't be updated with actual last line, don't use HMAC line for hmac
        lastLine = sc.Text()
        entryLines = append(entryLines, sc.Text())
    }
  	
  	entryLines = entryLines[:len(entryLines) - 1] //get rid of last line

  	//HMAC
  	pad := make([]byte, 32, 32)
  	copy(pad, pw)
  	hashpw := sha1.Sum(pad)
  	temp := bytes.Join([][]byte{hashpw[:16], []byte(hmacLines)}, []byte(""))
  	my_hmac := hmac.New(sha1.New, temp).Sum(nil)

  	file_hmac, _ := base64.StdEncoding.DecodeString(strings.Split(lastLine, "\n")[0]) //strip the newline

  	if hmac.Equal(my_hmac,file_hmac){
  		if(verbose){
  			fmt.Print("-valid password \n")
  		}
  		myWallet.masterPassword = pad
  	}else{
  		fmt.Print("Invalid password, exiting\n")
  		return nil
  	}


  	info := strings.Split(strings.Split(hmacLines, "\n")[0], "||")

  	gen, _ := strconv.Atoi(info[1])

  	myWallet.generationNum = gen

  	for _, e := range entryLines{
  		sp := strings.Split(e, "||")
  		var entry walletEntry
  		entry.entry = []byte(sp[0])
  		entry.salt, _ = base64.StdEncoding.DecodeString(sp[1])

  		cipher, _ := base64.StdEncoding.DecodeString(sp[2])
  		entry.password = decrypt(hashpw[:16], cipher, entry.salt)
  		entry.comment = []byte(sp[3])


  		myWallet.passwords = append(myWallet.passwords, entry)
  	}

	// Return the wall
	return &myWallet
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : saveWallet
// Description  : This function save a wallet to the file specified
//
// Inputs       : walletFile - the name of the wallet file
// Outputs      : true if successful test, false if failure

func (my_Wallet wallet) saveWallet() bool {

	if (verbose){
		fmt.Print("-saving wallet \n")
	}

	f, err := os.Create(my_Wallet.filename)
	if (err != nil){
		fmt.Print("Error, could not save wallet \n")
		return false
	}
	defer f.Close()

	var newLine string = time.Now().Format("Mon Jan 2 15:04:05 2006") +"||" + strconv.Itoa(my_Wallet.generationNum + 1) + "||\n"

	f.WriteString(newLine)

	hashpw := sha1.Sum(my_Wallet.masterPassword)
	AESKey := hashpw[:16]
	hmacLines := newLine

	for _, walletEntry := range my_Wallet.passwords{
		enc_salt := base64.StdEncoding.EncodeToString(walletEntry.salt)
		encrypt_pw := encrypt(AESKey, walletEntry.password, walletEntry.salt)
		enc_pw := base64.StdEncoding.EncodeToString(encrypt_pw) 

		l := strings.Split(string(walletEntry.entry),"\n")[0] + "||" + enc_salt + "||" + enc_pw + "||" + strings.Split(string(walletEntry.comment),"\n")[0] + "\n"
		hmacLines += l

		f.WriteString(l)
	}

	temp := bytes.Join([][]byte{hashpw[:16], []byte(hmacLines)},[]byte(""))
	new_hmac := hmac.New(sha1.New, temp).Sum(nil)
	enc_hmac := base64.StdEncoding.EncodeToString([]byte(new_hmac))
	enc_hmac += "\n"

	f.WriteString(enc_hmac)

	return true

}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : processWalletCommand
// Description  : This is the main processing function for the wallet
//
// Inputs       : walletFile - the name of the wallet file
//                command - the command to execute
// Outputs      : true if successful test, false if failure

func (my_wallet *wallet) processWalletCommand(command string) bool {

	// Process the command 
	switch command {
	case "add":

		fmt.Print("Name your entry\n")
		readIn := bufio.NewReader(os.Stdin)

		e_name, _ := readIn.ReadString('\n')
		for(len(e_name) > 32) {
			fmt.Print("Entry name must be shorter than 32 characters, please enter a new one\n")
			e_name, _ = readIn.ReadString('\n')
		}
		full_e_name := make([]byte, 32, 32)
		copy(full_e_name, e_name)

		pass := getPass(16)

		fmt.Print("Feel free to add a comment (max 128 characters)\n")
		com, _ := readIn.ReadString('\n')
		for len(com) > 128{
			fmt.Print("Too long! Only 128 characters allowed. Try again\n")
			com, _ = readIn.ReadString('\n')
		} 
		full_com := make([]byte, 32, 32)
		copy(full_com, com)

		salt := make([]byte, 16, 16)
		_,_ = rand.Read(salt)

		var new_entry walletEntry
		new_entry.entry = full_e_name
		new_entry.password = pass
		new_entry.salt = salt
		new_entry.comment = full_com

		my_wallet.passwords = append(my_wallet.passwords, new_entry)

		my_wallet.saveWallet()

	case "del":
		if len(my_wallet.passwords) - 1 < mod_entry{
			fmt.Print("Delete out of bounds, aborting")
		}else{
			fmt.Print("Are you sure you want to delete this entry? It will not be recoverable. (y/n)")

			readIn := bufio.NewReader(os.Stdin)
			ans, _ := readIn.ReadString('\n')

			if strings.ToLower(ans) == "y" || strings.ToLower(ans) == "yes"{
				before_del := my_wallet.passwords[:mod_entry]
				//after_del := my_wallet.passwords[(del_entry + 1):]
				my_wallet.passwords = append(before_del, my_wallet.passwords[(mod_entry + 1):]...)
			}
			if (verbose){
				fmt.Print("-deleted entry\n")
			}
		}
		my_wallet.saveWallet()

	case "show":
		
		
	case "chpw":
		// DO SOMETHING HERE
		
	case "reset":
		fmt.Print("Enter new master password:\n")
		my_wallet.masterPassword = getPass(32)
		my_wallet.saveWallet()
		
	case "list":
		fmt.Print("Current entries: \n")
		for _, entry := range my_wallet.passwords{
			fmt.Print(entry)
		}
		
	default:
		// Handle error, return failure
		fmt.Fprintf(os.Stderr, "Bad/unknown command for wallet [%s], aborting.\n", command)
		return false
	}

	// Return sucessfull
	return true
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : main
// Description  : The main function for the password generator program
//
// Inputs       : none
// Outputs      : 0 if successful test, -1 if failure

func main() {

	//test
	fmt.Print(time.Now())

	// Setup options for the program content
	getopt.SetUsage(walletUsage)
	rand.Seed(time.Now().UTC().UnixNano())
	helpflag := getopt.Bool('h', "", "help (this menu)")
	verboseflag := getopt.Bool('v', "", "enable verbose output")

	// Now parse the command line arguments
	err := getopt.Getopt(nil)
	if err != nil {
		// Handle error
		fmt.Fprintln(os.Stderr, err)
		getopt.Usage()
		os.Exit(-1)
	}

	// Process the flags
	fmt.Printf("help flag [%t]\n", *helpflag)
	fmt.Printf("verbose flag [%t]\n", *verboseflag)
	verbose = *verboseflag
	if *helpflag == true {
		getopt.Usage()
		os.Exit(-1)
	}

	// Check the arguments to make sure we have enough, process if OK
	if getopt.NArgs() < 2 {
		fmt.Printf("Not enough arguments for wallet operation.\n")
		getopt.Usage()
		os.Exit(-1)
	}
	fmt.Printf("wallet file [%t]\n", getopt.Arg(0))
	filename := getopt.Arg(0)
	fmt.Printf("command [%t]\n", getopt.Arg(1))
	command := strings.ToLower(getopt.Arg(1))

	if getopt.NArgs() > 2{
		mod_entry, err = strconv.Atoi(getopt.Arg(2))
		if err != nil{
			fmt.Print("Improper arguments, to delete or change password, pass integer of entry to be modified as the third argument. Aborting \n")
		}
	}
	

	// Now check if we are creating a wallet
	if command == "create" {

		// Create and save the wallet as needed
		meatWallet := createWallet(filename)
		if meatWallet != nil {
			meatWallet.saveWallet()
		}

	} else {

		// Load the wallet, then process the command
		my_wallet := loadWallet(filename)
		my_wallet.processWalletCommand(command)


	}

	// Return (no return code)
	return
}
