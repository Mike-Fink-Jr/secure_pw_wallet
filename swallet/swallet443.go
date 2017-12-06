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
	changed bool
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

// You may want to create more global variables

//
// Functions
 func vprint( s string){ 
 	if verbose{
 	fmt.printf("Verbose: %s",s)
}



func getPass(leng int) []byte]{

	reader := bufio.NewReader(os.Stdin)
	var checker bool :=false
	var checker2 bool := false
	while(!checker2){
		while ( !checker){

			fmt.Println("Master Password: ")
		  	input, _ := reader.ReadString('\n')
		  	if []byte(input) <=leng{ 
		  		vprint("password valid length")
		  		checker := true
		  	}else {
	  			fmt.printf("please enter a valid length password")
		  	} 
		}
		fmt.Println("re-enter Password: ")
		input2, _ := reader.ReadString('\n')

		if strings.Compare(input, input2)==0 {
			vprint("passwords match")
			checker2:=true
		}else{
			fmt.print("your passwords did not match: please retry")
		}

 	}
 	return []byte(input)
 }






func (entry walletEntry) encrypt() string{
	var pass string
	var salt string

	salt:= ncode(entry.salt)
	pass := ncode(entry.password)

	return string(entry.entry)+"||"+ string(salt)+"||"+string(pass)+"||"+string(entry.comment)+"\n"
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
	var meatWallet wallet 
	meatWallet.filename = filename
	meatWallet.masterPassword = make([]byte, 32, 32) // You need to take it from here

	meatWallet.masterPassword= getPass(32)
 	
	// Return the wall
	return &meatWallet
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : loadWallet
// Description  : This function loads an existing wallet
//
// Inputs       : filename - the name of the wallet file
// Outputs      : the wallet if created, nil otherwise

func loadWallet(filename string) *wallet {

	// Setup the wallet
	var meatWallet wallet 
	// DO THE LOADING HERE

	// Return the wall
	return &meatWallet
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : saveWallet
// Description  : This function save a wallet to the file specified
//
// Inputs       : walletFile - the name of the wallet file
// Outputs      : true if successful test, false if failure

func (meatWallet wallet) saveWallet() bool {


	// if passed in wallet isnt changed then no need to save
	if !meatWallet.changed{
		return true}
	

	// Setup the wallet
	
	file, err := os.Open(meatWallet.filename)
	defer file.close()
	if err != nil{
		vprint("error<"+time.Now().String()+"> file could not open filenmae: "+meatWallet.filename)
		return false
	}else{
		var data string

		data := time.Now().String() + "||" + meatWallet.generationNum + "||\n"
		var x int
		var entry walletEntry
		for x:=1; x<=len(meatWallet.passwords); x++ {
			entry := meatWallet.passwords[x]
			data := data+ entry.encrypt()
	}
	data := data+"\n"+HMAC()

	err = ioutil.WriteFile(meatWallet.filename, []byte(data), 0644)
    check(err)  
	// Return successfully
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

func (meatWallet wallet) processWalletCommand(command string) bool {

	// Process the command 
	switch command {
	case "add":


	case "del":
		// DO SOMETHING HERE
		
	case "show":
		// DO SOMETHING HERE
		
	case "chpw":
		// DO SOMETHING HERE
		
	case "reset":
		// DO SOMETHING HERE
		
	case "list":
		// DO SOMETHING HERE
		
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

	// Now check if we are creating a wallet
	if command == "create" {

		// Create and save the wallet as needed
		meatWallet := createWallet(filename)
		if meatWallet != nil {
			meatWallet.saveWallet()
		}

	} else {

		// Load the wallet, then process the command
		meatWallet := loadWallet(filename)
		if meatWallet != nil && meatWallet.processWalletCommand(command) {
			meatWallet.saveWallet()
		}

	}

	// Return (no return code)
	return
}
