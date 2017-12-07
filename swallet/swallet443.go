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
	//"golang.org/x/crypto/ssh/terminal"
	ui "github.com/gizak/termui"
	"strconv"
	"bytes"
	"crypto/sha1"
	"crypto/hmac"
	"encoding/base64"
	"crypto/aes"
	"crypto/cipher"
	// There will likely be several mode APIs you need
)



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
//var terminal bool =true
var mod_entry int = -1

// You may want to create more global variables

//
// Functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : vprint
// Description  : This function is used to output data to console quickly if the program is running in 'verbose' mode
//					it is primarily to cut down on time spent debugging and unit testing, all instances could be removed theoretically
//
// Called in 	: every where
//
// Inputs       : string s,		
//				: uses the global verbose variable
//
// Outputs      : prints to fmt, but otherwise is void
//
 func vprint( s string){ 
 	if verbose{
 	fmt.Printf("Verbose: %s\n",s)
	}
}



func encrypt(key []byte, plaintext []byte, salt []byte) []byte{
  	
  	block, _ := aes.NewCipher(key)

  	gcm, _ := cipher.NewGCMWithNonceSize(block, 16)
    
  	encryption := gcm.Seal(nil, salt, plaintext, nil)
	  vprint("-Password encrypted\n")
    
    return encryption
}

func decrypt(key []byte, ciphertext []byte, salt []byte) []byte{
  	// The key argument should be the AES key, either 16 or 32 bytes
  	// to select AES-128 or AES-256.
  	block, _ := aes.NewCipher(key)

  	gcm, _ := cipher.NewGCMWithNonceSize(block, 16)

  	decryption, err := gcm.Open(nil, salt, ciphertext, nil)
  	if err != nil {
  		panic(err.Error())
  	}
  
    vprint("-Password decrypted\n")
    
    return decryption
}





func getPass(leng int, pass string, pass2 string) []byte{

	pw := []byte{}

	pw_match := false


	for !pw_match{

		if (len(pass) <= leng){
			if (strings.Compare(pass,pass2) ==0){
				pw_match = true
				if(verbose){
					fmt.Print("-passwords match \n")
				}
				return []byte(pass)
			}else{
				fmt.Print("Passwords do not match\n\n exiting program\n")
				os.Exit(-1)
			}
		}else{
			fmt.Print("Password must be less than " + strconv.Itoa(leng) + " characters \n\nExiting Program\n")
			os.Exit(-1)
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

func createWallet(filename string, pass1 string,pass2 string) *wallet {
	// Setup the wallet
	var myWallet wallet 
	myWallet.filename = filename
	myWallet.masterPassword = make([]byte, 32, 32) // You need to take it from here
	myWallet.generationNum = -1

	//fmt.Print("Create master password: \n")
	mp := getPass(32, pass1, pass2)
	copy(myWallet.masterPassword, mp)
		vprint("-created wallet \n")
	


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

func loadWallet(filename string, master string) *wallet {
	vprint("-Loading wallet from " + filename)
	defer vprint("end Load wallet from " + filename )

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
	pw := master

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
  		
  		vprint("-valid password")
  		
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
  	fmt.Printf("%s %s ", string(myWallet.passwords[0].entry), string(myWallet.passwords[0].comment))
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

		vprint("-saving wallet")
	

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

func processWalletCommand(command string,filename string)  {

	// Process the command 
	switch command {

	case "create":
		 pass, pass2 := rcPrompt()
		my_wallet := createWallet(filename,pass,pass2)
		if(my_wallet==nil){
			fmt.Print("something went wrong creating the wallet\n\n exiting now\n")
			os.Exit(-1)
		}

		if (my_wallet.saveWallet()){
			vprint("operation success!")
		}
	

	case "add":
	var full_e_name []byte
		master,pass ,com,e_name := addPrompt()

		my_wallet := loadWallet(filename,master)
		if(my_wallet==nil){
			fmt.Print("something went wrong loading the wallet\n\nexiting now\n")
			os.Exit(-1)
		}

		if(len(e_name) > 32) {
			fmt.Print("Entry name must be shorter than 32 characters\n\nexiting now\n")
			os.Exit(-1)
		}else{
			for _, e := range my_wallet.passwords{
				if strings.Compare(string(e.entry),e_name)==0 {
				fmt.Print("Entry name taken already\n\nexiting now\n")
				os.Exit(-1)
				}
			}
			
			full_e_name = make([]byte, 32, 32)
			copy(full_e_name, e_name)
		
		var full_pass []byte

		if len(pass) > 16{
			fmt.Print("Too long! Only 16 characters allowed\n exiting now\n")
			os.Exit(-1)
		} else{
			full_pass = make([]byte, 16,16)
			copy(full_pass,pass)

		}

		
		if len(com) > 128{
			fmt.Print("Too long! Only 128 characters allowed. cutting off the execess\n")
			com=com[:127]
		} 

		full_com := make([]byte, 128, 128)
		copy(full_com, com)

		salt := make([]byte, 16, 16)
		_,_ = rand.Read(salt)

		var new_entry walletEntry
		new_entry.entry = full_e_name
		new_entry.password = full_pass
		new_entry.salt = salt
		new_entry.comment = full_com

		my_wallet.passwords = append(my_wallet.passwords, new_entry)

		my_wallet.saveWallet()
	}

	case "del":
		master,name := dsPrompt()

		my_wallet := loadWallet(filename,master)
		if(my_wallet==nil){
			fmt.Print("something went wrong loading the wallet\n\nexiting now\n")
			os.Exit(-1)
		}

	
		d :=-1
		for i, e := range my_wallet.passwords{
			if(strings.Compare(string(e.entry),name)==0){
				
				d=i
			}
		}
		if d==-1{
			fmt.Print("no entry by the name"+name+ "\n\naborting\n")
			os.Exit(-1)
		}
	
		
/*		fmt.Print("Are you sure you want to delete this entry? It will not be recoverable. (y/n)\n")

		readIn2 := bufio.NewReader(os.Stdin)
		ans, _ := readIn2.ReadString('\n')
		if strings.Compare(strings.ToLower(ans), "y\n") ==  0 || strings.ToLower(ans) == "yes\n"{
*/			my_wallet.passwords = append(my_wallet.passwords[:d], my_wallet.passwords[d+1:]...)

				vprint("-deleted entry")
			
		//}else{
			//fmt.Print("Deletion aborted \n")
		//}
			
		
		my_wallet.saveWallet()

	case "show":
	
		name,master := dsPrompt()

		my_wallet := loadWallet(filename,master)
		if(my_wallet==nil){
			fmt.Print("something went wrong loading the wallet\n\nexiting now\n")
			os.Exit(-1)
		}

		
		//var temp *walletEntry
		str:=""
		for _, e := range my_wallet.passwords{
			if(strings.Compare(string(e.entry),name)==0){
				fmt.Print("here")
				str= string(e.password)
			}
		}
		if strings.Compare(str,"")==0{
			fmt.Print("no entry by the name"+name+ "\n\naborting\n")
			os.Exit(-1)
		}
		//entry:=&temp

		fmt.Print("Password: ")
		fmt.Print(string(str))
		fmt.Print("\n")


		
		
	case "chpw":

		master,new_pass, name :=chpwPrompt()
		
		my_wallet := loadWallet(filename,master)
		if(my_wallet==nil){
			fmt.Print("something went wrong loading the wallet\n\nexiting now\n")
			os.Exit(-1)
		}


		//var temp *walletEntry
		c:=-1
		for i, e := range my_wallet.passwords{
			if(strings.Compare(string(e.entry),name)==0){
				c=i
			}
		}
		if c==-1{
			fmt.Print("no entry by the name "+name+ "\n\naborting\n")
			os.Exit(-1)
		}
		//entry:=&temp


		//new_pass = getPass(16, new_pass, new_pass2)

		copy(my_wallet.passwords[c].password, new_pass)

		
		vprint("-Password changed\n")
		

		my_wallet.saveWallet()


	case "reset":
		master,pass1:= rcPrompt()
		pass2:=pass1

		my_wallet := loadWallet(filename,master)
		if(my_wallet==nil){
			fmt.Print("something went wrong loading the wallet\n\nexiting now\n")
			os.Exit(-1)
		}

		my_wallet.masterPassword = getPass(32, pass1,pass2)
		my_wallet.saveWallet()
		
	case "list":
		master,_ := dsPrompt()


		my_wallet := loadWallet(filename,master)
		if(my_wallet==nil){
			fmt.Print("something went wrong loading the wallet\n\nexiting now\n")
			os.Exit(-1)
		}

		fmt.Print("Current entries: \n")
		for _, e := range my_wallet.passwords{
			i := 0
			for i < len(e.entry){
				fmt.Print(string(e.entry[i]))
				i ++
			}
			fmt.Print("\n")
		}
		
	default:
		// Handle error, return failure
		fmt.Fprintf(os.Stderr, "Bad/unknown command for wallet [%s], aborting.\n", command)
		os.Exit(-1)
	}

	
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

	// Setup options for the program content
	getopt.SetUsage(walletUsage)
	rand.Seed(time.Now().UTC().UnixNano())
	helpflag := getopt.Bool('h', "", "help (this menu)")
	verboseflag := getopt.Bool('v', "", "enable verbose output")
//	terminalflag := getopt.Bool('t', "", "run in terminal mode")

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
//	fmt.Printf("terminal flag [%t]\n", *terminalflag)
	verbose = *verboseflag
//	terminal= *terminalflag
	
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
	

	processWalletCommand(command,filename)



	
	// Return (no return code)
	return
}





//AMMARs ui code subject to change




func chpwPrompt() (string, string, string) {
	err := ui.Init()
	if err != nil {
		panic(err)
	}
	defer ui.Close()

	var masterPassword = ""
	var password = ""
	var entryName = ""
	var textboxActive = 0

	//This is textbox 0
	p := ui.NewPar("|")
	p.Height = 3
	p.Width = 50
	p.X = 5
	p.TextFgColor = ui.ColorWhite
	p.BorderLabel = "Wallet password"

	//This is textbox 1
	g := ui.NewPar("")
	g.Height = 3
	g.Width = 50
	g.X = 5
	g.Y = 4
	g.TextFgColor = ui.ColorWhite
	g.BorderLabel = "New Password"

	//This is textbox 2
	h := ui.NewPar("")
	h.Height = 3
	h.Width = 70
	h.X = 5
	h.Y = 10
	h.TextFgColor = ui.ColorWhite
	h.BorderLabel = "Entry name"

	ui.Render(p, g, h)

	//Handle when someone presses the enter key
	ui.Handle("/sys/kbd/<enter>", func(e ui.Event) {
		if (textboxActive == 0) {
			//Move on to the next textbox

			p.Text = p.Text[:len(p.Text) - 1] //Remove the cursor from the end of p
			textboxActive = 1
			g.Text = "|" //Add cursor to the end of g

			ui.Render(p, g, h)
		} else if (textboxActive == 1) {
			//Move on to the next textbox

			g.Text = g.Text[:len(g.Text) - 1] //Remove the cursor from the end of p
			textboxActive = 2
			h.Text = "|" //Add cursor to the end of g

			ui.Render(p, g, h)
		} else if (textboxActive == 2) {
			//User entry is complete
			ui.StopLoop()
		}
	})

	//Handle data entry into the textbox
	ui.Handle("/sys/kbd", func(e ui.Event) {

		//Handle backspaces
		if (string(e.Data.(ui.EvtKbd).KeyStr) == "C-8") {
			if ((textboxActive == 0) && (len(masterPassword) > 0)) {
				//We're removing from textbox 0

				masterPassword = masterPassword[:len(masterPassword) - 1]
				p.Text = p.Text[:len(p.Text) - 2] //Remove the cursor and star from the end
				p.Text = p.Text + "|" //Add the cursor back
			} else if ((textboxActive == 1) && (len(password) > 0)) {
				//We're removing from textbox 1

				password = password[:len(password) - 1]
				g.Text = g.Text[:len(g.Text) - 2] //Remove the cursor and star from the end
				g.Text = g.Text + "|" //Add the cursor back
			} else if ((textboxActive == 2) && (len(entryName) > 0)) {
				//We're removing from textbox 2

				entryName = entryName[:len(entryName) - 1]
				h.Text = h.Text[:len(h.Text) - 2] //Remove the cursor and star from the end
				h.Text = h.Text + "|" //Add the cursor back
			}

		//Handle writing into the textboxes
		} else if (textboxActive == 0) {
			//We're writing in textbox 0

			masterPassword = masterPassword + string(e.Data.(ui.EvtKbd).KeyStr)
			p.Text = p.Text[:len(p.Text) - 1] //Remove the cursor from the end
			p.Text = p.Text + "*|" //Add star and then the cursor back
		} else if (textboxActive == 1) {
			//We're writing in textbox 1

			password = password + string(e.Data.(ui.EvtKbd).KeyStr)
			g.Text = g.Text[:len(g.Text) - 1] //Remove the cursor from the end
			g.Text = g.Text + "*|" //Add star and then the cursor back
		} else if (textboxActive == 2) {
			//We're writing in textbox 2

			entryName = entryName + string(e.Data.(ui.EvtKbd).KeyStr)
			entryName = strings.Replace(entryName, "<space>", " ", -1)
			h.Text = h.Text[:len(h.Text) - 1] //Remove the cursor from the end
			h.Text = entryName + "|" //Add the data and then the cursor back
		}

		ui.Render(p, g, h)
	})

	ui.Handle("/sys/kbd/esc", func(ui.Event) {
		//If ESC is used, stop the loop and exit
		ui.StopLoop()
	})

	ui.Handle("/sys/kbd/C-c", func(ui.Event) {
		//If CTRL-C is used, stop the loop and exit
		ui.StopLoop()
	})

	ui.Handle("/sys/kbd/C-x", func(ui.Event) {
		//If CTRL-X is used, stop the loop and exit
		ui.StopLoop()
	})

	ui.Loop()

	return masterPassword, password, entryName
}

func dsPrompt() (string, string) {
	err := ui.Init()
	if err != nil {
		panic(err)
	}
	defer ui.Close()

	var masterPassword = ""
	var entryName = ""
	var textboxActive = 0

	//This is textbox 0
	p := ui.NewPar("|")
	p.Height = 3
	p.Width = 50
	p.X = 5
	p.TextFgColor = ui.ColorWhite
	p.BorderLabel = "Wallet password"

	//This is textbox 1
	g := ui.NewPar("")
	g.Height = 3
	g.Width = 50
	g.X = 5
	g.Y = 4
	g.TextFgColor = ui.ColorWhite
	g.BorderLabel = "Entry name"

	ui.Render(p, g)

	//Handle when someone presses the enter key
	ui.Handle("/sys/kbd/<enter>", func(e ui.Event) {
		if (textboxActive == 0) {
			//Move on to the next textbox

			p.Text = p.Text[:len(p.Text) - 1] //Remove the cursor from the end of p
			textboxActive = 1
			g.Text = "|" //Add cursor to the end of g

			ui.Render(p, g)
		} else if (textboxActive == 1) {
			//User entry is complete
			ui.StopLoop()
		}
	})

	//Handle data entry into the textbox
	ui.Handle("/sys/kbd", func(e ui.Event) {

		//Handle backspaces
		if (string(e.Data.(ui.EvtKbd).KeyStr) == "C-8") {
			if ((textboxActive == 0) && (len(masterPassword) > 0)) {
				//We're removing from textbox 0

				masterPassword = masterPassword[:len(masterPassword) - 1]
				p.Text = p.Text[:len(p.Text) - 2] //Remove the cursor and star from the end
				p.Text = p.Text + "|" //Add the cursor back
			} else if ((textboxActive == 1) && (len(entryName) > 0)) {
				//We're removing from textbox 1

				entryName = entryName[:len(entryName) - 1]
				g.Text = g.Text[:len(g.Text) - 2] //Remove the cursor and star from the end
				g.Text = g.Text + "|" //Add the cursor back
			}

		//Handle writing into the textboxes
		} else if (textboxActive == 0) {
			//We're writing in textbox 0

			masterPassword = masterPassword + string(e.Data.(ui.EvtKbd).KeyStr)
			p.Text = p.Text[:len(p.Text) - 1] //Remove the cursor from the end
			p.Text = p.Text + "*|" //Add star and then the cursor back
		} else if (textboxActive == 1) {
			//We're writing in textbox 1

			entryName = entryName + string(e.Data.(ui.EvtKbd).KeyStr)
			entryName = strings.Replace(entryName, "<space>", " ", -1)

			g.Text = g.Text[:len(g.Text) - 1] //Remove the cursor from the end
			g.Text = entryName + "|" //Add star and then the cursor back
		}

		ui.Render(p, g)
	})

	ui.Handle("/sys/kbd/esc", func(ui.Event) {
		//If ESC is used, stop the loop and exit
		ui.StopLoop()
	})

	ui.Handle("/sys/kbd/C-c", func(ui.Event) {
		//If CTRL-C is used, stop the loop and exit
		ui.StopLoop()
	})

	ui.Handle("/sys/kbd/C-x", func(ui.Event) {
		//If CTRL-X is used, stop the loop and exit
		ui.StopLoop()
	})

	ui.Loop()

	return masterPassword, entryName
}

func addPrompt() (string, string, string, string) {
	err := ui.Init()
	if err != nil {
		panic(err)
	}
	defer ui.Close()

	var masterPassword = ""
	var password = ""
	var comment = ""
	var entryName = ""
	var textboxActive = 0

	//This is textbox 0
	p := ui.NewPar("|")
	p.Height = 3
	p.Width = 50
	p.X = 5
	p.TextFgColor = ui.ColorWhite
	p.BorderLabel = "Wallet password"

	//This is textbox 1
	g := ui.NewPar("")
	g.Height = 3
	g.Width = 50
	g.X = 5
	g.Y = 4
	g.TextFgColor = ui.ColorWhite
	g.BorderLabel = "Password"

	//This is textbox 2
	h := ui.NewPar("")
	h.Height = 3
	h.Width = 70
	h.X = 5
	h.Y = 10
	h.TextFgColor = ui.ColorWhite
	h.BorderLabel = "Comment"

	//This is textbox 3
	j := ui.NewPar("")
	j.Height = 3
	j.Width = 70
	j.X = 5
	j.Y = 15
	j.TextFgColor = ui.ColorWhite
	j.BorderLabel = "Entry name"

	ui.Render(p, g, h, j)

	//Handle when someone presses the enter key
	ui.Handle("/sys/kbd/<enter>", func(e ui.Event) {
		if (textboxActive == 0) {
			//Move on to the next textbox

			p.Text = p.Text[:len(p.Text) - 1] //Remove the cursor from the end of p
			textboxActive = 1
			g.Text = "|" //Add cursor to the end of g

			ui.Render(p, g, h, j)
		} else if (textboxActive == 1) {
			//Move on to the next textbox

			g.Text = g.Text[:len(g.Text) - 1] //Remove the cursor from the end of p
			textboxActive = 2
			h.Text = "|" //Add cursor to the end of g

			ui.Render(p, g, h, j)
		} else if (textboxActive == 2) {
			//Move on to the next textbox

			h.Text = h.Text[:len(h.Text) - 1] //Remove the cursor from the end of p
			textboxActive = 3
			j.Text = "|" //Add cursor to the end of g

			ui.Render(p, g, h, j)
		} else if (textboxActive == 3) {
			//User entry is complete
			ui.StopLoop()
		}
	})

	//Handle data entry into the textbox
	ui.Handle("/sys/kbd", func(e ui.Event) {

		//Handle backspaces
		if (string(e.Data.(ui.EvtKbd).KeyStr) == "C-8") {
			if ((textboxActive == 0) && (len(masterPassword) > 0)) {
				//We're removing from textbox 0

				masterPassword = masterPassword[:len(masterPassword) - 1]
				p.Text = p.Text[:len(p.Text) - 2] //Remove the cursor and star from the end
				p.Text = p.Text + "|" //Add the cursor back
			} else if ((textboxActive == 1) && (len(password) > 0)) {
				//We're removing from textbox 1

				password = password[:len(password) - 1]
				g.Text = g.Text[:len(g.Text) - 2] //Remove the cursor and star from the end
				g.Text = g.Text + "|" //Add the cursor back
			} else if ((textboxActive == 2) && (len(comment) > 0)) {
				//We're removing from textbox 2

				comment = comment[:len(comment) - 1]
				h.Text = h.Text[:len(h.Text) - 2] //Remove the cursor and star from the end
				h.Text = h.Text + "|" //Add the cursor back
			} else if ((textboxActive == 3) && (len(entryName) > 0)) {
				//We're removing from textbox 3

				entryName = entryName[:len(entryName) - 1]
				j.Text = j.Text[:len(j.Text) - 2] //Remove the cursor and star from the end
				j.Text = j.Text + "|" //Add the cursor back
			}

		//Handle writing into the textboxes
		} else if (textboxActive == 0) {
			//We're writing in textbox 0

			masterPassword = masterPassword + string(e.Data.(ui.EvtKbd).KeyStr)
			p.Text = p.Text[:len(p.Text) - 1] //Remove the cursor from the end
			p.Text = p.Text + "*|" //Add star and then the cursor back
		} else if (textboxActive == 1) {
			//We're writing in textbox 1

			password = password + string(e.Data.(ui.EvtKbd).KeyStr)
			g.Text = g.Text[:len(g.Text) - 1] //Remove the cursor from the end
			g.Text = g.Text + "*|" //Add star and then the cursor back
		} else if (textboxActive == 2) {
			//We're writing in textbox 2

			comment = comment + string(e.Data.(ui.EvtKbd).KeyStr)
			comment = strings.Replace(comment, "<space>", " ", -1)
			h.Text = h.Text[:len(h.Text) - 1] //Remove the cursor from the end
			h.Text = comment + "|" //Add the data and then the cursor back
		} else if (textboxActive == 3) {
			//We're writing in textbox 3

			entryName = entryName + string(e.Data.(ui.EvtKbd).KeyStr)
			entryName = strings.Replace(entryName, "<space>", " ", -1)
			j.Text = j.Text[:len(j.Text) - 1] //Remove the cursor from the end
			j.Text = entryName + "|" //Add the data and then the cursor back
		}

		ui.Render(p, g, h, j)
	})

	ui.Handle("/sys/kbd/esc", func(ui.Event) {
		//If ESC is used, stop the loop and exit
		ui.StopLoop()
	})

	ui.Handle("/sys/kbd/C-c", func(ui.Event) {
		//If CTRL-C is used, stop the loop and exit
		ui.StopLoop()
	})

	ui.Handle("/sys/kbd/C-x", func(ui.Event) {
		//If CTRL-X is used, stop the loop and exit
		ui.StopLoop()
	})

	ui.Loop()

	return masterPassword, password, comment, entryName
}

func rcPrompt() (string, string) {
	err := ui.Init()
	if err != nil {
		panic(err)
	}
	defer ui.Close()

	var password1 = ""
	var password2 = ""
	var textboxActive = 0

	//This is textbox 0
	p := ui.NewPar("|")
	p.Height = 3
	p.Width = 50
	p.X = 5
	p.TextFgColor = ui.ColorWhite
	p.BorderLabel = "New wallet password"

	//This is textbox 1
	g := ui.NewPar("")
	g.Height = 3
	g.Width = 50
	g.X = 5
	g.Y = 4
	g.TextFgColor = ui.ColorWhite
	g.BorderLabel = "New wallet password (again)"

	ui.Render(p, g)

	//Handle when someone presses the enter key
	ui.Handle("/sys/kbd/<enter>", func(e ui.Event) {
		if (textboxActive == 0) {
			//Move on to the next textbox

			p.Text = p.Text[:len(p.Text) - 1] //Remove the cursor from the end of p
			textboxActive = 1
			g.Text = "|" //Add cursor to the end of g

			ui.Render(p, g)
		} else if (textboxActive == 1) {
			//User entry is complete
			ui.StopLoop()
		}
	})

	//Handle data entry into the textbox
	ui.Handle("/sys/kbd", func(e ui.Event) {

		//Handle backspaces
		if (string(e.Data.(ui.EvtKbd).KeyStr) == "C-8") {
			if ((textboxActive == 0) && (len(password1) > 0)) {
				//We're removing from textbox 0

				password1 = password1[:len(password1) - 1]
				p.Text = p.Text[:len(p.Text) - 2] //Remove the cursor and star from the end
				p.Text = p.Text + "|" //Add the cursor back
			} else if ((textboxActive == 1) && (len(password2) > 0)) {
				//We're removing from textbox 1

				password2 = password2[:len(password2) - 1]
				g.Text = g.Text[:len(g.Text) - 2] //Remove the cursor and star from the end
				g.Text = g.Text + "|" //Add the cursor back
			}

		//Handle writing into the textboxes
		} else if (textboxActive == 0) {
			//We're writing in textbox 0

			password1 = password1 + string(e.Data.(ui.EvtKbd).KeyStr)
			p.Text = p.Text[:len(p.Text) - 1] //Remove the cursor from the end
			p.Text = p.Text + "*|" //Add star and then the cursor back
		} else if (textboxActive == 1) {
			//We're writing in textbox 1

			password2 = password2 + string(e.Data.(ui.EvtKbd).KeyStr)
			g.Text = g.Text[:len(g.Text) - 1] //Remove the cursor from the end
			g.Text = g.Text + "*|" //Add star and then the cursor back
		}

		ui.Render(p, g)
	})

	ui.Handle("/sys/kbd/esc", func(ui.Event) {
		//If ESC is used, stop the loop and exit
		ui.StopLoop()
	})

	ui.Handle("/sys/kbd/C-c", func(ui.Event) {
		//If CTRL-C is used, stop the loop and exit
		ui.StopLoop()
	})

	ui.Handle("/sys/kbd/C-x", func(ui.Event) {
		//If CTRL-X is used, stop the loop and exit
		ui.StopLoop()
	})

	ui.Loop()

	return password1, password2
}


