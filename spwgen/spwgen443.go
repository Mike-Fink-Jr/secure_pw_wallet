////////////////////////////////////////////////////////////////////////////////
//
//  File           : spwgen443.go
//  Description    : This is the implementation file for the spwgen443 password
//                   generator program.
//
//  Collaborators  : Ammar Zuberi, Mike Fink, Gabe Stanton
//  Last Modified  : 12/4/2017
//

// Package statement
package main

//Imports
import ( 
	"fmt"
	"os"
	"math/rand"
	"strconv"
	"time"
	"github.com/pborman/getopt"
	"io/ioutil"
	"strings"
)

//Global constants
const dictionary = "/usr/share/dict/words"

//Global variables
var dictionaryWords []string
var lowercaseLetters = []rune("abcdefghijklmnopqrstuvwxyz")
var uppercaseLetters = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
var digits = []rune("0123456789")
var specialChars = []rune("~!@#$%^&*()-_=+{}[]:;/?<>,.|\\")

var patternval string = `
pattern (set of symbols defining password)

A pattern consists of a string of characters "xxxxx",
where the x pattern characters include:

d - digit
c - upper or lower case character
l - lower case character
u - upper case character
w - random word from /usr/share/dict/words (or /usr/dict/words)
	note that w# will identify a word of length #, if possible
s - special character in ~!@#$%^&*()-_=+{}[]:;/?<>,.|\

Note: the pattern overrides other flags, e.g., -w`

////////////////////////////////////////////////////////////////////////////////
//
// Function     : generatePasword
// Description  : This is the function to generate the password.
//
// Inputs       : length - length of password
//                pattern - pattern of the file ("" if no pattern)
//                webflag - is this a web password?
// Outputs      : 0 if successful test, -1 if failure
////////////////////////////////////////////////////////////////////////////////

func generatePasword(length int, pattern string, webflag bool) string {
	var generatedPassword string = ""

	if (pattern != "") {
		//We generate a password according to the pattern

		//Parse the pattern
		for i := 0; i < len(pattern); i++ {
			//Generate one digit
			if (pattern[i] == 'd') {
				generatedPassword = generatedPassword + string(generateOne("digit"))
			//Generate one upper or lower case letter
			} else if (pattern[i] == 'c') {
				if (rand.Intn(100) > 50) {
					//Generate a lower case
					generatedPassword = generatedPassword + string(generateOne("lower"))
				} else {
					//Generate an upper case
					generatedPassword = generatedPassword + string(generateOne("upper"))
				}
			//Genreate one lower case letter
			} else if (pattern[i] == 'l') {
				generatedPassword = generatedPassword + string(generateOne("lower"))
			//Generate one upper case letter	
			} else if (pattern[i] == 'u') {
				generatedPassword = generatedPassword + string(generateOne("upper"))
			//Generate one word (check next 2 indicies for word length)
			} else if (pattern[i] == 'w') {
				//The next character must be an integer

				//Handle the edge case where there are no more characters to parse
				if (len(pattern) - (i + 1) == 0) {
					fmt.Printf("[ERROR] Invalid pattern specified [%s]\n", pattern)
					os.Exit(-1)
				}

				if _, err := strconv.Atoi(string(pattern[i + 1])); err != nil {
					fmt.Printf("[ERROR] Invalid pattern specified [%s]\n", pattern)
					os.Exit(-1)
				} else {
					//The second digit is optional, there should never be a third
					if ((len(pattern) - (i + 2)) > 0) {
						if _, err := strconv.Atoi(string(pattern[i + 2])); err == nil {
							//Now we have a two digit word length
							generatedPassword = generatedPassword + string(generateWord(string(pattern[i + 1]) + string(pattern[i + 2])))
							i = i + 2
						} else {
							generatedPassword = generatedPassword + string(generateWord(string(pattern[i + 1])))
							i = i + 1
						}
					} else {
						generatedPassword = generatedPassword + string(generateWord(string(pattern[i + 1])))
						i = i + 1
					}
				}

			//Generate one special character
			} else if (pattern[i] == 's') {
				generatedPassword = generatedPassword + string(generateOne("special"))
			//Invalid input, return an error
			} else {
				fmt.Printf("[ERROR] Invalid pattern specified [%s]\n", pattern)
				os.Exit(-1)
			}
		}

		return generatedPassword
	} else {
		//We generate a password of length specified

		if (webflag == false) {
			//Generate a non web-safe password (special characters are allowed)
			for i := 0; i < length; i++ {
				var randInt int = rand.Intn(100)
				if ((0 <= randInt) && (randInt <= 33)) {
					//Generate a lower case
					generatedPassword = generatedPassword + string(generateOne("lower"))
				} else if ((34 <= randInt) && (randInt <= 66)) {
					//Generate an upper case
					generatedPassword = generatedPassword + string(generateOne("upper"))
				} else {
					//Generate an upper case
					generatedPassword = generatedPassword + string(generateOne("special"))
				}
			}
		} else {
			//Generate a web-safe password (special characters are not allowed)
			for i := 0; i < length; i++ {
				var randInt int = rand.Intn(100)
				if ((0 <= randInt) && (randInt <= 50)) {
					//Generate a lower case
					generatedPassword = generatedPassword + string(generateOne("lower"))
				} else {
					//Generate an upper case
					generatedPassword = generatedPassword + string(generateOne("upper"))
				}
			}
		}

		return generatedPassword
	}
}

func generateWord(length string) string {
	wordLength, _ := strconv.Atoi(length)
	var selectedWord string

	//Search dictionary for a word of the length we want
	for i := 0; i < len(dictionaryWords); i++ {
		if (len(dictionaryWords[i]) == wordLength) {
			selectedWord = dictionaryWords[i]
			break
		}
	}

	//Shuffle the dictionary to make it ready for the next use
	shuffleDictionary()

	return selectedWord
}

func loadDictionary() {
	content, err := ioutil.ReadFile(dictionary);
	if (err != nil) {
		fmt.Printf("[ERROR] Could not access dictionary file at %s\n", dictionary)
		os.Exit(-1)
	}

	dictionaryWords = strings.Split(string(content), "\n")
}

func shuffleDictionary() {
	for i := range dictionaryWords {
		j := rand.Intn(i + 1)
		dictionaryWords[i], dictionaryWords[j] = dictionaryWords[j], dictionaryWords[i]
	}
}

func generateOne(oneOf string) rune {
	switch oneOf {
		case "digit":
			return digits[rand.Intn(len(digits))]

		case "lower":
			return lowercaseLetters[rand.Intn(len(lowercaseLetters))]

		case "upper":
			return uppercaseLetters[rand.Intn(len(uppercaseLetters))]

		case "special":
			return specialChars[rand.Intn(len(specialChars))]

		default:
			return 'a'
	}
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : main
// Description  : The main function for the password generator program
//
// Inputs       : none
// Outputs      : 0 if successful test, -1 if failure
////////////////////////////////////////////////////////////////////////////////

func main() {
	//Seed the pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	//Set up command line options with getopt library
	helpflag := getopt.Bool('h', "", "help (this menu)")
	webflag := getopt.Bool('w', "", "web flag (no symbol characters, e.g., no &*...)")
	length := getopt.String('l', "", "length of password (in characters)")
	pattern := getopt.String('p', "", patternval)

	//Parse command line arguments with library
	err := getopt.Getopt(nil)

	//Show error from library, if there is one
	if (err != nil) {
		fmt.Fprintln(os.Stderr, err)
		getopt.Usage()
		os.Exit(-1)
	}

	//Show help menu if flag is set
	if (*helpflag == true) {
		getopt.Usage()
		return
	}

	//Safety check length parameter
	var passwordLength int = 16

	if (*length != "" && *pattern == "") {
		if passwordLength, err = strconv.Atoi(*length); err != nil {
			fmt.Printf("[ERROR] Invalid password length specified, expected int and got [%s]\n", *length)
			os.Exit(-1)
		}

		//If length provided is invalid, set to default of 16, else set the passwordLength variable
		if (passwordLength <= 0 || passwordLength > 64) {
			passwordLength = 16
		}
	}

	//Load and shuffle the dictionary in case we need it
	loadDictionary()
	shuffleDictionary()

	// Now generate the password and print it out
	generatedPassword := generatePasword(passwordLength, *pattern, *webflag)
	fmt.Printf("[SUCCESS] Generated password: %s\n", generatedPassword)

	return
}
