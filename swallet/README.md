# swallet
CS443 assign3 password wallet in GO

UIs needed:
------
new wallet password prompt: (done)
	- Two textboxes

master password prompt:
	- One textbox

password/comment prompt:
	- Two textboxes

entry # prompt:
	- One textbox

change password prompt:
	- Two textboxes

Functions:
------
create:
	- Prompt for new wallet master password
	- Calculate HMAC for empty wallet
	- Set system time, generation # and save to file

add:
	- Prompt for master password
	- Check HMAC
	- Prompt for password and comment
	- Create the new entry
	- Recalculate and update HMAC
	- Increment generation #, last modification time and save to file

del:
	- Prompt for master password
	- Check HMAC
	- Prompt for entry number to delete
	- Delete the entry
	- Recalculate and update HMAC
	- Increment generation #, last modification time and save to file

show:
	- Prompt for master password
	- Check HMAC
	- Prompt for entry number to show
	- Decrypt password
	- Print out the password for entry requested

chpw:
	- Prompt for master password
	- Check HMAC
	- Prompt for entry number and new password
	- Encrypt the new password and replace it in the line
	- Recalculate and update HMAC
	- Increment generation #, last modification time and save to file

reset:
	- Prompt for master password
	- Check HMAC
	- Prompt for new master password
	- Decrypt all passwords and encrypt again with new password individually
	- Recalculate and update HMAC
	- Increment generation #, last modification time and save to file

list:
	- Loop through wallet and display entry # and comment
