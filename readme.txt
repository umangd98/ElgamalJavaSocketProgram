Follow the below steps to run the Emulation of the Elgamal Enc. and Dec. Algorithm using Java Socket Programming.


1. Unzip the files in a Directory
2. Open two terminals in the above directory, one for the client side code and other for the server side code.
3. Compile all the files as,
	$> javac MySever.java (first terminal)
	$> javac MyClient.java (second terminal)
4. First run the server side code as,
	$> java Myserver (First terminal)
5. Then run the client side code as,
	$> java MyClient.java (Second terminal)
6. The code executes, file is read, parsed, encrypted and sent to the client side along with the public key, then the client uses the private key to decrypt the file and convert it back into the original message. 
