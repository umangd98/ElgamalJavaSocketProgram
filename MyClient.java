import java.io.*;  
import java.net.*;  
public class MyClient {  
public static void main(String[] args) {  
try{      
Socket s=new Socket("localhost",6666);  

ObjectOutputStream outputStream = new ObjectOutputStream(s.getOutputStream());
ObjectInputStream inStream = new ObjectInputStream(s.getInputStream());

Elgamal receivedScheme = (Elgamal)inStream.readObject();
System.out.println("Received Scheme " + receivedScheme.params.nb_bits);
Elgamal_KeySet kset = receivedScheme.KeyGen();
System.out.println("Secret Key:  " );
System.out.println("P: " + kset.skey.p);
System.out.println("d: " + kset.skey.x);

outputStream.writeObject(kset.pkey);
Elgamal_CipherText receivedCText = (Elgamal_CipherText)inStream.readObject();
System.out.println("C Text: ");
System.out.println("C1: " + receivedCText.c1);
System.out.println("C2: " + receivedCText.c2);
Elgamal_PlainText plain2 = receivedScheme.Decrypt(receivedCText, kset.skey);
System.out.println("Decryption...");

System.out.println("Plain text: " + plain2.m);
System.out.println("Plain text in char: ");

String output = plain2.m.toString();
// System.out.println("Plain text: " + output);

if(output.length()%3!=0){
		String ascii = output.substring(0,2);
		int ascii_int = Integer.parseInt(ascii);
		System.out.print((char)ascii_int);
		output = output.substring(2,output.length());
}
for(int i=0;i<output.length()-2;i+=3){

	String ascii = output.substring(i,i+3);
	int ascii_int = Integer.parseInt(ascii);
	// System.out.print(ascii_int);
		System.out.print((char)ascii_int);
}
System.out.println();
s.close();  
}catch(Exception e){System.out.println(e);}  
}  
} 