import java.io.*;  
import java.net.*;  
import java.util.Scanner; // Import the Scanner class to read text files
import java.util.Random;
import java.math.BigInteger;


public class MyServer {  
public static void main(String[] args){  
try{  
ServerSocket ss=new ServerSocket(6666);  
Socket s=ss.accept();//establishes connection   
ObjectInputStream inStream = new ObjectInputStream(s.getInputStream());


try{

    File myObj = new File("filename.txt");
    Scanner myReader = new Scanner(myObj);
    StringBuilder plaintext = new StringBuilder("");

    while (myReader.hasNextLine()) {
      String data = myReader.nextLine();
      plaintext.append(data);
    }
    //System.out.println(plaintext);
    StringBuilder sb = new StringBuilder(""); 
    String pt = new String(plaintext);
    char[] letters = pt.toCharArray();// = plaintext.toCharArray(); 
    for (char ch : letters) 
    {  
   	  if((int)ch > 99){

      	sb.append((int) ch); 

   	  }else if((int)ch < 99){
   	  	sb.append("0");
      	sb.append((int) ch); 
   	  }
      // sb.append((int) ch); 
    } 
    System.out.println("Plain text in ASCII is: " + sb.toString());
    myReader.close();

    System.out.println();
    Random generator = new Random();
    //System.out.println(generator);
    System.out.println(sb.length());
    int bitLen = sb.length();
    bitLen *= 3.4;
    System.out.println(bitLen);

    Elgamal scheme = new Elgamal( bitLen , generator);

    ObjectOutputStream outputStream = new ObjectOutputStream(s.getOutputStream());
  	outputStream.writeObject(scheme);

  	Elgamal_PublicKey receivedKeySet = (Elgamal_PublicKey)inStream.readObject();
  	System.out.println("Public Key: "  );
	System.out.println("P: " + receivedKeySet.p);
	System.out.println("e1: " + receivedKeySet.g);
	System.out.println("e2: " + receivedKeySet.h);

   	Elgamal_PlainText plain = new Elgamal_PlainText(new BigInteger( sb.toString() ));
    Elgamal_CipherText ctext = scheme.Encrypt(plain, receivedKeySet);
    System.out.println("Encryption...");
    System.out.println("C Text: ");
    System.out.println("C1: " + ctext.c1);
    System.out.println("C2: " + ctext.c2);

  	outputStream.writeObject(ctext);

} catch(FileNotFoundException e) {
      System.out.println("An error occurred.");
      e.printStackTrace();
  }
 


// String  str=(String)dis.readUTF();  
// System.out.println("message= "+str);  
ss.close();  
}catch(Exception e){System.out.println(e);}  
}  
}  