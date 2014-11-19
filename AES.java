//Don't trust anything that passing through the security border!

import java.util.Scanner;

import java.security.SecureRandom;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class AES
{
		public static String KEY_ALGORITHM = "AES";
		public static String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
		public static int BLOCK_SIZE = 16;
		public static int KEY_SIZE = 16; // AES key size can be {16,24,32} bytes

		public static Key byte2Key(byte[] key)throws Exception
		{
				SecretKeySpec sks = new SecretKeySpec(key,KEY_ALGORITHM);
				SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
				SecretKey sk = keyFactory.generateSecret(sks);
				//throws InvalidKeySpecException
				return sk;                       
		}

		public static byte[] decrypt(byte[]data,byte[]key,byte[]iv)throws Exception
		{
				byte[] ans=null;
				
				Key k = byte2Key(key);
				IvParameterSpec ips = new IvParameterSpec(iv);

				Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
				//throws NoSuchAlgorithmException,NoSuchPaddingException

				cipher.init(Cipher.DECRYPT_MODE,k,ips); 
				//throws InvalidKeyException,InvalidAlgorithmParameterException

				ans =  cipher.doFinal(data);
				//throws IllegalBlockSizeException,BadPaddingException(BadPadding only in DECRYPT_MODE)
				
				return ans;
		}

		public static byte[] encrypt(byte[]data,byte[]key,byte[]iv)throws Exception
		{
				Key k=byte2Key(key);
				IvParameterSpec ips = new IvParameterSpec(iv);

				Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
				cipher.init(Cipher.ENCRYPT_MODE,k,ips);
				return cipher.doFinal(data);
		}

		public static byte[] initRandomKey() throws Exception
		{
				KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
				//throws NoSuchAlgorithmException
				kg.init(KEY_SIZE*8,new SecureRandom());
				SecretKey sk = kg.generateKey();
				return sk.getEncoded();
		}


		
		public static byte[] initRandomIv()
		{
				byte[] iv = new byte[BLOCK_SIZE];
				SecureRandom sr = new SecureRandom();

				//byte[] seed = sr.generateSeed(BLOCK_SIZE);
				//sr.setSeed(seed);
				
				sr.nextBytes(iv);
				//If a call to setSeed had not occurred previously, the first call of nextBytes forces this SecureRandom object to seed itself.
				//By default, instances of this class will generate an initial seed using an internal entropy source, such as /dev/urandom. This seed is unpredictable and appropriate for secure use.
				//Calling setSeed(byte[]) may completely replace the cryptographically strong default seed causing the instance to return a predictable sequence of numbers unfit for secure use. Due to variations between implementations it is not recommended to use setSeed at all.
				//http://developer.android.com/reference/java/security/SecureRandom.html
				//https://docs.oracle.com/javase/7/docs/api/java/security/SecureRandom.html
				return iv;
		}

		public static void userEncrypt()
		{
				System.out.println("\nStart "+CIPHER_ALGORITHM+" encryption...");
				System.out.println("Input your plain text:");
				String plainText;
				Scanner scan = new Scanner(System.in);
				plainText = scan.nextLine();

				byte[] data= plainText.getBytes();

				try
				{
				byte[] key = initRandomKey();
				System.out.println("Generate random key(hex):\n"+byte2HexString(key)+"\n");

				byte[] iv = initRandomIv();
				System.out.println("Generate random iv(hex):\n"+byte2HexString(iv)+"\n");

				byte[] cipher = encrypt(data,key,iv);

				System.out.println("Encryption succeeded!");
				System.out.println("Encrypted text(hex):\n"+byte2HexString(cipher)+"\n");
				}
				catch (java.security.GeneralSecurityException e)
				{
						//e.printStackTrace();
						System.out.println("Encryption failed!!!");
				}
				finally
				{
						return;
				}


		}

		public static void userDecrypt()
		{
				System.out.println("\nStart "+CIPHER_ALGORITHM+" decryption...");
				String cipherText,ivText,keyText;
				Scanner scan = new Scanner(System.in);

				System.out.println("Input text for decryption(hex):");
				cipherText = scan.next();
				if(cipherText.length()%BLOCK_SIZE!=0)
				{
						System.out.println("Incorrect text length!Block size is "+BLOCK_SIZE+" bytes");
						return;
				}
				byte[] data= hexString2Bytes(cipherText);
				System.out.println("Get text for decryption:\n"+byte2HexString(data)+"\n");

				System.out.println("Input iv(hex):");
				ivText = scan.next();
				if(ivText.length()%BLOCK_SIZE!=0)
				{
						System.out.println("Incorret iv length!Block size is "+BLOCK_SIZE+" bytes");
						return;
				}
				byte[] iv = hexString2Bytes(ivText);
				System.out.println("Get iv:\n"+byte2HexString(iv)+"\n");

				System.out.println("Input key(hex):");
				keyText = scan.next();
				if(keyText.length()%BLOCK_SIZE!=0)
				{
						System.out.println("Incorrect key length!Key size is "+KEY_SIZE+" bytes");
						return;
				}
				byte[] key = hexString2Bytes(keyText);

				System.out.println("Get key:\n"+byte2HexString(key)+"\n");

				try
				{
					byte[] plain = decrypt(data,key,iv);
					System.out.println("Decryption succeeded!");
					System.out.println("Decrypted text(hex):\n"+byte2HexString(plain));
					System.out.println("Decrypted text(string):\n"+new String(plain)+"\n");
				}
				//catch (javax.crypto.BadPaddingException e1) 
				catch (java.security.GeneralSecurityException e)
				{
						//e.printStackTrace();
						System.out.println("Decryption failed!!!");
				}
				finally
				{
						return ;
				}
		}

		public static void main(String[] args)
		{			
			System.out.println("Algorithm:"+CIPHER_ALGORITHM);
			System.out.println("Key size:"+KEY_SIZE);

			Scanner sc = new Scanner(System.in);
			String opmod;
			while(true)
			{
				System.out.println("Please choose command(S/Q):");
				System.out.println("S for start an Encryption&Decryption round,Q for Quit");
				opmod=sc.nextLine();
				if(opmod.length()>0)
				{
						if(opmod.charAt(0)=='S'||opmod.charAt(0)=='s')
						{		
								userEncrypt();
								userDecrypt();
						}

						else if (opmod.charAt(0)=='Q'||opmod.charAt(0)=='q')
								break;
						}
			}

						
		}
		public static String byte2HexString(byte[]b)
		{
			String str="";
			for (int i=0;i<b.length;i++)
			{
				String hex=Integer.toHexString(b[i]&0xFF);
				if(hex.length()==1)
					hex = '0'+hex;
				str+=hex;
			}
			return str;
		}
		public static byte[] hexString2Bytes(String hexString) 
		{  
		    if (hexString == null || hexString.equals("")) {  
		        return null;  
		    }  
		    hexString = hexString.toUpperCase();  
		    int length = hexString.length() / 2;  
		    char[] hexChars = hexString.toCharArray();  
		    byte[] d = new byte[length];  
		    for (int i = 0; i < length; i++) {  
		        int pos = i * 2;  
		        d[i] = (byte) (char2Byte(hexChars[pos]) << 4 | char2Byte(hexChars[pos + 1]));  
		    }  
		    return d;  
		}  
		public static byte char2Byte(char c) {  
			    return (byte) "0123456789ABCDEF".indexOf(c); }
}

