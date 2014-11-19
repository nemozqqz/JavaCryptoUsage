import java.security.SecureRandom;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class DES
{
		public static String KEY_ALGORITHM = "DES";
		public static String CIPHER_ALGORITHM = "DES/CBC/PKCS5Padding";
		public static int BLOCK_SIZE = 8;//bytes
		public static int KEY_SIZE = 7;//jce only support 56 bit DES key

		public static Key byte2Key(byte[] key)throws Exception
		{
				SecretKeySpec sks = new SecretKeySpec(key,KEY_ALGORITHM);
				SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
				SecretKey sk = keyFactory.generateSecret(sks);
				return sk;
		}

		public static byte[] decrypt(byte[]data,byte[]key,byte[]iv)throws Exception
		{
				Key k = byte2Key(key);
				IvParameterSpec ips = new IvParameterSpec(iv);

				Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
				cipher.init(Cipher.DECRYPT_MODE,k,ips);
				return cipher.doFinal(data);
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
				kg.init(KEY_SIZE*8,new SecureRandom());
				SecretKey sk = kg.generateKey();
				return sk.getEncoded();
		}
		
		public static byte[] initRandomIv()
		{
				byte[] iv = new byte[BLOCK_SIZE];
				new SecureRandom().nextBytes(iv);
				return iv;
		}


		public static void main(String[] args)throws Exception
		{			

			String msg="this is top secret;秘密";
			byte[] data = msg.getBytes();
			
			byte[] key = initRandomKey();
			byte[] iv = initRandomIv();

			byte[] enc = encrypt(data,key,iv);

			byte[] dec = decrypt(enc,key,iv);

			System.out.println("Algorithm:"+CIPHER_ALGORITHM);
			System.out.println("Key size:"+KEY_SIZE);

			System.out.println("Plain text:"+msg);
			System.out.println("Key:"+byte2HexString(key));
			System.out.println("Iv:"+byte2HexString(iv));
			System.out.println("Encrypted text:"+byte2HexString(enc));
			System.out.println("Decode text:"+new String(dec));

						
		}
		public static String byte2HexString(byte[]b)
		{
			String str="0x";
			for (int i=0;i<b.length;i++)
			{
				String hex=Integer.toHexString(b[i]&0xFF);
				if(hex.length()==1)
					hex = '0'+hex;
				str+=hex;
			}
			return str;
		}
}

