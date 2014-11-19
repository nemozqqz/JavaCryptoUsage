import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class keypair
{
		public static void main(String args[])throws Exception
		{
				KeyPairGenerator keyPG = KeyPairGenerator.getInstance("RSA");
				keyPG.initialize(1024);
				KeyPair kp = keyPG.generateKeyPair();

				PrivateKey pk1 = kp.getPrivate();

				//从密钥字节还原密钥
				byte[] pkeyBytes = kp.getPrivate().getEncoded();
				PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(pkeyBytes);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				PrivateKey pk2 = keyFactory.generatePrivate(pkcs8KeySpec);

				byte[] pk1b = pk1.getEncoded();
				byte[] pk2b = pk2.getEncoded();
				printHexString(pk1b);
				printHexString(pk2b);

		}
		public static void printHexString(byte[]b)
		{
			if(b!=null)
			{
			System.out.print("0x");
			for (int i=0;i<b.length;i++)
			{
				String hex=Integer.toHexString(b[i]&0xFF);
				if(hex.length()==1)
					hex = '0'+hex;
				System.out.print(hex);
			}
			}
			System.out.println();
		}
}
