import java.security.MessageDigest;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;

//JCE supported digest algorithm:
//MD2,MD5,SHA-1,SHA-256,SHA-384,SHA-512
//
//Bouncy Castle supported digest algorithm
//MD2,MD4,MD5,SHA1,SHA224,SHA256,SHA384,SHA512

public class Hash {
	public static void main(String[] args)throws Exception
	{
		String msg = "this is a sample msg";
		
		MessageDigest md = MessageDigest.getInstance("MD5");
		printHexString(md.digest(msg.getBytes()));
		
		md = MessageDigest.getInstance("SHA-1"); 
		printHexString(md.digest(msg.getBytes()));

		md = MessageDigest.getInstance("MD4"); //from BouncyCastle
		printHexString(md.digest(msg.getBytes()));
		
		md = MessageDigest.getInstance("SHA-224");//from BoucyCastle 
		printHexString(md.digest(msg.getBytes()));

		md = MessageDigest.getInstance("SHA-256"); 
		printHexString(md.digest(msg.getBytes()));
		
	}
	public static void printHexString(byte[]b)
	{
		System.out.print("0x");
		for (int i=0;i<b.length;i++)
		{
			String hex=Integer.toHexString(b[i]&0xFF);
			if(hex.length()==1)
				hex = '0'+hex;
			System.out.print(hex);
		}
		System.out.println();
	}
}
