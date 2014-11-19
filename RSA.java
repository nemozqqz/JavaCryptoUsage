import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.bouncycastle.util.encoders.Base64;
public class RSA {

	public static final String KEY_ALGORITHM = "RSA";

	private static final String PUBLIC_KEY = "RSAPublicKey";

	private static final String PRIVATE_KEY = "RSAPrivateKey";

	private static final int KEY_SIZE = 1024;


	public static byte[] decryptByPrivateKey(byte[] data, byte[] key)
			throws Exception {

		// 取得私钥
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(key);

		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 生成私钥
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 对数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());

		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		return cipher.doFinal(data);
	}

	public static byte[] encryptByPublicKey(byte[] data, byte[] key)
			throws Exception {

		// 取得公钥
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(key);

		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);

		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());

		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		return cipher.doFinal(data);
	}



	public static byte[] getPrivateKey(Map<String, Object> keyMap)
			throws Exception {

		Key key = (Key) keyMap.get(PRIVATE_KEY);

		return key.getEncoded();
	}

	public static byte[] getPublicKey(Map<String, Object> keyMap)
			throws Exception {

		Key key = (Key) keyMap.get(PUBLIC_KEY);

		return key.getEncoded();
	}

	public static Map<String, Object> initKey() throws Exception {

		// 实例化密钥对生成器
		KeyPairGenerator keyPairGen = KeyPairGenerator
				.getInstance(KEY_ALGORITHM);

		// 初始化密钥对生成器
		keyPairGen.initialize(KEY_SIZE);

		// 生成密钥对
		KeyPair keyPair = keyPairGen.generateKeyPair();

		// 公钥
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

		// 私钥
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		// 封装密钥
		Map<String, Object> keyMap = new HashMap<String, Object>(2);

		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);

		return keyMap;
	}
	public static void main(String[] args)throws Exception
	{
			byte[] publicKey;
			byte[] privateKey;


			Map<String,Object> keyMap = initKey();
			publicKey = getPublicKey(keyMap);
			privateKey = getPrivateKey(keyMap);

			System.out.println("Public key:\n"+new String(Base64.encode(publicKey)));
			System.out.println("Private key:\n"+new String(Base64.encode(privateKey)));

			String msg = "RSA加密";
			System.out.println("Plain text:\n"+msg);
			byte[] data = msg.getBytes();
			byte[] enc = encryptByPublicKey(data,publicKey);

			byte[] dec = decryptByPrivateKey(enc,privateKey);
			System.out.println("Decoded text:\n"+new String(dec));

	}

}

