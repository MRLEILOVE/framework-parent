package xyz.yuanwl.util.coder;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * RSA非对称加密解密工具类。
 * 
 * <p>
 * 这种算法1978年就出现了，它是第一个既能用于数据加密也能用于数字签名的算法。它易于理解和操作，也很流行。 算法的名字以发明者的名字命名：Ron
 * Rivest, AdiShamir 和Leonard Adleman。 这种加密算法的特点主要是密钥的变化，RSA同时有两把钥匙，公钥与私钥。
 * 同时支持数字签名。数字签名的意义在于，对传输过来的数据进行校验。确保数据在传输工程中不被修改。
 * <p>
 * 流程分析：
 * <ol>
 * <li>甲方构建密钥对，将公钥公布给乙方，将私钥保留。</li>
 * <li>甲方使用私钥加密数据，然后用私钥对加密后的数据签名，发送给乙方签名以及加密后的数据；
 * 乙方使用公钥、签名来验证待解密数据是否有效，如果有效使用公钥对数据解密。</li>
 * <li>乙方使用公钥加密数据，向甲方发送经过加密后的数据；甲方获得加密数据，通过私钥解密。</li>
 * </ol>
 * <p>
 * <a href="https://github.com/wwwtyro/cryptico">前端demo<a> <br>
 * <br>
 * 创建人：梁栋【<a href="http://snowolf.iteye.com/blog/381767">原文点这<a>】 <br>
 * 创建时间：2017年10月23日 下午10:53:32 <br>
 * 修改人：yuanwl <br>
 * 修改时间： <br>
 * 修改备注： <br>
 * 
 * @version V1.0
 */
@Component
@Slf4j
public class RSACoder extends BaseCoder {

	/** 算法类型 */
	private static final String KEY_ALGORITHM = "RSA";

	/** RSA密钥长度必须是64的倍数，在512~65536之间。默认是1024 */
	private static final int KEY_SIZE = 1024;

	/**
	 * 填充方式。这里有【RSA/ECB/PKCS1Padding】填充（默认）和【RSA/ECB/NoPadding】填充两种可选。
	 * <p>
	 * 注意：使用 RSA/ECB/PKCS1Padding 填充时，公钥每次加密的字符串都会不一样，这样更安全；不使用则每次都一样。因为java默认是填充的，而安卓默认不填充，
	 * 所以安卓默认加密的密文，java默认不能解密！！必须手动指定他们用一致的填充方式，才能正确加密解密。
	 */
	private static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";

	/** 由公钥字节数组用Base64编码成的字符串，方便传播、储存 */
	private static String PUB_KEY_BASE64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPhuLKVwg6iyzpwRzkQPDPa3z5w/qwr2S5Nb7TczJZK7pRF5r+Va4h3EKxSn+jBpbmufvJgbpBr4uuJ8U0sPSx3GqoyIUiovbB7SLTKNRxMCfT+O3Qa+cKTqM3269ol8iW6QcmLXwM0nIwy0gLLWqUSPLjnAWJTJsIHDVEYW3rQQIDAQAB";
	/** 由私钥字节数组用Base64编码成的字符串，方便传播、储存 */
	private static String PRI_KEY_BASE64 = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAI+G4spXCDqLLOnBHORA8M9rfPnD+rCvZLk1vtNzMlkrulEXmv5VriHcQrFKf6MGlua5+8mBukGvi64nxTSw9LHcaqjIhSKi9sHtItMo1HEwJ9P47dBr5wpOozfbr2iXyJbpByYtfAzScjDLSAstapRI8uOcBYlMmwgcNURhbetBAgMBAAECgYAWmChprAvKk5BNeC4hLKv8KzKwaw6y89mKYpCY3wClEwIws+OdeEWCZRdGq7CuLGJjDhI6Jab5ojX+A5rC8byDacKz7ybU5v7RpKS1LZAk/yaD6WSoJmO6kR/9b/imU+Lpt14YweKTj8dYOaCc+cPltOpzaQaRLqaLwYeQUpCicQJBAOwH8pO2XW3PFP4o2x5dQKTOk1w9IcShp/sIP1ncoCA6AzzbIb++adx2XD0DSDMkvjKLZQRerjXQ1co7L9RXCQUCQQCbq3KLMGKNxUZE2NKXOV2Sx6uoz1A2X30nTLH9BRKL7DuHQRSuked8mUvPSKRynvqqyNqwHk1sgIpOhRa06n4NAkA6kx5YGgHFpoaHLIx0VKAeRkW7tlATBCsz2TAflOkIFl2HVLpjY1XSKG1rlszsJEovMPi4xOZm5JSpw1ZzU8YhAkBeYeHOAGUQndZP8cIlDBPu5X7vl9qDTPv9suOLi+LF0VH6XHwkp7PZeLxdDicek8NZfvQQqh65NWol102AHViVAkBybolSBahmdF7pL9uW7q5YKefzbvC0IQ0dF8Jpyvqw5w0nQiKOSXyIjn5vMdUuJeAdCKl8skUK6ewDjrPqQtbi";
	/** 公钥对象 */
	protected static PublicKey PUB_KEY;
	/** 私钥对象 */
	protected static PrivateKey PRI_KEY;

	@Value("${xyz.yuanwl.security.auth.pubKey}") // 静态属性不能用这个注解注入，只能放到普通public set方法上面，简介注入
	public void setPubKey(String pubKey){
		PUB_KEY_BASE64 = pubKey;
		try {
			PUB_KEY = restorePubKey(PUB_KEY_BASE64);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			log.error("初始化公钥出错", e);
		}
	}

	@Value("${xyz.yuanwl.security.auth.priKey}")
	public void setPriKey(String priKey){
		PRI_KEY_BASE64 = priKey;
		try {
			PRI_KEY = restorePriKey(PRI_KEY_BASE64);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			log.error("初始化私钥出错", e);
		}
	}

	// 初始化
	// ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓

	// 静态代码块，初始化密钥对象，供后面使用
//	static {
//		try {
//			PUB_KEY = restorePubKey(PUB_KEY_BASE64);
//			PRI_KEY = restorePriKey(PRI_KEY_BASE64);
//		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
//			log.error("初始化出错", e);
//		}
//	}

	/**
	 * 还原公钥，X509EncodedKeySpec 用于构建公钥的规范
	 * <p>
	 * 创建人：yuanwl <br>
	 * 创建时间：2018年8月18日 下午5:16:50 <br>
	 * <p>
	 * 修改人： <br>
	 * 修改时间： <br>
	 * 修改备注： <br>
	 * </p>
	 * 
	 * @param keyBase64
	 *            密钥编码成的base64字符串
	 * @return 公钥对象
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static PublicKey restorePubKey(String keyBase64)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(decryptBase64(keyBase64));
		KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
		PublicKey publicKey = factory.generatePublic(x509EncodedKeySpec);
		return publicKey;
	}

	/**
	 * 还原私钥，PKCS8EncodedKeySpec 用于构建私钥的规范
	 * <p>
	 * 创建人：yuanwl <br>
	 * 创建时间：2018年8月18日 下午5:19:09 <br>
	 * <p>
	 * 修改人： <br>
	 * 修改时间： <br>
	 * 修改备注： <br>
	 * </p>
	 * 
	 * @param keyBase64
	 *            密钥编码成的base64字符串
	 * @return 私钥对象
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static PrivateKey restorePriKey(String keyBase64)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decryptBase64(keyBase64));
		KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
		PrivateKey privateKey = factory.generatePrivate(pkcs8EncodedKeySpec);
		return privateKey;
	}

	// /**
	// * 从 .p12 文件中读取私钥。 <br>
	// * <br>
	// * 创建人： yuanwl <br>
	// * 创建时间： 2017年10月28日 下午4:21:56 <br>
	// *
	// * @param pfxKeyFileName
	// * .p12文件路径
	// * @param aliasName
	// * 私钥别名
	// * @param pfxPassword
	// * 私钥密码
	// * @return 私钥对象
	// * @throws KeyStoreException
	// * @throws NoSuchAlgorithmException
	// * @throws CertificateException
	// * @throws IOException
	// * @throws UnrecoverableKeyException
	// */
	// public static PrivateKey readP12Key(String pfxKeyFileName, String aliasName,
	// String pfxPassword)
	// throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
	// IOException,
	// UnrecoverableKeyException {
	// InputStream fis = new FileInputStream(pfxKeyFileName);
	// KeyStore keyStore = KeyStore.getInstance("PKCS12");
	// keyStore.load(fis, pfxPassword.toCharArray());
	// return (PrivateKey) keyStore.getKey(aliasName, pfxPassword.toCharArray());
	// }
	//
	// public static PublicKey readCerKey(String cerKeyFileName) {
	// return null;
	// }

	// 加密、解密
	// ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
	/**
	 * 通用加密操作
	 * <p>
	 * 创建人：yuanwl <br>
	 * 创建时间：2018年8月18日 下午5:37:32 <br>
	 * <p>
	 * 修改人： <br>
	 * 修改时间： <br>
	 * 修改备注： <br>
	 * </p>
	 * 
	 * @param key
	 *            公钥或私钥对象
	 * @param decoded
	 *            明文字符串
	 * @param charset
	 *            字符编码
	 * @return 密文字节数组用Base64算法编码成的字符串，方便传输、储存
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws UnsupportedEncodingException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	private static String encrypt(Key key, String decoded, String... charset)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {
		// 如果不传字符编码就默认用utf-8
		String c = ArrayUtils.isEmpty(charset) ? "UTF-8" : charset[0];
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return encryptBase64(cipher.doFinal(decoded.getBytes(c)));
	}

	/**
	 * 通用解密操作
	 * <p>
	 * 创建人：yuanwl <br>
	 * 创建时间：2018年8月18日 下午5:43:34 <br>
	 * <p>
	 * 修改人： <br>
	 * 修改时间： <br>
	 * 修改备注： <br>
	 * </p>
	 * 
	 * @param key
	 *            公钥或私钥对象
	 * @param encoded
	 *            密文字符串（由密文字节数组用Base64算法编码成的字符串）
	 * @param charset
	 *            字符编码
	 * @return 明文字符串
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 */
	private static String decrypt(Key key, String encoded, String... charset)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException {
		String c = ArrayUtils.isEmpty(charset) ? "UTF-8" : charset[0];
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(decryptBase64(encoded)), c);
	}

	/**
	 * 用公钥加密 <br>
	 * <br>
	 * 创建人： yuanwl <br>
	 * 创建时间： 2017年10月24日 下午2:00:49 <br>
	 *
	 * @param decoded
	 *            明文字符串
	 * @param charset
	 *            字符编码
	 * @return 密文字节数组用Base64算法编码成的字符串，方便传输、储存
	 * @throws UnsupportedEncodingException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static String encryptByPubKey(String decoded, String... charset)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {
		return encrypt(PUB_KEY, decoded, charset);
	}

	/**
	 * 用私钥解密 <br>
	 * <br>
	 * 创建人： yuanwl <br>
	 * 创建时间： 2017年10月24日 下午1:57:42 <br>
	 *
	 * @param encoded
	 *            密文字符串（由密文字节数组用Base64算法编码成的字符串）
	 * @param charset
	 *            字符编码
	 * @return 明文字符串
	 * @throws UnsupportedEncodingException
	 * @throws Exception
	 */
	public static String decryptByPriKey(String encoded, String... charset)
			throws UnsupportedEncodingException, Exception {
		return decrypt(PRI_KEY, encoded, charset);
	}

	/**
	 * 用私钥加密
	 * <p>
	 * 创建人：yuanwl <br>
	 * 创建时间：2018年8月18日 下午5:37:32 <br>
	 * <p>
	 * 修改人： <br>
	 * 修改时间： <br>
	 * 修改备注： <br>
	 * </p>
	 * 
	 * @param decoded
	 *            明文字符串
	 * @param charset
	 *            字符编码
	 * @return 密文字节数组用Base64算法编码成的字符串，方便传输、储存
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws UnsupportedEncodingException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String encryptByPriKey(String decoded, String... charset)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {
		return encrypt(PRI_KEY, decoded, charset);
	}

	/**
	 * 用公钥解密
	 * <p>
	 * 创建人：yuanwl <br>
	 * 创建时间：2018年8月18日 下午5:43:34 <br>
	 * <p>
	 * 修改人： <br>
	 * 修改时间： <br>
	 * 修改备注： <br>
	 * </p>
	 * 
	 * @param encoded
	 *            密文字符串（由密文字节数组用Base64算法编码成的字符串）
	 * @param charset
	 *            字符编码
	 * @return 明文字符串
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 */
	public static String decryptByPubKey(String encoded, String... charset)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException {
		return decrypt(PUB_KEY, encoded, charset);
	}

	
	// 更换密钥对
	// ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
	/**
	 * 生成密钥对。注意这里是生成密钥对KeyPair，再由密钥对获取公、私钥。一般情况下用不到这个方法，只有在需要换密钥对时才执行产生新的密钥对。
	 * <p>
	 * 创建人：yuanwl <br>
	 * 创建时间：2018年8月18日 下午7:35:21 <br>
	 * <p>
	 * 修改人： <br>
	 * 修改时间： <br>
	 * 修改备注： <br>
	 * </p>
	 */
	public static void generateKeyPair() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
			keyPairGenerator.initialize(KEY_SIZE);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			// 公钥、私钥用 encryptBase64 还是 encryptBase64Sun 加密都可以，后者的 Base64 是多行的，比较适合保存到文件的方式储存
			log.info("新公钥：{}", encryptBase64(publicKey.getEncoded()));

			RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
			log.info("新私钥：{}", encryptBase64(privateKey.getEncoded()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

}
