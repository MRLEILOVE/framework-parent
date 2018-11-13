package xyz.yuanwl.util.coder;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.RandomStringUtils;

import sun.misc.*;

/**
 * 基础编码工具类。注意： <br>
 * Base64加密可逆，一般用来编码信息发送，甚至可以把图片转换成字符串发送到前端显示。不能用来发送机密信息！ <br>
 * MD5、SHA、HMAC这三种加密算法，是不可逆加密，我们通常只把他们作为加密的基础。单纯的以上三种的加密并不可靠。
 * <p>
 * <br>
 * <br>
 * 创建人：yuanwl <br>
 * 创建时间：2017年10月23日 下午10:39:06 <br>
 * 修改人： <br>
 * 修改时间： <br>
 * 修改备注： <br>
 * 
 * @version V1.0
 */
@Slf4j
public class BaseCoder {

	private static final String KEY_SHA = "SHA";
	private static final String KEY_MD5 = "MD5";

	/**
	 * MAC算法可选以下多种算法
	 * 
	 * <pre>
	 * HmacMD5 
	 * HmacSHA1 
	 * HmacSHA256 
	 * HmacSHA384 
	 * HmacSHA512
	 * </pre>
	 */
	private static final String KEY_MAC = "HmacMD5";

	/**
	 * 字节数组转16进制字符串。 <br>
	 * <br>
	 * 创建人： yuanwl <br>
	 * 创建时间： 2017年10月28日 下午6:04:35 <br>
	 *
	 * @param input
	 *            字节数组
	 * @return 16进制字符串
	 */
	public static String bytesToHex(byte[] input) {
		return Hex.encodeHexString(input);
	}

	/**
	 * 16进制字符串转字节数组。 <br>
	 * <br>
	 * 创建人： yuanwl <br>
	 * 创建时间： 2017年10月28日 下午6:04:56 <br>
	 *
	 * @param input
	 *            16进制字符串
	 * @return 字节数组
	 * @throws DecoderException
	 */
	public static byte[] hexToBytes(String input) throws DecoderException {
		return Hex.decodeHex(input.toCharArray());
	}

	/**
	 * BASE64加密（Apache实现）
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String encryptBase64(byte[] key) {
		// 安卓自带实现，因为安卓用不了Apache的实现，所以只能用自带的实现。注意，Base64.CRLF才对应Apache的默认模式！
		// return Base64.encodeToString(key, Base64.CRLF);

		// Apache实现，推荐！注意要使用org.apache.commons.codec.binary包下的，否则图片转Base64字符串时，前端无法识别成图片！
		return new String(Base64.encodeBase64(key));
	}

	/**
	 * BASE64解密（Apache实现）
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptBase64(String key) {
		// 安卓自带实现
		// return Base64.decode(key, Base64.CRLF);

		// Apache实现
		return Base64.decodeBase64(key);
	}

	/**
	 * BASE64加密（Sun
	 * Jdk自带实现，因为是在sun.misc下的类，随时可能会被Java官方删掉，不推荐使用，但是RSA要用到，所以保留）。
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String encryptBase64Sun(byte[] key) {
		return (new BASE64Encoder()).encodeBuffer(key);
	}

	/**
	 * BASE64解密（Sun
	 * Jdk自带实现，因为是在sun.misc下的类，随时可能会被Java官方删掉，不推荐使用，但是RSA要用到，所以保留）。
	 * 
	 * @param key
	 * @return
	 * @throws IOException 
	 * @throws Exception
	 */
	public static byte[] decryptBase64Sun(String key) throws IOException {
		return (new BASE64Decoder()).decodeBuffer(key);
	}

	/**
	 * MD5加密
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws Exception
	 */
	public static byte[] encryptMD5(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md5 = MessageDigest.getInstance(KEY_MD5);
		md5.update(data);
		return md5.digest();
	}

	/**
	 * MD5加密，字符串到字符串
	 * 
	 * @param str
	 * @return
	 */
	public static String encryptMD5(String str) {
		return DigestUtils.md5Hex(str);
	}

	/**
	 * 3次MD5加密，字符串到字符串
	 * 
	 * @param str
	 * @return
	 */
	public static String encryptTriMD5(String str) {
		int count = 3;
		String md5 = str;
		for (int i = 0; i < count; i++) {
			md5 = BaseCoder.encryptMD5(md5);
		}
		return md5;
	}

	/**
	 * SHA加密
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws Exception
	 */
	public static byte[] encryptSHA(byte[] data) throws NoSuchAlgorithmException {

		MessageDigest sha = MessageDigest.getInstance(KEY_SHA);
		sha.update(data);
		return sha.digest();

	}

	/**
	 * SHA加密，字符串到字符串 <br>
	 * <br>
	 * 创建人： yuanwl <br>
	 * 创建时间： 2017年10月24日 下午8:49:51 <br>
	 *
	 * @param str
	 * @return
	 */
	public static String encryptSHA(String str) {
		return DigestUtils.sha1Hex(str);
	}

	/**
	 * 初始化HMAC密钥
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws Exception
	 */
	public static String initMacKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_MAC);

		SecretKey secretKey = keyGenerator.generateKey();
		return encryptBase64(secretKey.getEncoded());
	}

	/**
	 * HMAC加密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws Exception
	 */
	public static byte[] encryptHMAC(byte[] data, String key) throws NoSuchAlgorithmException, InvalidKeyException {

		SecretKey secretKey = new SecretKeySpec(decryptBase64(key), KEY_MAC);
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		mac.init(secretKey);

		return mac.doFinal(data);

	}

	/**
	 * 将 URL 编码
	 */
	public static String encodeURL(String str) {
		String target;
		try {
			target = URLEncoder.encode(str, "UTF-8");
		} catch (Exception e) {
			log.error("编码出错！", e);
			throw new RuntimeException(e);
		}
		return target;
	}

	/**
	 * 将 URL 解码
	 */
	public static String decodeURL(String str) {
		String target;
		try {
			target = URLDecoder.decode(str, "UTF-8");
		} catch (Exception e) {
			log.error("解码出错！", e);
			throw new RuntimeException(e);
		}
		return target;
	}

	/**
	 * 创建随机数
	 */
	public static String createRandom(int count) {
		return RandomStringUtils.randomNumeric(count);
	}

	/**
	 * 获取 UUID（32位）
	 */
	public static String createUUID() {
		return UUID.randomUUID().toString().replaceAll("-", "").toUpperCase();
	}

	public static void main(String[] args) throws UnsupportedEncodingException, Exception {
		String str = "123456";
		log.info(encryptBase64(str.getBytes("UTF-8")));
		log.info(encryptBase64Sun(str.getBytes("UTF-8")));
	}
}
