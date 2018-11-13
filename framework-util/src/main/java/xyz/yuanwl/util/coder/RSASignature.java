package xyz.yuanwl.util.coder;

import java.io.UnsupportedEncodingException;
import java.security.Signature;
import java.security.SignatureException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.ArrayUtils;

/**
 * RSA签名验签类
 */
public class RSASignature extends RSACoder {

	/**
	 * 用哪个算法来签名
	 */
	public static final String SIGNATURE_ALGORITHM = "SHA1WithRSA";

	/**
	 * 用RSA私钥对信息生成数字签名。 <br>
	 * <br>
	 * 创建人： yuanwl <br>
	 * 创建时间： 2017年10月28日 下午5:44:42 <br>
	 *
	 * @param encoded
	 *            加密字符串转换的字节数组
	 * @return Signature，方便进一步转换为其他数据
	 * @throws Exception
	 */
	private static Signature sign(byte[] encoded) throws Exception {
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(PRI_KEY);
		signature.update(encoded);
		return signature;
	}

	/**
	 * 用RSA私钥把密文生成Base64数字签名。 <br>
	 * <br>
	 * 创建人： yuanwl <br>
	 * 创建时间： 2017年10月28日 下午5:49:35 <br>
	 *
	 * @param encoded
	 *            加密字符串
	 * @param charset
	 *            字符编码
	 * @return 签名，已用Base64编码
	 * @throws UnsupportedEncodingException
	 * @throws SignatureException
	 * @throws Exception
	 */
	public static String signToBase64(String encoded, String... charset)
			throws SignatureException, UnsupportedEncodingException, Exception {
		// 如果不传字符编码就默认用utf-8
		String c = ArrayUtils.isEmpty(charset) ? "UTF-8" : charset[0];
		return encryptBase64(sign(encoded.getBytes(c)).sign());
	}

	/**
	 * 用RSA私钥把密文生成16进制数字签名。 <br>
	 * <br>
	 * 创建人： yuanwl <br>
	 * 创建时间： 2017年10月28日 下午5:52:30 <br>
	 *
	 * @param encoded
	 *            加密字符串
	 * @param charset
	 *            字符编码
	 * @return 签名，已用转16进制字符串
	 * @throws SignatureException
	 * @throws UnsupportedEncodingException
	 * @throws Exception
	 */
	public static String signToHex(String encoded, String...charset)
			throws SignatureException, UnsupportedEncodingException, Exception {
		String c = ArrayUtils.isEmpty(charset) ? "UTF-8" : charset[0];
		return bytesToHex(sign(encoded.getBytes(c)).sign());
	}

	/**
	 * 用RSA公钥校验数字签名。 <br>
	 * <br>
	 * 创建人： yuanwl <br>
	 * 创建时间： 2017年10月28日 下午5:56:35 <br>
	 *
	 * @param data
	 *            加密字符串转换的字节数组
	 * @param signed
	 *            签名，已用Base64编码
	 * @return
	 * @throws Exception
	 */
	public static Signature verify(byte[] data) throws Exception {
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(PUB_KEY);
		signature.update(data);
		return signature;
	}

	/**
	 * 用RSA公钥校验Base64数字签名。 <br>
	 * <br>
	 * 创建人： yuanwl <br>
	 * 创建时间： 2017年10月28日 下午6:00:25 <br>
	 *
	 * @param encoded
	 *            加密数据
	 * @param signed
	 *            签名，已用Base64编码
	 * @param charset
	 *            字符编码
	 * @return 校验成功返回true 失败返回false
	 * @throws UnsupportedEncodingException
	 * @throws SignatureException
	 * @throws Exception
	 */
	public static boolean verifyFromBase64(String encoded, String signed, String...charset)
			throws SignatureException, UnsupportedEncodingException, Exception {
		String c = ArrayUtils.isEmpty(charset) ? "UTF-8" : charset[0];
		return verify(encoded.getBytes(c)).verify(decryptBase64(signed));
	}

	/**
	 * 用RSA公钥校验16进制数字签名。 <br>
	 * <br>
	 * 创建人： yuanwl <br>
	 * 创建时间： 2017年10月28日 下午6:10:24 <br>
	 *
	 * @param data
	 *            加密数据
	 * @param signed
	 *            签名，是由字节数组转换成的16进制字符串
	 * @param charset
	 *            字符编码
	 * @return 校验成功返回true 失败返回false
	 * @throws SignatureException
	 * @throws UnsupportedEncodingException
	 * @throws DecoderException
	 * @throws Exception
	 */
	public static boolean verifyFromHex(String data, String signed, String...charset)
			throws SignatureException, UnsupportedEncodingException, DecoderException, Exception {
		String c = ArrayUtils.isEmpty(charset) ? "UTF-8" : charset[0];
		return verify(data.getBytes(c)).verify(hexToBytes(signed));
	}

}
