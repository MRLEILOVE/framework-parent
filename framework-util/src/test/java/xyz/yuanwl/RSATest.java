package xyz.yuanwl;

import lombok.extern.slf4j.Slf4j;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import xyz.yuanwl.util.coder.RSACoder;
import xyz.yuanwl.util.coder.RSASignature;

import static org.junit.Assert.*;

@SpringBootTest
@RunWith(SpringJUnit4ClassRunner.class)
@Slf4j
public class RSATest {

	@Test
	public void testNewKeyPair() {
		RSACoder.generateKeyPair();
	}

	/**
	 * 公钥加密 >> 私钥解密 <br>
	 * <br>
	 * 创建人： yuanwl <br>
	 * 创建时间： 2017年10月24日 下午1:54:05 <br>
	 *
	 * @throws Exception
	 */
	@Test
	public void testPubToPri() throws Exception {
		log.info("公钥加密 >> 私钥解密");

		String inputStr = "222222";
		log.info("原文：{}", inputStr);

		// 加密
		String encodedData = RSACoder.encryptByPubKey(inputStr, "UTF-8");
		log.info("加密后：" + encodedData);

		// 解密
		 String outputStr = RSACoder.decryptByPriKey(encodedData, "UTF-8");
//		String outputStr = RSACoder.decryptByPriKey(
//				"ZE1jGGikES9kg4njHJUYcsHUYUe+VLpHSvWO19UV3Y/ktvQmtaHa3BoB/Cyy1nIRd/OP0Gcf/bI6F7VjmOmdgDcTf3H1cli8uaSr/F5BOf65+16BSX5VwUauhqqVf/d/5FFsEOFwUjKNlMpHo5aqe+JCVsjyU0RemTMzGORx1l4=",
//				"UTF-8");
		log.info("解密后：" + outputStr);

	}

	/**
	 * 私钥加密 >> 公钥解密；签名 >> 验证 <br>
	 * <br>
	 * 创建人： yuanwl <br>
	 * 创建时间： 2017年10月24日 下午1:54:21 <br>
	 *
	 * @throws Exception
	 */
	@Test
	public void testSignAndVerify() throws Exception {

		log.info("私钥加密 >> 公钥解密");

		String inputStr = "sign";
		log.info("原文：{}", inputStr);

		String encodedData = RSACoder.encryptByPriKey(inputStr, "UTF-8");
		log.info("加密后：" + encodedData);

		String decodedData = RSACoder.decryptByPubKey(encodedData, "UTF-8");
		log.info("解密后：" + decodedData);

		
		log.info("私钥签名 >> 公钥验证签名");
		log.info("产生签名");
		String sign = RSASignature.signToBase64(encodedData);
		log.info("签名：{}", sign);

		// 验证签名
		boolean status = RSASignature.verifyFromBase64(encodedData, sign);
		log.info("状态：{}", status);
		
		assertTrue(status);

	}

}
