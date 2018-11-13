package xyz.yuanwl.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * <p>通用简单系统安全属性
 *
 * @author Yuanwl
 * @date 2018/10/21 17:23
 */
@Data
@ConfigurationProperties(prefix = "xyz.yuanwl.security.auth")
@Component
public class AuthProperties {
	/** 保存用户对象到session的key */
	public static String KEY_USER = "USER";
	/** 保存图片验证码到session的key */
	public static String KEY_IMG_CODE = "IMG_CODE";

	/** 登录用户名 */
	private String username="dev";
	/** 登录密码 */
	private String password="111111";

	/** 图片验证码长度 */
	private Integer imgCodeLen=4;
	/** 图片验证码类型 */
	private Integer imgCodeType=0;

}
