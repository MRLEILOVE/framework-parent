package xyz.yuanwl.vo;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.hibernate.validator.constraints.NotBlank;

/**
 * <p>简单用户对象
 *
 * @author Yuanwl
 * @date 2018/10/26 20:47
 */
@Data
public class User {
	@NotBlank(message = "请输入用户名！")
	private String username;

	@NotBlank(message = "请输入密码！")
	@JsonIgnore
	private String password;

	@NotBlank(message = "请输入验证码！")
	@JsonIgnore
	private String imgCode;

}
