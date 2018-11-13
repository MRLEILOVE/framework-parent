package xyz.yuanwl.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import xyz.yuanwl.annotation.DoNotCheckLogin;
import xyz.yuanwl.config.AuthProperties;
import xyz.yuanwl.util.coder.RSACoder;
import xyz.yuanwl.util.coder.VerificationCoder;
import xyz.yuanwl.vo.Response;
import xyz.yuanwl.vo.User;

import javax.imageio.ImageIO;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * <p>通用简单安全（登录）控制器
 *
 * @author Yuanwl
 * @date 2018/10/26 20:17
 */
@RestController
@RequestMapping("auth")
@DoNotCheckLogin
public class AuthController {

	@Autowired
	AuthProperties authProperties;

	/**
	 * 登录
	 * @param session 
	 * @param user 
	 * @return xyz.yuanwl.vo.Response
	 * @author Yuanwl
	 * @date 2018-11-13 19:13:26
	 * @version v1.0.0
	 */
	@PostMapping
	public Response login(HttpSession session, User user) throws Exception {
		// 取出session中的验证码判断
		String imgCode = (String) session.getAttribute(AuthProperties.KEY_IMG_CODE);
		if (user.getImgCode().equalsIgnoreCase(imgCode)) {
			session.removeAttribute(AuthProperties.KEY_IMG_CODE);
			String pwd = RSACoder.decryptByPriKey(user.getPassword());
			if (authProperties.getUsername().equals(user.getUsername())
					&& authProperties.getPassword().equals(pwd)) {
				session.setAttribute(AuthProperties.KEY_USER, user);
				return Response.success("登录成功！", user);
			} else return Response.errNotAuthenticated("用户名或密码错误，登录失败！");
		} else {
			return Response.errNotAuthenticated("验证码错误，登录失败！");
		}
	}

	/**
	 * 获取登录用户信息
	 * @param session 
	 * @return xyz.yuanwl.vo.Response
	 * @author Yuanwl
	 * @date 2018-11-13 19:13:17
	 * @version v1.0.0
	 */
	@GetMapping
	public Response getUser(HttpSession session) {
		User user = (User) session.getAttribute(AuthProperties.KEY_USER);
		if (user == null) return Response.errNotFound("找不到登录用户信息，可能登录已失效！");
		else return Response.success(user);
	}

	/**
	 * 退出登录
	 * @param session 
	 * @return xyz.yuanwl.vo.Response
	 * @author Yuanwl
	 * @date 2018-11-13 19:13:10
	 * @version v1.0.0
	 */
	@DeleteMapping
	public Response logout(HttpSession session) {
		session.removeAttribute(AuthProperties.KEY_USER);
		return Response.success();
	}

	/**
	 * 获取图片验证码
	 * @param session 
	 * @param response 
	 * @param imgCodeWidth 
	 * @param imgCodeHeight 
	 * @author Yuanwl
	 * @date 2018-11-13 19:12:56
	 * @version v1.0.0
	 */
	@GetMapping("imgCode")
	public void imgCode(HttpSession session, HttpServletResponse response, Integer imgCodeWidth, Integer imgCodeHeight) throws IOException {
		if (imgCodeWidth != null && imgCodeHeight != null) {
			// 先生成验证码字符串保存到session
			String code = VerificationCoder.generateTextCode(authProperties.getImgCodeType(), authProperties.getImgCodeLen(), null);
			session.setAttribute(AuthProperties.KEY_IMG_CODE, code);

			// 设置响应头
			response.setHeader("Pragma", "No-cache");
			response.setHeader("Cache-Control", "no-cache");
			response.setDateHeader("Expires", 0);
			response.setContentType("image/jpeg");

			// 返回图片验证码到前端
			ImageIO.write(VerificationCoder.generateImageCode(code, imgCodeWidth, imgCodeHeight), "JPEG", response.getOutputStream());
		}
	}
}
