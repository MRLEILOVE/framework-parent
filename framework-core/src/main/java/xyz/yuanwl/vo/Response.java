package xyz.yuanwl.vo;

import java.util.HashMap;

/**
 * <p>
 * 响应对象。包含响应编码、信息和数据，在 Controller 处理完请求后将此对象转换成 json 返回给前台。注意：
 * <ul>
 * <li>处理成功一般返回响应编码、信息和数据，失败只返回响应编码和信息。具体返回什么需看接口文档。</li>
 * <li>处理成功结果码一般是200，失败码具体看出了什么错，对照 HTTP 响应码填。</li>
 * <li>默认处理方法慎用，前台最想要拿到的还是具体的结果码和信息。</li>
 * </ul>
 * @author Yuanwl
 * @date 2018/11/6 10:53
 */
public class Response extends HashMap<String, Object> {

	private static final long serialVersionUID = -5014913608403388248L;

	/** 响应编码键 */
	public static final String KEY_CODE = "code";
	/** 响应信息键 */
	public static final String KEY_MSG = "msg";
	/** 响应数据键 */
	public static final String KEY_DATA = "data";

	/** 默认成功响应码 */
	public static final int SUCC_CODE_DEAFAULT = 200;
	/** 默认成功响应信息 */
	public static final String SUCC_MSG_DEAFAULT = "请求/处理成功！";

	/** 默认错误响应码 */
	public static final int ERR_CODE_DEAFAULT = 500;
	/** 默认错误响应信息 */
	public static final String ERR_MSG_DEAFAULT = "请求/处理错误！";
	/** 用户未验证（令牌无效、失效或用户名、密码错误）错误响应码 */
	public static final int ERR_CODE_NOT_AUTHENTICATED = 401;
	/** 用户未授权（没有权限）访问错误响应码 */
	public static final int ERR_CODE_NOT_AUTHORISED = 403;
	/** 资源未找到错误响应码 */
	public static final int ERR_CODE_NOT_FOUND = 404;

	public Response(){}

	public Response(int code, String msg, Object data){
		this.put(KEY_CODE, code);
		this.put(KEY_MSG, msg);
		this.put(KEY_DATA, data);
	}


	/**
	 * 响应-返回成功或失败的编码、信息和数据
	 * @param code 编码
	 * @param msg 响应信息
	 * @param data 响应数据
	 * @return {code: code, msg: msg, data: data}
	 * @author Yuanwl
	 * @date 2018-11-06 14:01:35
	 * @version v1.0.0
	 */
	public static Response response(int code, String msg, Object data){
		return new Response(code, msg, data);
	}


	/**
	 * 成功响应-默认
	 * @return {code: 200, msg: "请求/处理成功！", data: null}
	 * @author Yuanwl
	 * @date 2018-11-06 11:17:14
	 * @version v1.0.0
	 */
	public static Response success(){
		return new Response(SUCC_CODE_DEAFAULT, SUCC_MSG_DEAFAULT, null);
	}

	/**
	 * 成功响应-返回成功数据
	 * @param data 响应数据
	 * @return {code: 200, msg: "请求/处理成功！", data: data}
	 * @author Yuanwl
	 * @date 2018-11-06 11:18:43
	 * @version v1.0.0
	 */
	public static Response success(Object data){
		return new Response(SUCC_CODE_DEAFAULT, SUCC_MSG_DEAFAULT, data);
	}

	/**
	 * 成功响应-返回成功信息和数据
	 * @param msg 响应信息
	 * @param data 响应数据
	 * @return {code: 200, msg: msg, data: data}
	 * @author Yuanwl
	 * @date 2018-11-06 11:21:18
	 * @version v1.0.0
	 */
	public static Response success(String msg, Object data){
		return new Response(SUCC_CODE_DEAFAULT, msg, data);
	}



	/**
	 * 错误响应-默认
	 * @return {code: 500, msg: "请求/处理失败！", data: null}
	 * @author Yuanwl
	 * @date 2018-11-06 11:24:12
	 * @version v1.0.0
	 */
	public static Response error(){
		return new Response(ERR_CODE_DEAFAULT, ERR_MSG_DEAFAULT, null);
	}

	/**
	 * 错误响应-返回错误编码和信息
	 * @param code 编码
	 * @param msg 信息
	 * @return {code: code, msg: msg, data: null}
	 * @author Yuanwl
	 * @date 2018-11-06 11:26:28
	 * @version v1.0.0
	 */
	public static Response error(int code, String msg){
		return new Response(code, msg, null);
	}

	/**
	 * 错误响应-用户未验证（令牌无效、失效或用户名、密码错误）
	 * @param msg 信息
	 * @return Response
	 * @author Yuanwl
	 * @date 2018-11-06 14:46:43
	 * @version v1.0.0
	 */
	public static Response errNotAuthenticated(String msg){
		return new Response(ERR_CODE_NOT_AUTHENTICATED, msg, null);
	}

	/**
	 * 错误响应-用户未授权
	 * @param msg 信息
	 * @return Response
	 * @author Yuanwl
	 * @date 2018-11-06 14:46:43
	 * @version v1.0.0
	 */
	public static Response errNotAuthorised(String msg){
		return new Response(ERR_CODE_NOT_AUTHORISED, msg, null);
	}

	/**
	 * 错误响应-资源未找到
	 * @param msg 信息
	 * @return Response
	 * @author Yuanwl
	 * @date 2018-11-06 14:46:43
	 * @version v1.0.0
	 */
	public static Response errNotFound(String msg){
		return new Response(ERR_CODE_NOT_FOUND, msg, null);
	}

}
