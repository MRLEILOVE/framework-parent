package xyz.yuanwl.exception;

/**
 * 登录验证异常。
 * <p>
 * 创建人：袁炜林 <br>
 * 创建时间：2017年10月15日 下午10:01:56 <br>
 * <p>
 * 修改人： <br>
 * 修改时间： <br>
 * 修改备注： <br>
 * </p>
 */
public class AuthException extends RuntimeException {

    /** 
	* @Fields serialVersionUID: 
	*/
	private static final long serialVersionUID = 6309987337838292906L;

	public AuthException(String message) {
        super(message);
    }
}
