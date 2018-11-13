package xyz.yuanwl.annotation;

import java.lang.annotation.*;

/**
 * 不检查登录状态注解。
 * <br>1）放在Controller的类上面，表示该类的所有方法都不用经过安全拦截验证；
 * <br>2）放在Controller的方法上面，表示该方法不用经过安全拦截验证。
 * <p>
 * 创建人：袁炜林 <br>
 * 创建时间：2017年10月15日 下午10:02:16 <br>
 * <p>
 * 修改人： <br>
 * 修改时间： <br>
 * 修改备注： <br>
 * </p>
 */
@Documented
@Target({ElementType.TYPE, ElementType.METHOD}) /* 表示该注解能应用于哪些地方，这里应用于类和方法 */
@Retention(RetentionPolicy.RUNTIME) /* 表示该注解存在的时间：SOURCE-该注解最长能存在于java源代码阶段；CLASS-该注解最长能存在于java字节码阶段；
RUNTIME-该注解最长能存在于java运行阶段 */
public @interface DoNotCheckLogin {
}
