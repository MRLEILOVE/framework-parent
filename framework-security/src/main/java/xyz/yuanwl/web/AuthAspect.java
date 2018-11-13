package xyz.yuanwl.web;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import xyz.yuanwl.annotation.DoNotCheckLogin;
import xyz.yuanwl.config.AuthProperties;
import xyz.yuanwl.exception.AuthException;
import xyz.yuanwl.vo.User;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.lang.reflect.Method;

/**
 * 通用简单登录验证切面
 *
 * @author Yuanwl
 * @version 1.0.0
 * @date 16/5/17 上午10:42.
 */
@Aspect
@Order(1) //标识切面的优先级，值越小，优先级越高
@Component
@Slf4j
public class AuthAspect {

	@Pointcut("execution(public * *..controller..*.*(..))")
	public void pointCut() {
	}

	@Around("pointCut()")
	public Object doAround(ProceedingJoinPoint pjp) throws Throwable {
		log.info("AuthAspect.doAround 拦截处理请求开始...");

		Object ret = null;

		ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		HttpServletRequest request = attributes.getRequest();
		Signature signature = pjp.getSignature();

		// 判断被拦截controller方法上面或其所属 Controller 类上面是否有 @DoNotCheckLogin 注解，如果都没有就要检查登录状态
		MethodSignature methodSignature = (MethodSignature) signature;
		Method targetMethod = methodSignature.getMethod();
		if (!signature.getDeclaringType().isAnnotationPresent(DoNotCheckLogin.class) && !targetMethod.isAnnotationPresent(DoNotCheckLogin.class)) {
			HttpSession session = request.getSession();
			User user = (User) session.getAttribute(AuthProperties.KEY_USER);
			if (user == null) {
				/*
				 * 注意这个自定义异常应该继承RuntimeException或其子类，否则可能最终抛出的异常会包装成UndeclaredThrowableException
				 * 而无法正常被@ControllerAdvice处理。原因：https://www.jianshu.com/p/7edab536e4b9，https://segmentfault.com/a/1190000012262244
				 */
				throw new AuthException("请先登录！");
			}
		}

		ret = pjp.proceed();
		log.info("AuthAspect.doAround 拦截处理请求结束...");
		return ret;
	}

}

