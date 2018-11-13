package xyz.yuanwl.web;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;

/**
 * 请求统计切面
 *
 * @author Yuanwl
 * @version 1.0.0
 * @date 16/5/17 上午10:42.
 */
@Aspect
@Order(0) //标识切面的优先级，值越小，优先级越高
@Component
@Slf4j
public class RequestAspect {

	@Pointcut("execution(public * *..controller..*.*(..))")
	public void pointCut() {
	}

	@Around("pointCut()")
	public Object doAround(ProceedingJoinPoint pjp) throws Throwable {
		log.info("================================================================================================================");
		log.info("请求统计开始 ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓");

		Object ret = null;
		long startTime = System.currentTimeMillis();

		// 接收到请求，记录请求内容
		ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		HttpServletRequest request = attributes.getRequest();
		Signature signature = pjp.getSignature();
		// 记录下请求内容
		log.info("接收到来自 {} 的 {} 请求：{} 》 {}.{}({})",
				request.getRemoteAddr(), request.getMethod(), request.getRequestURL().toString(),
				signature.getDeclaringTypeName(),
				signature.getName(), Arrays.toString(pjp.getArgs()));

		try {
			ret = pjp.proceed();
		} catch (Throwable t){
			throw t;
		} finally {
			// 上面可能会抛出异常，为了保证这些信息肯定打印，要放在finally里面
			log.info("返回值：{}，本次请求耗时：{}毫秒", ret == null ? "无" : ret, System.currentTimeMillis() - startTime);
			log.info("请求统计结束 ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑");
			log.info("================================================================================================================");
		}

		return ret;
	}

}

