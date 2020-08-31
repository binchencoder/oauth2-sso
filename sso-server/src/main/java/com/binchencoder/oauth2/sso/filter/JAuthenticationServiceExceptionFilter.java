package com.binchencoder.oauth2.sso.filter;

import com.binchencoder.oauth2.sso.exception.ServiceExceptionAuthenticationException;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.GenericFilterBean;

public class JAuthenticationServiceExceptionFilter extends GenericFilterBean {

	private static final Logger LOGGER =
		LoggerFactory.getLogger(JAuthenticationServiceExceptionFilter.class);

	private AuthenticationEntryPoint authenticationEntryPoint;

	public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
		throws IOException, ServletException {
		try {
			chain.doFilter(request, response);
		} catch (Exception ex) {
			LOGGER.error("认证服务异常", ex);
			authenticationEntryPoint.commence((HttpServletRequest) request,
				(HttpServletResponse) response,
				new ServiceExceptionAuthenticationException("认证服务内部异常", ex));
		}
	}

}
