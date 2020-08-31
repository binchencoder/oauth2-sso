package com.binchencoder.oauth2.sso.filter;

import com.binchencoder.oauth2.sso.authentication.JUsernameTokenAuthenticationToken;
import com.binchencoder.oauth2.sso.exception.IdentifyCodeErrorAuthenticationException;
import com.binchencoder.oauth2.sso.exception.NeedIdentifyCodeAuthenticationException;
import com.binchencoder.oauth2.sso.service.AuthenticationFailureCountingService;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class JUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	public static final String IDENTIFY_CODE = "identifyCode";
	private static final Logger LOGGER = LoggerFactory
		.getLogger(JUsernamePasswordAuthenticationFilter.class);
	private AuthenticationFailureCountingService authenticationFailureCountingService;

	private String tokenParameter = "token";
	private String identifyParameter = "identify";
	private AuthenticationFailureHandler failureHandler;

	public JUsernamePasswordAuthenticationFilter() {
		super();
	}

	/**
	 * 认证异常计数服务
	 */
	public void setAuthenticationFailureCountingService(
		AuthenticationFailureCountingService authenticationFailureCountingService) {
		this.authenticationFailureCountingService = authenticationFailureCountingService;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
		throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		LOGGER
			.debug("requestURI:{}, contextPath:{}", request.getRequestURI(), request.getContextPath());

//    String saveInfo = request.getParameter("saveinfo");
//    boolean persist =
//        StringUtils.isNotBlank(saveInfo) && !"false".equalsIgnoreCase(saveInfo.trim());
//    JGrpcUsernamePasswordAuthenticationProvider.PersistSession.set(persist);

		try {
			super.doFilter(req, res, chain);
		} finally {
//      JGrpcUsernamePasswordAuthenticationProvider.PersistSession.remove();
		}
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
		HttpServletResponse response) throws AuthenticationException {
		// 1. 用户表单登录，支持登录帐号 + Token
		String username = obtainUsername(request);
		String password = obtainPassword(request);
		String token = obtainToken(request);

		// 检测 password 为空才验证 username + token，防止 url 带有 token 无法表单登录。
		if (StringUtils.isEmpty(password) && StringUtils.isEmpty(token)) {
			if (username == null) {
				username = "";
			}

			JUsernameTokenAuthenticationToken authRequest = new JUsernameTokenAuthenticationToken(
				username, token.trim());
			// Allow subclasses to set the "details" property
			setDetails(request, authRequest);
			return this.getAuthenticationManager().authenticate(authRequest);
		}

		// 2. 用户帐号 + 密码登录
		// 2.1 先验证图形验证码，防止密码试探
		String identify = obtainIdentify(request);
		if (authenticationFailureCountingService
			.isNeedCheckIdentifyCode(request, response)) { // 需要验证码检验
			if (StringUtils.isEmpty(identify)) {
				throw new NeedIdentifyCodeAuthenticationException("Need Identify Code");
			}

//      String key = "SSOIDEN_" + request.getSession().getId();
//      String identifyCode = this.cacheClient.get(key);
//      this.cacheClient.remove0(key); // 获取验证码后需要清除，否则会有重复利用安全风险

			String identifyCode = "";
			if (!identify.trim().equalsIgnoreCase(identifyCode)) {
				throw new IdentifyCodeErrorAuthenticationException("Identify Code Error");
			}
		}

		Authentication authentication = super.attemptAuthentication(request, response);
		return authentication;
	}

	public void setTokenParameter(String tokenParameter) {
		Assert.hasText(tokenParameter, "Token parameter must not be empty or null");
		this.tokenParameter = tokenParameter;
	}

	public void setIdentifyParameter(String identifyParameter) {
		Assert.hasText(tokenParameter, "Identify parameter must not be empty or null");
		this.identifyParameter = identifyParameter;
	}

	protected String obtainToken(HttpServletRequest request) {
		return request.getParameter(tokenParameter);
	}

	protected String obtainIdentify(HttpServletRequest request) {
		return request.getParameter(identifyParameter);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
		FilterChain chain, Authentication authResult) throws IOException, ServletException {
		authenticationFailureCountingService.resetAuthenticationFailure(request, response);
		setDetails(request, (UsernamePasswordAuthenticationToken) authResult);
		super.successfulAuthentication(request, response, chain, authResult);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request,
		HttpServletResponse response, AuthenticationException failed)
		throws IOException, ServletException {
		authenticationFailureCountingService.increaseAuthenticationFailure(request, response);
		failureHandler.onAuthenticationFailure(request, response, failed);
		// 去掉登录失败去掉默认清理上次登录信息功能
		// Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		// super.unsuccessfulAuthentication(request, response, failed);
		// SecurityContextHolder.getContext().setAuthentication(auth);
	}

	public void setAuthenticationFailureHandler(AuthenticationFailureHandler failureHandler) {
		super.setAuthenticationFailureHandler(failureHandler);
		this.failureHandler = failureHandler;
	}
}
