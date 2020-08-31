package com.binchencoder.oauth2.sso.handler;

import com.binchencoder.oauth2.sso.matcher.JUidCidTokenRequestMatcher;
import com.binchencoder.oauth2.sso.route.Routes;
import java.io.IOException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.bind.annotation.RequestMethod;

public class JAuthenticationEntryPoint
	implements AuthenticationEntryPoint, AuthenticationFailureHandler {

	private static final Logger LOGGER = LoggerFactory.getLogger(JAuthenticationEntryPoint.class);

	// ~ Instance fields
	// ================================================================================================
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	private String loginPage = "/login";
	private RequestMatcher entryPointMatcher;

	private RequestMatcher jtokenRequestMatcher =
		new JUidCidTokenRequestMatcher(Routes.OAUTH_AUTHORIZE, RequestMethod.GET.toString());

	public JAuthenticationEntryPoint(RequestMatcher entryPointMatcher) {
		this.entryPointMatcher = entryPointMatcher;
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
		AuthenticationException exception) throws IOException, ServletException {
		LOGGER.debug("onAuthenticationFailure authenticationException", exception);
		if (!response.isCommitted()) {
			request.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, exception);
			String dispatcherUrl = Routes.OAUTH_FAILURE;
			if (jtokenRequestMatcher.matches(request)) {
				dispatcherUrl = Routes.OAUTH_FAILURE_HTML;
			}
			RequestDispatcher dispatcher = request.getRequestDispatcher(dispatcherUrl);
			dispatcher.forward(request, response);
		}
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
		AuthenticationException authException) throws IOException, ServletException {
		LOGGER.debug("commence authenticationException", authException);

		// 账号停用、冻结、公司停用 等情况。 需要清理当前的 Cookie，防止进入无限循环提示。
//    Cookie cookie = AccessTokenRepresentSecurityContextRepository
//        .getOrNewAccessTokenCookie(request);
//    if (StringUtils.isNotBlank(cookie.getValue())) {
//      cookie.setValue("");
//      cookie.setMaxAge(0);
//      response.addCookie(cookie);
//    }

		if (!response.isCommitted()) {
			if (entryPointMatcher.matches(request)) {
				RequestDispatcher dispatcher = request.getRequestDispatcher(Routes.OAUTH_LOGIN);
				dispatcher.forward(request, response);
			} else {
				redirectStrategy.sendRedirect(request, response, loginPage);
			}
		}
	}
}
