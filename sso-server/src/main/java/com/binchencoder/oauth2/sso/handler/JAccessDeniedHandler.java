package com.binchencoder.oauth2.sso.handler;

import static org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI;

import com.binchencoder.oauth2.sso.exception.AnotherUserLoginedAccessDeniedException;
import com.binchencoder.oauth2.sso.exception.NotRequiredUserAccessDeniedException;
import com.binchencoder.oauth2.sso.matcher.JUidCidTokenRequestMatcher;
import com.binchencoder.oauth2.sso.route.Routes;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMethod;

// handle 403 page
@Component
public class JAccessDeniedHandler implements AccessDeniedHandler {

	private static final Logger LOGGER = LoggerFactory.getLogger(JAccessDeniedHandler.class);

	private static final RequestMatcher REQUEST_MATCHER = new JUidCidTokenRequestMatcher(
		DEFAULT_AUTHORIZATION_ENDPOINT_URI, RequestMethod.GET.toString());

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
		AccessDeniedException accessDeniedException) throws IOException, ServletException {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth != null) {
			LOGGER.info("User '" + auth.getName() + "' attempted to access the protected URL: "
				+ request.getRequestURI());
		}

		if (response.isCommitted()) {
			return;
		}
		// Put exception into request scope (perhaps of use to a view)
		request.setAttribute(WebAttributes.ACCESS_DENIED_403, accessDeniedException);
		// 一键登录用户与当前用户不匹配处理
		if (accessDeniedException instanceof AnotherUserLoginedAccessDeniedException) {
			// forward to error page.
			request.getRequestDispatcher(REQUEST_MATCHER.matches(request) ?
				Routes.OAUTH_DENIED_UNMATCHUSER_HTML : Routes.OAUTH_DENIED_UNMATCHUSER)
				.forward(request, response);
		} else if (accessDeniedException instanceof NotRequiredUserAccessDeniedException) {
			request.getRequestDispatcher(Routes.OAUTH_DENIED_NOTREQUIREDUSER_HTML)
				.forward(request, response);
		} else {
			// Set the 403 status code.
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
		}
	}
}
