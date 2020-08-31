package com.binchencoder.oauth2.sso.matcher;

import com.binchencoder.oauth2.sso.authentication.JUidCidTokenAuthenticationToken;
import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

public class JUidCidTokenRequestMatcher implements RequestMatcher {

	private static final Logger logger = LoggerFactory.getLogger(JUidCidTokenRequestMatcher.class);

	private RequestMatcher pathMatcher;

	public JUidCidTokenRequestMatcher(String pattern) {
		pathMatcher = new AntPathRequestMatcher(pattern);
	}

	/**
	 * Creates a matcher with the supplied pattern and HTTP method in a case insensitive manner.
	 *
	 * @param pattern the ant pattern to use for matching
	 * @param httpMethod the HTTP method. The {@code matches} method will return false if the incoming
	 * request doesn't have the same method.
	 */
	public JUidCidTokenRequestMatcher(String pattern, String httpMethod) {
		pathMatcher = new AntPathRequestMatcher(pattern, httpMethod);
	}

	/**
	 * Creates a matcher with the supplied pattern which will match the specified Http method
	 *
	 * @param pattern the ant pattern to use for matching
	 * @param httpMethod the HTTP method. The {@code matches} method will return false if the incoming
	 * request doesn't doesn't have the same method.
	 * @param caseSensitive true if the matcher should consider case, else false
	 */
	public JUidCidTokenRequestMatcher(String pattern, String httpMethod, boolean caseSensitive) {
		pathMatcher = new AntPathRequestMatcher(pattern, httpMethod, caseSensitive);
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		if (!request.getMethod().toUpperCase().equals("GET")) {
			return false;
		}

		String contentType = request.getContentType();
		if (contentType != null && contentType.toLowerCase()
			.contains("application/x-www-form-urlencoded")) {
			return false;
		}

		if (pathMatcher.matches(request)) {
			String uid = request.getParameter("uid");
			String cid = request.getParameter("cid");
			String token = request.getParameter("token");
			String alias = request.getParameter("account");
			if (uid == null || uid.trim().isEmpty() || token == null || token.trim().isEmpty()) {
				String redirect_uri = request.getParameter("redirect_uri");
				if (redirect_uri == null || redirect_uri.isEmpty()) {
					return false;
				}
				MultiValueMap<String, String> params = UriComponentsBuilder.fromUriString(redirect_uri)
					.build().getQueryParams();
				uid = params.getFirst("uid");
				cid = params.getFirst("cid");
				token = params.getFirst("token");
				alias = params.getFirst("account");
				if (uid == null || uid.isEmpty() || token == null || token.isEmpty()) {
					return false;
				}
			}
			long pcid = 0; // 转义过后cid
			if (cid != null && !cid.isEmpty()) {
				try {
					pcid = Long.parseLong(cid);
				} catch (NumberFormatException e) {
					// NOTHING
				}
			}

			try {
				request.setAttribute(JUidCidTokenAuthenticationToken.JToken_Attribute,
					new JUidCidTokenAuthenticationToken(uid.trim(), pcid, token, alias));
				return true;
			} catch (NumberFormatException e) {
				logger.debug("一键登录参数错误", e);
			}
		}
		return false;
	}

}
