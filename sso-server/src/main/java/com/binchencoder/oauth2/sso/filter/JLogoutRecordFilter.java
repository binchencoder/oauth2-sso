package com.binchencoder.oauth2.sso.filter;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

public class JLogoutRecordFilter implements Filter {

	private RequestMatcher requiresAuthenticationRequestMatcher;

	public JLogoutRecordFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
		this.requiresAuthenticationRequestMatcher = requiresAuthenticationRequestMatcher;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
		throws IOException, ServletException {
		if (requiresAuthenticationRequestMatcher.matches((HttpServletRequest) request)) {
			String clientId = request.getParameter("client_id");
			if (clientId != null && !clientId.isEmpty()) {
				clientId = clientId.trim();
				Cookie[] cookies = ((HttpServletRequest) request).getCookies();
				Set<String> clientIds = new HashSet<>();
				if (cookies != null) {
					for (Cookie cookie : cookies) {
						if ("apps".equals(cookie.getName())) {
							String apps = cookie.getValue();
							if (apps != null) {
								String[] arr = apps.split(",");
								if (arr != null) {
									for (String id : arr) {
										if (!id.isEmpty()) {
											clientIds.add(id.trim());
										}
									}
								}
							}
						}
					}
				}

				if (!clientIds.contains(clientId)) {
					clientIds.add(clientId);
					Cookie cookie =
						new Cookie("apps", StringUtils.collectionToCommaDelimitedString(clientIds));
					cookie.setHttpOnly(true);
					cookie.setPath("/");
					((HttpServletResponse) response).addCookie(cookie);
				}
			}
		}
		chain.doFilter(request, response);
	}


	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
	}

	@Override
	public void destroy() {
	}
}
