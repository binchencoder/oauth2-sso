package com.binchencoder.oauth2.sso.filter;

import com.binchencoder.oauth2.sso.exception.NotRequiredUserAccessDeniedException;
import com.binchencoder.oauth2.sso.service.JUserDetails;
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class JRequiredUserCheckFilter implements Filter {

	private RequestMatcher requiresAuthenticationRequestMatcher;

	public JRequiredUserCheckFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
		this.requiresAuthenticationRequestMatcher = requiresAuthenticationRequestMatcher;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
		throws IOException, ServletException {
		if (requiresAuthenticationRequestMatcher.matches((HttpServletRequest) request)) {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			if (auth != null && auth.getPrincipal() instanceof JUserDetails) {
				String uid = request.getParameter("uid");
				if (uid != null && !uid.isEmpty()) {
					if (!String.valueOf(((JUserDetails) auth.getPrincipal()).getUserID())
						.equals(uid.trim())) {
						throw new NotRequiredUserAccessDeniedException(
							"An logined user not match required user");
					}
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
