package com.binchencoder.oauth2.sso.filter;

import static org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI;

import com.binchencoder.oauth2.sso.authentication.JUidCidTokenAuthenticationToken;
import com.binchencoder.oauth2.sso.matcher.JUidCidTokenRequestMatcher;
import com.binchencoder.oauth2.sso.service.JWebAuthenticationDetailsSource;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * 提供基于 Token 签名 授权支持 / 跨IDC Token 一键登录处理
 *
 * 检测同时包含: uid、cid、token -> {@code JTokenAuthenticationToken}<br>
 *
 * 权限验证支持： {@code JTokenUserDetailsAuthenticationProvider}
 *
 * 凭证存放方式：
 *
 * <pre>
 * 		 path?redirect_uri=....uid={uid}&cid={cid}&token={token}
 * 		 path?uid={uid}&cid={cid}&token={token}
 * </pre>
 */
public class JUidCidTokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	/**
	 * Creates an instance which will authenticate against the supplied {@code AuthenticationManager}
	 * and use the supplied {@code AuthenticationEntryPoint} to handle authentication failures.
	 */
	public JUidCidTokenAuthenticationFilter() {
		super(new JUidCidTokenRequestMatcher(DEFAULT_AUTHORIZATION_ENDPOINT_URI,
			RequestMethod.GET.toString()));

		super.setAuthenticationDetailsSource(new JWebAuthenticationDetailsSource());
		super.setContinueChainBeforeSuccessfulAuthentication(true);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
		HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
		JUidCidTokenAuthenticationToken token = (JUidCidTokenAuthenticationToken) request
			.getAttribute(JUidCidTokenAuthenticationToken.JToken_Attribute);
		Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
		if (existingAuth != null && existingAuth.isAuthenticated()
			&& !(existingAuth instanceof AnonymousAuthenticationToken)) {
			if (existingAuth.getPrincipal() instanceof UserDetails) {
				UserDetails userDetails = (UserDetails) existingAuth.getPrincipal();
				if (token.getUid().equals(userDetails.getUsername())) {
					return existingAuth;
				}
			}
		}
		token.setDetails(authenticationDetailsSource.buildDetails(request));
		existingAuth = getAuthenticationManager().authenticate(token);
		SecurityContextHolder.getContext().setAuthentication(existingAuth);
		return existingAuth;
	}

	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
		FilterChain chain, Authentication authResult) throws IOException, ServletException {
		((AbstractAuthenticationToken) authResult)
			.setDetails(authenticationDetailsSource.buildDetails(request));
		if (logger.isDebugEnabled()) {
			logger.debug(
				"Authentication success. Updating SecurityContextHolder to contain: " + authResult);
		}
		SecurityContextHolder.getContext().setAuthentication(authResult);
		// Fire event
		if (this.eventPublisher != null) {
			eventPublisher
				.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
		}
		// 登录成功会进行默认重定向 OAuth2
		// super.successfulAuthentication(request, response, chain, authResult);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request,
		HttpServletResponse response, AuthenticationException failed)
		throws IOException, ServletException {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		super.unsuccessfulAuthentication(request, response, failed);
		SecurityContextHolder.getContext().setAuthentication(auth);
	}
}
