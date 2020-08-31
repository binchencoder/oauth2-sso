package com.binchencoder.oauth2.sso.exception;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class JTokenAuthenticationException extends AuthenticationException {

	private Authentication authentication;

	public JTokenAuthenticationException(String msg, Authentication authentication) {
		super(msg);
		this.authentication = authentication;
	}

	public JTokenAuthenticationException(String msg, Authentication authentication, Throwable t) {
		super(msg, t);
		this.authentication = authentication;
	}

	public Authentication getAuthentication() {
		return authentication;
	}

	public void setAuthentication(Authentication authentication) {
		this.authentication = authentication;
	}

}
