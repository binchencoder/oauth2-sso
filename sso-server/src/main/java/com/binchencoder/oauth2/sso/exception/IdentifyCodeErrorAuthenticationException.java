package com.binchencoder.oauth2.sso.exception;

import org.springframework.security.core.AuthenticationException;


public class IdentifyCodeErrorAuthenticationException extends AuthenticationException {

	private static final long serialVersionUID = 6318152898780213075L;

	public IdentifyCodeErrorAuthenticationException(String msg, Throwable t) {
		super(msg, t);
	}

	public IdentifyCodeErrorAuthenticationException(String msg) {
		super(msg);
	}
}
