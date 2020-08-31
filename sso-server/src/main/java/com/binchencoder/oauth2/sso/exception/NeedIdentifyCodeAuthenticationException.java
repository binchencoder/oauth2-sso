package com.binchencoder.oauth2.sso.exception;

import org.springframework.security.core.AuthenticationException;


public class NeedIdentifyCodeAuthenticationException extends AuthenticationException {

	private static final long serialVersionUID = 6318152898780213075L;

	public NeedIdentifyCodeAuthenticationException(String msg, Throwable t) {
		super(msg, t);
	}

	public NeedIdentifyCodeAuthenticationException(String msg) {
		super(msg);
	}
}
