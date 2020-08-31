package com.binchencoder.oauth2.sso.exception;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;

public class AnotherUserLoginedAccessDeniedException extends AccessDeniedException {

	private static final long serialVersionUID = 1L;

	private Authentication existingAuth;
	private Authentication auth;

	public AnotherUserLoginedAccessDeniedException(String msg, Authentication existingAuth,
		Authentication auth) {
		super(msg);
		this.existingAuth = existingAuth;
		this.auth = auth;
	}

	public Authentication getAuth() {
		return auth;
	}

	public void setAuth(Authentication auth) {
		this.auth = auth;
	}

	public Authentication getExistingAuth() {
		return existingAuth;
	}

	public void setExistingAuth(Authentication existingAuth) {
		this.existingAuth = existingAuth;
	}

}
