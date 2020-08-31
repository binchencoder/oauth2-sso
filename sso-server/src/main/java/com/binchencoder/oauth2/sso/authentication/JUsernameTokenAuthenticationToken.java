package com.binchencoder.oauth2.sso.authentication;

import java.util.Collection;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class JUsernameTokenAuthenticationToken extends UsernamePasswordAuthenticationToken {

	private static final long serialVersionUID = -8367501473497762775L;

	public JUsernameTokenAuthenticationToken(Object principal, Object credentials,
		Collection<? extends GrantedAuthority> authorities) {
		super(principal, credentials, authorities);
	}

	public JUsernameTokenAuthenticationToken(Object principal, Object credentials) {
		super(principal, credentials);
	}
}
