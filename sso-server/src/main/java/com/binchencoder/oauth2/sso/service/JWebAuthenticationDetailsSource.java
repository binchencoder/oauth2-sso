package com.binchencoder.oauth2.sso.service;

import javax.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;

public class JWebAuthenticationDetailsSource
	implements AuthenticationDetailsSource<HttpServletRequest, JWebAuthenticationDetails> {

	@Override
	public JWebAuthenticationDetails buildDetails(HttpServletRequest context) {
		return new JWebAuthenticationDetails(context);
	}

}
