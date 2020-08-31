package com.binchencoder.oauth2.sso.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * 服务问题导致拒绝访问
 *
 * @author houzhj@jingoal.com 2015年6月14日
 */
@SuppressWarnings("serial")
public class ServiceExceptionAuthenticationException extends AuthenticationException {

	public ServiceExceptionAuthenticationException(String msg) {
		super(msg);
	}

	public ServiceExceptionAuthenticationException(String msg, Throwable t) {
		super(msg, t);
	}
}
