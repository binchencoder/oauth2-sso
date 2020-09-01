package com.binchencoder.oauth2.sso.exception;

import org.springframework.security.core.AuthenticationException;

public class NotRequiredUserAuthenticationException extends AuthenticationException {

  private static final long serialVersionUID = 8182454920799892107L;

  public NotRequiredUserAuthenticationException(String msg, Throwable t) {
    super(msg, t);
  }

  public NotRequiredUserAuthenticationException(String msg) {
    super(msg);
  }
}
