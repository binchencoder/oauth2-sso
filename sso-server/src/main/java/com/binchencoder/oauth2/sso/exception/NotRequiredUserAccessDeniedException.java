package com.binchencoder.oauth2.sso.exception;

import org.springframework.security.access.AccessDeniedException;

public class NotRequiredUserAccessDeniedException extends AccessDeniedException {

  private static final long serialVersionUID = 3482718524586700999L;

  public NotRequiredUserAccessDeniedException(String msg, Throwable t) {
    super(msg, t);
  }

  public NotRequiredUserAccessDeniedException(String msg) {
    super(msg);
  }
}
