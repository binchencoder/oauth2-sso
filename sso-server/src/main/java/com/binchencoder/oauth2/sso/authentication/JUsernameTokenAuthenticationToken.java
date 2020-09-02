package com.binchencoder.oauth2.sso.authentication;

import java.util.Collection;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class JUsernameTokenAuthenticationToken extends UsernamePasswordAuthenticationToken {

  public JUsernameTokenAuthenticationToken(Object principal, Object credentials,
    Collection<? extends GrantedAuthority> authorities) {
    super(principal, credentials, authorities);
  }

  public JUsernameTokenAuthenticationToken(Object principal, Object credentials) {
    super(principal, credentials);
  }
}
