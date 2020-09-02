package com.binchencoder.oauth2.sso.authentication;

import java.util.Collection;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class JUidCidTokenAuthenticationToken extends UsernamePasswordAuthenticationToken {

  public static final String JToken_Attribute = JUidCidTokenAuthenticationToken.class.getName();
  // ~ Instance fields
  // ================================================================================================
  private long cid; // 公司ID
  private String alias; // 登录帐号

  // ~ Constructors
  // ===================================================================================================

  /**
   * This constructor can be safely used by any code that wishes to create a
   * <code>UsernamePasswordAuthenticationToken</code>, as the {@link #isAuthenticated()} will
   * return
   * <code>false</code>.
   */
  public JUidCidTokenAuthenticationToken(String uid, long cid, String token) {
    super(uid, token);
    this.cid = cid;
  }

  public JUidCidTokenAuthenticationToken(String uid, long cid, String token, String alias) {
    this(uid, cid, token);
    this.alias = alias;
  }

  /**
   * This constructor should only be used by <code>AuthenticationManager</code> or
   * <code>AuthenticationProvider</code> implementations that are satisfied with producing a
   * trusted (i.e. {@link #isAuthenticated()} = <code>true</code>) authentication token.
   */
  public JUidCidTokenAuthenticationToken(String uid, long cid, String token,
    Collection<? extends GrantedAuthority> authorities) {
    super(uid, token, authorities);
    this.cid = cid;
  }

  public JUidCidTokenAuthenticationToken(String uid, long cid, String token, String alias,
    Collection<? extends GrantedAuthority> authorities) {
    this(uid, cid, token, authorities);
    this.alias = alias;
  }

  // ~ Methods
  // ========================================================================================================
  public String getUid() {
    return getPrincipal().toString();
  }

  public long getCid() {
    return cid;
  }

  public String getToken() {
    return (String) getCredentials();
  }

  public String getAlias() {
    return alias;
  }
}
