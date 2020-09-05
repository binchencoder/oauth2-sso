package com.binchencoder.oauth2.sso.service;

import com.binchencoder.oauth2.sso.route.Routes;
import java.util.Collections;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

public class AccessTokenRepresentSecurityContextRepository implements SecurityContextRepository {

  private static final String SESSIONID = "TSESSIONID";

//  @Autowired
//  private AuthnService authnService;

  @Override
  public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
    SecurityContext context = SecurityContextHolder.createEmptyContext();

    String accessToken = this.getAccessToken(requestResponseHolder.getRequest());
    if (StringUtils.isBlank(accessToken)) {
      return context;
    }

    try {
      // TODO(binchencoder):
      UserDetails ud = User.withUsername("user1")
          .password("password")
          .roles("USER")
          .build();
      Authentication auth = new UsernamePasswordAuthenticationToken(ud, accessToken,
          Collections.emptySet());

      context.setAuthentication(auth);
      return context;
    } catch (Exception e) {
      // TODO(binchencoder): 对于Auth 服务出问题的情况，考虑给用户一个提示，此处直接throw页面500.
      return context;
    }
  }

  @Override
  public void saveContext(SecurityContext context, HttpServletRequest request,
      HttpServletResponse response) {
    // Do nothing, saved by SessionStrategies in SecurityConfiguration.configure.
  }

  @Override
  public boolean containsContext(HttpServletRequest request) {
    String accessToken = this.getAccessToken(request);
    return StringUtils.isNotBlank(accessToken);
  }

  /**
   * 获取 AccessToken.
   */
  private String getAccessToken(HttpServletRequest request) {
    return this.getOrNewAccessTokenCookie(request).getValue();
  }

  /**
   * 从HttpServletRequest获取或新建AccessToken对应的Cookie.
   */
  public static Cookie getOrNewAccessTokenCookie(HttpServletRequest request) {
    Cookie cookie = null;

    Cookie[] cookies = request.getCookies();
    if (cookies != null && cookies.length > 0) {
      for (Cookie c : cookies) {
        if (SESSIONID.equals(c.getName())) {
          cookie = c;
        }
      }
    }

    if (cookie == null) {
      cookie = new Cookie(SESSIONID, "");
    }

    cookie.setHttpOnly(true);
//    cookie.setSecure(true);
    cookie.setPath(Routes.DEFAULT);

    return cookie;
  }
}
