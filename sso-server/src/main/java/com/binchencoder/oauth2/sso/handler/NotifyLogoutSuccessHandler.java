package com.binchencoder.oauth2.sso.handler;

import com.binchencoder.oauth2.account.service.AuthnService;
import com.binchencoder.oauth2.sso.resover.LogoutNotifyAddressResover;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationTargetUrlRequestHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.Assert;

/**
 * 支持退出登录后回调不同 IDC 退出服务功能. 回调方式: jsonp
 */
public class NotifyLogoutSuccessHandler extends AbstractAuthenticationTargetUrlRequestHandler
    implements LogoutSuccessHandler, InitializingBean {

  private final Logger LOGGER = LoggerFactory.getLogger(NotifyLogoutSuccessHandler.class);

  private final ObjectMapper mapper = new ObjectMapper();
  // JSONP 回调方式 XSS 攻击过滤
  private final Pattern pattern = Pattern.compile("^[0-9a-zA-Z_.]+$");

  private LogoutNotifyAddressResover logoutNotifyAddressResover;

	private AuthnService authnService;

  public NotifyLogoutSuccessHandler() {
  }

  public NotifyLogoutSuccessHandler(LogoutNotifyAddressResover logoutNotifyAddressResover) {
    this.logoutNotifyAddressResover = logoutNotifyAddressResover;
  }

  public void setLogoutNotifyAddressResover(LogoutNotifyAddressResover logoutNotifyAddressResover) {
    this.logoutNotifyAddressResover = logoutNotifyAddressResover;
  }

	public void setAuthnService(AuthnService authnService) {
		this.authnService = authnService;
	}

  @Override
  public void afterPropertiesSet() {
    Assert.notNull(this.logoutNotifyAddressResover, "An LogoutNotifyAddressResover is required");
  }

  @Override
  public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    String callback = request.getParameter("callback");
    if (callback != null && !callback.isEmpty()) {
      if (!pattern.matcher(callback).matches()) {
        LOGGER.warn("JSONP XSS attack, callback：{}", callback);
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "非法Callbcak方法名");
        return;
      }
      List<String> notifies = logoutNotifyAddressResover.resolve(request, authentication);
      notifies = notifies == null ? new ArrayList<>() : notifies;

      Cookie cookie = new Cookie("apps", "");
      cookie.setHttpOnly(true);
      cookie.setPath("/");
      cookie.setMaxAge(0); // 删除已登录应用列表
      response.addCookie(cookie);

//      Cookie tokenCookie = AccessTokenRepresentSecurityContextRepository.getOrNewAccessTokenCookie(request);
//      if (!StringUtils.isBlank(tokenCookie.getValue())) {
//        tokenCookie.setMaxAge(0); // 删除用户会话
//        response.addCookie(tokenCookie);

//        authnService.revokeToken(tokenCookie.getValue());
//      }

      response.setContentType("application/javascript");
      response.getWriter()
          .print(callback + "&&" + callback + "(" + mapper.writeValueAsString(notifies) + ");");
    } else {
      super.handle(request, response, authentication);
    }
  }

}
