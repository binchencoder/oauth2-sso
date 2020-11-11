package com.binchencoder.oauth2.sso.resover;

import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

/**
 * 退出登录回调地址解析器
 */
public interface LogoutNotifyAddressResover {

  List<String> resolve(HttpServletRequest request, Authentication authentication);

}
