/*
 * Copyright 2012-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.binchencoder.oauth2.sso.web;

import com.binchencoder.oauth2.sso.exception.AnotherUserLoginedAccessDeniedException;
import com.binchencoder.oauth2.sso.exception.IdentifyCodeErrorAuthenticationException;
import com.binchencoder.oauth2.sso.exception.JTokenAuthenticationException;
import com.binchencoder.oauth2.sso.exception.NeedIdentifyCodeAuthenticationException;
import com.binchencoder.oauth2.sso.exception.NotRequiredUserAccessDeniedException;
import com.binchencoder.oauth2.sso.exception.NotRequiredUserAuthenticationException;
import com.binchencoder.oauth2.sso.exception.ServiceExceptionAuthenticationException;
import com.binchencoder.oauth2.sso.route.Routes;
import com.binchencoder.oauth2.sso.service.AuthenticationFailureCountingService;
import com.binchencoder.oauth2.sso.service.JUserDetails;
import java.awt.Color;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author binchencoder
 */
@Controller
public class AuthorizationController {

	private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationController.class);

	private static final Pattern mobilePattern = Pattern.compile("\\d+");
	private static final String ALIAS = "alias";
	private static final String ID = "id";
	private static final Map<Class<? extends Exception>, String> EXCEPTION_MAP = new HashMap<>();

	static {
		// 初始化登陆异常与异常code的对应关系
		EXCEPTION_MAP.put(JTokenAuthenticationException.class, "JTokenError");
		EXCEPTION_MAP.put(UsernameNotFoundException.class, "UsernameNotFound");
		EXCEPTION_MAP.put(BadCredentialsException.class, "BadCredentials");
		EXCEPTION_MAP.put(DisabledException.class, "UserDisable");
//		EXCEPTION_MAP.put(SuspendedException.class, "UserSuspended");
		EXCEPTION_MAP.put(LockedException.class, "CompanyDisable");
		EXCEPTION_MAP.put(NotRequiredUserAuthenticationException.class, "NotRequiredUser");
		EXCEPTION_MAP.put(IdentifyCodeErrorAuthenticationException.class, "IdentifyCodeError");
		EXCEPTION_MAP.put(NeedIdentifyCodeAuthenticationException.class, "NeedIdentifyCode");
		EXCEPTION_MAP.put(ServiceExceptionAuthenticationException.class, "ServiceException");
	}

	@Autowired
	private AuthenticationFailureCountingService authenticationFailureCountingService;

	@Value("${login.success.default.target}")
	private String defaultLoginSuccessTarget;

	/**
	 * 表单登录页: <br/>
	 *
	 * 1. 已经登录用户重定向到默认页
	 *
	 * 2. 未登录用户，展示不同登录页
	 */
	@RequestMapping(value = Routes.DEFAULT, method = RequestMethod.GET)
	public String index(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication, @RequestParam(required = false, defaultValue = "0") long uid,
		Model model) {
		LOGGER.info("Authentication {}", authentication);
		if (authentication != null
			&& (authentication.getPrincipal() instanceof JUserDetails)) { // 已经登录用户
			LOGGER.info("Redirect to {}", defaultLoginSuccessTarget);
			return "redirect:" + defaultLoginSuccessTarget;
		}

		model.addAttribute("showIdentifyCode",
			authenticationFailureCountingService.isNeedCheckIdentifyCode(request, response));
		if (uid != 0) {
			model.addAttribute("uid", uid);
		}

		LOGGER.info("To page {}", Routes.LOGIN_DEFAULT);
		return Routes.LOGIN_DEFAULT;
	}

	@RequestMapping({Routes.OAUTH_LOGIN, Routes.LOGIN, Routes.OAUTH_FAILURE_HTML})
	public String getOAuthLogin(HttpServletRequest request, HttpServletResponse response,
		@RequestParam(required = false) String display,
		@RequestParam(required = false) String clientId,
		@RequestParam(required = false, defaultValue = "0") long uid,
		@RequestParam(required = false) String redirectUri, Model model) {
		if (!"relogin".equals(display) && !"mobile".equals(display) && !"dialog".equals(display)) {
			display = "default";
		}
		model.addAttribute("showIdentifyCode",
			authenticationFailureCountingService.isNeedCheckIdentifyCode(request, response));
		if (uid != 0) {
			model.addAttribute("uid", uid);
		}

		AuthenticationException exception =
			(AuthenticationException) request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
		String errorMsg = getErrorMsg(exception);
		if (errorMsg != null) {
			model.addAttribute("error", errorMsg);
		}

		return Routes.LOGIN_URL + display;
	}

	@RequestMapping(Routes.OAUTH_SUCCESS)
	@ResponseBody
	public Map<String, Boolean> getOAuthSuccess() {
		Map<String, Boolean> ret = Collections.singletonMap("ok", true);
		return ret;
	}

	@RequestMapping(Routes.OAUTH_FAILURE)
	@ResponseBody
	public Map<String, Object> getOAuthFailure(HttpServletRequest request,
		HttpServletResponse response) {
		Map<String, Object> ret = new HashMap<>();
		// 登录名记忆
		String username = request.getParameter("username");
		if (StringUtils.isNotEmpty(username) || mobilePattern.matcher(username).matches()) {
			ret.put("username", username);
		}

		ret.put("showIdentifyCode",
			authenticationFailureCountingService.isNeedCheckIdentifyCode(request, response));

		AuthenticationException exception =
			(AuthenticationException) request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
		String errorMsg = this.getErrorMsg(exception);
		if (errorMsg != null) {
			ret.put("error", errorMsg);
		} else {
			LOGGER.warn("未捕获的授权异常", exception);
			ret.put("error", "UnknownException");
		}
		return ret;
	}

	@RequestMapping(Routes.OAUTH_DENIED_NOTREQUIREDUSER)
	@ResponseBody
	public Map<String, Object> getOAuthDeniedNotRequiredUser(HttpServletRequest request,
		HttpServletResponse response) {
		Map<String, Object> ret = new HashMap<>();
		// 登录名记忆
		String username = request.getParameter("username");
		if (username != null && !username.isEmpty()
			&& (username.contains("@") || mobilePattern.matcher(username).matches())) { // 包含 @
			// 符号的登录名才进行记忆
			ret.put("username", username);
		}

		ret.put("showIdentifyCode",
			authenticationFailureCountingService.isNeedCheckIdentifyCode(request, response));
		NotRequiredUserAccessDeniedException exception = (NotRequiredUserAccessDeniedException)
			request.getAttribute(WebAttributes.ACCESS_DENIED_403);
		ret.put("error", "NotRequiredUser");
		return ret;
	}

	@RequestMapping(Routes.OAUTH_DENIED_UNMATCHUSER)
	@ResponseBody
	public Map<String, Object> getOAuthDeniedUnMatchUser(HttpServletRequest request) {
		Map<String, Object> ret = new HashMap<>();

		AnotherUserLoginedAccessDeniedException ex = (AnotherUserLoginedAccessDeniedException) request
			.getAttribute(WebAttributes.ACCESS_DENIED_403);
		if (ex == null) {
			return ret;
		}

		Map<String, Serializable> pre_user =
			getAliasAndId((UserDetails) ex.getExistingAuth().getPrincipal());
		Map<String, Serializable> current_user =
			getAliasAndId((UserDetails) ex.getAuth().getPrincipal());

		ret.put("currUser", current_user.get(ALIAS));
		ret.put("preUser", pre_user.get(ALIAS));

//    try {
//      ret.put("token",
//          tokenService.allocateToken((Serializable) current_user.get(ALIAS), 2 * 60 * 60));
//    } catch (Exception e) {
//      LOGGER.error("访问Token Service 异常", e);
//    }
		ret.put("error", "UnmatchUser");
		return ret;
	}

	/**
	 * 根据exception获取对应的错误描述
	 */
	protected String getErrorMsg(Exception exception) {
		if (exception == null) {
			return null;
		}
		return EXCEPTION_MAP.get(exception.getClass());
	}

	private Color getRandColor(Random random, int fc, int bc) {
		if (fc > 255) {
			fc = 255;
		}
		if (bc > 255) {
			bc = 255;
		}
		int r = fc + random.nextInt(bc - fc);
		int g = fc + random.nextInt(bc - fc);
		int b = fc + random.nextInt(bc - fc);
		return new Color(r, g, b);
	}

	private Map<String, Serializable> getAliasAndId(UserDetails userDetails) {
		Map<String, Serializable> map = new HashMap<>();
		if (userDetails instanceof JUserDetails) {
			JUserDetails details = (JUserDetails) userDetails;

			long id = details.getUserID();
			String alias = details.getAlias();
			if (StringUtils.isBlank(alias)) {
//        User user = userService.getUserById(id);
//        if (user != null) {
//          Company company = companyService.getCompanyById(user.getCompanyId());
//          if (company != null) {
//            alias = user.getLoginName() + AuthnService.SPLIT + company.getCode();
//          } else {
//            alias = String.valueOf(id);
//          }
			} else {
				alias = String.valueOf(id);
			}

			map.put(ID, id);
			map.put(ALIAS, alias);

			return map;
		}

		return map;
	}
}
