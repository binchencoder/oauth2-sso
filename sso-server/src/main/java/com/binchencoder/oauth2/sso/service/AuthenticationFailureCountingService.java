package com.binchencoder.oauth2.sso.service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 登录异常计数器
 */
public interface AuthenticationFailureCountingService {

	/**
	 * 增加异常计数
	 */
	public void increaseAuthenticationFailure(HttpServletRequest request,
		HttpServletResponse response);

	/**
	 * 重置异常计数
	 */
	public void resetAuthenticationFailure(HttpServletRequest request, HttpServletResponse response);

	/**
	 * 获取异常计算
	 */
	public int getAuthenticationFailure(HttpServletRequest request, HttpServletResponse response);

	/**
	 * 是否需要验证图形验证码
	 */
	public boolean isNeedCheckIdentifyCode(HttpServletRequest request, HttpServletResponse response);

}
