package com.binchencoder.oauth2.sso.service;

import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

public class JWebAuthenticationDetails extends WebAuthenticationDetails {

	private static final long serialVersionUID = 3584408499585629410L;

	private String uid;
	private long loginTime; // 登录时间
	private String loginType; // 登录方式

	public JWebAuthenticationDetails(HttpServletRequest request) {
		super(request);
		uid = request.getParameter("uid");
		if (uid != null) {
			uid = uid.trim();
		}
		loginTime = System.currentTimeMillis();
		loginType = request.getParameter("login_type");
	}

	public boolean matchUid(String uid) {
		if (StringUtils.isBlank(uid)) {
			return false;
		}

		if (this.uid == null || this.uid.isEmpty()) {
			return true;
		}

		if (uid.indexOf("@") > 0) {
			uid = uid.substring(0, uid.indexOf("@"));
		}

		return this.uid.equals(uid);
	}

	public boolean matchUid(long uid) {
		if (this.uid == null || this.uid.isEmpty()) {
			return true;
		}
		return this.uid.equals(String.valueOf(uid));
	}

	public long getLoginTime() {
		return loginTime;
	}

	public String getLoginType() {
		return loginType;
	}

	public void setLoginType(String loginType) {
		this.loginType = loginType;
	}

	public String getUid() {
		return uid;
	}
}
