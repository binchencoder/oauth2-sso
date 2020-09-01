package com.binchencoder.oauth2.sso.route;

/**
 * 路由相关信息
 */
public class Routes {

	// requestParameter
	public static final String REFERER = "referer";
	public static final String CLIENT_ID = "client_id";
	public static final String USER_AGENT = "User-Agent";
	public static final String HTTP_AUTH_HEADER = "Authorization";
	public static final String[] HTTP_IP_HEADERS = new String[]{"X-Forwarded-For", "Proxy-Client-IP",
		"WL-Proxy-Client-IP"};
	public static final String UID = "uid";
	public static final String TOKEN = "token";

	/**
	 * 默认页
	 */
	public static final String DEFAULT = "/";
	/**
	 * 默认登录地址
	 */
	public static final String LOGIN_DEFAULT = "login/default";

	public static final String OAUTH_DENIED_UNMATCHUSER_HTML = "/oauth/denied/UnmatchUser.html";

	public static final String OAUTH_DENIED_NOTREQUIREDUSER_HTML = "/oauth/denied/NotRequiredUser.html";

	public static final String OAUTH_DENIED_UNMATCHUSER = "/oauth/denied/UnmatchUser";

	public static final String OAUTH_DENIED_NOTREQUIREDUSER = "/oauth/denied/NotRequiredUser";

	public static final String OAUTH_FAILURE_HTML = "/oauth/failure.html";

	public static final String OAUTH_SUCCESS = "/oauth/success";

	public static final String OAUTH_FAILURE = "/oauth/failure";

	// return image/JPEG  begin
	public static final String OIMAGES_AUTHCODE_JPG = "/images/authcode.jpg";
	public static final String IMAGES_CAPTCHA_JPG = "images/captcha.jpg";
	// return image/JPEG end

	// SecurityConfiguration Routes
	public static final String OAUTH_AUTHORIZE = "/oauth2/authorize";

	// Login & Logout
	public static final String LOGIN = "/login";
	public static final String LOGIN_URL = "login/";
	public static final String OAUTH_LOGIN = "/oauth/login";
	public static final String LOGOUT = "/logout";
}
