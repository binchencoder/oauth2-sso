package com.binchencoder.oauth2.sso.header;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class ConditionXFrameOptionsHeaderWriter implements HeaderWriter {

	private XFrameOptionsHeaderWriter xFrameOptionsHeaderWriter = new XFrameOptionsHeaderWriter();

	private RequestMatcher ignore;
	private RequestMatcher match;

	/**
	 * 忽略 X-Frame-Options 保护
	 */
	public ConditionXFrameOptionsHeaderWriter ignore(RequestMatcher ignore) {
		this.ignore = ignore;
		return this;
	}

	/**
	 * 进行 X-Frame-Options 保护, 默认除 ignore 外全部进行保护
	 */
	public ConditionXFrameOptionsHeaderWriter match(RequestMatcher match) {
		this.match = match;
		return this;
	}

	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		if ((ignore == null || !ignore.matches(request)) && (match == null || match.matches(request))) {
			xFrameOptionsHeaderWriter.writeHeaders(request, response);
		}
	}
}
