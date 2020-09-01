package com.binchencoder.oauth2.sso.handler;

import com.binchencoder.oauth2.sso.route.Routes;
import com.binchencoder.oauth2.sso.service.JUserDetails;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

public class JForwardAuthenticationSuccessHandler extends
	SavedRequestAwareAuthenticationSuccessHandler {

	private static final Logger LOGGER =
		LoggerFactory.getLogger(JForwardAuthenticationSuccessHandler.class);

	private String targetUrl = Routes.OAUTH_SUCCESS;

	public void setTargetUrl(String targetUrl) {
		this.targetUrl = targetUrl;
	}

//  private KafkaStorageAdapter kafkaStorageAdapter;
//  public void setKafkaStorageAdapter(KafkaStorageAdapter kafkaStorageAdapter) {
//    this.kafkaStorageAdapter = kafkaStorageAdapter;
//  }

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) throws IOException, ServletException {
		RequestDispatcher dispatcher = request.getRequestDispatcher(targetUrl);
		dispatcher.forward(request, response);

		if (authentication.getPrincipal() instanceof JUserDetails) {
			JUserDetails details = (JUserDetails) authentication.getPrincipal();
			try {
				this.sendKafkaMessage(request, details.getUserID(), details.getCompanyID());
			} catch (Exception e) {
				LOGGER.error("Notify uid:" + details.getUserID() + ", cid:" + details.getCompanyID()
					+ " login success to DataCenter Fail.", e);
			}
		}
//
//		super.onAuthenticationSuccess(request, response, authentication);
	}

	private void sendKafkaMessage(HttpServletRequest request, long userId, long companyId) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmssSSSZ");
		String dateStr = sdf.format(new Date());
		String ip = this.getRemoteIpNginx(request);
		String userAgent = request.getHeader(Routes.USER_AGENT);
		userAgent = StringUtils.isNotBlank(userAgent) ? userAgent.trim() : "";

		String messages = dateStr + "|" + companyId + "|" + userId + "|" + ip + "|" + userAgent;
		LOGGER.debug("messages:{}", messages);

//    kafkaStorageAdapter.sendKafkaMessage(Logtopic.MGTLOGIN, messages);
		LOGGER.debug("Login success, send kafka msg: {}", messages);
	}

	private String getRemoteIpNginx(HttpServletRequest request) {
		String ip = request.getHeader("X-Forwarded-For");
		if (ip != null && ip.contains(",")) {
			ip = ip.split(",")[0];
		}
		if (ip == null || ip.length() == 0) {
			ip = request.getHeader("X-Real-IP");
		}
		if (ip == null || ip.length() == 0) {
			ip = request.getRemoteAddr();
		}
		return ip;
	}
}
