package com.binchencoder.oauth2.account.service;

import com.binchencoder.oauth2.sso.service.JUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class AuthnService {

	private static final Logger LOGGER = LoggerFactory.getLogger(AuthnService.class);

	@Autowired
	public AuthnService() {
	}

	/**
	 * GrantOauthToken requests new access_token and refresh_token for third party applications.
	 *
	 * Reference: https://downloadus4.teamviewer.com/integrate/TeamViewer_API_Documentation.pdf pp 18
	 *
	 * Error code: ErrorCode_OAUTH_INVALID_CLIENT: 客户端认证失败<br>
	 * ErrorCode_OAUTH_INVALID_REQUEST: 无效请求<br>
	 * ErrorCode_OAUTH_UNSUPPORTED_GRANT_TYPE: 不支持的许可类型<br>
	 * ErrorCode_OAUTH_INVALID_GRANT: 无效许可<br>
	 */
//	public GrantOauthTokenResponse grantOauthToken(GrantOauthTokenRequest req) {
//		long start = System.currentTimeMillis();
//		try {
//			GrantOauthTokenResponse resp = this.authnServerClient
//				.withDeadlineAfter(this.timeoutLongInSeconds, TimeUnit.SECONDS).grantOauthToken(req);
//
//			Metrics.CALL_GRPC_METHOD_ERROR_CODE.labels(new String[]{"grantOauthToken", "OK"})
//				.observe((System.currentTimeMillis() - start) / 1000.0);
//
//			return resp;
//		} catch (StatusRuntimeException e) {
//			Frontend.ErrorCode errorCode = GrpcErrorUtils.getGrpcErrorCode(e);
//			Metrics.CALL_GRPC_METHOD_ERROR_CODE
//				.labels(new String[]{"grantOauthToken", errorCode.toString()})
//				.observe((System.currentTimeMillis() - start) / 1000.0);
//
//			switch (errorCode) {
//				case NOT_FOUND:
//					throw new InvalidGrantException("oauth_invalid_code");
//				case OAUTH_INVALID_CLIENT:
//					throw new InvalidClientException("oauth_invalid_client");
//				case OAUTH_INVALID_REQUEST:
//					throw new InvalidGrantException("oauth_invalid_request");
//				case OAUTH_UNSUPPORTED_GRANT_TYPE:
//					throw new InvalidGrantException("oauth_unsupported_grant_type");
//				case OAUTH_INVALID_GRANT:
//					throw new InvalidGrantException("oauth_invalid_grant");
//				default:
//					LOGGER.error("Failed to call AuthN.grantOauthToken", e);
//					throw new ServiceExceptionAuthenticationException("AuthnService grantOauthToken error",
//						e);
//			}
//		} catch (Exception e) {
//			LOGGER.error("Failed to call AuthN.grantOauthToken", e);
//
//			Metrics.CALL_GRPC_METHOD_ERROR_CODE
//				.labels(new String[]{"grantOauthToken", e.getClass().getName()})
//				.observe((System.currentTimeMillis() - start) / 1000.0);
//
//			throw new ServiceExceptionAuthenticationException("AuthnService grantOauthToken error", e);
//		}
//	}

	/**
	 * VerifyTokenRequest verify the access_token still valid.
	 */
	public String verifyToken(String accessToken) {
		try {
			return "user1";
		} catch (Exception e) {
			LOGGER.error("AccountService verifyToken error", e);

			throw new BadCredentialsException("AuthnService verifyToken error", e);
		}
	}

	/**
	 * RevokeToken revokes an access token that was created using oauth.
	 *
	 * The access token has to be included in the header Authorization field.
	 * After revoking it, it and its attached refresh token cannot be used any longer.
	 */
//	public void revokeToken(String accessToken) {
//		RevokeTokenRequest req = RevokeTokenRequest.newBuilder()
//			.setTokenType("bearer")
//			.setAccessToken(accessToken).build();
//
//		long start = System.currentTimeMillis();
//		try {
//			this.authnServerClient.withDeadlineAfter(this.timeoutLongInSeconds, TimeUnit.SECONDS)
//				.revokeToken(req);
//
//			Metrics.CALL_GRPC_METHOD_ERROR_CODE.labels(new String[]{"revokeToken", "OK"})
//				.observe((System.currentTimeMillis() - start) / 1000.0);
//		} catch (StatusRuntimeException e) {
//			LOGGER.error("AuthnService revokeToken", e);
//
//			Frontend.ErrorCode errorCode = GrpcErrorUtils.getGrpcErrorCode(e);
//			Metrics.CALL_GRPC_METHOD_ERROR_CODE
//				.labels(new String[]{"revokeToken", errorCode.toString()})
//				.observe((System.currentTimeMillis() - start) / 1000.0);
//		} catch (Exception e) {
//			LOGGER.error("AuthnService revokeToken", e);
//
//			Metrics.CALL_GRPC_METHOD_ERROR_CODE
//				.labels(new String[]{"revokeToken", e.getClass().getName()})
//				.observe((System.currentTimeMillis() - start) / 1000.0);
//		}
//	}

	/**
	 * get org.springframework.security.core.userdetails
	 */
	public UserDetails getUserDetails(String userName) {
		if (userName.equals("user1")) {
			JUserDetails details = new JUserDetails(179, 10, "", "user1");

			return details;
		}

		return null;
	}
}
