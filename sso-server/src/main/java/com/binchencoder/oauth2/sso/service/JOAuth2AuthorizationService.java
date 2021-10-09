package com.binchencoder.oauth2.sso.service;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.util.Assert;

public class JOAuth2AuthorizationService implements OAuth2AuthorizationService {

	private static final Logger LOGGER = LoggerFactory.getLogger(JOAuth2AuthorizationService.class);

	// TODO(binchencoder): store db
	private final Map<String, OAuth2Authorization> authorizations = new ConcurrentHashMap<>();

	@Override
	public void save(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		this.authorizations.put(authorization.getId(), authorization);
	}

	@Override
	public void remove(OAuth2Authorization authorization) {

	}

	@Nullable
	@Override
	public OAuth2Authorization findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		return this.authorizations.get(id);
	}

	@Nullable
	@Override
	public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
		Assert.hasText(token, "token cannot be empty");

		OAuth2Authorization auth = null;
		for (OAuth2Authorization authorization : this.authorizations.values()) {
			if (hasToken(authorization, token, tokenType)) {
				auth = authorization;
				break;
			}
		}
		if (null == auth) {
			LOGGER.warn("Not found OAuth2Authorization by token:{}", token);
			return null;
		}

		OAuth2Authorization.Builder authBuilder = OAuth2Authorization.from(auth);
		// TODO(binchencoder): get from db
		Map<String, Object> addition = new HashMap<>();
		addition.put("userId", 179);
		addition.put("companyId", 10);
		authBuilder.attributes(u -> u.putAll(addition));

		return authBuilder.build();
	}

	private static boolean hasToken(OAuth2Authorization authorization, String token,
		@Nullable OAuth2TokenType tokenType) {
		if (tokenType == null) {
			return matchesState(authorization, token) ||
				matchesAuthorizationCode(authorization, token) ||
				matchesAccessToken(authorization, token) ||
				matchesRefreshToken(authorization, token);
		} else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
			return matchesState(authorization, token);
		} else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
			return matchesAuthorizationCode(authorization, token);
		} else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
			return matchesAccessToken(authorization, token);
		} else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
			return matchesRefreshToken(authorization, token);
		}
		return false;
	}

	private static boolean matchesState(OAuth2Authorization authorization, String token) {
		return token.equals(authorization.getAttribute(OAuth2ParameterNames.STATE));
	}

	private static boolean matchesAuthorizationCode(OAuth2Authorization authorization, String token) {
		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
			authorization.getToken(OAuth2AuthorizationCode.class);
		return authorizationCode != null && authorizationCode.getToken().getTokenValue().equals(token);
	}

	private static boolean matchesAccessToken(OAuth2Authorization authorization, String token) {
		OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
			authorization.getToken(OAuth2AccessToken.class);
		return accessToken != null && accessToken.getToken().getTokenValue().equals(token);
	}

	private static boolean matchesRefreshToken(OAuth2Authorization authorization, String token) {
		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
			authorization.getToken(OAuth2RefreshToken.class);
		return refreshToken != null && refreshToken.getToken().getTokenValue().equals(token);
	}
}
