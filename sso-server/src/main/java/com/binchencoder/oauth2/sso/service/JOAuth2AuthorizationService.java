package com.binchencoder.oauth2.sso.service;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.util.Assert;

public class JOAuth2AuthorizationService implements OAuth2AuthorizationService {

	private static final Logger LOGGER = LoggerFactory.getLogger(JOAuth2AuthorizationService.class);

	// TODO(binchencoder): store db
	private final Map<OAuth2AuthorizationId, OAuth2Authorization> authorizations = new ConcurrentHashMap<>();

	@Override
	public void save(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		Object accessTokenAttr = authorization
			.getAttribute(OAuth2AuthorizationAttributeNames.ACCESS_TOKEN_ATTRIBUTES);
		if (null != accessTokenAttr) { // Save accessToken
			AbstractOAuth2Token accessToken = (AbstractOAuth2Token) accessTokenAttr;
		} else { // Save authorization code

		}

		OAuth2AuthorizationId authorizationId = new OAuth2AuthorizationId(
			authorization.getRegisteredClientId(), authorization.getPrincipalName());
		this.authorizations.put(authorizationId, authorization);
	}

	@Override
	public void remove(OAuth2Authorization authorization) {

	}

	@Override
	public OAuth2Authorization findByToken(String token, TokenType tokenType) {
		Assert.hasText(token, "token cannot be empty");
		OAuth2Authorization auth = this.authorizations.values().stream()
			.filter(authorization -> hasToken(authorization, token, tokenType))
			.findFirst()
			.orElse(null);
		if (null == auth) {
			LOGGER.warn("Not found OAuth2Authorization by token:{}", token);
		}

		OAuth2Authorization.Builder authBuilder = OAuth2Authorization.from(auth);
		// TODO(binchencoder): get from db
		Map<String, Object> addition = new HashMap<>();
		addition.put("userId", 179);
		addition.put("companyId", 10);
		authBuilder.attributes(u -> u.putAll(addition));

		return authBuilder.build();
	}

	private boolean hasToken(OAuth2Authorization authorization, String token, TokenType tokenType) {
		if (TokenType.AUTHORIZATION_CODE.equals(tokenType)) {
			return token.equals(authorization.getAttribute(OAuth2AuthorizationAttributeNames.CODE));
		} else if (TokenType.ACCESS_TOKEN.equals(tokenType)) {
			return authorization.getAccessToken() != null &&
				authorization.getAccessToken().getTokenValue().equals(token);
		}
		return false;
	}

	private static class OAuth2AuthorizationId implements Serializable {

		private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
		private final String registeredClientId;
		private final String principalName;

		private OAuth2AuthorizationId(String registeredClientId, String principalName) {
			this.registeredClientId = registeredClientId;
			this.principalName = principalName;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null || getClass() != obj.getClass()) {
				return false;
			}
			OAuth2AuthorizationId that = (OAuth2AuthorizationId) obj;
			return Objects.equals(this.registeredClientId, that.registeredClientId) &&
				Objects.equals(this.principalName, that.principalName);
		}

		@Override
		public int hashCode() {
			return Objects.hash(this.registeredClientId, this.principalName);
		}
	}
}
