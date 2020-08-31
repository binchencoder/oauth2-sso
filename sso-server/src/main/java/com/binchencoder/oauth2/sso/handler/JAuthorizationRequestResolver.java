package com.binchencoder.oauth2.sso.handler;

import java.util.LinkedHashSet;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

public class JAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

	private final OAuth2AuthorizationRequestResolver defaultAuthorizationRequestResolver;

	public JAuthorizationRequestResolver(
		ClientRegistrationRepository clientRegistrationRepository) {
		this.defaultAuthorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(
			clientRegistrationRepository, "/oauth2/authorization");
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
		OAuth2AuthorizationRequest authorizationRequest =
			this.defaultAuthorizationRequestResolver.resolve(request);
		if (authorizationRequest != null) {
			return customAuthorizationRequest(authorizationRequest);
		}
		return null;
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request,
		String clientRegistrationId) {
		OAuth2AuthorizationRequest authorizationRequest =
			this.defaultAuthorizationRequestResolver.resolve(request, clientRegistrationId);
		if (authorizationRequest != null) {
			return customAuthorizationRequest(authorizationRequest);
		}
		return null;
	}

	private OAuth2AuthorizationRequest customAuthorizationRequest(
		OAuth2AuthorizationRequest authorizationRequest) {
		Set<String> scopes = new LinkedHashSet<>(authorizationRequest.getScopes());
		scopes.add("contacts");
		return OAuth2AuthorizationRequest.from(authorizationRequest)
			.scopes(scopes)
			.build();
	}
}
