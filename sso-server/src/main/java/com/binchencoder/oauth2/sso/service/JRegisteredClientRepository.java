package com.binchencoder.oauth2.sso.service;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;

/**
 * Implements for OAuth 2.0 {@link RegisteredClient}(s).
 *
 * The client information store in db.
 */
public class JRegisteredClientRepository implements RegisteredClientRepository {

	@Override
	public RegisteredClient findById(String id) {
		return null;
	}

	@Override
	public RegisteredClient findByClientId(String clientId) {
		if (!clientId.equals("messaging-client")) {
			return null;
		}

		Set<String> redirectUris = new HashSet<>(2);
		redirectUris.add("http://www.baidu.com");
		redirectUris.add("http://localhost:8080/authorized");

		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
			.clientId("messaging-client")
			.clientSecret("secret")
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.clientAuthenticationMethod(ClientAuthenticationMethod.POST)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.authorizationGrantType(AuthorizationGrantType.PASSWORD)
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.redirectUris(uris -> uris.addAll(redirectUris))
			.scope("message.read")
			.scope("message.write")
			.clientSettings((client) -> new ClientSettings())
			.build();
		return registeredClient;
	}
}
