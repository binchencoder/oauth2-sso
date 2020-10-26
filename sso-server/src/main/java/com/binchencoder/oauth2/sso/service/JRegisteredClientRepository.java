package com.binchencoder.oauth2.sso.service;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * Implements for OAuth 2.0 {@link RegisteredClient}(s).
 *
 * The client information store in db.
 */
public class JRegisteredClientRepository implements RegisteredClientRepository {

	private final Map<String, RegisteredClient> clientIdRegistrationMap;

	/**
	 * Constructs an {@code JRegisteredClientRepository} using the provided parameters.
	 *
	 * @param registrations the client registration(s)
	 */
	public JRegisteredClientRepository(RegisteredClient... registrations) {
		this(Arrays.asList(registrations));
	}

	/**
	 * Constructs an {@code JRegisteredClientRepository} using the provided parameters.
	 *
	 * @param registrations the client registration(s)
	 */
	public JRegisteredClientRepository(List<RegisteredClient> registrations) {
		Assert.notEmpty(registrations, "registrations cannot be empty");
		ConcurrentHashMap<String, RegisteredClient> clientIdRegistrationMapResult = new ConcurrentHashMap<>();
		for (RegisteredClient registration : registrations) {
			Assert.notNull(registration, "registration cannot be null");
			String clientId = registration.getClientId();
			if (clientIdRegistrationMapResult.containsKey(clientId)) {
				throw new IllegalArgumentException("Registered client must be unique. " +
					"Found duplicate client identifier: " + clientId);
			}
			clientIdRegistrationMapResult.put(clientId, registration);
		}
		this.clientIdRegistrationMap = clientIdRegistrationMapResult;
	}

	@Override
	public RegisteredClient findById(String id) {
		return null;
	}

	@Override
	public RegisteredClient findByClientId(String clientId) {
		Assert.hasText(clientId, "clientId cannot be empty");
		return this.clientIdRegistrationMap.get(clientId);
	}
}
