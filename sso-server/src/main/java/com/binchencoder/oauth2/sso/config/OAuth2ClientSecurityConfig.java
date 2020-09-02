/*
 * Copyright 2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.binchencoder.oauth2.sso.config;

import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author binchencoder
 */
@EnableWebSecurity
@Order(101)
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

//	@Autowired
//	private ClientRegistrationRepository clientRegistrationRepository;

	@Override
	public void configure(WebSecurity web) {
		web
			.ignoring()
			.antMatchers("/webjars/**");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
//		http
//			.oauth2Client(oauth2 -> oauth2
//				.clientRegistrationRepository(clientRegistrationRepository)
//				.authorizedClientRepository(this.authorizedClientRepository())
//				.authorizedClientService(this.authorizedClientService())
//				.authorizationCodeGrant(codeGrant -> codeGrant
//					.authorizationRequestRepository(this.authorizationRequestRepository())
//					.authorizationRequestResolver(this.authorizationRequestResolver())
//					.accessTokenResponseClient(this.accessTokenResponseClient())
//				)
//			);
		// @formatter:on
	}

//	@Bean
//	public OAuth2AuthorizedClientManager authorizedClientManager(
//		ClientRegistrationRepository clientRegistrationRepository,
//		OAuth2AuthorizedClientRepository authorizedClientRepository) {
//
//		OAuth2AuthorizedClientProvider authorizedClientProvider =
//			OAuth2AuthorizedClientProviderBuilder.builder()
//				.authorizationCode()
//				.refreshToken()
//				.clientCredentials()
//				.password()
//				.build();
//
//		DefaultOAuth2AuthorizedClientManager authorizedClientManager =
//			new DefaultOAuth2AuthorizedClientManager(
//				clientRegistrationRepository, authorizedClientRepository);
//		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
//
//		return authorizedClientManager;
//	}
}
