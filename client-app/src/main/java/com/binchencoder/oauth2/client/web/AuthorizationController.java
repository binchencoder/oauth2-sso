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
package com.binchencoder.oauth2.client.web;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;
import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * @author binchencoder
 */
@Controller
public class AuthorizationController {

	private final WebClient webClient;
	private final String messagesBaseUri;

	public AuthorizationController(WebClient webClient,
		@Value("${messages.base-uri}") String messagesBaseUri) {
		this.webClient = webClient;
		this.messagesBaseUri = messagesBaseUri;
	}

	@GetMapping("/logout")
	@ResponseBody
	public void logout(HttpServletRequest request, HttpServletResponse response) {
		// 容错处理: 先清除session
		request.getSession().invalidate();

		this.deleteCookie(response, "JSESSIONID");
	}

	@GetMapping("/authorized")    // registered redirect_uri for authorization_code
	public String authorized(Model model) {
		String[] messages = retrieveMessages("messaging-client-authorization-code");
		model.addAttribute("messages", messages);
		return "index";
	}

	@GetMapping(value = "/authorize", params = "grant_type=authorization_code")
	public String authorizationCodeGrant(Model model,
		@RegisteredOAuth2AuthorizedClient("messaging-client-authorization-code")
			OAuth2AuthorizedClient authorizedClient) {

		String[] messages = this.retrieveMessages(authorizedClient);
		model.addAttribute("messages", messages);

		return "index";
	}

	@GetMapping(value = "/authorize", params = "grant_type=client_credentials")
	public String clientCredentialsGrant(Model model) {

		String[] messages = this.retrieveMessages("messaging-client-client-credentials");
		model.addAttribute("messages", messages);

		return "index";
	}

	private void deleteCookie(HttpServletResponse response, String cookieName) {
		Cookie cookie = new Cookie(cookieName, "");
		cookie.setPath("/");
		cookie.setMaxAge(0);
		response.addCookie(cookie);
	}

	private String[] retrieveMessages(String clientRegistrationId) {
		return this.webClient
			.get()
			.uri(this.messagesBaseUri)
			.attributes(clientRegistrationId(clientRegistrationId))
			.retrieve()
			.bodyToMono(String[].class)
			.block();
	}

	private String[] retrieveMessages(OAuth2AuthorizedClient authorizedClient) {
		return this.webClient
			.get()
			.uri(this.messagesBaseUri)
			.attributes(oauth2AuthorizedClient(authorizedClient))
			.retrieve()
			.bodyToMono(String[].class)
			.block();
	}
}
