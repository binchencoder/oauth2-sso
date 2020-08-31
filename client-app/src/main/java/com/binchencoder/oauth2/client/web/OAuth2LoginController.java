/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * @author Joe Grandja
 * @author Rob Winch
 */
@Controller
public class OAuth2LoginController {

  @Value("${messages.base-uri}")
  private String messagesBaseUri;

  @Autowired
  private WebClient webClient;

  @GetMapping("/")
  public String index(Model model,
      @RegisteredOAuth2AuthorizedClient("messaging-client-auth-code") OAuth2AuthorizedClient authorizedClient,
      @AuthenticationPrincipal OAuth2User oauth2User) {
    OAuth2AccessToken accessToken = authorizedClient.getAccessToken();

    model.addAttribute("userName", oauth2User.getName());
    model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName());
    model.addAttribute("userAttributes", oauth2User.getAttributes());
    return "index";
  }

  @GetMapping("/authorized")    // registered redirect_uri for authorization_code
  public String authorized(Model model) {
    String[] messages = retrieveMessages("messaging-client-auth-code");
    model.addAttribute("messages", messages);
    return "index";
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
}
