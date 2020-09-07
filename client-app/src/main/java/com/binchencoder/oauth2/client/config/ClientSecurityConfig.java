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
package com.binchencoder.oauth2.client.config;

import com.binchencoder.oauth2.client.handler.CustomRequestEntityConverter;
import com.binchencoder.oauth2.client.handler.JAccessTokenResponseConverter;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

/**
 * @author binchencoder
 */
@EnableWebSecurity
public class ClientSecurityConfig extends WebSecurityConfigurerAdapter {

  private static final Logger LOGGER = LoggerFactory.getLogger(ClientSecurityConfig.class);

  @Autowired
  private ClientRegistrationRepository clientRegistrationRepository;

  @Override
  public void configure(WebSecurity web) {
    web
      .ignoring()
      .antMatchers("/webjars/**");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    // @formatter:off
//		http.authorizeRequests()
//      .antMatchers("/oauth_login", "/loginFailure", "/")
//      .permitAll()
//      .anyRequest()
//      .authenticated()
//      .and()
//      .oauth2Login()
//      .loginPage("/oauth_login")
//      .authorizationEndpoint()
//        .authorizationRequestResolver( new CustomAuthorizationRequestResolver(clientRegistrationRepository,"/oauth2/authorize-client"))
//      .baseUri("/oauth2/authorize-client")
//      .authorizationRequestRepository(authorizationRequestRepository())
//      .and()
//      .tokenEndpoint()
//      .accessTokenResponseClient(accessTokenResponseClient())
//      .and()
//      .defaultSuccessUrl("/loginSuccess")
//      .failureUrl("/loginFailure");


//		http
//      .authorizeRequests()
//        .anyRequest().authenticated()
//      .and()
//      .formLogin()
//        .loginPage("/login")
//        .failureUrl("/login-handler").permitAll()
//      .and()
//      .oauth2Client();


    // 免登录
    http
			.authorizeRequests()
//				.antMatchers("/authorized").authenticated()
				.anyRequest().permitAll().and()
			.logout()
				.disable()
//			.anonymous().disable()
			.oauth2Client();
		// @formatter:on
  }

  //  @Bean
  public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
    return new HttpSessionOAuth2AuthorizationRequestRepository();
  }

  //  @Bean
  public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
    DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
    accessTokenResponseClient.setRequestEntityConverter(new CustomRequestEntityConverter());

    OAuth2AccessTokenResponseHttpMessageConverter tokenResponseHttpMessageConverter = new OAuth2AccessTokenResponseHttpMessageConverter();
    tokenResponseHttpMessageConverter
      .setTokenResponseConverter(new JAccessTokenResponseConverter());
    RestTemplate restTemplate = new RestTemplate(
      Arrays.asList(new FormHttpMessageConverter(), tokenResponseHttpMessageConverter));
    restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
    accessTokenResponseClient.setRestOperations(restTemplate);
    return accessTokenResponseClient;
  }
}
