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

import com.binchencoder.oauth2.sso.authentication.JUserNamePasswordAuthenticationProvider;
import com.binchencoder.oauth2.sso.filter.JAuthenticationServiceExceptionFilter;
import com.binchencoder.oauth2.sso.filter.JLogoutRecordFilter;
import com.binchencoder.oauth2.sso.filter.JRequiredUserCheckFilter;
import com.binchencoder.oauth2.sso.filter.JUidCidTokenAuthenticationFilter;
import com.binchencoder.oauth2.sso.filter.JUsernamePasswordAuthenticationFilter;
import com.binchencoder.oauth2.sso.handler.JAccessDeniedHandler;
import com.binchencoder.oauth2.sso.handler.JAuthenticationEntryPoint;
import com.binchencoder.oauth2.sso.handler.JForwardAuthenticationSuccessHandler;
import com.binchencoder.oauth2.sso.handler.NotifyLogoutSuccessHandler;
import com.binchencoder.oauth2.sso.matcher.JUidCidTokenRequestMatcher;
import com.binchencoder.oauth2.sso.route.Routes;
import com.binchencoder.oauth2.sso.service.AuthenticationFailureCountingService;
import com.binchencoder.oauth2.sso.service.JUserDetailsService;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.keys.KeyManager;
import org.springframework.security.crypto.keys.StaticKeyGeneratingKeyManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * @author binchencoder
 */
@EnableWebSecurity
public class AuthorizationServerSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private NotifyLogoutSuccessHandler notifyLogoutSuccessHandler;

	@Autowired
	@Qualifier("languageCleanLogoutHandler")
	private LogoutHandler languageCleanLogoutHandler;

	@Autowired
	private JAuthenticationEntryPoint jAuthenticationEntryPoint;

	@Autowired
	private JAccessDeniedHandler jAccessDeniedHandler;

	@Autowired
	private AuthenticationFailureCountingService authenticationFailureCountingService;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(this.authenticationProvider());
	}

	@Override
	public void configure(WebSecurity web) {
		web
			.ignoring()
			.antMatchers("/webjars/**");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		List<SessionAuthenticationStrategy> sessionStrategies = new ArrayList<>(1);
		sessionStrategies.add((authentication, request, response) -> {
//			String accessToken = authentication.getCredentials().toString();
//        Cookie cookie =
//            AccessTokenRepresentSecurityContextRepository.getOrNewAccessTokenCookie(request);
//			Cookie cookie = new Cookie("", "");
//			String saveInfo = request.getParameter("saveinfo");
//			boolean persist =
//				!StringUtils.isEmpty(saveInfo) && !"false".equalsIgnoreCase(saveInfo.trim());
//			if (!cookie.getValue().equals(accessToken) || persist) {
//				cookie.setValue(accessToken);
//				if (persist) {
//					cookie.setMaxAge(30 * 24 * 60 * 60);
//				}
//
//				response.addCookie(cookie);
//			}
		});

		JUsernamePasswordAuthenticationFilter jUsernamePasswordAuthenticationFilter =
			getJUsernamePasswordAuthenticationFilter(sessionStrategies);
		OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
			new OAuth2AuthorizationServerConfigurer<>();

		// @formatter:off
		http
//			.requestMatcher(new OrRequestMatcher(authorizationServerConfigurer.getEndpointMatchers()))
			.authorizeRequests()
			.antMatchers(Routes.DEFAULT, Routes.LOGIN).permitAll().anyRequest().authenticated().and()
//			.formLogin()
//			.loginPage(Routes.LOGIN)
//			.failureUrl("/login-handler")
//			.permitAll().and()
			.exceptionHandling() // 3. -> 安全异常处理 LogoutFilter 之后，确保所有登录异常纳入异常处理
			.authenticationEntryPoint(jAuthenticationEntryPoint)
			.accessDeniedHandler(jAccessDeniedHandler).and().csrf()
			.requireCsrfProtectionMatcher(new AntPathRequestMatcher(Routes.OAUTH_AUTHORIZE)).disable()
			.logout().logoutSuccessHandler(notifyLogoutSuccessHandler).logoutUrl(Routes.LOGOUT)
			.addLogoutHandler(languageCleanLogoutHandler).and()
			// 认证服务内部异常处理
			.addFilterBefore(getJAuthenticationServiceExceptionFilter(),
				ExceptionTranslationFilter.class)
			// 已经登录帐号冲突检测
			.addFilterAfter(getJRequiredUserCheckFilter(), ExceptionTranslationFilter.class)
			// 账号登陆记录
			.addFilterAfter(getJLogoutRecordFilter(), getJRequiredUserCheckFilter().getClass())
			// 表单登录 --> 使可以被异常捕获
			.addFilterAfter(jUsernamePasswordAuthenticationFilter,
				getJRequiredUserCheckFilter().getClass())
			// 一键登录 --> 使可以被异常捕获
			.addFilterAfter(getJUidCidTokenAuthenticationFilter(sessionStrategies),
				jUsernamePasswordAuthenticationFilter.getClass())
			.apply(authorizationServerConfigurer);

		http.anonymous(); // 允许配置匿名用户
		http.csrf().disable(); // 关跨域保护
		http.headers().frameOptions().disable();
		// @formatter:on
	}

//	@Override
//	public UserDetailsService userDetailsServiceBean() throws Exception {
//		return userDetailsService();
//	}
//
//	@Override
//	public AuthenticationManager authenticationManagerBean() throws Exception {
//		List<AuthenticationProvider> providers = new ArrayList<>();
//		providers.add(authenticationProvider());
//
//		return new ProviderManager(providers);
//	}

	// @formatter:off
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
//    Set<String> redirectUris = new HashSet<>(2);
//    redirectUris.add("http://localhost:8080");
//    redirectUris.add("http://localhost:8080/authorized");

		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
			.clientId("messaging-client")
			.clientSecret("secret")
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.authorizationGrantType(AuthorizationGrantType.PASSWORD)
			.redirectUri("http://localhost:8080")
//        .redirectUris(uris -> uris.addAll(redirectUris))
			.scope("message.read")
			.scope("message.write")
			.build();
		return new InMemoryRegisteredClientRepository(registeredClient);
	}
	// @formatter:on

	@Bean
	public KeyManager keyManager() {
		return new StaticKeyGeneratingKeyManager();
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new JUserNamePasswordAuthenticationProvider(
			userDetailsService());
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}

	@Bean
	public UserDetailsService userDetailsService() {
		return new JUserDetailsService(passwordEncoder());
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// 表单登录
	private JUsernamePasswordAuthenticationFilter getJUsernamePasswordAuthenticationFilter(
		List<SessionAuthenticationStrategy> sessionStrategies) throws Exception {
		JUsernamePasswordAuthenticationFilter formLogin = new JUsernamePasswordAuthenticationFilter();
		JForwardAuthenticationSuccessHandler jForwardAuthenticationSuccessHandler =
			new JForwardAuthenticationSuccessHandler();
		// TODO(binchencoder): Login success kafka message
//    jForwardAuthenticationSuccessHandler.setKafkaStorageAdapter(kafkaStorageAdapter);
		formLogin.setAuthenticationSuccessHandler(jForwardAuthenticationSuccessHandler);
		formLogin.setAuthenticationFailureCountingService(authenticationFailureCountingService);
		formLogin.setRequiresAuthenticationRequestMatcher(
			new AntPathRequestMatcher(Routes.OAUTH_AUTHORIZE, RequestMethod.POST.toString()));
		formLogin.setAuthenticationManager(authenticationManagerBean());
		formLogin.setUsernameParameter(OAuth2ParameterNames.USERNAME);
		formLogin.setPasswordParameter(OAuth2ParameterNames.PASSWORD);
		formLogin.setAuthenticationFailureHandler(jAuthenticationEntryPoint);
		formLogin.setSessionAuthenticationStrategy(
			new CompositeSessionAuthenticationStrategy(sessionStrategies));
		return formLogin;
	}

	// 退出登录记录生成器
	private JLogoutRecordFilter getJLogoutRecordFilter() {
		return new JLogoutRecordFilter(
			new AntPathRequestMatcher(Routes.OAUTH_AUTHORIZE, RequestMethod.GET.toString()));
	}

	// 一键登录
	private JUidCidTokenAuthenticationFilter getJUidCidTokenAuthenticationFilter(
		List<SessionAuthenticationStrategy> sessionStrategies) throws Exception {
		JUidCidTokenAuthenticationFilter jTokenLogin = new JUidCidTokenAuthenticationFilter();
		jTokenLogin.setAuthenticationManager(authenticationManagerBean());
		jTokenLogin.setAuthenticationFailureHandler(jAuthenticationEntryPoint);
		jTokenLogin.setSessionAuthenticationStrategy(
			new CompositeSessionAuthenticationStrategy(sessionStrategies));
		return jTokenLogin;
	}

	private JAuthenticationServiceExceptionFilter getJAuthenticationServiceExceptionFilter() {
		JAuthenticationServiceExceptionFilter serviceExceptionFilter =
			new JAuthenticationServiceExceptionFilter();
		serviceExceptionFilter.setAuthenticationEntryPoint(jAuthenticationEntryPoint);
		return serviceExceptionFilter;
	}

	private JRequiredUserCheckFilter getJRequiredUserCheckFilter() {
		return new JRequiredUserCheckFilter(new AndRequestMatcher(
			new OrRequestMatcher(
				new AntPathRequestMatcher(Routes.DEFAULT, RequestMethod.GET.toString()),
				new AntPathRequestMatcher(Routes.OAUTH_AUTHORIZE, RequestMethod.GET.toString())),
			new NegatedRequestMatcher(new JUidCidTokenRequestMatcher(Routes.OAUTH_AUTHORIZE))));
	}
}
