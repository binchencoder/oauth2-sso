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

import static org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI;

import com.binchencoder.oauth2.sso.exception.AnotherUserLoginedAccessDeniedException;
import com.binchencoder.oauth2.sso.exception.NotRequiredUserAuthenticationException;
import com.binchencoder.oauth2.sso.filter.JAuthenticationServiceExceptionFilter;
import com.binchencoder.oauth2.sso.filter.JLogoutRecordFilter;
import com.binchencoder.oauth2.sso.filter.JRequiredUserCheckFilter;
import com.binchencoder.oauth2.sso.filter.JUidCidTokenAuthenticationFilter;
import com.binchencoder.oauth2.sso.filter.JUsernamePasswordAuthenticationFilter;
import com.binchencoder.oauth2.sso.handler.CustomRequestEntityConverter;
import com.binchencoder.oauth2.sso.handler.JAccessDeniedHandler;
import com.binchencoder.oauth2.sso.handler.JAccessTokenResponseConverter;
import com.binchencoder.oauth2.sso.handler.JAuthenticationEntryPoint;
import com.binchencoder.oauth2.sso.handler.JForwardAuthenticationSuccessHandler;
import com.binchencoder.oauth2.sso.handler.NotifyLogoutSuccessHandler;
import com.binchencoder.oauth2.sso.matcher.JUidCidTokenRequestMatcher;
import com.binchencoder.oauth2.sso.route.Routes;
import com.binchencoder.oauth2.sso.service.AccessTokenRepresentSecurityContextRepository;
import com.binchencoder.oauth2.sso.service.AuthenticationFailureCountingService;
import com.binchencoder.oauth2.sso.service.JUserDetails;
import com.binchencoder.oauth2.sso.service.JWebAuthenticationDetails;
import com.google.common.collect.Lists;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import javax.servlet.http.Cookie;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.client.RestTemplate;

/**
 * @author binchencoder
 */
@EnableWebSecurity
public class AuthorizationServerSecurityConfig extends WebSecurityConfigurerAdapter {

	private static final Logger LOGGER = LoggerFactory
		.getLogger(AuthorizationServerSecurityConfig.class);

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
	private AccessTokenRepresentSecurityContextRepository accessTokenRepresentSecurityContextRepository;

	@Autowired
	private AuthenticationFailureCountingService authenticationFailureCountingService;

	@Autowired
	@Qualifier("daoAuthenticationProvider")
	private AuthenticationProvider authenticationProvider;

	@Autowired
	private OAuth2AuthorizationService oAuth2AuthorizationService;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.eraseCredentials(false);
		auth.authenticationProvider(authenticationProvider);
	}

	@Override
	public void configure(WebSecurity web) {
		StrictHttpFirewall firewall = new StrictHttpFirewall();
		// 去掉";"黑名单
		firewall.setAllowSemicolon(true);
		web
			.httpFirewall(firewall) // 加入自定义的防火墙
			.ignoring()
			.antMatchers("/webjars/**", "/js/**", "/css/**", "/img/**");
	}

	// @formatter:off
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.setSharedObject(SecurityContextRepository.class,
			accessTokenRepresentSecurityContextRepository);
		http.setSharedObject(OAuth2AuthorizationService.class, oAuth2AuthorizationService);

		List<SessionAuthenticationStrategy> sessionStrategies =
			this.getAuthenticationSessionStrategies();
		JUsernamePasswordAuthenticationFilter jUsernamePasswordAuthenticationFilter =
			this.getJUsernamePasswordAuthenticationFilter(sessionStrategies);

		OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer<>();
		List<RequestMatcher> requestMatchers = Lists.newArrayList(
		  authorizationServerConfigurer.getEndpointsMatcher());
		requestMatchers.add(JUsernamePasswordAuthenticationFilter.J_USERNAME_PASSWORD_REQUEST_MATCHER);
		requestMatchers.add(new AntPathRequestMatcher(Routes.LOGOUT, RequestMethod.GET.toString()));

		http
      .requestMatcher(new OrRequestMatcher(requestMatchers.toArray(new RequestMatcher[0])))
      .authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
			.httpBasic().and() // it indicate basic authentication is requires
//			.formLogin()
//        .successHandler()
//			.loginPage(Routes.LOGIN)
//			.failureUrl("/login-handler")
//			.permitAll().and()
//			.oauth2Login()
//        .tokenEndpoint()
//        .accessTokenResponseClient(accessTokenResponseClient()).and().and()
			.exceptionHandling() // 允许配置异常处理 -> 安全异常处理 LogoutFilter 之后, 确保所有登录异常纳入异常处理
			  .authenticationEntryPoint(jAuthenticationEntryPoint)
			  .accessDeniedHandler(jAccessDeniedHandler).and()
			.csrf()
				.requireCsrfProtectionMatcher(new AntPathRequestMatcher(DEFAULT_AUTHORIZATION_ENDPOINT_URI))
			.disable()
			.logout()
			  .logoutSuccessHandler(notifyLogoutSuccessHandler)
			  .addLogoutHandler(languageCleanLogoutHandler)
				.clearAuthentication(true).and()
			// 禁止匿名用户登录
			.anonymous().disable()
			// 认证服务内部异常处理
			.addFilterBefore(getJAuthenticationServiceExceptionFilter(), ExceptionTranslationFilter.class)
			// 已经登录帐号冲突检测
			.addFilterAfter(getJRequiredUserCheckFilter(), ExceptionTranslationFilter.class)
			// 账号登陆记录
			.addFilterAfter(getJLogoutRecordFilter(), getJRequiredUserCheckFilter().getClass())
			// 表单登录 --> 使可以被异常捕获
			.addFilterAfter(jUsernamePasswordAuthenticationFilter,
				getJRequiredUserCheckFilter().getClass())
			// 一键登录 --> 使可以被异常捕获
			.addFilterAfter(getJUidCidTokenAuthenticationFilter(sessionStrategies),
				AbstractPreAuthenticatedProcessingFilter.class)
      .apply(authorizationServerConfigurer);

		// maximumSessions配置一个用户的最大session数量, 默认不限,这里设1。先在一个浏览器如chrome登录,
		// 然后在另一个浏览器如firefox登录,此时同时登录数为2超出参数1,之前chrome的session将会过期,
		// 再去chrome发出请求会跳转到过期url.
		http.sessionManagement()
			.maximumSessions(1)
			.maxSessionsPreventsLogin(false)
			.expiredUrl("/expired");

		http.csrf().disable(); // 关跨域保护
		http.headers() // 2. -> 安全头添加
			.contentTypeOptions().and()
			.xssProtection().and()
			.cacheControl().and() // 自动禁用缓存
			.httpStrictTransportSecurity().and() // HSTS 保护
			.frameOptions().disable(); // 将安全标头添加到响应
		// @formatter:on
	}

	@Bean
	public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
		DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient =
			new DefaultAuthorizationCodeTokenResponseClient();
		accessTokenResponseClient.setRequestEntityConverter(new CustomRequestEntityConverter());

		OAuth2AccessTokenResponseHttpMessageConverter tokenResponseHttpMessageConverter =
			new OAuth2AccessTokenResponseHttpMessageConverter();
		tokenResponseHttpMessageConverter.setTokenResponseConverter(new JAccessTokenResponseConverter());
		RestTemplate restTemplate = new RestTemplate(
			Arrays.asList(new FormHttpMessageConverter(), tokenResponseHttpMessageConverter));
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
		accessTokenResponseClient.setRestOperations(restTemplate);
		return accessTokenResponseClient;
	}

	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		AuthenticationManager acture = super.authenticationManagerBean();
		return authentication -> {
			Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
			Authentication authResult = acture.authenticate(authentication);

			// 检测登录后的用户与期望的用户是否匹配。
			if (authentication != null && authResult != null
				&& authentication.getDetails() instanceof JWebAuthenticationDetails) {
				JWebAuthenticationDetails webDetails =
					(JWebAuthenticationDetails) authentication.getDetails();

				// 纯企业账号登录
				if (authResult.getPrincipal() instanceof JUserDetails) {
					JUserDetails details = (JUserDetails) authResult.getPrincipal();
					if (!webDetails.matchUid(details.getUserID())) {
						throw new NotRequiredUserAuthenticationException(
							"Authentication user not match required user");
					}
				}
			}

			if (existingAuth != null && authResult != null
				&& existingAuth.isAuthenticated()
				&& authResult.isAuthenticated()
				&& !(existingAuth instanceof AnonymousAuthenticationToken)) {
				if (existingAuth.getPrincipal() instanceof JUserDetails
					&& authResult.getPrincipal() instanceof JUserDetails
					&& !Objects.equals(authResult.getName(), existingAuth.getName())) {
					throw new AnotherUserLoginedAccessDeniedException(
						"Authentication not match current user", existingAuth, authResult);
				}
			}

			// // 一键登录成功清理token 个人账号token有复用,不复用时取消注释
			// if (authentication instanceof JUidCidTokenAuthenticationToken) {
			// tokenService.removeToken(((JUidCidTokenAuthenticationToken) authentication).getToken());
			// }

			// 账号冲突登陆成功清理token
//        if (authentication instanceof JUsernameTokenAuthenticationToken) {
//          tokenService.removeToken(authentication.getCredentials().toString());
//        }

			return authResult;
		};
	}

	// 表单登录
	private JUsernamePasswordAuthenticationFilter getJUsernamePasswordAuthenticationFilter(
		List<SessionAuthenticationStrategy> sessionStrategies) throws Exception {
		JUsernamePasswordAuthenticationFilter formLogin = new JUsernamePasswordAuthenticationFilter();
		JForwardAuthenticationSuccessHandler successHandler =	new JForwardAuthenticationSuccessHandler();
		// TODO(binchencoder): Login success kafka message
//    successHandler.setKafkaStorageAdapter(kafkaStorageAdapter);
		formLogin.setAuthenticationSuccessHandler(successHandler);
		formLogin.setAuthenticationFailureCountingService(authenticationFailureCountingService);
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
			new AntPathRequestMatcher(DEFAULT_AUTHORIZATION_ENDPOINT_URI,	RequestMethod.GET.toString()));
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
		return new JRequiredUserCheckFilter(new AndRequestMatcher(new OrRequestMatcher(
				new AntPathRequestMatcher(Routes.DEFAULT, RequestMethod.GET.toString()),
				new AntPathRequestMatcher(DEFAULT_AUTHORIZATION_ENDPOINT_URI,	RequestMethod.GET.toString())),
			new NegatedRequestMatcher(new JUidCidTokenRequestMatcher(DEFAULT_AUTHORIZATION_ENDPOINT_URI)))
		);
	}

	private List<SessionAuthenticationStrategy> getAuthenticationSessionStrategies() {
		List<SessionAuthenticationStrategy> sessionStrategies = new ArrayList<>(1);
		sessionStrategies.add((authentication, request, response) -> {
			String accessToken = authentication.getCredentials().toString();
			Cookie cookie =
				AccessTokenRepresentSecurityContextRepository.getOrNewAccessTokenCookie(request);
			String saveInfo = request.getParameter("saveinfo");
			boolean persist =
				StringUtils.isNotBlank(saveInfo) && !"false".equalsIgnoreCase(saveInfo.trim());
			if (!cookie.getValue().equals(accessToken) || persist) {
				cookie.setValue(accessToken);
				if (persist) {
					cookie.setMaxAge(30 * 24 * 60 * 60);
				}
				// For test, 设置'TSESSIONID' cookie 有效期为5分钟
				cookie.setMaxAge(5 * 60);

				response.addCookie(cookie);
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Add cookie:{} to response", cookie);
				}
			}
		});
		return sessionStrategies;
	}
}
