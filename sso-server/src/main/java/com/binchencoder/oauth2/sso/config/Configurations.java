package com.binchencoder.oauth2.sso.config;

import static org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI;

import com.binchencoder.oauth2.account.service.AuthnService;
import com.binchencoder.oauth2.sso.authentication.JUserNamePasswordAuthenticationProvider;
import com.binchencoder.oauth2.sso.handler.JAccessDeniedHandler;
import com.binchencoder.oauth2.sso.handler.JAuthenticationEntryPoint;
import com.binchencoder.oauth2.sso.handler.NotifyLogoutSuccessHandler;
import com.binchencoder.oauth2.sso.resover.LogoutNotifyAddressResover;
import com.binchencoder.oauth2.sso.route.Routes;
import com.binchencoder.oauth2.sso.service.AccessTokenRepresentSecurityContextRepository;
import com.binchencoder.oauth2.sso.service.AuthenticationFailureCountingService;
import com.binchencoder.oauth2.sso.service.JOAuth2AuthorizationService;
import com.binchencoder.oauth2.sso.service.JRegisteredClientRepository;
import com.binchencoder.oauth2.sso.service.JUserDetailsService;
import com.google.common.collect.Lists;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

@Configuration
public class Configurations {

	private static final Logger LOGGER = LoggerFactory.getLogger(Configurations.class);

	public static final String REQUEST_STATUS_METRICS_FILTER_BEAN_NAME = "requestStatusMetricsFilter";

	@Autowired
	private Environment env;

	@Autowired
	private AuthnService authnService;

	@Bean(name = "daoAuthenticationProvider")
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new JUserNamePasswordAuthenticationProvider(
			userDetailsService());
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}

	@Bean
	public OAuth2AuthorizationService jOAuth2AuthorizationService() {
		return new JOAuth2AuthorizationService();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		return new JUserDetailsService(passwordEncoder());
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public JWKSource jwkSource() {
		return new ImmutableJWKSet(new JWKSet());
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		List<RegisteredClient> clients = Lists.newArrayList();
		clients.add(RegisteredClient.withId(UUID.randomUUID().toString())
			.clientId("messaging-client")
			.clientSecret("secret")
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.clientAuthenticationMethod(ClientAuthenticationMethod.POST)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.authorizationGrantType(AuthorizationGrantType.PASSWORD)
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.redirectUris(uris -> {
				uris.add("http://www.baidu.com");
				uris.add("http://localhost:8080/authorized");
			})
//			.scope("message.read")
//			.scope("message.write")
			.clientSettings((client) -> new ClientSettings())
			.tokenSettings((token) -> new TokenSettings().accessTokenTimeToLive(Duration.ofSeconds(20)))
			.build());

		return new JRegisteredClientRepository(clients);
	}

	@Bean
	public NotifyLogoutSuccessHandler notifyLogoutSuccessHandler(
		LogoutNotifyAddressResover logoutNotifyAddressResover) {
		NotifyLogoutSuccessHandler handler = new NotifyLogoutSuccessHandler(logoutNotifyAddressResover);
		handler.setAuthnService(authnService);
		return handler;
	}

	/**
	 * 退出登录通知列表解析器
	 *
	 * 退出登录时通知所有退出登录接口
	 */
	@Bean
	public LogoutNotifyAddressResover logoutNotifyAddressResover(
		@Value("${logout.notifies.urls}") String urls) throws IOException {
		List<String> defaultUrls = new ArrayList<>();
		if (StringUtils.isNotBlank(urls)) {
			for (String url : urls.split(",")) {
				if (!StringUtils.isEmpty(url)) {
					defaultUrls.add(url.trim());
				}
			}
		}

		return (request, authentication) -> {
			Set<String> clientIds = new HashSet<>();
			Cookie[] cookies = request.getCookies();
			if (cookies != null) {
				for (Cookie cookie : cookies) {
					if ("apps".equals(cookie.getName())) {
						String apps = cookie.getValue();
						if (apps != null) {
							String[] arr = apps.split(",");
							if (arr != null) {
								for (String clientId : arr) {
									if (!clientId.isEmpty()) {
										clientIds.add(clientId.trim());
									}
								}
							}
						}
					}
				}
			}

			Set<String> notifies = new HashSet<>(defaultUrls);
			for (String clientId : clientIds) {
				String urlKey = "logout.url." + clientId;
				String urls1 = Configurations.this.env.getProperty(urlKey);
				if (StringUtils.isEmpty(urls1)) {
					LOGGER.warn("clientid:{} ,logout url loss");
					continue;
				}
				for (String url : urls1.split(",")) {
					if (!StringUtils.isEmpty(url)) {
						notifies.add(url.trim());
					}
				}
			}
			return new ArrayList<>(notifies);
		};
	}

	// 退出登录时, 清理掉cookie中设置的缓存语言信息
	@Bean(name = "languageCleanLogoutHandler")
	public LogoutHandler languageCleanLogoutHandler() {
		return (request, response, authentication) -> {
			Cookie[] cookies = request.getCookies();
			if (cookies != null) {
				String sessionCookieName = request.getServletContext().getSessionCookieConfig().getName();
				sessionCookieName = sessionCookieName == null ? "JSESSIONID" : sessionCookieName;
				for (Cookie cookie : cookies) {
					if (sessionCookieName.equals(cookie.getName())
						|| AccessTokenRepresentSecurityContextRepository.TSESSIONID.equals(cookie.getName())) {
						cookie.setPath("/");
						cookie.setMaxAge(0);
						response.addCookie(cookie);
					}
				}
			}
		};
	}

//	@Bean
//	public TokenService tokenService() {
//		return new TokenService();
//	}

	/* 认证端点 & 认证失败处理器 */
	@Bean
	public JAuthenticationEntryPoint jAuthenticationEntryPoint() {
		return new JAuthenticationEntryPoint(new OrRequestMatcher(
			new AntPathRequestMatcher(Routes.DEFAULT, HttpMethod.GET.toString()),
			new AntPathRequestMatcher(DEFAULT_AUTHORIZATION_ENDPOINT_URI, HttpMethod.GET.toString()))
		);
	}

	/* 认证拒绝处理器 */
	@Bean
	public JAccessDeniedHandler jAccessDeniedHandler() {
		return new JAccessDeniedHandler();
	}

	@Bean
	public AuthenticationFailureCountingService authenticationFailureCountingService() {
		return new AuthenticationFailureCountingService() {
			private String usernameParameter = "username";

			private String cacheKey(String username) {
				return "";
			}

			@Override
			public void resetAuthenticationFailure(HttpServletRequest request,
				HttpServletResponse response) {
				String username = request.getParameter(usernameParameter);
				if (!StringUtils.isEmpty(username)) {
					// 重置异常计数
				}
			}

			@Override
			public void increaseAuthenticationFailure(HttpServletRequest request,
				HttpServletResponse response) {
				String username = request.getParameter(usernameParameter);
				if (!StringUtils.isEmpty(username)) {
					// 增加异常计数
				}
			}

			@Override
			public int getAuthenticationFailure(HttpServletRequest request,
				HttpServletResponse response) {
				int countAccount = 0;
				String username = request.getParameter(usernameParameter);
				if (!StringUtils.isEmpty(username)) {

				}
				return countAccount;
			}

			@Override
			public boolean isNeedCheckIdentifyCode(HttpServletRequest request,
				HttpServletResponse response) {
				return getAuthenticationFailure(request, response) >= 5;
			}
		};
	}

	@Bean
	public AccessTokenRepresentSecurityContextRepository accessTokenRepresentSecurityContextRepository() {
		return new AccessTokenRepresentSecurityContextRepository();
	}

	@Bean
	public AuthnService authnService() {
		return new AuthnService();
	}

	private void deleteCookie(HttpServletResponse response, String cookieName) {
		Cookie cookie = new Cookie(cookieName, "");
		cookie.setPath("/");
		cookie.setMaxAge(0);
		response.addCookie(cookie);
	}
}
