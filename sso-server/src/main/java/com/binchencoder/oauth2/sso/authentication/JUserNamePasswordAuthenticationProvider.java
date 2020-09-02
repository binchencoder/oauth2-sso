package com.binchencoder.oauth2.sso.authentication;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class JUserNamePasswordAuthenticationProvider extends DaoAuthenticationProvider {

	private static final Logger LOGGER =
		LoggerFactory.getLogger(JUserNamePasswordAuthenticationProvider.class);

	private final UserDetailsService userDetailsService;

	public static final ThreadLocal<Boolean> PERSIST_SESSION = ThreadLocal.withInitial(() -> false);

	public JUserNamePasswordAuthenticationProvider(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
		super.setUserDetailsService(userDetailsService);
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
		String username = token.getName();
		String password = token.getCredentials().toString();

		String accessToken = "";
		if (StringUtils.isNotBlank(username)) {
//      VerifyAccountResponse resp = this.authnService.verifyAccount(username, password, persist);
//      accessToken = resp.getAccessToken();
		} else {// when only pass in 'token' which awarded by authn.
			accessToken = password;
		}

		// Find user from db
		UserDetails userDetails = null;
		if (username != null) {
			userDetails = userDetailsService.loadUserByUsername(username);
		}
		if (userDetails == null) {
			throw new UsernameNotFoundException("用户名/密码无效");
		} else if (!userDetails.isEnabled()) {
			throw new DisabledException("用户已被禁用");
		} else if (!userDetails.isAccountNonExpired()) {
			throw new AccountExpiredException("账号已过期");
		} else if (!userDetails.isAccountNonLocked()) {
			throw new LockedException("账号已被锁定");
		} else if (!userDetails.isCredentialsNonExpired()) {
			throw new LockedException("凭证已过期");
		}

		// 数据库用户的密码
		String dbPassword = userDetails.getPassword();
		// 与authentication里面的credentials相比较
		if (!dbPassword.equals(password)) {
			throw new BadCredentialsException("Invalid username/password");
		}

		// 授权
		return this.makeToken(authentication, userDetails, accessToken);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		// 返回true后才会执行上面的authenticate方法, 这步能确保authentication能正确转换类型
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private UsernamePasswordAuthenticationToken makeToken(Authentication auth,
		UserDetails userDetails, String accessToken) {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
			userDetails, accessToken, userDetails.getAuthorities());
		token.setDetails(auth.getDetails());

		return token;
	}
}
