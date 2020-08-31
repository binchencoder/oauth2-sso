package com.binchencoder.oauth2.sso.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class JUserDetailsService implements UserDetailsService {

	private static final Logger LOGGER = LoggerFactory.getLogger(JUserDetailsService.class);

	@Override
	public JUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		LOGGER.info("loadUserByUsername {}", username);

		if (username.equals("user1")) {
			// TODO(chenbin) Load user from db
			UserDetails ud = User.withUsername("user1")
				.password("password")
				.roles("USER")
				.build();

			JUserDetails jUser = new JUserDetails(179, 10, ud.getPassword(), ud.getUsername());
			return jUser;
		}

		throw new UsernameNotFoundException("访问不到帐户数据,帐号:" + username);
	}
}
