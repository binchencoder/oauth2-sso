package com.binchencoder.oauth2.sso.service;

import java.util.Collection;
import java.util.Collections;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class JUserDetails implements UserDetails {

	private long userID;
	private long companyID;
	private boolean disable; // 帐号不可用
	private boolean locked; // 公司被停用
	private String password;
	private String alias; // 登录帐户名

	public JUserDetails() {
	}

	public JUserDetails(long userID, long companyID, String password) {
		this.userID = userID;
		this.companyID = companyID;
		this.password = password;
	}

	public JUserDetails(long userID, long companyID, String password, String alias) {
		this(userID, companyID, password);
		this.alias = alias;
	}

	public long getUserID() {
		return userID;
	}

	public void setUserID(long userID) {
		this.userID = userID;
	}

	public long getCompanyID() {
		return companyID;
	}

	public void setCompanyID(long companyID) {
		this.companyID = companyID;
	}

	public String getJid() {
		return userID + "@" + companyID;
	}

	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Collections.emptySet();
	}

	@Override
	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@Override
	public String getUsername() {
		return String.valueOf(userID);
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	// 使用帐号锁定代表 公司被禁用
	@Override
	public boolean isAccountNonLocked() {
		return !locked;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	// 使用帐号是否可用代表 用户是否可用
	@Override
	public boolean isEnabled() {
		return !disable;
	}

	public void setDisable(boolean disable) {
		this.disable = disable;
	}

	public void setLocked(boolean locked) {
		this.locked = locked;
	}

}
