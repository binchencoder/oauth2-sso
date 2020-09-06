# Preface

Spring团队废弃https://github.com/spring-projects/spring-security-oauth 之后，发布了OAuth 2.0的升级指南，推荐使用https://github.com/spring-projects-experimental/spring-authorization-server 作为Authorization Server. 但是作为一个社区项目，我在使用上还是遇到了一些问题，不知道是不打算支持还是目前没有实现（因为截止到现在2020/09/05，该项目也才刚发布0.0.1版本）

## 列出在开发中遇到的一些问题

### Q1：不支持grant_type=password获取access token

`oauth2/token` endpoint 是在org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter 中实现的，grant_type 只支持**authorization_code**和**client_credentials**

### Q2：OAuth2AccessTokenResponse 无法设置additionalParameters

```java
private void sendAccessTokenResponse(HttpServletResponse response, OAuth2AccessToken accessToken) throws IOException {
		OAuth2AccessTokenResponse.Builder builder =
				OAuth2AccessTokenResponse.withToken(accessToken.getTokenValue())
						.tokenType(accessToken.getTokenType())
						.scopes(accessToken.getScopes());
		if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null) {
			builder.expiresIn(ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()));
		}
		OAuth2AccessTokenResponse accessTokenResponse = builder.build();
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.accessTokenHttpResponseConverter.write(accessTokenResponse, null, httpResponse);
	}
```

