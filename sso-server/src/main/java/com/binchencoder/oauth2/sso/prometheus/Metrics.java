package com.binchencoder.oauth2.sso.prometheus;

import io.prometheus.client.Counter;
import io.prometheus.client.Histogram;

public class Metrics {

	/**
	 * URL 访问 Metrics
	 */
	public final static Histogram RESPONSE_URL_METHOD_STATUS = Histogram.build()
		.namespace("sso")
		.subsystem("web")
		.name("request_url_method_status")
		.labelNames(new String[]{"url", "method", "status"})
		.help("request url method status.")
		.register();

	/**
	 * 一键登录 Metrics
	 */
	public final static Counter VERIFY_TOKEN_COUNTER = Counter.build()
		.namespace("sso")
		.subsystem("web")
		.name("verify_token_counter")
		.labelNames(new String[]{"type", "result"})
		.help("verify token counts.").register();

	/**
	 * 第三方 API 调用 Metrics
	 */
	public final static Histogram THIRD_PARTY_API_CALL_COUNTER = Histogram.build()
		.namespace("sso")
		.subsystem("api")
		.name("third_party_call_counter")
		.labelNames(new String[]{"url", "clientId", "errorCode"})
		.help("third-party open api call counter.")
		.register();

	/**
	 * DB method call Metrics
	 */
	public final static Counter CALL_DB_METHOD_COUNTER = Counter.build()
		.name("sso")
		.subsystem("db")
		.name("method_call_counter")
		.labelNames(new String[]{"method"})
		.help("call db method counter")
		.register();

	/**
	 * Redis method call Metrics
	 */
	public final static Counter CALL_REDIS_METHOD_COUNTER = Counter.build()
		.name("sso")
		.subsystem("redis")
		.name("method_call_counter")
		.labelNames(new String[]{"method"})
		.help("call db method counter")
		.register();

	/**
	 * 调用 SSO 内部方法计数
	 */
	public final static Counter CALL_SSO_METHOD_COUNTER = Counter.build()
		.name("sso")
		.subsystem("logic")
		.name("method_call_counter")
		.labelNames(new String[]{"method"})
		.help("call sso inner method counter")
		.register();
}
