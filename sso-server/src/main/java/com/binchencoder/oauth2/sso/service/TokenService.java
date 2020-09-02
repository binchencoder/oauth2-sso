package com.binchencoder.oauth2.sso.service;

import com.binchencoder.oauth2.sso.prometheus.Metrics;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenService {

	private static final Logger LOGGER = LoggerFactory.getLogger(TokenService.class);

	CacheLoader<String, Object> loader = new CacheLoader<String, Object>() {
		public String load(String key) throws Exception {
//			System.out.println(key + " is loaded from a cacheLoader!");
			return null;
		}
	};

	LoadingCache<String, Object> cache = CacheBuilder.newBuilder()
		// 设置并发级别为8，并发级别是指可以同时写缓存的线程数
		.concurrencyLevel(8)
		// 设置缓存容器的初始容量为10
		.initialCapacity(10)
		// 设置缓存最大容量为100，超过100之后就会按照LRU最近虽少使用算法来移除缓存项
		.maximumSize(100)
		// 是否需要统计缓存情况,该操作消耗一定的性能,生产环境应该去除
		.recordStats()
		// 设置写缓存后n秒钟过期
		.expireAfterWrite(17, TimeUnit.SECONDS)
		// 设置读写缓存后n秒钟过期,实际很少用到,类似于expireAfterWrite
		// .expireAfterAccess(17, TimeUnit.SECONDS)
		// 只阻塞当前数据加载线程，其他线程返回旧值
		// .refreshAfterWrite(13, TimeUnit.SECONDS)
		// 设置缓存的移除通知
		.removalListener(notification -> {
			System.out.println(
				notification.getKey() + " " + notification.getValue() + " 被移除,原因:" + notification
					.getCause());
		})
		// build方法中可以指定CacheLoader，在缓存不存在时通过CacheLoader的实现自动加载缓存
		.build(loader);

	public TokenService() {
	}

	public boolean verifyToken(String token, String account) {
		if (StringUtils.isBlank(account)) {
			String result =
				StringUtils.isBlank(token) ? "empty" : token.length() <= 10 ? token : "unmatch";

			Metrics.VERIFY_TOKEN_COUNTER.labels(new String[]{"empty", result}).inc();
			return false;
		}

		String type = null;
		if (StringUtils.isNumeric(account)) {
			type = "uid";
		} else {
			type = "aid";
		}

		if (StringUtils.isBlank(token)) {
			Metrics.VERIFY_TOKEN_COUNTER.labels(new String[]{type, "empty"}).inc();
			return false;
		}

		if (token.length() <= 10) {
			Metrics.VERIFY_TOKEN_COUNTER.labels(new String[]{type, token}).inc();
			return false;
		}

		try {
			Map<String, Object> map = (Map<String, Object>) cache.get(token);
			if (map == null || map.size() == 0) {
				Metrics.VERIFY_TOKEN_COUNTER.labels(new String[]{type, "miss"}).inc();
				return false;
			}

			Object expiredObj = map.get("expired");
			if (null == expiredObj) {
				LOGGER.warn("TokenAuthentication: token={} lose attribute 'expired'", token);

				Metrics.VERIFY_TOKEN_COUNTER.labels(new String[]{type, "miss_expired"}).inc();
				return false;
			}

			Object userId = map.get("userId");
			if (userId == null) {
				LOGGER.warn("TokenAuthentication: token={} lose attribute 'userId'", token);

				Metrics.VERIFY_TOKEN_COUNTER.labels(new String[]{type, "miss_userId"}).inc();
				return false;
			}

			Long expired = new Long(expiredObj.toString());
			if (System.currentTimeMillis() > expired.longValue()) {
				LOGGER.warn("TokenAuthentication: token={} is invalid", token);

				this.removeToken(token);
				Metrics.VERIFY_TOKEN_COUNTER.labels(new String[]{type, "invalid"}).inc();
				return false;
			}

			boolean matched = userId.toString().equals(account);
			if (!matched) {
				Metrics.VERIFY_TOKEN_COUNTER.labels(new String[]{type, "unmatch"}).inc();
			} else {
				Metrics.VERIFY_TOKEN_COUNTER.labels(new String[]{type, "ok"}).inc();
			}

			return matched;
		} catch (Exception e) {
			LOGGER
				.error("TokenAuthentication error:token:{},uid:{}, {} ", new Object[]{token, account, e});

			Metrics.VERIFY_TOKEN_COUNTER.labels(new String[]{type, "exception"}).inc();
			return false;
		}
	}

	/**
	 * 申请 Token
	 *
	 * @param id 用户ID uid or aid
	 * @param expInSecond 过期秒数
	 */
	public String allocateToken(Serializable id, int expInSecond) {
		String token = UUID.randomUUID().toString();
		Map<String, Serializable> map = new HashMap<>();
		map.put("expired", System.currentTimeMillis() + expInSecond * 1000);
		map.put("userId", id);

//		cacheClient.set(token, map, expInSecond);
		cache.put(token, map);
		return token;
	}

	/**
	 * 清理token
	 */
	public void removeToken(String token) {
		cache.invalidate(token);
	}
}
