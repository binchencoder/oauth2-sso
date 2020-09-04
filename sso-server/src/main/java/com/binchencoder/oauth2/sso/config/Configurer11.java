package com.binchencoder.oauth2.sso.config;

/**
 * Created by chenbin on 20-9-4.
 */

import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

public class Configurer11<B extends HttpSecurityBuilder<B>>
	extends AbstractHttpConfigurer<Configurer11<B>, B> {

	@Override
	public void init(B builder) throws Exception {
		super.init(builder);
	}

	@Override
	public void configure(B builder) throws Exception {
		super.configure(builder);

//		builder.build().getFilters()
	}

	@Override
	public B and() {
		return super.and();
	}

	@Override
	protected <T> T postProcess(T object) {
		return super.postProcess(object);
	}

	@Override
	public void addObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
		super.addObjectPostProcessor(objectPostProcessor);
	}

	@Override
	public void setBuilder(B builder) {
		super.setBuilder(builder);
	}
}
