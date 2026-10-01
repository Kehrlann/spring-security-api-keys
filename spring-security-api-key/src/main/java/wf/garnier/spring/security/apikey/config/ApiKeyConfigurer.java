/*
 * Copyright 2026-present the original author or authors.
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

package wf.garnier.spring.security.apikey.config;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import wf.garnier.spring.security.apikey.ApiKeyPasswordEncoders;
import wf.garnier.spring.security.apikey.ApiKeyRepository;
import wf.garnier.spring.security.apikey.authentication.ApiKeyAuthenticationProvider;
import wf.garnier.spring.security.apikey.web.ApiKeyAuthenticationConverter;
import wf.garnier.spring.security.apikey.web.ApiKeyAuthenticationFilter;

/**
 * Adds API key authentication to an {@link HttpSecurity}:
 *
 * <pre>
 * http.with(ApiKeyConfigurer.apiKey(), Customizer.withDefaults());
 * </pre>
 *
 * @author Daniel Garnier-Moiroux
 */
public final class ApiKeyConfigurer extends AbstractHttpConfigurer<ApiKeyConfigurer, HttpSecurity> {

	private static final Logger log = LoggerFactory.getLogger(ApiKeyConfigurer.class);

	private @Nullable ApiKeyRepository<?> apiKeyRepository;

	private @Nullable PasswordEncoder passwordEncoder;

	private @Nullable String headerName;

	private @Nullable AuthenticationConverter authenticationConverter;

	private boolean unauthorizedOnMissingApiKey = true;

	private @Nullable AuthenticationConverter resolvedConverter;

	private ApiKeyConfigurer() {
	}

	public static ApiKeyConfigurer apiKey() {
		return new ApiKeyConfigurer();
	}

	public ApiKeyConfigurer apiKeyRepository(ApiKeyRepository<?> apiKeyRepository) {
		Assert.notNull(apiKeyRepository, "apiKeyRepository cannot be null");
		this.apiKeyRepository = apiKeyRepository;
		return this;
	}

	/**
	 * The encoder used to verify secrets. The application's own {@link PasswordEncoder}
	 * bean is never picked up.
	 */
	public ApiKeyConfigurer passwordEncoder(PasswordEncoder passwordEncoder) {
		Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
		this.passwordEncoder = passwordEncoder;
		return this;
	}

	public ApiKeyConfigurer headerName(String headerName) {
		Assert.hasText(headerName, "headerName cannot be empty");
		this.headerName = headerName;
		return this;
	}

	public ApiKeyConfigurer authenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
		return this;
	}

	/**
	 * Whether an unauthenticated request denied by authorization gets a bare 401.
	 * Defaults to {@code true}.
	 */
	public ApiKeyConfigurer unauthorizedOnMissingApiKey(boolean unauthorizedOnMissingApiKey) {
		this.unauthorizedOnMissingApiKey = unauthorizedOnMissingApiKey;
		return this;
	}

	@Override
	public void init(HttpSecurity http) {
		Assert.state(this.headerName == null || this.authenticationConverter == null,
				"headerName and authenticationConverter cannot both be set");
		ApiKeyRepository<?> repository = resolveRepository(http);
		// A user-supplied converter is used as-is: post-processing it could
		// re-initialize a bean
		AuthenticationConverter converter = this.authenticationConverter != null ? this.authenticationConverter
				: postProcess(new ApiKeyAuthenticationConverter(
						this.headerName != null ? this.headerName : ApiKeyAuthenticationConverter.DEFAULT_HEADER_NAME));
		this.resolvedConverter = converter;

		PasswordEncoder encoder = this.passwordEncoder != null ? this.passwordEncoder
				: ApiKeyPasswordEncoders.createDelegatingPasswordEncoder();
		http.authenticationProvider(postProcess(new ApiKeyAuthenticationProvider(repository, encoder)));

		if (this.unauthorizedOnMissingApiKey) {
			http.exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
					new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED), AnyRequestMatcher.INSTANCE));
		}

		CsrfConfigurer<?> csrf = http.getConfigurer(CsrfConfigurer.class);
		if (csrf != null) {
			csrf.ignoringRequestMatchers(carriesApiKey(converter));
		}
	}

	@Override
	public void configure(HttpSecurity http) {
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		AuthenticationConverter converter = this.resolvedConverter;
		Assert.state(converter != null, "init(HttpSecurity) must be called before configure(HttpSecurity)");
		ApiKeyAuthenticationFilter filter = postProcess(
				new ApiKeyAuthenticationFilter(authenticationManager, converter));
		http.addFilterBefore(filter, BasicAuthenticationFilter.class);
	}

	private RequestMatcher carriesApiKey(AuthenticationConverter converter) {
		return (request) -> {
			try {
				return converter.convert(request) != null;
			}
			catch (AuthenticationException ex) {
				log.debug("API key converter failed, ignoring CSRF so the filter rejects the request");
				return true;
			}
		};
	}

	private ApiKeyRepository<?> resolveRepository(HttpSecurity http) {
		if (this.apiKeyRepository != null) {
			return this.apiKeyRepository;
		}
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);
		String[] names = context == null ? new String[0] : context.getBeanNamesForType(ApiKeyRepository.class);
		Assert.state(names.length > 0,
				"No ApiKeyRepository configured: call apiKeyRepository(...) or declare an ApiKeyRepository bean");
		Assert.state(names.length == 1,
				"Several ApiKeyRepository beans found, call apiKeyRepository(...) to choose one");
		return context.getBean(names[0], ApiKeyRepository.class);
	}

}
