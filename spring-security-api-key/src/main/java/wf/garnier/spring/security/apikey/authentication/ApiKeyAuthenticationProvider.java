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

package wf.garnier.spring.security.apikey.authentication;

import java.util.ArrayList;
import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import wf.garnier.spring.security.apikey.ApiKey;
import wf.garnier.spring.security.apikey.ApiKeyPasswordEncoders;
import wf.garnier.spring.security.apikey.ApiKeyRepository;

/**
 * Authenticates {@link ApiKeyAuthenticationToken}s against an {@link ApiKeyRepository}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class ApiKeyAuthenticationProvider implements AuthenticationProvider {

	/**
	 * The factor of every successful API key authentication.
	 */
	public static final String FACTOR_API_KEY = "API_KEY";

	private static final String BAD_CREDENTIALS = "Invalid API key";

	private static final Logger log = LoggerFactory.getLogger(ApiKeyAuthenticationProvider.class);

	private final ApiKeyRepository<?> repository;

	private final PasswordEncoder passwordEncoder;

	private final String dummyHash;

	public ApiKeyAuthenticationProvider(ApiKeyRepository<?> repository) {
		this(repository, ApiKeyPasswordEncoders.createDelegatingPasswordEncoder());
	}

	public ApiKeyAuthenticationProvider(ApiKeyRepository<?> repository, PasswordEncoder passwordEncoder) {
		this.repository = repository;
		this.passwordEncoder = passwordEncoder;
		this.dummyHash = passwordEncoder.encode("dummy-secret-for-timing-equalization");
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		ApiKeyAuthenticationToken token = (ApiKeyAuthenticationToken) authentication;
		String keyId = keyId(token);
		Object presented = token.getCredentials();
		String rawSecret = presented == null ? "" : presented.toString();

		ApiKey details;
		try {
			details = this.repository.findByKeyId(keyId);
		}
		catch (RuntimeException ex) {
			throw new InternalAuthenticationServiceException("Could not look up API key", ex);
		}

		if (details == null) {
			this.passwordEncoder.matches(rawSecret, this.dummyHash);
			log.debug("API key authentication failed: unknown key id [{}]", keyId);
			throw new BadCredentialsException(BAD_CREDENTIALS);
		}
		String stored = details.getSecret();
		if (stored == null || !matches(rawSecret, stored)) {
			log.debug("API key authentication failed: wrong secret for key id [{}]", keyId);
			throw new BadCredentialsException(BAD_CREDENTIALS);
		}

		Collection<GrantedAuthority> authorities = new ArrayList<>(details.getAuthorities());
		authorities.add(FactorGrantedAuthority.fromFactor(FACTOR_API_KEY));
		ApiKeyAuthenticationToken result = ApiKeyAuthenticationToken.authenticated(details, authorities);
		result.setDetails(token.getDetails());
		log.debug("API key authentication succeeded for key id [{}]", keyId);
		return result;
	}

	private static String keyId(ApiKeyAuthenticationToken token) {
		if (token.getPrincipal() instanceof ApiKey details) {
			return details.getId();
		}
		return String.valueOf(token.getPrincipal());
	}

	private boolean matches(String rawSecret, String stored) {
		try {
			return this.passwordEncoder.matches(rawSecret, stored);
		}
		catch (IllegalArgumentException ex) {
			return false;
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return ApiKeyAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
