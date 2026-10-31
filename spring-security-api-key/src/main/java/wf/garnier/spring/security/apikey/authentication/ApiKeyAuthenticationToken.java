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

import java.util.Collection;
import java.util.List;

import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.Transient;
import org.springframework.util.Assert;

import wf.garnier.spring.security.apikey.ApiKey;

/**
 * An API key authentication. Never persisted to a session.
 *
 * @author Daniel Garnier-Moiroux
 */
@Transient
public class ApiKeyAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 1L;

	private final Object principal;

	private @Nullable String secret;

	private ApiKeyAuthenticationToken(Object principal, @Nullable String secret,
			Collection<? extends GrantedAuthority> authorities, boolean authenticated) {
		super(authorities);
		this.principal = principal;
		this.secret = secret;
		super.setAuthenticated(authenticated);
	}

	private ApiKeyAuthenticationToken(Builder builder) {
		super(builder);
		this.principal = builder.principal;
		this.secret = builder.secret;
	}

	/**
	 * The key id and raw secret presented by a client.
	 */
	public static ApiKeyAuthenticationToken unauthenticated(String keyId, String rawSecret) {
		return new ApiKeyAuthenticationToken(keyId, rawSecret, List.of(), false);
	}

	public static ApiKeyAuthenticationToken authenticated(ApiKey details,
			Collection<? extends GrantedAuthority> authorities) {
		return new ApiKeyAuthenticationToken(details, null, authorities, true);
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public @Nullable Object getCredentials() {
		return this.secret;
	}

	@Override
	public String getName() {
		if (this.principal instanceof ApiKey details) {
			return details.getPrincipalName();
		}
		return String.valueOf(this.principal);
	}

	/**
	 * Only {@link #authenticated} creates a trusted token.
	 */
	@Override
	public void setAuthenticated(boolean authenticated) {
		Assert.isTrue(!authenticated, "Cannot set this token to trusted - use authenticated(...) instead");
		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		this.secret = null;
		if (this.principal instanceof CredentialsContainer container) {
			container.eraseCredentials();
		}
	}

	@Override
	public Builder toBuilder() {
		return new Builder(this);
	}

	public static final class Builder extends AbstractAuthenticationBuilder<Builder> {

		private Object principal;

		private @Nullable String secret;

		private Builder(ApiKeyAuthenticationToken token) {
			super(token);
			this.principal = token.principal;
			this.secret = token.secret;
		}

		@Override
		public Builder principal(@Nullable Object principal) {
			this.principal = principal == null ? this.principal : principal;
			return this;
		}

		@Override
		public Builder credentials(@Nullable Object credentials) {
			this.secret = credentials == null ? null : credentials.toString();
			return this;
		}

		@Override
		public ApiKeyAuthenticationToken build() {
			return new ApiKeyAuthenticationToken(this);
		}

	}

}
