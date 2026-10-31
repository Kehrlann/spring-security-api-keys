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

package wf.garnier.spring.security.apikey.samples.userdetails;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.GrantedAuthority;

import wf.garnier.spring.security.apikey.ApiKeyDetails;

/**
 * An API key owned by a user. The authenticated name is the owner's username.
 *
 * @author Daniel Garnier-Moiroux
 */
public final class UserApiKeyDetails implements ApiKeyDetails {

	private final String id;

	private @Nullable String secret;

	private final String username;

	private final String label;

	private final List<GrantedAuthority> authorities;

	private final Instant createdAt;

	UserApiKeyDetails(String id, @Nullable String secret, String username, String label,
			Collection<? extends GrantedAuthority> authorities, Instant createdAt) {
		this.id = id;
		this.secret = secret;
		this.username = username;
		this.label = label;
		this.authorities = List.copyOf(authorities);
		this.createdAt = createdAt;
	}

	@Override
	public String getId() {
		return this.id;
	}

	@Override
	public @Nullable String getSecret() {
		return this.secret;
	}

	@Override
	public String getPrincipalName() {
		return this.username;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public String getLabel() {
		return this.label;
	}

	public Instant getCreatedAt() {
		return this.createdAt;
	}

	@Override
	public void eraseCredentials() {
		this.secret = null;
	}

	@Override
	public String toString() {
		return "UserApiKeyDetails [id=" + this.id + ", user=" + this.username + "]";
	}

}
