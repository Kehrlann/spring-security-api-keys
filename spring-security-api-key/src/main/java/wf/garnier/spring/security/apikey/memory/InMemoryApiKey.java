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

package wf.garnier.spring.security.apikey.memory;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.List;

import org.jspecify.annotations.Nullable;
import wf.garnier.spring.security.apikey.ApiKey;

import org.springframework.security.core.GrantedAuthority;

/**
 * A simple {@link ApiKey}, usable as a {@link InMemoryApiKeyRepository.DetailsFactory}
 * with {@code InMemoryApiKey::new}.
 *
 * @author Daniel Garnier-Moiroux
 */
public final class InMemoryApiKey implements ApiKey, Serializable {

	@Serial
	private static final long serialVersionUID = 1L;

	private final String id;

	private final String name;

	private final String label;

	private final List<GrantedAuthority> authorities;

	private @Nullable String secret;

	public InMemoryApiKey(String id, String secret, String name, String label,
			Collection<? extends GrantedAuthority> authorities) {
		this.id = id;
		this.secret = secret;
		this.name = name;
		this.label = label;
		this.authorities = List.copyOf(authorities);
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
		return this.name;
	}

	@Override
	public String getLabel() {
		return this.label;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public void eraseCredentials() {
		this.secret = null;
	}

	@Override
	public String toString() {
		return "InMemoryApiKey [id=" + this.id + ", name=" + this.name + ", label=" + this.label + "]";
	}

}
