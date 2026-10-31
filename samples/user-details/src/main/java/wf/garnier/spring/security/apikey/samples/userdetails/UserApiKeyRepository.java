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

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import wf.garnier.spring.security.apikey.ApiKeyRepository;
import wf.garnier.spring.security.apikey.GeneratedApiKey;
import wf.garnier.spring.security.apikey.memory.InMemoryApiKey;
import wf.garnier.spring.security.apikey.memory.InMemoryApiKeyRepository;

/**
 * API keys owned by users of a {@link UserDetailsService}. Wraps an
 * {@link InMemoryApiKeyRepository}, which stores the keys, and checks every key against
 * its owner.
 * <p>
 * The owner is loaded on every lookup, so a key stops working as soon as its owner is
 * deleted, disabled, locked or expired. A key grants the authorities it was created with,
 * minus those its owner no longer has.
 *
 * @author Daniel Garnier-Moiroux
 */
public class UserApiKeyRepository implements ApiKeyRepository<InMemoryApiKey> {

	private final InMemoryApiKeyRepository<InMemoryApiKey> delegate;

	private final UserDetailsService userDetailsService;

	public UserApiKeyRepository(InMemoryApiKeyRepository<InMemoryApiKey> delegate,
			UserDetailsService userDetailsService) {
		this.delegate = delegate;
		this.userDetailsService = userDetailsService;
	}

	@Override
	public @Nullable InMemoryApiKey findByKeyId(String keyId) {
		InMemoryApiKey key = this.delegate.findByKeyId(keyId);
		if (key == null) {
			return null;
		}
		UserDetails user = loadActiveUser(key.getPrincipalName());
		if (user == null) {
			return null;
		}
		return restrictToOwner(key, user);
	}

	/**
	 * The keys owned by {@code principalName}, sorted by label. They never carry the
	 * secret or its hash. Empty if the owner is no longer active.
	 */
	@Override
	public List<InMemoryApiKey> findByPrincipalName(String principalName) {
		UserDetails user = loadActiveUser(principalName);
		if (user == null) {
			return List.of();
		}
		return this.delegate.findByPrincipalName(principalName)
			.stream()
			.map((key) -> restrictToOwner(key, user))
			.sorted(Comparator.comparing(InMemoryApiKey::getLabel).thenComparing(InMemoryApiKey::getId))
			.toList();
	}

	@Override
	public GeneratedApiKey generate(String principalName, String label,
			Collection<? extends GrantedAuthority> authorities) {
		return this.delegate.generate(principalName, label, authorities);
	}

	@Override
	public void delete(String keyId) {
		this.delegate.delete(keyId);
	}

	/**
	 * Delete a key, only if it is owned by {@code username}.
	 */
	public void delete(String username, String keyId) {
		InMemoryApiKey key = this.delegate.findByKeyId(keyId);
		if (key != null && key.getPrincipalName().equals(username)) {
			this.delegate.delete(keyId);
		}
	}

	private static InMemoryApiKey restrictToOwner(InMemoryApiKey key, UserDetails user) {
		Set<@Nullable String> granted = user.getAuthorities()
			.stream()
			.map(GrantedAuthority::getAuthority)
			.collect(Collectors.toSet());
		List<GrantedAuthority> authorities = key.getAuthorities()
			.stream()
			.filter((authority) -> granted.contains(authority.getAuthority()))
			.map(GrantedAuthority.class::cast)
			.toList();
		return new InMemoryApiKey(key.getId(), key.getSecret(), key.getPrincipalName(), key.getLabel(), authorities);
	}

	private @Nullable UserDetails loadActiveUser(String username) {
		UserDetails user;
		try {
			user = this.userDetailsService.loadUserByUsername(username);
		}
		catch (UsernameNotFoundException ex) {
			return null;
		}
		if (!user.isEnabled() || !user.isAccountNonLocked() || !user.isAccountNonExpired()) {
			return null;
		}
		return user;
	}

}
