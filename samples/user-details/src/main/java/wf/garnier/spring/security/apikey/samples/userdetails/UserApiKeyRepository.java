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
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

import wf.garnier.spring.security.apikey.ApiKeyPasswordEncoders;
import wf.garnier.spring.security.apikey.ApiKeyRepository;
import wf.garnier.spring.security.apikey.ApiKeySecrets;
import wf.garnier.spring.security.apikey.GeneratedApiKey;

/**
 * In-memory API keys owned by users of a {@link UserDetailsService}.
 * <p>
 * The owner is loaded on every lookup, so a key stops working as soon as its owner is
 * deleted, disabled, locked or expired. A key grants the authorities it was created with,
 * minus those its owner no longer has.
 *
 * @author Daniel Garnier-Moiroux
 */
public class UserApiKeyRepository implements ApiKeyRepository<UserApiKeyDetails> {

	private static final Pattern VALID = Pattern.compile("[A-Za-z0-9_-]+");

	private static final String DEFAULT_LABEL = "API key";

	private static final String ID_PREFIX = "api";

	private final Map<String, StoredKey> keys = new ConcurrentHashMap<>();

	private final AtomicLong sequence = new AtomicLong();

	private final PasswordEncoder passwordEncoder = ApiKeyPasswordEncoders.createDelegatingPasswordEncoder();

	private final UserDetailsService userDetailsService;

	public UserApiKeyRepository(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	@Override
	public @Nullable UserApiKeyDetails findByKeyId(String keyId) {
		StoredKey key = this.keys.get(keyId);
		if (key == null) {
			return null;
		}
		UserDetails user = loadActiveUser(key.username());
		if (user == null) {
			return null;
		}
		return toDetails(keyId, key.hash(), key, user);
	}

	/**
	 * Generate a key owned by {@code username}, with a default label.
	 */
	@Override
	public GeneratedApiKey generate(String principalName, Collection<? extends GrantedAuthority> authorities) {
		return generate(principalName, DEFAULT_LABEL, authorities);
	}

	/**
	 * Generate a key owned by {@code username}. Ids are {@code api1}, {@code api2}, and
	 * so on.
	 */
	public GeneratedApiKey generate(String username, String label, Collection<? extends GrantedAuthority> authorities) {
		String secret = ApiKeySecrets.generate();
		StoredKey key = new StoredKey(this.passwordEncoder.encode(secret), username, label, List.copyOf(authorities),
				Instant.now());
		// Skips ids already taken by seeded keys
		while (true) {
			String id = ID_PREFIX + this.sequence.incrementAndGet();
			if (this.keys.putIfAbsent(id, key) == null) {
				return new GeneratedApiKey(id, secret);
			}
		}
	}

	/**
	 * Add a key with a known id and secret, owned by {@code username}. For demos only.
	 */
	public void addApiKey(String id, String rawSecret, String username, String label,
			Collection<? extends GrantedAuthority> authorities) {
		Assert.isTrue(VALID.matcher(id).matches(), "id must match [A-Za-z0-9_-]+");
		Assert.isTrue(VALID.matcher(rawSecret).matches(), "secret must match [A-Za-z0-9_-]+");
		StoredKey key = new StoredKey(this.passwordEncoder.encode(rawSecret), username, label, List.copyOf(authorities),
				Instant.now());
		if (this.keys.putIfAbsent(id, key) != null) {
			throw new IllegalArgumentException("An API key with id '" + id + "' already exists");
		}
	}

	/**
	 * The keys owned by {@code principalName}, oldest first. They never carry the secret
	 * or its hash. Empty if the owner is no longer active.
	 */
	@Override
	public List<UserApiKeyDetails> findByPrincipalName(String principalName) {
		UserDetails user = loadActiveUser(principalName);
		if (user == null) {
			return List.of();
		}
		return this.keys.entrySet()
			.stream()
			.filter((entry) -> entry.getValue().username().equals(principalName))
			.map((entry) -> toDetails(entry.getKey(), null, entry.getValue(), user))
			.sorted(Comparator.comparing(UserApiKeyDetails::getCreatedAt).thenComparing(UserApiKeyDetails::getId))
			.toList();
	}

	@Override
	public void delete(String keyId) {
		this.keys.remove(keyId);
	}

	/**
	 * Delete a key, only if it is owned by {@code username}.
	 */
	public void delete(String username, String keyId) {
		this.keys.computeIfPresent(keyId, (id, key) -> key.username().equals(username) ? null : key);
	}

	private static UserApiKeyDetails toDetails(String keyId, @Nullable String hash, StoredKey key, UserDetails user) {
		Set<@Nullable String> granted = user.getAuthorities()
			.stream()
			.map(GrantedAuthority::getAuthority)
			.collect(Collectors.toSet());
		List<GrantedAuthority> authorities = key.authorities()
			.stream()
			.filter((authority) -> granted.contains(authority.getAuthority()))
			.toList();
		return new UserApiKeyDetails(keyId, hash, key.username(), key.label(), authorities, key.createdAt());
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

	private record StoredKey(String hash, String username, String label, List<GrantedAuthority> authorities,
			Instant createdAt) {
	}

}
