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

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

import wf.garnier.spring.security.apikey.ApiKeyDetails;
import wf.garnier.spring.security.apikey.ApiKeyPasswordEncoders;
import wf.garnier.spring.security.apikey.ApiKeyRepository;
import wf.garnier.spring.security.apikey.ApiKeySecrets;
import wf.garnier.spring.security.apikey.GeneratedApiKey;

/**
 * An in-memory {@link ApiKeyRepository}, for demos, tests and local development.
 * <p>
 * Details instances are built by a {@link DetailsFactory} on every
 * {@link #findByKeyId(String)} call.
 *
 * @param <T> the type of details returned
 * @author Daniel Garnier-Moiroux
 */
public class InMemoryApiKeyRepository<T extends ApiKeyDetails> implements ApiKeyRepository<T> {

	private static final Pattern VALID = Pattern.compile("[A-Za-z0-9_-]+");

	private final Map<String, StoredKey> keys = new ConcurrentHashMap<>();

	private final AtomicInteger sequence = new AtomicInteger();

	private final DetailsFactory<T> detailsFactory;

	private final PasswordEncoder passwordEncoder;

	public InMemoryApiKeyRepository(DetailsFactory<T> detailsFactory) {
		this(detailsFactory, ApiKeyPasswordEncoders.createDelegatingPasswordEncoder());
	}

	public InMemoryApiKeyRepository(DetailsFactory<T> detailsFactory, PasswordEncoder passwordEncoder) {
		this.detailsFactory = detailsFactory;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public @Nullable T findByKeyId(String keyId) {
		StoredKey stored = this.keys.get(keyId);
		if (stored == null) {
			return null;
		}
		return this.detailsFactory.create(keyId, stored.hash(), stored.name(), stored.authorities());
	}

	@Override
	public GeneratedApiKey generate(String principalName, Collection<? extends GrantedAuthority> authorities) {
		String secret = ApiKeySecrets.generate();
		StoredKey stored = new StoredKey(this.passwordEncoder.encode(secret), principalName, List.copyOf(authorities));
		while (true) {
			String id = "api" + this.sequence.incrementAndGet();
			if (this.keys.putIfAbsent(id, stored) == null) {
				return new GeneratedApiKey(id, secret);
			}
		}
	}

	/**
	 * Add a key with a known id and secret. Intended for tests, demos and local
	 * development only.
	 */
	public void addApiKey(String id, String rawSecret, String name,
			Collection<? extends GrantedAuthority> authorities) {
		Assert.isTrue(VALID.matcher(id).matches(), "id must match [A-Za-z0-9_-]+");
		Assert.isTrue(VALID.matcher(rawSecret).matches(), "secret must match [A-Za-z0-9_-]+");
		StoredKey stored = new StoredKey(this.passwordEncoder.encode(rawSecret), name, List.copyOf(authorities));
		if (this.keys.putIfAbsent(id, stored) != null) {
			throw new IllegalArgumentException("An API key with id '" + id + "' already exists");
		}
	}

	/**
	 * All stored keys, in no particular order. Credentials are erased, so the returned
	 * details never carry the secret or its hash.
	 */
	public List<T> listKeys() {
		return this.keys.entrySet().stream().map(this::toErasedDetails).toList();
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Keys are returned in no particular order.
	 */
	@Override
	public List<T> findByPrincipalName(String principalName) {
		return this.keys.entrySet()
			.stream()
			.filter((entry) -> entry.getValue().name().equals(principalName))
			.map(this::toErasedDetails)
			.toList();
	}

	private T toErasedDetails(Map.Entry<String, StoredKey> entry) {
		StoredKey stored = entry.getValue();
		T details = this.detailsFactory.create(entry.getKey(), stored.hash(), stored.name(), stored.authorities());
		details.eraseCredentials();
		return details;
	}

	@Override
	public void delete(String keyId) {
		this.keys.remove(keyId);
	}

	/**
	 * Builds a details instance from stored key data.
	 *
	 * @param <T> the type of details built
	 */
	@FunctionalInterface
	public interface DetailsFactory<T extends ApiKeyDetails> {

		/**
		 * Build a fresh details instance.
		 * @param id the key id
		 * @param secret the encoded secret
		 * @param name the key name
		 * @param authorities the authorities granted by the key
		 */
		T create(String id, String secret, String name, List<GrantedAuthority> authorities);

	}

	private record StoredKey(String hash, String name, List<GrantedAuthority> authorities) {
	}

}
