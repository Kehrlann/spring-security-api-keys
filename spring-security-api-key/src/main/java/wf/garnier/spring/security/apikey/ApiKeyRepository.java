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

package wf.garnier.spring.security.apikey;

import java.util.Collection;
import java.util.List;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.GrantedAuthority;

/**
 * Storage for API keys.
 * <p>
 * Contract for implementations:
 * <ul>
 * <li>Secrets must be hashed before being stored, never stored in plaintext. Use
 * {@link ApiKeySecrets#generate()} to create secrets.</li>
 * <li>{@link #findByKeyId(String)} must return a fresh instance on each call, as
 * credentials are erased after authentication.</li>
 * <li>Key ids must match {@code [A-Za-z0-9_-]+}.</li>
 * <li>Keys that are expired or revoked must not be returned.</li>
 * </ul>
 *
 * @param <T> the type of details stored
 * @author Daniel Garnier-Moiroux
 */
public interface ApiKeyRepository<T extends ApiKeyDetails> {

	/**
	 * Find a key by id.
	 * @return a fresh instance, or {@code null} if the id is unknown
	 */
	@Nullable T findByKeyId(String keyId);

	/**
	 * List the keys owned by a principal. Credentials are erased, so the returned details
	 * never carry the secret or its hash.
	 * @return the keys, or an empty list if the principal owns none
	 */
	List<T> findByPrincipalName(String principalName);

	/**
	 * Generate, hash and persist a new key. The raw secret is only available in the
	 * returned value.
	 */
	GeneratedApiKey generate(String principalName, Collection<? extends GrantedAuthority> authorities);

	/**
	 * Delete a key. Deleting an unknown id is a no-op.
	 */
	void delete(String keyId);

}
