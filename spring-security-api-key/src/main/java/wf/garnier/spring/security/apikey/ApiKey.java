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

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;

/**
 * A stored API key along with the authorities and name it grants. Implementations are
 * used as the principal of an authenticated API key.
 *
 * @author Daniel Garnier-Moiroux
 */
public interface ApiKey extends CredentialsContainer {

	String getId();

	/**
	 * The encoded hash of the secret, never the raw secret presented by a client.
	 * {@code null} once credentials have been erased.
	 */
	@Nullable String getSecret();

	Collection<? extends GrantedAuthority> getAuthorities();

	/**
	 * The name of the authenticated principal. Defaults to the key id.
	 */
	default String getPrincipalName() {
		return getId();
	}

	/**
	 * A human-readable label for the key, for example to list a user's keys. Defaults to
	 * the key id.
	 */
	default String getLabel() {
		return getId();
	}

}
