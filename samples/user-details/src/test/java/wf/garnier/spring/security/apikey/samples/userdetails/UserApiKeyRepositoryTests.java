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

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import wf.garnier.spring.security.apikey.GeneratedApiKey;
import wf.garnier.spring.security.apikey.memory.InMemoryApiKey;
import wf.garnier.spring.security.apikey.memory.InMemoryApiKeyRepository;

import static org.assertj.core.api.Assertions.assertThat;

class UserApiKeyRepositoryTests {

	InMemoryApiKeyRepository<InMemoryApiKey> keys = new InMemoryApiKeyRepository<>(InMemoryApiKey::new);

	InMemoryUserDetailsManager users = new InMemoryUserDetailsManager(
			User.withUsername("alice").password("{noop}password").roles("USER").build(),
			User.withUsername("bob").password("{noop}password").roles("USER").build());

	UserApiKeyRepository repository = new UserApiKeyRepository(this.keys, this.users);

	@Test
	void listsOwnKeysByLabelWithoutCredentials() {
		this.repository.generate("alice", "Zeta", List.of());
		this.repository.generate("alice", "Alpha", List.of());
		this.repository.generate("bob", "Bob's key", List.of());

		List<InMemoryApiKey> keys = this.repository.findByPrincipalName("alice");

		assertThat(keys).extracting(InMemoryApiKey::getLabel).containsExactly("Alpha", "Zeta");
		assertThat(keys).extracting(InMemoryApiKey::getSecret).containsOnlyNulls();
	}

	@Test
	void keyGrantsOnlyAuthoritiesItsOwnerHas() {
		GeneratedApiKey key = this.repository.generate("alice", "Key",
				AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN"));

		InMemoryApiKey found = this.repository.findByKeyId(key.id());

		assertThat(found).isNotNull();
		assertThat(found.getSecret()).isNotNull();
		assertThat(found.getAuthorities()).extracting("authority").containsExactly("ROLE_USER");
		assertThat(this.repository.findByPrincipalName("alice")).flatExtracting(InMemoryApiKey::getAuthorities)
			.extracting("authority")
			.containsExactly("ROLE_USER");
	}

	@Test
	void keyOfInactiveOwnerIsNotFound() {
		GeneratedApiKey key = this.repository.generate("alice", "Key", List.of());
		this.users.updateUser(User.withUsername("alice").password("{noop}password").disabled(true).build());

		assertThat(this.repository.findByKeyId(key.id())).isNull();
		assertThat(this.repository.findByPrincipalName("alice")).isEmpty();
	}

	@Test
	void deletesOnlyOwnKeys() {
		GeneratedApiKey key = this.repository.generate("alice", "Key", List.of());

		this.repository.delete("bob", key.id());
		assertThat(this.repository.findByKeyId(key.id())).isNotNull();

		this.repository.delete("alice", key.id());
		assertThat(this.repository.findByKeyId(key.id())).isNull();
	}

}
