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

import static org.assertj.core.api.Assertions.assertThat;

class UserApiKeyRepositoryTests {

	UserApiKeyRepository repository = new UserApiKeyRepository(new InMemoryUserDetailsManager(
			User.withUsername("alice").password("{noop}password").roles("USER").build()));

	@Test
	void generatedIdsAreSequential() {
		assertThat(this.repository.generate("alice", List.of()).id()).isEqualTo("api1");
		assertThat(this.repository.generate("alice", List.of()).id()).isEqualTo("api2");
		assertThat(this.repository.generate("alice", List.of()).id()).isEqualTo("api3");
	}

	@Test
	void generatedIdsSkipSeededIds() {
		this.repository.addApiKey("api2", "seeded-secret", "alice", "Seeded",
				AuthorityUtils.createAuthorityList("ROLE_USER"));

		assertThat(this.repository.generate("alice", List.of()).id()).isEqualTo("api1");
		assertThat(this.repository.generate("alice", List.of()).id()).isEqualTo("api3");
		assertThat(this.repository.findByPrincipalName("alice")).extracting(UserApiKey::getLabel)
			.containsExactly("Seeded", "API key", "API key");
	}

	@Test
	void userFacingKeyIsIdDotSecret() {
		GeneratedApiKey key = this.repository.generate("alice", List.of());
		assertThat(key.getUserFacingApiKey()).isEqualTo("api1." + key.rawSecret()).matches("api1\\.[A-Za-z0-9_-]{43}");
	}

}
