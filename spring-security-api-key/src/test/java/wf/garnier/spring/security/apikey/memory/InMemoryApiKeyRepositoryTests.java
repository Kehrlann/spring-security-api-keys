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

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import wf.garnier.spring.security.apikey.ApiKey;
import wf.garnier.spring.security.apikey.GeneratedApiKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class InMemoryApiKeyRepositoryTests {

	InMemoryApiKeyRepository<InMemoryApiKey> repository = new InMemoryApiKeyRepository<>(InMemoryApiKey::new);

	@Test
	void generatesSequentialIds() {
		assertThat(this.repository.generate("a", List.of()).id()).isEqualTo("api1");
		assertThat(this.repository.generate("b", List.of()).id()).isEqualTo("api2");
	}

	@Test
	void generateSkipsSeededIds() {
		this.repository.addApiKey("api1", "secret", "seeded", List.of());
		GeneratedApiKey key = this.repository.generate("a", List.of());
		assertThat(key.id()).isEqualTo("api2");
		InMemoryApiKey seeded = this.repository.findByKeyId("api1");
		assertThat(seeded).isNotNull();
		assertThat(seeded.getPrincipalName()).isEqualTo("seeded");
	}

	@Test
	void seedingValidatesIdAndSecret() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.repository.addApiKey("a.b", "secret", "n", List.of()));
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.repository.addApiKey("a", "se cret", "n", List.of()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.repository.addApiKey("", "secret", "n", List.of()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.repository.addApiKey("a", "", "n", List.of()));
	}

	@Test
	void duplicateSeedingThrows() {
		this.repository.addApiKey("a", "secret", "n", List.of());
		assertThatIllegalArgumentException().isThrownBy(() -> this.repository.addApiKey("a", "other", "n", List.of()));
	}

	@Test
	void secretsAreStoredHashed() {
		this.repository.addApiKey("a", "secret", "n", List.of());
		InMemoryApiKey details = this.repository.findByKeyId("a");
		assertThat(details).isNotNull();
		assertThat(details.getSecret()).startsWith("{sha256}").doesNotContain("secret");
	}

	@Test
	void findReturnsFreshInstances() {
		this.repository.addApiKey("a", "secret", "n", List.of(new SimpleGrantedAuthority("X")));
		InMemoryApiKey first = this.repository.findByKeyId("a");
		assertThat(first).isNotNull();
		first.eraseCredentials();
		assertThat(first.getSecret()).isNull();
		InMemoryApiKey second = this.repository.findByKeyId("a");
		assertThat(second).isNotNull();
		assertThat(second.getSecret()).isNotNull();
		assertThat(second.getAuthorities()).extracting("authority").containsExactly("X");
	}

	@Test
	void seedingWithLabelStoresLabel() {
		this.repository.addApiKey("a", "secret", "n", "CI pipeline", List.of());
		InMemoryApiKey details = this.repository.findByKeyId("a");
		assertThat(details).isNotNull();
		assertThat(details.getLabel()).isEqualTo("CI pipeline");
		assertThat(this.repository.listKeys()).extracting(InMemoryApiKey::getLabel).containsExactly("CI pipeline");
	}

	@Test
	void labelDefaultsToId() {
		this.repository.addApiKey("a", "secret", "n", List.of());
		GeneratedApiKey generated = this.repository.generate("g", List.of());
		assertThat(this.repository.findByKeyId("a")).extracting(InMemoryApiKey::getLabel).isEqualTo("a");
		assertThat(this.repository.findByKeyId(generated.id())).extracting(InMemoryApiKey::getLabel)
			.isEqualTo(generated.id());
	}

	@Test
	void unknownIdIsNull() {
		assertThat(this.repository.findByKeyId("nope")).isNull();
	}

	@Test
	void deleteRemovesAndIsIdempotent() {
		this.repository.addApiKey("a", "secret", "n", List.of());
		this.repository.delete("a");
		this.repository.delete("a");
		this.repository.delete("never-existed");
		assertThat(this.repository.findByKeyId("a")).isNull();
	}

	@Test
	void listKeysReturnsAllKeysWithoutCredentials() {
		this.repository.addApiKey("a", "secret", "seeded", List.of(new SimpleGrantedAuthority("X")));
		GeneratedApiKey generated = this.repository.generate("generated", List.of());
		this.repository.addApiKey("deleted", "secret", "deleted", List.of());
		this.repository.delete("deleted");

		List<InMemoryApiKey> keys = this.repository.listKeys();

		assertThat(keys).extracting(InMemoryApiKey::getId).containsExactlyInAnyOrder("a", generated.id());
		assertThat(keys).extracting(InMemoryApiKey::getPrincipalName).containsExactlyInAnyOrder("seeded", "generated");
		assertThat(keys).extracting(InMemoryApiKey::getSecret).containsOnlyNulls();
		InMemoryApiKey found = this.repository.findByKeyId("a");
		assertThat(found).isNotNull();
		assertThat(found.getSecret()).isNotNull();
	}

	@Test
	void listKeysIsEmptyWhenNoKeys() {
		assertThat(this.repository.listKeys()).isEmpty();
	}

	@Test
	void listByPrincipalNameReturnsOwnedKeysWithoutCredentials() {
		this.repository.addApiKey("a", "secret", "alice", List.of(new SimpleGrantedAuthority("X")));
		GeneratedApiKey generated = this.repository.generate("alice", List.of());
		this.repository.addApiKey("b", "secret", "bob", List.of());
		this.repository.addApiKey("deleted", "secret", "alice", List.of());
		this.repository.delete("deleted");

		List<InMemoryApiKey> keys = this.repository.findByPrincipalName("alice");

		assertThat(keys).extracting(InMemoryApiKey::getId).containsExactlyInAnyOrder("a", generated.id());
		assertThat(keys).extracting(InMemoryApiKey::getSecret).containsOnlyNulls();
		InMemoryApiKey found = this.repository.findByKeyId("a");
		assertThat(found).isNotNull();
		assertThat(found.getSecret()).isNotNull();
	}

	@Test
	void listByPrincipalNameIsEmptyForUnknownPrincipal() {
		this.repository.addApiKey("a", "secret", "alice", List.of());
		assertThat(this.repository.findByPrincipalName("bob")).isEmpty();
	}

	@Test
	void usesCustomEncoder() {
		PasswordEncoder encoder = new PasswordEncoder() {
			public String encode(@Nullable CharSequence raw) {
				return "custom:" + raw;
			}

			public boolean matches(@Nullable CharSequence raw, @Nullable String encoded) {
				return ("custom:" + raw).equals(encoded);
			}
		};
		InMemoryApiKeyRepository<InMemoryApiKey> custom = new InMemoryApiKeyRepository<>(InMemoryApiKey::new, encoder);
		custom.addApiKey("a", "secret", "n", List.of());
		InMemoryApiKey seeded = custom.findByKeyId("a");
		assertThat(seeded).isNotNull();
		assertThat(seeded.getSecret()).isEqualTo("custom:secret");
		GeneratedApiKey key = custom.generate("g", List.of());
		InMemoryApiKey generated = custom.findByKeyId(key.id());
		assertThat(generated).isNotNull();
		assertThat(generated.getSecret()).isEqualTo("custom:" + key.rawSecret());
	}

	@Test
	void usesDetailsFactory() {
		InMemoryApiKeyRepository<TaggedApiKey> tagged = new InMemoryApiKeyRepository<>(
				(id, secret, name, label, authorities) -> new TaggedApiKey(
						new InMemoryApiKey(id, secret, name, label, authorities), "tag-" + id));
		tagged.addApiKey("a", "secret", "n", "My key", List.of(new SimpleGrantedAuthority("X")));
		TaggedApiKey details = tagged.findByKeyId("a");
		assertThat(details).isNotNull();
		assertThat(details.tag()).isEqualTo("tag-a");
		assertThat(details.getPrincipalName()).isEqualTo("n");
		assertThat(details.delegate().getLabel()).isEqualTo("My key");
		assertThat(details.getSecret()).startsWith("{sha256}");
		assertThat(details.getAuthorities()).extracting("authority").containsExactly("X");
	}

	record TaggedApiKey(ApiKey delegate, String tag) implements ApiKey {

		@Override
		public String getId() {
			return this.delegate.getId();
		}

		@Override
		public @Nullable String getSecret() {
			return this.delegate.getSecret();
		}

		@Override
		public String getPrincipalName() {
			return this.delegate.getPrincipalName();
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return this.delegate.getAuthorities();
		}

		@Override
		public void eraseCredentials() {
			this.delegate.eraseCredentials();
		}

	}

}
