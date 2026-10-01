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

package wf.garnier.spring.security.apikey.authentication;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.Transient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import wf.garnier.spring.security.apikey.ApiKeyDetails;
import wf.garnier.spring.security.apikey.memory.InMemoryApiKeyDetails;
import wf.garnier.spring.security.apikey.memory.InMemoryApiKeyRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class ApiKeyAuthenticationTokenTests {

	InMemoryApiKeyDetails details() {
		InMemoryApiKeyRepository<InMemoryApiKeyDetails> repository = new InMemoryApiKeyRepository<>(
				InMemoryApiKeyDetails::new);
		repository.addApiKey("id", "secret", "Display Name", List.of(new SimpleGrantedAuthority("A")));
		InMemoryApiKeyDetails details = repository.findByKeyId("id");
		assertThat(details).isNotNull();
		return details;
	}

	@Test
	void unauthenticatedState() {
		ApiKeyAuthenticationToken token = ApiKeyAuthenticationToken.unauthenticated("id", "secret");
		assertThat(token.isAuthenticated()).isFalse();
		assertThat(token.getName()).isEqualTo("id");
		assertThat(token.getCredentials()).isEqualTo("secret");
		assertThat(token.getAuthorities()).isEmpty();
	}

	@Test
	void authenticatedState() {
		InMemoryApiKeyDetails details = details();
		ApiKeyAuthenticationToken token = ApiKeyAuthenticationToken.authenticated(details, details.getAuthorities());
		assertThat(token.isAuthenticated()).isTrue();
		assertThat(token.getName()).isEqualTo("Display Name");
		assertThat(token.getPrincipal()).isSameAs(details);
		assertThat(token.getCredentials()).isNull();
		assertThat(token.getAuthorities()).extracting("authority").containsExactly("A");
	}

	@Test
	void cannotBeMarkedTrusted() {
		ApiKeyAuthenticationToken token = ApiKeyAuthenticationToken.unauthenticated("id", "secret");
		assertThatIllegalArgumentException().isThrownBy(() -> token.setAuthenticated(true));
		assertThat(token.isAuthenticated()).isFalse();
		InMemoryApiKeyDetails details = details();
		ApiKeyAuthenticationToken authenticated = ApiKeyAuthenticationToken.authenticated(details,
				details.getAuthorities());
		authenticated.setAuthenticated(false);
		assertThat(authenticated.isAuthenticated()).isFalse();
	}

	@Test
	void eraseCredentialsErasesPrincipalHash() {
		InMemoryApiKeyDetails details = details();
		ApiKeyAuthenticationToken token = ApiKeyAuthenticationToken.authenticated(details, details.getAuthorities());
		token.eraseCredentials();
		assertThat(details.getSecret()).isNull();
		ApiKeyAuthenticationToken raw = ApiKeyAuthenticationToken.unauthenticated("id", "secret");
		raw.eraseCredentials();
		assertThat(raw.getCredentials()).isNull();
	}

	@Test
	void toBuilderIsDeclaredAndPreservesState() throws Exception {
		assertThat(ApiKeyAuthenticationToken.class.getDeclaredMethod("toBuilder")).isNotNull();
		InMemoryApiKeyDetails details = details();
		ApiKeyAuthenticationToken token = ApiKeyAuthenticationToken.authenticated(details, details.getAuthorities());
		var rebuilt = token.toBuilder().authorities((a) -> a.add(new SimpleGrantedAuthority("B"))).build();
		assertThat(rebuilt.getPrincipal()).isSameAs(details);
		assertThat(rebuilt.getName()).isEqualTo("Display Name");
		assertThat(rebuilt.isAuthenticated()).isTrue();
		assertThat(rebuilt.getAuthorities()).extracting("authority").containsExactlyInAnyOrder("A", "B");
	}

	@Test
	void unauthenticatedSurvivesSerialization() throws Exception {
		ApiKeyAuthenticationToken token = roundTrip(ApiKeyAuthenticationToken.unauthenticated("id", "secret"));
		assertThat(token.isAuthenticated()).isFalse();
		assertThat(token.getName()).isEqualTo("id");
		assertThat(token.getCredentials()).isEqualTo("secret");
		assertThat(token.getAuthorities()).isEmpty();
	}

	@Test
	void authenticatedSurvivesSerialization() throws Exception {
		InMemoryApiKeyDetails details = details();
		ApiKeyAuthenticationToken token = roundTrip(
				ApiKeyAuthenticationToken.authenticated(details, details.getAuthorities()));
		assertThat(token.isAuthenticated()).isTrue();
		assertThat(token.getName()).isEqualTo("Display Name");
		assertThat(token.getCredentials()).isNull();
		assertThat(token.getAuthorities()).extracting("authority").containsExactly("A");
		ApiKeyDetails principal = (ApiKeyDetails) token.getPrincipal();
		assertThat(principal.getId()).isEqualTo("id");
		assertThat(principal.getSecret()).isEqualTo(details.getSecret());
		assertThat(principal.getAuthorities()).extracting("authority").containsExactly("A");
	}

	private static ApiKeyAuthenticationToken roundTrip(ApiKeyAuthenticationToken token)
			throws IOException, ClassNotFoundException {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
			out.writeObject(token);
		}
		try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
			return (ApiKeyAuthenticationToken) in.readObject();
		}
	}

	@Test
	void isTransient() {
		assertThat(ApiKeyAuthenticationToken.class.isAnnotationPresent(Transient.class)).isTrue();
	}

}
