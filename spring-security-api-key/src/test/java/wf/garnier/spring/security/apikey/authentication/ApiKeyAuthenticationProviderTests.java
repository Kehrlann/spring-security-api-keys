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

import java.util.ArrayList;
import java.util.List;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import wf.garnier.spring.security.apikey.ApiKeyPasswordEncoders;
import wf.garnier.spring.security.apikey.GeneratedApiKey;
import wf.garnier.spring.security.apikey.memory.InMemoryApiKeyDetails;
import wf.garnier.spring.security.apikey.memory.InMemoryApiKeyRepository;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ApiKeyAuthenticationProviderTests {

	InMemoryApiKeyRepository<InMemoryApiKeyDetails> repository = new InMemoryApiKeyRepository<>(
			InMemoryApiKeyDetails::new);

	List<String> encoderCalls = new ArrayList<>();

	PasswordEncoder spyEncoder = new PasswordEncoder() {
		final PasswordEncoder delegate = ApiKeyPasswordEncoders.createDelegatingPasswordEncoder();

		public @Nullable String encode(@Nullable CharSequence raw) {
			return this.delegate.encode(raw);
		}

		public boolean matches(@Nullable CharSequence raw, @Nullable String encoded) {
			ApiKeyAuthenticationProviderTests.this.encoderCalls.add(String.valueOf(raw));
			return this.delegate.matches(raw, encoded);
		}
	};

	ApiKeyAuthenticationProvider provider = new ApiKeyAuthenticationProvider(this.repository, this.spyEncoder);

	@Test
	void successCarriesAuthoritiesAndFactor() {
		this.repository.addApiKey("id", "secret", "Name", List.of(new SimpleGrantedAuthority("A")));
		Authentication result = this.provider.authenticate(ApiKeyAuthenticationToken.unauthenticated("id", "secret"));
		assertThat(result.isAuthenticated()).isTrue();
		assertThat(result.getName()).isEqualTo("Name");
		assertThat(result.getCredentials()).isNull();
		assertThat(result.getAuthorities()).extracting(GrantedAuthority::getAuthority)
			.containsExactlyInAnyOrder("A", "FACTOR_API_KEY");
		assertThat(ApiKeyAuthenticationProvider.FACTOR_API_KEY).isEqualTo("API_KEY");
	}

	@Test
	void looksUpTheKeyIdNotTheNameWhenThePrincipalIsDetails() {
		this.repository.addApiKey("id", "secret", "Name", List.of());
		InMemoryApiKeyDetails details = this.repository.findByKeyId("id");
		assertThat(details).isNotNull();
		ApiKeyAuthenticationToken token = ApiKeyAuthenticationToken.authenticated(details, List.of())
			.toBuilder()
			.credentials("secret")
			.authenticated(false)
			.build();
		assertThat(this.provider.authenticate(token).getName()).isEqualTo("Name");
	}

	@Test
	void unknownIdAndWrongSecretLookIdentical() {
		GeneratedApiKey key = this.repository.generate("n", List.of());
		assertThatThrownBy(
				() -> this.provider.authenticate(ApiKeyAuthenticationToken.unauthenticated(key.id(), "wrong")))
			.isInstanceOf(BadCredentialsException.class)
			.hasMessage("Invalid API key");
		assertThatThrownBy(
				() -> this.provider.authenticate(ApiKeyAuthenticationToken.unauthenticated("nobody", "wrong")))
			.isInstanceOf(BadCredentialsException.class)
			.hasMessage("Invalid API key");
	}

	@Test
	void unknownIdStillPerformsAHashComparison() {
		var token = ApiKeyAuthenticationToken.unauthenticated("nobody", "presented");
		assertThatThrownBy(() -> this.provider.authenticate(token)).isInstanceOf(BadCredentialsException.class);
		assertThat(this.encoderCalls).containsExactly("presented");
	}

	@Test
	void repositoryFailureIsWrapped() {
		var failing = new InMemoryApiKeyRepository<>(InMemoryApiKeyDetails::new) {
			@Override
			public InMemoryApiKeyDetails findByKeyId(String keyId) {
				throw new IllegalStateException("db down");
			}
		};
		ApiKeyAuthenticationProvider p = new ApiKeyAuthenticationProvider(failing);
		assertThatExceptionOfType(InternalAuthenticationServiceException.class)
			.isThrownBy(() -> p.authenticate(ApiKeyAuthenticationToken.unauthenticated("id", "s")));
	}

	@Test
	void supportsOnlyApiKeyTokens() {
		assertThat(this.provider.supports(ApiKeyAuthenticationToken.class)).isTrue();
		assertThat(this.provider.supports(UsernamePasswordAuthenticationToken.class)).isFalse();
	}

}
