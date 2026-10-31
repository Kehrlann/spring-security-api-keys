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

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

class ApiKeyUnitTests {

	PasswordEncoder encoder = ApiKeyPasswordEncoders.createDelegatingPasswordEncoder();

	@Test
	void encodesWithSha256PrefixAndLowercaseHex() {
		assertThat(this.encoder.encode("secret"))
			.isEqualTo("{sha256}2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b");
	}

	@Test
	void matchesSha256AndRejectsWrongSecret() {
		String hash = this.encoder.encode("secret");
		assertThat(this.encoder.matches("secret", hash)).isTrue();
		assertThat(this.encoder.matches("other", hash)).isFalse();
	}

	@Test
	void matchesBcryptHashes() {
		String hash = "{bcrypt}" + new BCryptPasswordEncoder().encode("secret");
		assertThat(this.encoder.matches("secret", hash)).isTrue();
		assertThat(this.encoder.matches("other", hash)).isFalse();
	}

	@Test
	void secretsAreUnpaddedBase64UrlOf43CharsAndUnique() {
		Set<String> seen = new HashSet<>();
		for (int i = 0; i < 100; i++) {
			String secret = ApiKeySecrets.generate();
			assertThat(secret).matches("[A-Za-z0-9_-]{43}");
			seen.add(secret);
		}
		assertThat(seen).hasSize(100);
	}

	@Test
	void generatedApiKeyFormatAndRedaction() {
		GeneratedApiKey key = new GeneratedApiKey("api1", "s3cret");
		assertThat(key.id()).isEqualTo("api1");
		assertThat(key.rawSecret()).isEqualTo("s3cret");
		assertThat(key.getUserFacingApiKey()).isEqualTo("api1.s3cret");
		assertThat(key.toString()).contains("api1").doesNotContain("s3cret");
	}

	@Test
	void detailsNameAndLabelDefaultToId() {
		ApiKeyDetails details = new ApiKeyDetails() {
			public String getId() {
				return "abc";
			}

			public String getSecret() {
				return "x";
			}

			public java.util.Collection<org.springframework.security.core.GrantedAuthority> getAuthorities() {
				return java.util.List.of();
			}

			public void eraseCredentials() {
			}
		};
		assertThat(details.getPrincipalName()).isEqualTo("abc");
		assertThat(details.getLabel()).isEqualTo("abc");
	}

}
