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

package wf.garnier.spring.security.apikey.web;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ApiKeyAuthenticationConverterTests {

	ApiKeyAuthenticationConverter converter = new ApiKeyAuthenticationConverter();

	private @Nullable Authentication convert(String... values) {
		MockHttpServletRequest request = new MockHttpServletRequest();
		for (String value : values) {
			request.addHeader("X-API-Key", value);
		}
		return this.converter.convert(request);
	}

	@Test
	void noHeader() {
		assertThat(convert()).isNull();
	}

	@Test
	void validKey() {
		Authentication auth = convert("id1.sec_ret-2");
		assertThat(auth).isNotNull();
		assertThat(auth.getName()).isEqualTo("id1");
		assertThat(auth.getCredentials()).isEqualTo("sec_ret-2");
		assertThat(auth.isAuthenticated()).isFalse();
	}

	@Test
	void trimsWhitespace() {
		Authentication auth = convert("  id.secret \t");
		assertThat(auth).isNotNull();
		assertThat(auth.getName()).isEqualTo("id");
	}

	@Test
	void blankIsNull() {
		assertThat(convert("   ")).isNull();
		assertThat(convert("")).isNull();
	}

	@Test
	void malformedIsRejected() {
		for (String value : new String[] { "nodot", "a.b.c", ".secret", "id.", ".", "i d.secret", "id.sec ret",
				"id.sécret", "a=.b" }) {
			assertThatExceptionOfType(BadCredentialsException.class).as(value)
				.isThrownBy(() -> convert(value))
				.withMessage("Malformed API key");
		}
	}

	@Test
	void duplicateHeadersAreRejected() {
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> convert("a.b", "c.d"));
	}

	@Test
	void customHeaderName() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("X-Acme-Key", "id.secret");
		assertThat(new ApiKeyAuthenticationConverter("X-Acme-Key").convert(request)).isNotNull();
		assertThat(this.converter.convert(request)).isNull();
	}

}
