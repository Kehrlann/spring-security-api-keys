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

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;

import wf.garnier.spring.security.apikey.authentication.ApiKeyAuthenticationProvider;
import wf.garnier.spring.security.apikey.memory.InMemoryApiKeyDetails;
import wf.garnier.spring.security.apikey.memory.InMemoryApiKeyRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ApiKeyAuthenticationFilterTests {

	InMemoryApiKeyRepository<InMemoryApiKeyDetails> repository = new InMemoryApiKeyRepository<>(
			InMemoryApiKeyDetails::new);

	AuthenticationManager manager = new ProviderManager(new ApiKeyAuthenticationProvider(this.repository));

	MockHttpServletRequest request = new MockHttpServletRequest();

	MockHttpServletResponse response = new MockHttpServletResponse();

	MockFilterChain chain = new MockFilterChain();

	ApiKeyAuthenticationFilterTests() {
		this.repository.addApiKey("id", "secret", "n", List.of());
	}

	@Test
	void passesThroughWithoutKey() throws Exception {
		new ApiKeyAuthenticationFilter(this.manager).doFilter(this.request, this.response, this.chain);
		assertThat(this.chain.getRequest()).isNotNull();
		assertThat(this.response.getStatus()).isEqualTo(200);
	}

	@Test
	void validKeyContinuesChainWithoutRedirectOrSession() throws Exception {
		this.request.addHeader("X-API-Key", "id.secret");
		new ApiKeyAuthenticationFilter(this.manager).doFilter(this.request, this.response, this.chain);
		assertThat(this.chain.getRequest()).isNotNull();
		assertThat(this.response.getRedirectedUrl()).isNull();
		assertThat(this.request.getSession(false)).isNull();
		SecurityContext context = new RequestAttributeSecurityContextRepository().loadDeferredContext(this.request)
			.get();
		assertThat(context.getAuthentication()).isNotNull();
		assertThat(context.getAuthentication().getName()).isEqualTo("n");
	}

	@Test
	void invalidKeyGetsBare401() throws Exception {
		this.request.addHeader("X-API-Key", "id.wrong");
		new ApiKeyAuthenticationFilter(this.manager).doFilter(this.request, this.response, this.chain);
		assertThat(this.chain.getRequest()).isNull();
		assertThat(this.response.getStatus()).isEqualTo(401);
		assertThat(this.response.getContentAsString()).isEmpty();
		assertThat(this.response.getHeader("WWW-Authenticate")).isNull();
	}

	@Test
	void authenticationServiceExceptionIsRethrown() {
		AuthenticationManager failing = (a) -> {
			throw new AuthenticationServiceException("down");
		};
		this.request.addHeader("X-API-Key", "id.secret");
		assertThatExceptionOfType(AuthenticationServiceException.class).isThrownBy(
				() -> new ApiKeyAuthenticationFilter(failing).doFilter(this.request, this.response, this.chain));
	}

	@Test
	void customConverterConstructor() throws Exception {
		var filter = new ApiKeyAuthenticationFilter(this.manager, new ApiKeyAuthenticationConverter("X-Other"));
		this.request.addHeader("X-Other", "id.wrong");
		filter.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(401);
	}

}
