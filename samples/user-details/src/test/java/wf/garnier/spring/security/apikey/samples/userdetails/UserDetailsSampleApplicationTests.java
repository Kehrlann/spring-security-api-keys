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

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.test.web.servlet.assertj.MvcTestResult;

import wf.garnier.spring.security.apikey.GeneratedApiKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;

@SpringBootTest
@AutoConfigureMockMvc
class UserDetailsSampleApplicationTests {

	@Autowired
	MockMvcTester mvc;

	@Autowired
	UserApiKeyRepository apiKeyRepository;

	@Autowired
	InMemoryUserDetailsManager users;

	@Test
	void apiKeyAuthenticatesAsItsOwner() {
		assertThat(this.mvc.get().uri("/api/me").header("X-API-Key", "alice-admin.alice-admin-secret")).hasStatusOk()
			.bodyJson()
			.isLenientlyEqualTo("""
					{ "name": "alice", "authorities": ["ROLE_USER", "ROLE_ADMIN", "FACTOR_API_KEY"] }
					""");
	}

	@Test
	void apiKeyIsScopedToItsAuthorities() {
		assertThat(this.mvc.get().uri("/api/admin").header("X-API-Key", "alice-admin.alice-admin-secret"))
			.hasStatusOk();
		assertThat(this.mvc.get().uri("/api/admin").header("X-API-Key", "alice-user.alice-user-secret"))
			.hasStatus(HttpStatus.FORBIDDEN);
	}

	@Test
	void apiKeyNeverGrantsMoreThanItsOwnerHas() {
		assertThat(this.mvc.get().uri("/api/me").header("X-API-Key", "bob.bob-secret")).hasStatusOk()
			.bodyJson()
			.isLenientlyEqualTo("""
					{ "name": "bob", "authorities": ["ROLE_USER", "FACTOR_API_KEY"] }
					""");
		assertThat(this.mvc.get().uri("/api/admin").header("X-API-Key", "bob.bob-secret"))
			.hasStatus(HttpStatus.FORBIDDEN);
	}

	@Test
	void apiKeyOfDisabledUserIsRejected() {
		assertThat(this.mvc.get().uri("/api/me").header("X-API-Key", "carol.carol-secret"))
			.hasStatus(HttpStatus.UNAUTHORIZED);
	}

	@Test
	void apiKeyOfDeletedUserIsRejected() {
		this.users.createUser(User.withUsername("dave").password("{noop}password").roles("USER").build());
		GeneratedApiKey key = this.apiKeyRepository.generate("dave", AuthorityUtils.createAuthorityList("ROLE_USER"));
		assertThat(this.mvc.get().uri("/api/me").header("X-API-Key", key.getUserFacingApiKey())).hasStatusOk();

		this.users.deleteUser("dave");

		assertThat(this.mvc.get().uri("/api/me").header("X-API-Key", key.getUserFacingApiKey()))
			.hasStatus(HttpStatus.UNAUTHORIZED);
	}

	@Test
	void apiWithoutCredentialsGets401() {
		assertThat(this.mvc.get().uri("/api/me")).hasStatus(HttpStatus.UNAUTHORIZED);
	}

	@Test
	void browserIsRedirectedToLogin() {
		assertThat(this.mvc.get().uri("/").accept(MediaType.TEXT_HTML)).hasStatus3xxRedirection()
			.hasRedirectedUrl("/login");
	}

	@Test
	void pageListsOwnKeysOnly() {
		MockHttpSession session = login("alice");
		assertThat(this.mvc.get().uri("/").session(session)).hasStatusOk()
			.bodyText()
			.contains("alice-admin", "Admin key", "alice-user", "Read-only key")
			.doesNotContain("Overreaching key");
	}

	@Test
	void createKey() {
		MockHttpSession session = login("alice");
		MvcTestResult result = this.mvc.post()
			.uri("/api-keys")
			.session(session)
			.param("label", "CI")
			.param("roles", "ROLE_USER")
			.with(csrf())
			.exchange();
		assertThat(result).hasRedirectedUrl("/").flash().containsKey("newApiKey");
		String apiKey = (String) result.getMvcResult().getFlashMap().get("newApiKey");
		assertThat(apiKey).isNotNull();

		assertThat(this.mvc.get().uri("/api/me").header("X-API-Key", apiKey)).hasStatusOk()
			.bodyJson()
			.isLenientlyEqualTo("""
					{ "name": "alice", "authorities": ["ROLE_USER", "FACTOR_API_KEY"] }
					""");
		assertThat(this.mvc.get().uri("/").session(session)).hasStatusOk().bodyText().contains("CI");
	}

	@Test
	void createdKeyCannotCarryRolesTheUserLacks() {
		MockHttpSession session = login("bob");
		MvcTestResult result = this.mvc.post()
			.uri("/api-keys")
			.session(session)
			.param("label", "Sneaky")
			.param("roles", "ROLE_USER", "ROLE_ADMIN")
			.with(csrf())
			.exchange();
		String apiKey = (String) result.getMvcResult().getFlashMap().get("newApiKey");
		assertThat(apiKey).isNotNull();

		assertThat(this.mvc.get().uri("/api/admin").header("X-API-Key", apiKey)).hasStatus(HttpStatus.FORBIDDEN);
	}

	@Test
	void deleteOwnKey() {
		GeneratedApiKey key = this.apiKeyRepository.generate("alice", AuthorityUtils.createAuthorityList("ROLE_USER"));
		MockHttpSession session = login("alice");

		assertThat(this.mvc.post().uri("/api-keys/{id}/delete", key.id()).session(session).with(csrf()))
			.hasRedirectedUrl("/");

		assertThat(this.mvc.get().uri("/api/me").header("X-API-Key", key.getUserFacingApiKey()))
			.hasStatus(HttpStatus.UNAUTHORIZED);
	}

	@Test
	void cannotDeleteSomeoneElsesKey() {
		GeneratedApiKey key = this.apiKeyRepository.generate("alice", AuthorityUtils.createAuthorityList("ROLE_USER"));
		MockHttpSession session = login("bob");

		assertThat(this.mvc.post().uri("/api-keys/{id}/delete", key.id()).session(session).with(csrf()))
			.hasRedirectedUrl("/");

		assertThat(this.mvc.get().uri("/api/me").header("X-API-Key", key.getUserFacingApiKey())).hasStatusOk();
	}

	@Test
	void apiKeyCannotManageKeys() {
		// Authenticated, but without the password factor: sent to log in with a password
		assertThat(this.mvc.get().uri("/").header("X-API-Key", "alice-admin.alice-admin-secret"))
			.hasRedirectedUrl("/login?factor.type=password&factor.reason=missing");
		assertThat(this.mvc.post()
			.uri("/api-keys")
			.header("X-API-Key", "alice-admin.alice-admin-secret")
			.param("label", "Minted with a key")).hasRedirectedUrl("/login?factor.type=password&factor.reason=missing");
		assertThat(this.apiKeyRepository.findByPrincipalName("alice")).extracting(UserApiKey::getLabel)
			.doesNotContain("Minted with a key");
	}

	private MockHttpSession login(String username) {
		MvcTestResult result = this.mvc.perform(formLogin().user(username).password("password"));
		assertThat(result).hasRedirectedUrl("/");
		HttpSession session = result.getRequest().getSession(false);
		assertThat(session).isNotNull();
		return (MockHttpSession) session;
	}

}
