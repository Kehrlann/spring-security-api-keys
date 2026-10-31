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

package wf.garnier.spring.security.apikey.config;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;
import wf.garnier.spring.security.apikey.ApiKeyRepository;
import wf.garnier.spring.security.apikey.memory.InMemoryApiKey;
import wf.garnier.spring.security.apikey.memory.InMemoryApiKeyRepository;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

class ApiKeyConfigurerTests {

	static final InMemoryApiKeyRepository<InMemoryApiKey> REPOSITORY = new InMemoryApiKeyRepository<>(
			InMemoryApiKey::new);

	static {
		REPOSITORY.addApiKey("k", "secret", "Key Owner", List.of(new SimpleGrantedAuthority("ROLE_X")));
	}

	/** Builds a web context with the given chain customizer and returns MockMvcTester. */
	static MockMvcTester mvc(Consumer<HttpSecurity> customizer, Class<?>... extra) {
		AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
		context.setServletContext(new org.springframework.mock.web.MockServletContext());
		context.register(WebConfig.class);
		if (extra.length > 0) {
			context.register(extra);
		}
		CUSTOMIZER = customizer;
		context.refresh();
		return MockMvcTester.from(context, (builder) -> builder.apply(springSecurity()).build());
	}

	static Consumer<HttpSecurity> CUSTOMIZER = (http) -> {
	};

	private static void accept(HttpSecurity http) {
		http.authorizeHttpRequests((a) -> a.anyRequest().authenticated())
			.httpBasic(Customizer.withDefaults())
			.with(ApiKeyConfigurer.apiKey(), (c) -> c.apiKeyRepository(REPOSITORY).unauthorizedOnMissingApiKey(false));
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	static class WebConfig {

		@Bean
		SecurityFilterChain chain(HttpSecurity http) {
			CUSTOMIZER.accept(http);
			return build(http);
		}

		private static SecurityFilterChain build(HttpSecurity http) {
			return http.build();
		}

		@Bean
		Ctl ctl() {
			return new Ctl();
		}

	}

	@RestController
	static class Ctl {

		@GetMapping("/me")
		String me(Authentication authentication) {
			return authentication.getName() + "|" + authentication.getClass().getSimpleName();
		}

		@PostMapping("/me")
		String postMe(Authentication authentication) {
			return authentication.getName();
		}

		@GetMapping("/principal")
		String principal(
				@org.springframework.security.core.annotation.AuthenticationPrincipal InMemoryApiKey details) {
			return details.getId() + "|" + details.getSecret();
		}

		@GetMapping("/factors")
		String factors(Authentication authentication) {
			return authentication.getAuthorities()
				.stream()
				.map(GrantedAuthority::getAuthority)
				.sorted()
				.toList()
				.toString();
		}

	}

	static void defaults(HttpSecurity http) {
		try {
			http.authorizeHttpRequests((a) -> a.anyRequest().authenticated());
			http.with(ApiKeyConfigurer.apiKey(), (c) -> c.apiKeyRepository(REPOSITORY));
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	@Test
	void customHeaderName() {
		MockMvcTester mvc = mvc((http) -> {
			http.authorizeHttpRequests((a) -> a.anyRequest().authenticated());
			http.with(ApiKeyConfigurer.apiKey(), (c) -> c.apiKeyRepository(REPOSITORY).headerName("X-Acme-Key"));
		});
		assertThat(mvc.get().uri("/me").header("X-Acme-Key", "k.secret")).hasStatusOk();
		assertThat(mvc.get().uri("/me").header("X-API-Key", "k.secret")).hasStatus(HttpStatus.UNAUTHORIZED);
	}

	@Test
	void customConverter() {
		MockMvcTester mvc = mvc((http) -> {
			http.authorizeHttpRequests((a) -> a.anyRequest().authenticated());
			http.with(ApiKeyConfigurer.apiKey(),
					(c) -> c.apiKeyRepository(REPOSITORY).authenticationConverter((request) -> {
						String header = request.getHeader("Authorization");
						if (header == null || !header.startsWith("Bearer ")) {
							return null;
						}
						String[] parts = header.substring(7).split("\\.");
						return wf.garnier.spring.security.apikey.authentication.ApiKeyAuthenticationToken
							.unauthenticated(parts[0], parts[1]);
					}));
		});
		assertThat(mvc.get().uri("/me").header("Authorization", "Bearer k.secret")).hasStatusOk();
	}

	@Test
	void headerNameAndConverterTogetherFailAtStartup() {
		assertThatThrownBy(() -> mvc((http) -> {
			try {
				http.with(ApiKeyConfigurer.apiKey(),
						(c) -> c.apiKeyRepository(REPOSITORY)
							.headerName("X-Foo")
							.authenticationConverter((request) -> null));
			}
			catch (Exception ex) {
				throw new IllegalStateException(ex);
			}
		})).hasStackTraceContaining("headerName and authenticationConverter cannot both be set");
	}

	@Test
	void noRepositoryFailsAtStartup() {
		assertThatThrownBy(() -> mvc((http) -> {
			try {
				http.with(ApiKeyConfigurer.apiKey(), Customizer.withDefaults());
			}
			catch (Exception ex) {
				throw new IllegalStateException(ex);
			}
		})).hasStackTraceContaining("No ApiKeyRepository");
	}

	@Test
	void severalRepositoryBeansFailAtStartup() {
		assertThatThrownBy(
				() -> mvc((http) -> http.with(ApiKeyConfigurer.apiKey(), Customizer.withDefaults()), TwoRepos.class))
			.hasStackTraceContaining("Several ApiKeyRepository beans");
	}

	@Test
	void singleRepositoryBeanIsPickedUp() {
		var mvc = mvc((http) -> http.authorizeHttpRequests((a) -> a.anyRequest().authenticated())
			.with(ApiKeyConfigurer.apiKey(), Customizer.withDefaults()), OneRepo.class);
		assertThat(mvc.get().uri("/me").header("X-API-Key", "k.secret")).hasStatusOk();
	}

	@Configuration
	static class OneRepo {

		@Bean
		InMemoryApiKeyRepository<InMemoryApiKey> repo() {
			return REPOSITORY;
		}

	}

	@Configuration
	static class TwoRepos {

		@Bean
		InMemoryApiKeyRepository<InMemoryApiKey> repo1() {
			return REPOSITORY;
		}

		@Bean
		InMemoryApiKeyRepository<InMemoryApiKey> repo2() {
			return REPOSITORY;
		}

	}

	@Test
	void unauthorizedOnMissingApiKeyCanBeDisabled() {
		MockMvcTester mvc = mvc((http) -> http.authorizeHttpRequests((a) -> a.anyRequest().authenticated())
			.httpBasic(Customizer.withDefaults())
			.with(ApiKeyConfigurer.apiKey(), (c) -> c.apiKeyRepository(REPOSITORY).unauthorizedOnMissingApiKey(false)));
		assertThat(mvc.get().uri("/me")).hasStatus(HttpStatus.UNAUTHORIZED).containsHeader("WWW-Authenticate");
	}

	@Test
	void explicitEntryPointWins() {
		MockMvcTester mvc = mvc((http) -> http.authorizeHttpRequests((a) -> a.anyRequest().authenticated())
			.exceptionHandling((e) -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.I_AM_A_TEAPOT)))
			.with(ApiKeyConfigurer.apiKey(), (c) -> c.apiKeyRepository(REPOSITORY)));
		assertThat(mvc.get().uri("/me")).hasStatus(HttpStatus.I_AM_A_TEAPOT);
	}

	@Test
	void keyWithoutRequiredRoleGets403() {
		MockMvcTester mvc = mvc((http) -> {
			http.authorizeHttpRequests((a) -> a.anyRequest().hasRole("ADMIN"));
			http.with(ApiKeyConfigurer.apiKey(), (c) -> c.apiKeyRepository(REPOSITORY));
		});
		assertThat(mvc.get().uri("/me").header("X-API-Key", "k.secret")).hasStatus(HttpStatus.FORBIDDEN);
	}

	@Test
	void keyWithoutRequiredFactorIsSentToFormLogin() {
		MockMvcTester mvc = mvc((http) -> {
			http.authorizeHttpRequests((a) -> a.anyRequest().hasAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY));
			http.formLogin(Customizer.withDefaults());
			http.with(ApiKeyConfigurer.apiKey(), (c) -> c.apiKeyRepository(REPOSITORY));
		});
		assertThat(mvc.get().uri("/me").header("X-API-Key", "k.secret")).hasStatus(HttpStatus.FOUND)
			.hasRedirectedUrl("/login?factor.type=password&factor.reason=missing");
		assertThat(mvc.get().uri("/me").header("X-API-Key", "k.secret").accept("text/html")).hasStatus(HttpStatus.FOUND)
			.hasRedirectedUrl("/login?factor.type=password&factor.reason=missing");
		assertThat(mvc.get().uri("/me").with(user("alice"))).hasStatus(HttpStatus.FOUND)
			.hasRedirectedUrl("/login?factor.type=password&factor.reason=missing");
	}

	@Test
	void keyWithoutRequiredFactorIsChallengedByHttpBasic() {
		MockMvcTester mvc = mvc((http) -> {
			http.authorizeHttpRequests((a) -> a.anyRequest().hasAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY));
			http.httpBasic(Customizer.withDefaults());
			http.with(ApiKeyConfigurer.apiKey(), (c) -> c.apiKeyRepository(REPOSITORY));
		});
		assertThat(mvc.get().uri("/me").header("X-API-Key", "k.secret").accept("application/json"))
			.hasStatus(HttpStatus.UNAUTHORIZED)
			.containsHeader("WWW-Authenticate");
		assertThat(mvc.get().uri("/me").with(user("alice"))).hasStatus(HttpStatus.UNAUTHORIZED)
			.containsHeader("WWW-Authenticate");
	}

	@Test
	void alreadyAuthenticatedWithoutKeyIsNotRejected() {
		MockMvcTester mvc = mvc(ApiKeyConfigurerTests::defaults);
		assertThat(mvc.get().uri("/me").with(user("alice"))).hasStatusOk().bodyText().startsWith("alice|");
	}

	@Test
	void keyWinsOverExistingAuthentication() {
		MockMvcTester mvc = mvc(ApiKeyConfigurerTests::defaults);
		assertThat(mvc.get().uri("/me").with(user("alice")).header("X-API-Key", "k.secret"))
			.hasBodyTextEqualTo("Key Owner|ApiKeyAuthenticationToken");
		assertThat(mvc.get().uri("/me").with(user("alice")).header("X-API-Key", "k.wrong"))
			.hasStatus(HttpStatus.UNAUTHORIZED);
	}

	@Test
	void duplicateHeadersGet401() {
		MockMvcTester mvc = mvc(ApiKeyConfigurerTests::defaults);
		assertThat(mvc.get().uri("/me").header("X-API-Key", "k.secret").header("X-API-Key", "k.secret"))
			.hasStatus(HttpStatus.UNAUTHORIZED);
	}

	@Test
	void csrfBypassedWithKeyButNotWithoutAndDuplicatesAre401NotError() {
		MockMvcTester mvc = mvc(ApiKeyConfigurerTests::defaults);
		assertThat(mvc.post().uri("/me").header("X-API-Key", "k.secret")).hasStatusOk();
		assertThat(mvc.post().uri("/me").with(user("alice"))).hasStatus(HttpStatus.FORBIDDEN);
		assertThat(mvc.post().uri("/me").header("X-API-Key", "k.secret").header("X-API-Key", "k.secret"))
			.hasStatus(HttpStatus.UNAUTHORIZED);
	}

	@Test
	void repositoryFailureIs500() {
		ApiKeyRepository<InMemoryApiKey> failing = new InMemoryApiKeyRepository<>(InMemoryApiKey::new) {
			@Override
			public InMemoryApiKey findByKeyId(String keyId) {
				throw new IllegalStateException("db down");
			}
		};
		MockMvcTester mvc = mvc((http) -> http.authorizeHttpRequests((a) -> a.anyRequest().authenticated())
			.with(ApiKeyConfigurer.apiKey(), (c) -> c.apiKeyRepository(failing)));
		assertThat(mvc.get().uri("/me").header("X-API-Key", "k.secret")).hasFailed()
			.failure()
			.hasRootCauseMessage("db down");
	}

	@Test
	void principalIsTheApiKeyDetailsWithErasedSecret() {
		MockMvcTester mvc = mvc(ApiKeyConfigurerTests::defaults);
		assertThat(mvc.get().uri("/principal").header("X-API-Key", "k.secret")).hasBodyTextEqualTo("k|null");
		InMemoryApiKey details = REPOSITORY.findByKeyId("k");
		assertThat(details).isNotNull();
		assertThat(details.getSecret()).startsWith("{sha256}");
	}

	@Test
	void factorAuthorityIsPresent() {
		MockMvcTester mvc = mvc(ApiKeyConfigurerTests::defaults);
		assertThat(mvc.get().uri("/factors").header("X-API-Key", "k.secret"))
			.hasBodyTextEqualTo("[FACTOR_API_KEY, ROLE_X]");
		assertThat(FactorGrantedAuthority.fromFactor("API_KEY").getAuthority()).isEqualTo("FACTOR_API_KEY");
	}

	@Configuration
	@EnableMultiFactorAuthentication(authorities = {})
	static class Mfa {

	}

	@Test
	void mergesWithExistingAuthenticationOfSameNameUnderMultiFactor() {
		REPOSITORY.addApiKey("alice-key", "secret", "alice", List.of(new SimpleGrantedAuthority("ROLE_X")));
		MockMvcTester mvc = mvc(ApiKeyConfigurerTests::defaults, Mfa.class);
		assertThat(mvc.get()
			.uri("/factors")
			.with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
				.authentication(new TestingAuthenticationToken("alice", "pw", "FACTOR_PASSWORD")))
			.header("X-API-Key", "alice-key.secret")).hasBodyTextEqualTo("[FACTOR_API_KEY, FACTOR_PASSWORD, ROLE_X]");
	}

	static final List<String> EVENTS = new ArrayList<>();

	@Configuration
	static class Publisher {

		@Bean
		AuthenticationEventPublisher publisher() {
			return new AuthenticationEventPublisher() {
				public void publishAuthenticationSuccess(Authentication authentication) {
					EVENTS.add("success:" + authentication.getName());
				}

				public void publishAuthenticationFailure(AuthenticationException exception,
						Authentication authentication) {
					EVENTS.add("failure:" + authentication.getName());
				}
			};
		}

	}

	@Test
	void eventsArePublished() {
		EVENTS.clear();
		MockMvcTester mvc = mvc(ApiKeyConfigurerTests::defaults, Publisher.class);
		assertThat(mvc.get().uri("/me").header("X-API-Key", "k.secret")).hasStatusOk();
		assertThat(mvc.get().uri("/me").header("X-API-Key", "k.wrong")).hasStatus(HttpStatus.UNAUTHORIZED);
		assertThat(EVENTS).containsExactly("success:Key Owner", "failure:k");
	}

}
