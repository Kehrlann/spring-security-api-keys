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

import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.test.web.servlet.assertj.MvcTestResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import wf.garnier.spring.security.apikey.config.ApiKeyConfigurer;
import wf.garnier.spring.security.apikey.memory.InMemoryApiKey;
import wf.garnier.spring.security.apikey.memory.InMemoryApiKeyRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = ApiKeyTests.Config.class)
@WebAppConfiguration
class ApiKeyTests {

	static final String SEEDED = "seeded.seeded-secret_123";

	@Autowired
	WebApplicationContext context;

	@Autowired
	InMemoryApiKeyRepository<InMemoryApiKey> repository;

	MockMvcTester mvc;

	@BeforeEach
	void setUp() {
		this.mvc = MockMvcTester.from(this.context, (builder) -> builder.apply(springSecurity()).build());
	}

	@Test
	void seededKey() {
		assertThat(this.mvc.get().uri("/me").header("X-API-Key", SEEDED)).hasStatusOk()
			.hasBodyTextEqualTo("Seeded Key|ROLE_READER,FACTOR_API_KEY");
	}

	@Test
	void generatedKey() {
		GeneratedApiKey key = this.repository.generate("Generated", List.of(new SimpleGrantedAuthority("ROLE_READER")));
		assertThat(this.mvc.get().uri("/me").header("X-API-Key", key.getUserFacingApiKey())).hasStatusOk()
			.hasBodyTextEqualTo("Generated|ROLE_READER,FACTOR_API_KEY");
	}

	@Test
	void postWithoutCsrfTokenAndNoSession() {
		MvcTestResult result = this.mvc.post().uri("/write").header("X-API-Key", SEEDED).exchange();
		assertThat(result).hasStatusOk().doesNotContainHeader(HttpHeaders.LOCATION);
		assertThat(result.getRequest().getSession(false)).isNull();
	}

	@Test
	void authorityProtectedEndpoint() {
		assertThat(this.mvc.get().uri("/reader").header("X-API-Key", SEEDED)).hasStatusOk();
		GeneratedApiKey key = this.repository.generate("No authorities", List.of());
		assertThat(this.mvc.get().uri("/reader").header("X-API-Key", key.getUserFacingApiKey()))
			.hasStatus(HttpStatus.FORBIDDEN);
	}

	@Test
	void wrongSecretAndUnknownIdGetIdenticalBare401() {
		assertThat(this.mvc.get().uri("/me").header("X-API-Key", "seeded.wrong")).hasStatus(HttpStatus.UNAUTHORIZED)
			.doesNotContainHeader(HttpHeaders.WWW_AUTHENTICATE)
			.bodyText()
			.isEmpty();
		assertThat(this.mvc.get().uri("/me").header("X-API-Key", "unknown.wrong")).hasStatus(HttpStatus.UNAUTHORIZED)
			.doesNotContainHeader(HttpHeaders.WWW_AUTHENTICATE)
			.bodyText()
			.isEmpty();
	}

	@Test
	void missingKeyOnProtectedEndpointGets401() {
		assertThat(this.mvc.get().uri("/me")).hasStatus(HttpStatus.UNAUTHORIZED);
	}

	@Test
	void missingKeyOnPermitAllPassesThrough() {
		assertThat(this.mvc.get().uri("/public")).hasStatusOk();
	}

	@Test
	void malformedKeyIsRejected() {
		assertThat(this.mvc.get().uri("/me").header("X-API-Key", "no-dot")).hasStatus(HttpStatus.UNAUTHORIZED);
		assertThat(this.mvc.get().uri("/public").header("X-API-Key", "no-dot")).hasStatus(HttpStatus.UNAUTHORIZED);
	}

	@Test
	void deletedKeyIsRejected() {
		GeneratedApiKey key = this.repository.generate("Temp", List.of());
		assertThat(this.mvc.get().uri("/me").header("X-API-Key", key.getUserFacingApiKey())).hasStatusOk();
		this.repository.delete(key.id());
		assertThat(this.mvc.get().uri("/me").header("X-API-Key", key.getUserFacingApiKey()))
			.hasStatus(HttpStatus.UNAUTHORIZED);
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	static class Config {

		@Bean
		InMemoryApiKeyRepository<InMemoryApiKey> repository() {
			InMemoryApiKeyRepository<InMemoryApiKey> repository = new InMemoryApiKeyRepository<>(
					InMemoryApiKey::new);
			repository.addApiKey("seeded", "seeded-secret_123", "Seeded Key",
					List.of(new SimpleGrantedAuthority("ROLE_READER")));
			return repository;
		}

		@Bean
		SecurityFilterChain chain(HttpSecurity http) {
			http.authorizeHttpRequests((a) -> a.requestMatchers("/public")
				.permitAll()
				.requestMatchers("/reader")
				.hasAuthority("ROLE_READER")
				.anyRequest()
				.authenticated());
			http.with(ApiKeyConfigurer.apiKey(), Customizer.withDefaults());
			return http.build();
		}

		@Bean
		Controller controller() {
			return new Controller();
		}

	}

	@RestController
	static class Controller {

		@GetMapping("/me")
		String me(Authentication authentication) {
			return authentication.getName() + "|"
					+ authentication.getAuthorities()
						.stream()
						.map(GrantedAuthority::getAuthority)
						.collect(Collectors.joining(","));
		}

		@PostMapping("/write")
		String write() {
			return "ok";
		}

		@GetMapping("/reader")
		String reader() {
			return "ok";
		}

		@GetMapping("/public")
		String publicEndpoint() {
			return "ok";
		}

	}

}
