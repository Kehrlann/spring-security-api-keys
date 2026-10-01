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

import wf.garnier.spring.security.apikey.config.ApiKeyConfigurer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

@SpringBootApplication
public class UserDetailsSampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserDetailsSampleApplication.class, args);
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) {
		return http.authorizeHttpRequests((authorize) -> {
			authorize.requestMatchers("/api/admin").hasRole("ADMIN");
			authorize.requestMatchers("/api/**").authenticated();
			authorize.requestMatchers("/error").authenticated();
			// Managing keys requires a password login, so that a leaked key cannot
			// create new keys
			authorize.anyRequest().hasAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY);
		})
			.formLogin(Customizer.withDefaults())
			// The API gets a bare 401, browsers are redirected to the login page
			.exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
					new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
					PathPatternRequestMatcher.pathPattern("/api/**")))
			.with(ApiKeyConfigurer.apiKey(), (apiKey) -> apiKey.unauthorizedOnMissingApiKey(false))
			.build();
	}

	@Bean
	InMemoryUserDetailsManager userDetailsService() {
		return new InMemoryUserDetailsManager(
				User.withUsername("alice").password("{noop}password").roles("USER", "ADMIN").build(),
				User.withUsername("bob").password("{noop}password").roles("USER").build(),
				User.withUsername("carol").password("{noop}password").roles("USER").disabled(true).build());
	}

	@Bean
	UserApiKeyRepository apiKeyRepository(UserDetailsService userDetailsService) {
		UserApiKeyRepository repository = new UserApiKeyRepository(userDetailsService);
		// Known keys, for the demo only
		repository.addApiKey("alice-admin", "alice-admin-secret", "alice", "Admin key",
				AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN"));
		repository.addApiKey("alice-user", "alice-user-secret", "alice", "Read-only key",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		// bob is not an admin, so this key does not grant ROLE_ADMIN
		repository.addApiKey("bob", "bob-secret", "bob", "Overreaching key",
				AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN"));
		// carol is disabled, so this key is rejected
		repository.addApiKey("carol", "carol-secret", "carol", "Disabled user's key",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		return repository;
	}

}
