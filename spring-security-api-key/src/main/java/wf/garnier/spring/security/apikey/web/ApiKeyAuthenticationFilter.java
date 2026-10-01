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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

/**
 * Authenticates requests that carry an API key. A request without a (valid-looking) key
 * passes through; an invalid key gets a bare 401. Whenever a key is presented, it wins
 * over any existing authentication.
 *
 * @author Daniel Garnier-Moiroux
 */
public class ApiKeyAuthenticationFilter extends AuthenticationFilter {

	public ApiKeyAuthenticationFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, new ApiKeyAuthenticationConverter());
	}

	public ApiKeyAuthenticationFilter(AuthenticationManager authenticationManager,
			AuthenticationConverter authenticationConverter) {
		super(authenticationManager, authenticationConverter);
		setSuccessHandler((HttpServletRequest request, HttpServletResponse response, Authentication authentication) -> {
		});
		AuthenticationEntryPointFailureHandler failureHandler = new AuthenticationEntryPointFailureHandler(
				new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
		failureHandler.setRethrowAuthenticationServiceException(true);
		setFailureHandler(failureHandler);
	}

}
