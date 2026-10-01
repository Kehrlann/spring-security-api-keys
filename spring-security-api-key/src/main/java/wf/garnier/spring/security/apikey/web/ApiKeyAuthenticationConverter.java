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

import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.Assert;

import wf.garnier.spring.security.apikey.authentication.ApiKeyAuthenticationToken;

/**
 * Reads an API key, {@code id.secret}, from a single request header.
 * <p>
 * No header or a blank value yields {@code null}, so that the request is treated as
 * unauthenticated. A malformed value or several header values are rejected with a
 * {@link BadCredentialsException}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class ApiKeyAuthenticationConverter implements AuthenticationConverter {

	public static final String DEFAULT_HEADER_NAME = "X-API-Key";

	private static final Pattern API_KEY = Pattern.compile("([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)");

	private final String headerName;

	public ApiKeyAuthenticationConverter() {
		this(DEFAULT_HEADER_NAME);
	}

	public ApiKeyAuthenticationConverter(String headerName) {
		Assert.hasText(headerName, "headerName cannot be empty");
		this.headerName = headerName;
	}

	@Override
	public @Nullable Authentication convert(HttpServletRequest request) {
		List<String> values = Collections.list(request.getHeaders(this.headerName));
		if (values.isEmpty()) {
			return null;
		}
		if (values.size() > 1) {
			throw new BadCredentialsException("Multiple API key headers");
		}
		String value = values.get(0).trim();
		if (value.isEmpty()) {
			return null;
		}
		var matcher = API_KEY.matcher(value);
		if (!matcher.matches()) {
			throw new BadCredentialsException("Malformed API key");
		}
		return ApiKeyAuthenticationToken.unauthenticated(matcher.group(1), matcher.group(2));
	}

}
