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

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Factory for the default {@link PasswordEncoder}: encodes with {@code {sha256}}, and
 * verifies any standard Spring Security prefix such as {@code {bcrypt}}.
 *
 * @author Daniel Garnier-Moiroux
 */
public final class ApiKeyPasswordEncoders {

	public static final String SHA256_ID = "sha256";

	private ApiKeyPasswordEncoders() {
	}

	public static PasswordEncoder createDelegatingPasswordEncoder() {
		Map<String, PasswordEncoder> encoders = new HashMap<>();
		encoders.put(SHA256_ID, new Sha256PasswordEncoder());
		DelegatingPasswordEncoder standard = (DelegatingPasswordEncoder) PasswordEncoderFactories
			.createDelegatingPasswordEncoder();
		DelegatingPasswordEncoder delegating = new DelegatingPasswordEncoder(SHA256_ID, encoders);
		delegating.setDefaultPasswordEncoderForMatches(standard);
		return delegating;
	}

}
