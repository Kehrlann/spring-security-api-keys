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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import org.jspecify.annotations.Nullable;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

/**
 * Unsalted SHA-256, as lowercase hex. Suitable for high-entropy secrets only. Hashes are
 * compared in constant time.
 *
 * @author Daniel Garnier-Moiroux
 */
final class Sha256PasswordEncoder implements PasswordEncoder {

	@Override
	public String encode(@Nullable CharSequence rawPassword) {
		Assert.notNull(rawPassword, "rawPassword cannot be null");
		return HexFormat.of().formatHex(digest(rawPassword));
	}

	@Override
	public boolean matches(@Nullable CharSequence rawPassword, @Nullable String encodedPassword) {
		if (rawPassword == null || encodedPassword == null) {
			return false;
		}
		byte[] expected = encodedPassword.getBytes(StandardCharsets.UTF_8);
		byte[] actual = encode(rawPassword).getBytes(StandardCharsets.UTF_8);
		return MessageDigest.isEqual(expected, actual);
	}

	private static byte[] digest(CharSequence raw) {
		try {
			return MessageDigest.getInstance("SHA-256").digest(raw.toString().getBytes(StandardCharsets.UTF_8));
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException(ex);
		}
	}

}
