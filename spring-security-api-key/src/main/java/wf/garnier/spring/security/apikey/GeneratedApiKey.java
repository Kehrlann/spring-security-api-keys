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

/**
 * A newly generated API key. This is the only place the raw secret is available.
 *
 * @author Daniel Garnier-Moiroux
 */
public record GeneratedApiKey(String id, String rawSecret) {

	/**
	 * The full key, {@code id.secret}, as the client must send it.
	 */
	public String getUserFacingApiKey() {
		return this.id + "." + this.rawSecret;
	}

	@Override
	public String toString() {
		return "GeneratedApiKey [id=" + this.id + ", rawSecret=[REDACTED]]";
	}

}
