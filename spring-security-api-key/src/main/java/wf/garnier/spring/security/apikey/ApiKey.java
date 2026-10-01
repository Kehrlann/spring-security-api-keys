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

import org.jspecify.annotations.Nullable;

/**
 * The <em>stored</em> view of an API key. The secret is the encoded hash, never the raw
 * secret presented by a client. It is {@code null} once credentials have been erased.
 *
 * @author Daniel Garnier-Moiroux
 */
public interface ApiKey {

	String getId();

	@Nullable String getSecret();

}
