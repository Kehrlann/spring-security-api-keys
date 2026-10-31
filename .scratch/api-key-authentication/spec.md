# Spec: API key authentication for Spring Security

Status: ready-for-agent

## Problem Statement

Spring Security has first-class support for form login, HTTP Basic, OAuth2 and SAML, but none for API keys, even though API keys are the most common way to authenticate machine-to-machine callers and personal access tokens. Application developers who need API keys end up hand-rolling a filter, an authentication provider and a token type. Homegrown implementations routinely get the security-sensitive details wrong:

- secrets stored in plaintext;
- non-constant-time comparisons;
- timing oracles that reveal which key ids exist;
- CSRF protection blocking legitimate API calls;
- success handlers that redirect;
- sessions created for stateless API calls;
- entry points that clobber the rest of the application's security configuration.

They also have to rediscover how to integrate correctly with Spring Security 7 features such as multi-factor authentication authorities and authentication events.

## Solution

A standalone library, `wf.garnier:spring-security-api-key`, that adds API key authentication to Spring Security 7 Servlet applications.

**How developers use it**

- A developer applies a single configurer to their `HttpSecurity` and provides a repository of API keys.
- From then on, clients authenticate by sending a key in the `X-API-Key` header. The header name is configurable.

**Keys**

- A key has the format `<keyId>.<secret>`.
- The key id is used to look up the stored key.
- The secret is verified against a stored hash through a `PasswordEncoder`. The default hashes with fast SHA-256, which suits high-entropy secrets.
- The repository can also generate new keys. It returns the raw secret exactly once and persists only the hash.
- An in-memory repository ships for demos, tests and local development, and can be seeded with known keys.

**Behaviour**

- A missing key passes through, so other mechanisms or authorization rules decide.
- An invalid key is rejected with a bare 401.
- By default, an unauthenticated request that authorization denies also gets a 401, instead of a 403 or a login redirect.
- Authentication is stateless.
- Requests that carry a key bypass CSRF protection.
- Authentication events are published.
- Every authenticated API key carries a `FACTOR_API_KEY` authority, so it works with Spring Security 7 multi-factor authentication.

**Building blocks**

All the pieces are public: the token, the provider, the converter, the filter and the repository. Developers with unusual needs can assemble them by hand instead of using the configurer.

## User Stories

### Wiring it up

1. As an application developer, I want to add API key authentication to my `SecurityFilterChain` with a single configurer applied through `http.with(...)`, so that it feels like `httpBasic()` or `oauth2ResourceServer()`.
2. As an application developer, I want the configurer to pick up a single `ApiKeyRepository` bean from my application context when I don't pass one explicitly, so that I don't have to wire it twice.
3. As an application developer, I want application startup to fail with a clear message if there is no `ApiKeyRepository` (neither configured nor a bean), or if several candidate beans exist, so that I find misconfiguration immediately rather than at the first request.
4. As an application developer, I want to pass an `ApiKeyRepository` explicitly to the configurer, so that I can use different repositories in different filter chains.
5. As an application developer, I want the configurer to register its authentication provider with the `HttpSecurity` shared authentication manager, so that it coexists with my other authentication mechanisms in the same chain.
6. As an application developer, I want the API key filter to be inserted before `BasicAuthenticationFilter`, so that it runs at a predictable position relative to other authentication mechanisms.
7. As an application developer, I want to assemble the filter, converter, provider and token by hand without the configurer, so that I can handle cases the configurer doesn't support, such as a custom `AuthenticationManager`.

### Wire format and extraction

8. As an API client, I want to send my key in the `X-API-Key` header, so that I follow the most common convention for API keys.
9. As an application developer, I want to change the header name (for example to `X-Acme-Key`), so that I can match an existing API contract.
10. As an application developer, I want to plug in my own `AuthenticationConverter`, so that I can read the key from somewhere else, for example `Authorization: Bearer`.
11. As an application developer, I want application startup to fail if I set both a header name and a custom converter, so that one of them is never silently ignored.
12. As an API client, I want leading and trailing whitespace around my key to be tolerated, so that clients or proxies that add whitespace don't break authentication.
13. As an API client, I want a request with no key or a blank key to be treated as unauthenticated rather than as an error, so that public endpoints keep working. A malformed key (wrong charset, no dot, several dots, an empty id or secret) is rejected with 401, so that a broken client fails loudly instead of silently being anonymous.
14. As a security reviewer, I want a request carrying several `X-API-Key` headers to be rejected with 401, so that ambiguous credentials are never resolved by guessing.

### Verification

15. As an application developer, I want the library, not my code, to compare the presented secret with the stored hash, so that I can't get the comparison wrong.
16. As a security reviewer, I want stored secrets to be hashed with a `PasswordEncoder`, by default a `DelegatingPasswordEncoder` that encodes with `{sha256}`, so that a database leak doesn't expose usable keys.
17. As a security reviewer, I want SHA-256 hashes compared in constant time, so that response timing doesn't reveal the stored hash.
18. As an application developer, I want verification to be fast (no bcrypt cost on every request by default), so that API latency isn't dominated by password hashing for high-entropy secrets.
19. As an application developer, I want the default encoder to also verify `{bcrypt}`, `{argon2}` and other standard prefixed hashes, so that I can migrate or mix hashing schemes without breaking existing keys.
20. As an application developer, I want to set the verification `PasswordEncoder` explicitly on the configurer, so that I control hashing. My application's user-password `PasswordEncoder` bean must not be picked up silently.
21. As a security reviewer, I want an unknown key id and a wrong secret to produce the same 401 in the same amount of time (a dummy hash comparison for unknown ids), so that attackers can't find out which key ids exist.
22. As an operator, I want a failure in the repository (for example, the database being down) to produce a 500 rather than a 401, so that outages aren't hidden as authentication failures and clients don't rotate good keys.

### Responses and the entry point

23. As an API client, I want an invalid key to get a bare 401 with no body and no `WWW-Authenticate` header, so that the response is unambiguous and leaks nothing.
24. As an API client, I want a request with a valid key to continue to the endpoint without any redirect, so that API calls behave like API calls.
25. As an application developer, I want unauthenticated requests that authorization denies to get a 401 by default (`unauthorizedOnMissingApiKey`, defaulting to `true`), so that API clients don't get 403s or login redirects.
26. As an application developer, I want to turn `unauthorizedOnMissingApiKey` off, so that another mechanism's entry point (for example form login) applies.
27. As an application developer, I want an authentication entry point I set explicitly through `http.exceptionHandling(...)` to win over the library's default 401, so that the library never overrides my configuration.
28. As an application developer, I want a request that is already authenticated by another mechanism and has no API key not to be rejected, so that mixed chains (session plus API key) work.
29. As an application developer, I want a request that carries an API key to always be authenticated with that key, even if it's already authenticated some other way, so that the explicit credential wins.

### Principal and authorities

30. As an application developer, I want the authenticated principal to be my own `ApiKeyDetails` implementation, so that I can use `@AuthenticationPrincipal` with my rich type.
31. As an application developer, I want the authenticated token's authorities to come from `ApiKeyDetails#getAuthorities()`, so that I can scope keys.
32. As an application developer, I want `Authentication#getName()` to return `ApiKeyDetails#getPrincipalName()`, which defaults to the key id, so that personal access tokens can report the owning user's name.
33. As an application developer, I want every successful API key authentication to carry a `FACTOR_API_KEY` factor authority, exposed as a public constant, so that I can write rules such as "authenticated by API key".
34. As an application developer using `@EnableMultiFactorAuthentication`, I want an API key authentication to merge with an existing authentication that has the same name, so that a user can combine factors such as password plus API key.
35. As a security reviewer, I want the raw secret and the stored hash erased from the `Authentication` after it succeeds, so that credentials don't linger in memory or end up serialized.

### Statelessness, CSRF and events

36. As an application developer, I want API key authentication never to create or update an HTTP session, so that API calls stay stateless.
37. As an application developer, I want the API key token never to be persisted to a session, even if a session-based `SecurityContextRepository` is in use, so that a key can't turn into a session.
38. As an API client, I want a POST, PUT or DELETE that carries a key not to be blocked by CSRF protection, so that I don't need CSRF tokens. Browsers don't send custom headers on their own, so this is safe.
39. As an API client, I want a request with a key that breaks the converter (for example duplicate headers) to get a 401 from the API key filter rather than a 500 raised during the CSRF check, so that errors are consistent.
40. As an operator, I want success and failure authentication events published through the application's `AuthenticationEventPublisher`, so that I can audit API key usage with the same tooling as other logins.
41. As an operator, I want DEBUG logs that mention the key id and never the secret, so that I can troubleshoot without leaking credentials.

### Repository contract

42. As an application developer, I want to implement a small `ApiKeyRepository<T extends ApiKeyDetails>` interface with `findByKeyId`, `generate` and `delete`, so that I can store keys in any storage.
43. As an application developer, I want `findByKeyId` to return `null` for an unknown key id, so that I get `UserDetailsService`-like ergonomics without exceptions.
44. As an application developer, I want the repository Javadoc to state that `findByKeyId` must return a fresh instance on each call, so that credential erasure never corrupts stored data.
45. As an application developer, I want the repository Javadoc to state that implementations must hash the secret before storing it, and to point me to the library's secret generator, so that my implementation is safe by default.
46. As an application developer, I want `ApiKeyDetails` to stay minimal (id, hashed secret, authorities, principal name, label; no expiry or enabled flags), and to return `null` for expired or revoked keys, so that I don't implement methods I don't need.

### Key generation

47. As an application developer, I want to call `generate(name, authorities)` on my repository and get back a `GeneratedApiKey`, so that creating a key is one call.
48. As an application developer, I want `GeneratedApiKey` to expose `getId()`, `getRawSecret()` and `getUserFacingApiKey()` (the full `id.secret` string), so that I show the client exactly what they must send and never build the format myself.
49. As a security reviewer, I want `GeneratedApiKey#toString()` to redact the secret, so that an accidental log statement doesn't leak a key.
50. As an application developer writing my own repository, I want a public helper that generates secrets (32 `SecureRandom` bytes, unpadded base64url), so that every implementation produces secrets in the same format and with the same strength.
51. As an application developer, I want to delete a key by id, with deleting an unknown id being a no-op, so that revocation endpoints are idempotent.

### In-memory repository

52. As an application developer, I want an `InMemoryApiKeyRepository`, so that I can run demos, tests and local development without a database.
53. As an application developer, I want the in-memory repository to generate readable sequential ids (`api1`, `api2`, …), so that keys are easy to tell apart during development.
54. As an application developer, I want to seed the in-memory repository with a known id and raw secret, plus name and authorities, so that sample apps and tests can use a fixed key without printing one at startup.
55. As an application developer, I want seeding to hash the secret with the repository's encoder, so that even the in-memory store never keeps plaintext.
56. As an application developer, I want seeding to fail fast when the id or secret contains characters outside `[A-Za-z0-9_-]`, so that I never seed a key the converter would treat as malformed.
57. As an application developer, I want seeding a duplicate id to fail, so that keys are never overwritten silently.
58. As an application developer, I want `generate()` to skip ids already taken by seeded keys, so that generated keys never overwrite seeded ones.
59. As an application developer, I want to give the in-memory repository a custom `PasswordEncoder`, defaulting to the library's `{sha256}` delegating encoder, so that I can use the same hashing in tests as in production.

### Library consumers and maintainers

60. As a library consumer, I want the library's types to have JSpecify nullability annotations, so that Kotlin and NullAway users get accurate null-safety.
61. As a library maintainer, I want NullAway enforced in the build, so that nullability annotations can't drift from behaviour.
62. As a library consumer, I want a README that documents setup, the key format, the stored hash format, how to write a custom repository, and the caveats for mixed chains, so that I can adopt the library without reading its source.

## Implementation Decisions

### Platform and project

- Spring Security 7.x, Spring Framework 7, Java 17 baseline. Servlet stack only.
- Single-module Maven build. Apache 2.0 licence. GitHub Actions CI on JDK 17. The README is the documentation.
- Coordinates: `wf.garnier:spring-security-api-key`. No Spring Boot starter.
- Root package `wf.garnier.spring.security.apikey`, with these sub-packages:
  - root: `ApiKeyDetails`, `ApiKeyRepository`, `GeneratedApiKey`, the secret generator helper and the default encoder factory.
  - `authentication`: `ApiKeyAuthenticationProvider` and `ApiKeyAuthenticationToken`.
  - `web`: `ApiKeyAuthenticationConverter` and `ApiKeyAuthenticationFilter`.
  - `memory`: `InMemoryApiKeyRepository` and its details type.
  - `config`: `ApiKeyConfigurer`.
- Every package is `@NullMarked` (JSpecify). NullAway runs through Error Prone in the Maven build and fails the build on violations.
- Prior art: the API-key package in `spring-ai-community/mcp-security` (`mcp-server-security`, package `...server.apikey`) by the same author. Start from it and apply the deviations listed below.

### Domain types

- **`ApiKeyDetails`** is the *stored* view of a key. It extends `CredentialsContainer` and declares:
  - `getId()`;
  - `@Nullable getSecret()`: the encoded hash, `null` after erasure. It is never used for the incoming raw secret;
  - `getAuthorities()`;
  - `getPrincipalName()`, defaulting to `getId()`;
  - `getLabel()`, a human-readable label for the key, defaulting to `getId()`.
  - There is no separate credential-only `ApiKey` supertype: nothing consumes the id and hash without the rest.
  - It has no status methods (expiry, enabled).
  - It has no `copy()` method, unlike mcp-security's `ApiKeyEntity`.
  - Renamed from mcp-security's `ApiKeyEntity`.
- **`ApiKeyRepository<T extends ApiKeyDetails>`** is a plain interface with three methods:
  - `@Nullable T findByKeyId(String keyId)`: must return a fresh instance on each call.
  - `GeneratedApiKey generate(String name, Collection<? extends GrantedAuthority> authorities)`: the implementation generates the id, generates the secret and hashes it.
  - `void delete(String keyId)`: deleting an unknown id is a no-op.
  - There is no abstract base class: generation details are specific to each implementation. The Javadoc states the contract: hash before storing, return fresh instances, ids must match `[A-Za-z0-9_-]+`, and use the secret helper.
  - Renamed from mcp-security's `ApiKeyEntityRepository`.
- **`GeneratedApiKey`** exposes `getId()`, `getRawSecret()` and `getUserFacingApiKey()`, which returns `id + "." + rawSecret`. Its `toString()` redacts the secret. It does *not* implement `ApiKeyDetails`.
- **The secret generator helper** is a public utility, for example `ApiKeySecrets.generate()`. It produces 32 bytes from `SecureRandom`, encoded as unpadded base64url (43 characters).
- **The default encoder factory** returns a `DelegatingPasswordEncoder`:
  - It encodes with id `{sha256}`.
  - It can also match the standard Spring Security ids (`{bcrypt}`, `{argon2}`, …).
  - `{sha256}` is a new, small encoder: lowercase hex of unsalted SHA-256 over the UTF-8 bytes of the secret, compared with `MessageDigest.isEqual`.
  - Only the secret is hashed, never the full `id.secret` string.

### Token

- **`ApiKeyAuthenticationToken`** is marked `@Transient`, so it is never persisted to a session.
- **Unauthenticated state:** holds the key id and the raw secret presented by the client.
- **Authenticated state:** the principal is the `ApiKeyDetails`, the authorities come from it (plus the factor authority), and the credentials are erased.
- Both states are created through static factories: `unauthenticated(...)` and `authenticated(...)`.
- `getName()` returns the key id while unauthenticated, and `ApiKeyDetails#getPrincipalName()` once authenticated.
- The token class declares its own `toBuilder()`. Spring Security 7's multi-factor merge checks for that method on the concrete class itself; the interface default doesn't count.
- `eraseCredentials()` clears the raw secret and calls through to the principal.

### Provider

**`ApiKeyAuthenticationProvider`** supports `ApiKeyAuthenticationToken` only. Its constructor takes the repository, with an optional `PasswordEncoder` that defaults to the library's delegating encoder.

Behaviour:
- **Lookup:** it looks up the key by id. An unknown id runs a dummy `matches()` against a precomputed hash and then throws `BadCredentialsException`.
- **Mismatch:** a wrong secret throws `BadCredentialsException` with the same message as an unknown id.
- **Repository errors:** any exception from the repository is wrapped in `InternalAuthenticationServiceException`. The filter's failure handler rethrows it, so the client gets a 500.
- **Success:** it returns an authenticated token whose authorities are those of `ApiKeyDetails` plus `FactorGrantedAuthority` `FACTOR_API_KEY`. The factor name is a public constant.

Deviations from mcp-security:
- the default encoder;
- the dummy hash for unknown ids;
- the exception wrapping;
- the factor authority.

### Converter

**`ApiKeyAuthenticationConverter`** reads a single header, `X-API-Key` by default, with the name configurable through its constructor.

| Input | Result |
|---|---|
| No header | `null` (pass through) |
| More than one header value | `BadCredentialsException` (401) |
| Blank value after trimming | `null` |
| Leading or trailing whitespace | Trimmed |
| Anything other than exactly two non-empty `[A-Za-z0-9_-]+` parts separated by one `.` | `BadCredentialsException("Malformed API key")` (401) |
| Valid value | Unauthenticated token |

### Filter

**`ApiKeyAuthenticationFilter`** extends Spring Security's generic `AuthenticationFilter`. It has two constructors: (authentication manager, converter), and (authentication manager), which uses the default header converter.

- **Success handler:** a pass-through handler that only continues the chain, as in mcp-security. The parent's default redirects.
- **Failure handler:** an `AuthenticationEntryPointFailureHandler` wrapping a bare 401 `HttpStatusEntryPoint`. It is fixed and not exposed by the configurer. `AuthenticationServiceException` is rethrown (the parent's default behaviour).
- **Security context:** stored through `RequestAttributeSecurityContextRepository`, the parent's default, so no session is used.
- **Key always wins:** whenever the converter produces a token, the filter authenticates with it, whatever authentication already exists.

### Configurer

**`ApiKeyConfigurer`** extends `AbstractHttpConfigurer`. It is obtained from a static factory `ApiKeyConfigurer.apiKey()` and applied with `http.with(...)`.

Options:
- `apiKeyRepository(...)`
- `passwordEncoder(...)`
- `headerName(...)`
- `authenticationConverter(...)`
- `unauthorizedOnMissingApiKey(boolean)`, defaulting to `true`

There is no `authenticationManager(...)` option in v1.

Fail-fast validations at build time:
- `headerName` and `authenticationConverter` are both set.
- No repository is set and there is no single `ApiKeyRepository` bean (none, or more than one).

**In `init()`:**
- Register the provider (repository plus encoder; never the application's `PasswordEncoder` bean) through `http.authenticationProvider(...)`, so that it joins the shared `AuthenticationManager`, which carries the context's `AuthenticationEventPublisher`.
- When `unauthorizedOnMissingApiKey` is true, register a bare 401 entry point with `exceptionHandling().defaultAuthenticationEntryPointFor(..., any request)`.
  - Unlike mcp-security, this uses `defaultAuthenticationEntryPointFor`, not `authenticationEntryPoint(...)`, so an entry point the user sets explicitly always wins.
  - The README must document how ordering works with other configurers' defaults in mixed chains.
- If CSRF is enabled, add a CSRF-ignoring request matcher: "the converter returns a non-null token". If the converter throws an `AuthenticationException` inside that matcher, it counts as a match (`true`), so the request reaches the filter and gets a 401.

**In `configure()`:**
- Read the shared `AuthenticationManager`.
- Build the filter with the resolved converter, passing both the converter and the filter through `postProcess(...)`. Post-processing is what lets `@EnableMultiFactorAuthentication` turn on multi-factor merging.
- Insert the filter before `BasicAuthenticationFilter`.

**Logging:** DEBUG level. Logs may include the key id and must never include the secret.

### In-memory repository

**`InMemoryApiKeyRepository<T extends ApiKeyDetails>`** implements `ApiKeyRepository<T>`. It takes a `DetailsFactory<T>` that builds a `T` from the stored id, hash, name and authorities, and an optional `PasswordEncoder` constructor argument that defaults to the library encoder. `InMemoryApiKeyDetails` is a ready-made details type, usable as `InMemoryApiKeyDetails::new`.

- **Storage:** immutable data in a concurrent map. Each `findByKeyId` call builds a fresh details instance through the factory.
- **`generate(name, authorities)`:**
  - The id is `"api"` plus the next value of an `AtomicInteger`, skipping ids that are already taken.
  - The secret comes from the library helper and is hashed with the encoder.
  - It returns a `GeneratedApiKey`.
- **Seeding (`addApiKey(id, rawSecret, name, authorities)` or similar):**
  - Validates the id and the secret against `[A-Za-z0-9_-]+`.
  - Throws on a duplicate id.
  - Hashes the secret on the way in.
  - The Javadoc says it is intended for tests, demos and local development.
- **`delete`:** removes the key; an unknown id is a no-op.

## Testing Decisions

### What makes a good test

- A test checks behaviour observable through a public API: HTTP status, the authenticated principal and its authorities, the exception type and message, the returned values. It never checks private state or internal call order.
- Tests must not mock Spring Security internals in ways that encode the implementation.
- Use real `ProviderManager`, `HttpSecurity` and MockMvc wherever practical.
- Collaborators that are the user's responsibility, such as the repository, may be stubbed in tests of the provider.

### Integration seam: the configured `SecurityFilterChain` through MockMvc

The primary seam is a minimal Spring context, without Spring Boot, with a `SecurityFilterChain` built through `http.with(ApiKeyConfigurer.apiKey(), …)`, driven by MockMvc. It covers:

- **Extraction:** valid, missing, blank, whitespace-padded, malformed and duplicate headers; a custom header name; a custom converter.
- **Responses:**
  - 401 for an invalid key;
  - 401 or pass-through for a missing key, depending on `unauthorizedOnMissingApiKey`;
  - an entry point set explicitly in `http.exceptionHandling` winning;
  - a request already authenticated by another mechanism without a key not being rejected;
  - a key always winning;
  - a repository exception giving a 500.
- **CSRF:** a POST with a key passes; a POST with duplicate key headers gets a 401, not a 500.
- **Principal:** name, authorities, `FACTOR_API_KEY`, and a custom `ApiKeyDetails` reachable through `@AuthenticationPrincipal`.
- **Multi-factor:** merging under `@EnableMultiFactorAuthentication` with a same-name existing authentication.
- **Statelessness:** no session created.
- **Events:** success and failure events published to the context's `AuthenticationEventPublisher`.
- **Startup failures:** header name together with a converter, no repository, several repository beans, all appearing as context-startup failures.
- **End to end:** a key from `generate()`, and a seeded key, used through `getUserFacingApiKey()`. This also covers the `{sha256}` stored format.

### Tracer-bullet tests

A small set of MockMvc tests that each go through the whole stack: header, converter, filter, shared `ProviderManager`, provider, `InMemoryApiKeyRepository`, `{sha256}` encoder, and finally a real controller endpoint. These are the first tests to write. They prove the pieces connect before the detailed behaviour above is filled in, and they stay as the suite's smoke tests.

The fixture is a minimal chain:
- `ApiKeyConfigurer` with its defaults;
- one endpoint that requires authentication and returns the authenticated name and authorities;
- one endpoint that requires a specific authority;
- one `permitAll` endpoint;
- an `InMemoryApiKeyRepository` seeded with one known key, plus one key created through `generate()`.

The cases:

1. **Happy path with a seeded key:** a GET with a valid `X-API-Key` gets a 200. The body shows the expected name, the seeded authorities and `FACTOR_API_KEY`.
2. **Happy path with a generated key:** a GET using `GeneratedApiKey#getUserFacingApiKey()` gets a 200 with the expected name.
3. **Happy path with a write request:** a POST with a valid key and no CSRF token gets a 200 (CSRF bypass), with no redirect and no session created.
4. **Authorization on top of authentication:** a valid key with the required authority gets a 200 from the authority-protected endpoint; a valid key without it gets a 403.
5. **Wrong secret:** a known id with a wrong secret gets a bare 401, with no body and no `WWW-Authenticate`.
6. **Unknown key id:** gets a bare 401, identical to case 5.
7. **No key on a protected endpoint:** gets a 401 from the default entry point.
8. **No key on a `permitAll` endpoint:** gets a 200 (pass-through).
9. **Malformed key:** gets a 401 on a protected endpoint, and also on the `permitAll` endpoint (rejected by the converter, not treated as missing).
10. **Deleted key:** a key that worked, then `delete(keyId)`, then the same request gets a 401.
11. **Repository failure:** with a repository stub that throws, a request with a key gets a 500, not a 401.

### Unit tests for every class

Every public class gets its own unit test, testing its contract in isolation:

- **The `{sha256}` encoder and the default delegating encoder:**
  - stored format (`{sha256}` plus lowercase hex);
  - matching;
  - matching `{bcrypt}` hashes;
  - rejecting wrong secrets.
- **Secret generator helper:** length, charset (unpadded base64url) and uniqueness across calls.
- **`GeneratedApiKey`:** user-facing format and redacted `toString()`.
- **`ApiKeyDetails` default methods:** `getPrincipalName()` and `getLabel()` default to the id.
- **`ApiKeyAuthenticationToken`:**
  - both factory states;
  - `getName()` in each state;
  - credential erasure, which also erases the principal's stored hash;
  - `toBuilder()` declared on the class and preserving the principal and authorities.
- **`ApiKeyAuthenticationProvider`, with a stubbed repository:**
  - success with the factor authority;
  - unknown id;
  - wrong secret;
  - the same exception for an unknown id and a wrong secret;
  - a dummy hash comparison performed for unknown ids, checked through an observable effect such as a spy encoder;
  - repository exceptions wrapped in `InternalAuthenticationServiceException`;
  - unsupported token types.
- **`ApiKeyAuthenticationConverter`:** every row of the extraction table above.
- **`ApiKeyAuthenticationFilter`, with a mock filter chain and a real `ProviderManager`:**
  - pass-through on a `null` conversion;
  - chain continues with no redirect on success;
  - bare 401 on failure;
  - `AuthenticationServiceException` rethrown;
  - context stored as a request attribute and not in a session;
  - both constructors.
- **`ApiKeyConfigurer`:** option validation and fail-fast messages, repository bean resolution, and the default for `unauthorizedOnMissingApiKey`. Where behaviour is only observable through a built chain, that test lives in the integration suite.
- **`InMemoryApiKeyRepository`:**
  - `generate()` producing the sequence `api1`, `api2`, …;
  - skipping taken ids;
  - seeding validation;
  - duplicate seeded ids throwing;
  - secrets stored hashed;
  - `findByKeyId` returning fresh instances (erasing one leaves the stored data intact);
  - `null` for an unknown id;
  - `delete` removing a key and being a no-op for an unknown id;
  - a custom encoder being used.

### Prior art

- The `mcp-security` tests: `ApiKeyImplTests`, `InMemoryApiKeyEntityRepositoryTest`, `ApiKeyAuthenticationConverterTests`, `ApiKeyAuthenticationFilterTests`, `McpApiKeyConfigurerTest`.
- Spring Security's own configurer tests, which build chains with MockMvc inside a Spring test context.

This repository has no code yet, so there is no in-repo prior art.

## Out of Scope

- A Spring Boot starter or auto-configuration.
- Reactive / WebFlux support.
- A JDBC repository (planned for v2, outside this effort).
- Test-support helpers for library consumers: MockMvc request post-processors, `@WithApiKey`-style annotations.
- Key status in the model (expiry, enabled, last-used); repositories return `null` for keys that are no longer valid.
- Listing keys, or any key management UI or endpoints.
- A custom `AuthenticationManager` option on the configurer.
- A configurable failure handler or entry point on the configurer; users override the missing-key entry point through `http.exceptionHandling` or assemble the filter by hand.
- A "missing `FACTOR_API_KEY`" access-denied handler.
- Key prefixes for secret scanning.
- Query-parameter or `Authorization`-header extraction out of the box (possible through a custom converter).

## Further Notes

- **Publishing:** the release strategy was not settled explicitly. Assumption: Maven Central eventually, with a `0.1.0-SNAPSHOT` version in the pom for now and no API-stability promise before `1.0`. Revisit before the first release.
- **The plaintext rule is documented, not enforced:** with no abstract base class, "never store plaintext secrets" is a documented contract for custom `ApiKeyRepository` implementations. The README must make this prominent.
- **Two encoders:** verification (configurer) and generation (repository) use separate encoders that share one default. Because the delegating encoder can match any standard prefix, they rarely diverge; the README must warn that fully custom encoders have to match on both sides.
- **Mixed chains:** when `formLogin()` and API keys share a chain, the 401 default entry point is one of several defaults, and the first one registered acts as the fallback. The README should show the recommended setup.
- **Spring Security 7 facts behind these decisions** (checked against the 7.0.7 and 7.1.1 sources):
  - `AuthenticationFilter`'s default success handler redirects and *then* continues the chain.
  - Its default failure handler sends a bare 401 and rethrows `AuthenticationServiceException`.
  - Multi-factor merging requires the token class to declare its own `toBuilder()`, a matching `getName()`, and a filter that has been post-processed.
  - `HttpSecurity`'s shared authentication manager gets the `AuthenticationEventPublisher` bean, or a default one.
