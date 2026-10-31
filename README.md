# spring-security-api-key

API key authentication for Spring Security 7 (Servlet). Java 17+.

```xml
<dependency>
  <groupId>wf.garnier</groupId>
  <artifactId>spring-security-api-key</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

No API stability promise before 1.0.

## Setup

```java
@Bean
SecurityFilterChain chain(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(a -> a.anyRequest().authenticated())
        .with(ApiKeyConfigurer.apiKey(), c -> c.apiKeyRepository(repository))
        .build();
}
```

If you omit `apiKeyRepository(...)`, the configurer uses the single `ApiKeyRepository` bean. Startup fails if there is none, or several.

Options: `apiKeyRepository`, `passwordEncoder`, `headerName` (default `X-API-Key`), `authenticationConverter` (mutually exclusive with `headerName`), `unauthorizedOnMissingApiKey` (default `true`).

Behaviour:

- No key (or a blank one): the request passes through; authorization decides.
- Invalid or malformed key: bare `401`. Several `X-API-Key` headers: `401`.
- Repository failure: `500`.
- Stateless: no session is created, and the token is never saved to one.
- Requests carrying a key skip CSRF protection.
- A key always wins over an existing authentication.
- Authentication events go through the context's `AuthenticationEventPublisher`.
- Authenticated keys carry `FACTOR_API_KEY` (`ApiKeyAuthenticationProvider.FACTOR_API_KEY`), so they work with `@EnableMultiFactorAuthentication`.
- A key that lacks a required factor (e.g. `FACTOR_PASSWORD`) is handled like any other authentication missing that factor: Spring Security sends it to that factor's entry point (a form-login redirect, an HTTP Basic `401` challenge), not a `403`.

## Keys

A key is `<keyId>.<secret>`; both parts match `[A-Za-z0-9_-]+`. Generate one with `repository.generate(name, authorities)`; the raw secret is returned once, in the `GeneratedApiKey` (`getUserFacingApiKey()`).

Only the secret is hashed, never the full key. The default encoder is a `DelegatingPasswordEncoder` that encodes with `{sha256}` (lowercase hex of unsalted SHA-256, compared in constant time) and also verifies `{bcrypt}`, `{argon2}`, etc. SHA-256 is appropriate because secrets are 32 random bytes. The application's own `PasswordEncoder` bean is never used.

Verification (configurer) and generation (repository) use separate encoders sharing one default. If you plug in a fully custom encoder, set it on both.

`InMemoryApiKeyRepository<T>` is for demos, tests and local development. It takes a `DetailsFactory<T>` that builds your details type from the stored data, e.g. `new InMemoryApiKeyRepository<>(InMemoryApiKey::new)`. `addApiKey(id, rawSecret, name, label, authorities)` seeds a known key; `addApiKey(id, rawSecret, name, authorities)` and `generate` use the key id as the label.

## Custom repository

Implement `ApiKeyRepository<T extends ApiKeyDetails>`:

- **Never store plaintext secrets.** Hash with a `PasswordEncoder` before persisting. Use `ApiKeySecrets.generate()` for secrets.
- `findByKeyId` returns a fresh instance on every call (credentials are erased after authentication) and `null` for unknown, expired or revoked keys.
- Ids must match `[A-Za-z0-9_-]+`.
- `delete` of an unknown id is a no-op.

## Mixed chains

With the default `unauthorizedOnMissingApiKey(true)`, the configurer registers a bare-401 entry point through `defaultAuthenticationEntryPointFor(anyRequest)`. An entry point you set with `http.exceptionHandling(e -> e.authenticationEntryPoint(...))` always wins. When other configurers (e.g. `formLogin()`) also register default entry points, the first one registered is the fallback; to keep the login redirect for browsers, set `unauthorizedOnMissingApiKey(false)` or register your own entry point with `defaultAuthenticationEntryPointFor(...)` and a request matcher.

## Manual assembly

All building blocks are public: `ApiKeyAuthenticationToken`, `ApiKeyAuthenticationProvider`, `ApiKeyAuthenticationConverter` and `ApiKeyAuthenticationFilter`. Use them directly for cases the configurer does not cover, such as a custom `AuthenticationManager`.

## Samples

- [`samples/user-details`](samples/user-details): API keys owned by `UserDetailsService` users, as personal access tokens, with form login and a page to manage your own keys.

## Building

`./mvnw verify` builds the library (`spring-security-api-key`) and the samples. NullAway runs through Error Prone and fails the build; `.mvn/jvm.config` carries the required `--add-exports`.
