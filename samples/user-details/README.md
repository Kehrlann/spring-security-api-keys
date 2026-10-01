# Sample: API keys owned by users

API keys as personal access tokens: users sign in with a password, manage their own keys on a web page, and use them to call the API as themselves.

## Running

```sh
./mvnw -pl samples/user-details -am spring-boot:run
```

Open http://localhost:8080, sign in, then create and delete keys. A new key is shown once, right after it is created.

| User    | Password   | Roles          | Seeded keys                                                                           |
|---------|------------|----------------|---------------------------------------------------------------------------------------|
| `alice` | `password` | USER, ADMIN    | `alice-admin.alice-admin-secret` (USER, ADMIN), `alice-user.alice-user-secret` (USER) |
| `bob`   | `password` | USER           | `bob.bob-secret` (USER, ADMIN, but bob is not an admin)                               |
| `carol` | `password` | USER, disabled | `carol.carol-secret`                                                                  |

```sh
curl -H "X-API-Key: alice-admin.alice-admin-secret" localhost:8080/api/me
# {"name":"alice","authorities":["ROLE_USER","ROLE_ADMIN","FACTOR_API_KEY"]}

curl -i -H "X-API-Key: alice-user.alice-user-secret" localhost:8080/api/admin   # 403
curl -i -H "X-API-Key: bob.bob-secret" localhost:8080/api/admin                 # 403
curl -i -H "X-API-Key: carol.carol-secret" localhost:8080/api/me                # 401
curl -i localhost:8080/api/me                                                   # 401
```

## How it works

`UserApiKeyRepository` is a custom `ApiKeyRepository` that stores hashed keys in memory, each with an owner and a label. Generated keys look like `api<n>.<secret>`, where `<n>` is an incrementing number (`api1`, `api2`, …) that skips seeded ids. It loads the owner on every lookup:

- the authenticated name is the owner's username;
- a key grants the roles it was created with, minus those its owner no longer has;
- a key stops working as soon as its owner is deleted, disabled, locked or expired.

The security configuration mixes form login and API keys in one chain:

- `/api/**` accepts API keys (or a login session). Without credentials it gets a bare 401, through `defaultAuthenticationEntryPointFor`, with `unauthorizedOnMissingApiKey(false)`.
- Every other page requires `FACTOR_PASSWORD`. An API key can call the API, but it can never reach the key management page, so a leaked key cannot create new keys. Spring Security sends a request authenticated only with an API key to the login page instead.
- Users can only create keys with roles they have, and only delete their own keys.
