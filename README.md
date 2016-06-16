# hapi-google-id-token
Authenticate using a Google ID Token

[![Build Status](https://travis-ci.org/wwalser/hapi-google-id-token.svg?branch=master)](https://travis-ci.org/wwalser/hapi-google-id-token)

See [Google Identity Platform docs](https://developers.google.com/identity/sign-in/web/backend-auth) for information on obtaining a Google ID Token.


## Documentation

- `clientId` - (***required***) Your application's Google apps clientId.
- `validateToken` - (***optional***) the function which is run once the Token has been decoded and verified against Google public keys.
 signature `function(decoded, request, callback)` where:
    - `decoded` - (***required***) is the ***decoded*** and ***verified*** JWT received from the client in **request.headers.authorization**
    - `request` - (***required***) is the original ***request*** received from the client
    - `callback` - (***required***) a callback function with the signature `function(err, credentials)` where:
        - `err` - an internal error.
        - `credentials` - (***optional***) alternative credentials to be set instead of `decoded`.
- `urlKey` - (***optional***) Used to override the query parameter that can be used to accept the token. Defaults to `id_token`. May be set to `false` to disable query parameter checks.
- `cookieKey` - (***optional***) Used to override the cookie key that can be used to accept the token. Defaults to `id_token`. May be set to `false` to disable cookie checks.
- `headerKey` - (***optional***) Used to override the header that can be used to accept the token. Defaults to `authorization`, because it's standard and cors friendly.