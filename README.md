# CAS Proxy

Proxy CAS3/Oauth2 auth request to oidc client.

```
+----------------+     +---------------------+     +-------------------+
|                |     |                     |     |                   |
|   Keycloak     |     |    authcas-cra      |     |    CAS Server    |
|                |     |                     |     |                   |
+-------+--------+     +---------+-----------+     +-------+-----------+
        |                      |                           |
        |  /authorize?         |                           |
        +--------------------->|                           |
        |                      | /cas/login?service=...    |
        |                      |-------------------------->|
        |                      |                           |
        |                      |          ticket           |
        |                      |<--------------------------|
        |                      |                           |
        |                      | /callback?ticket=...      |
        |                      +-------------------------->|
        |                      |                           |
        |                      |         auth_code         |
        |                      |<--------------------------|
        |       auth_code      |                           |
        |<---------------------+                           |
        |                      |                           |
        |   /token?code=...    |                           |
        +--------------------->|                           |
        |                      |                           |
        |                      |      access_token         |
        |                      |<--------------------------|
        |  /userinfo?          |                           |
        +--------------------->|                           |
        |                      |                           |
        |                      |     User Information      |
        |                      |<--------------------------|
        |                      |                           |
        v                      v                           v

```

