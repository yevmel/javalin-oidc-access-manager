# javalin-oidc-access-manager
OpenID Connect Access Manager for Javalin

## usage

```kotlin
val baseUrl = "https://xxxxxxx.auth0.com/"
val callbackPath = "/auth/callback"
val clientId = "..."
val clientSecret = "..."

val server = Javalin.create() {
   it.accessManager(OidcAccessManager(OidcAccessManagerConfiguration(
         oidcClientId = clientId,
         oidcBaseUrl = baseUrl,
         callbackPath = callbackPath
      ), listOf("/auth/callback", "/auth/login")
   ))
}

server.get("/auth/callback", CodeCallbackHandler(
   CodeCallbackHandlerConfiguration(
      oidcClientId = clientId,
      oidcClientSecret = clientSecret,
      oidcBaseUrl = baseUrl,
      callbackPath = callbackPath
   )
))
```
