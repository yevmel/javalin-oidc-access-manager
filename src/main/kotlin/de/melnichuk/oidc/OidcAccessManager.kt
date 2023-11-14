package de.melnichuk.oidc

import com.auth0.jwk.JwkProvider
import com.auth0.jwk.JwkProviderBuilder
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.TokenExpiredException
import com.auth0.jwt.interfaces.DecodedJWT
import com.fasterxml.jackson.annotation.JsonProperty
import io.javalin.http.Context
import io.javalin.http.Handler
import io.javalin.http.HttpStatus
import io.javalin.security.AccessManager
import io.javalin.security.RouteRole
import org.slf4j.LoggerFactory
import java.lang.Exception
import java.lang.IllegalArgumentException
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey

private val LOG = LoggerFactory.getLogger("oidc")

data class User(
   val username: String
)

data class OidcAccessManagerConfiguration(
   val oidcClientId: String,
   val oidcBaseUrl: String,
   val callbackPath: String
)

class OidcAccessManager(
   private val configuration: OidcAccessManagerConfiguration,
   private val unprotectedEndpoints: List<String>
) : AccessManager {
   private val jwkProvider: JwkProvider = JwkProviderBuilder(configuration.oidcBaseUrl).cached(true).build()

   override fun manage(handler: Handler, ctx: Context, routeRoles: Set<RouteRole>) {
      if (unprotectedEndpoints.contains(ctx.path())) {
         handler.handle(ctx)
      } else {
         try {
            val token = ctx.cookie("id")
            if (token == null) {
               LOG.info("missing 'id' cookie.")
               redirectLogin(ctx)
            } else {
               val jwt = JWT.decode(token)
               val algorithm = setupAlgorithm(jwt)
               val verifier = JWT.require(algorithm).withIssuer(configuration.oidcBaseUrl).build()
               val verifiedJWT = verifier.verify(jwt)

               val username = verifiedJWT.getClaim("name").asString()
               val user = User(username)
               ctx.attribute("user", user)

               handler.handle(ctx)
            }
         } catch (e: TokenExpiredException) {
            LOG.info("token expired.")
            redirectLogin(ctx)
         } catch (e: Exception) {
            LOG.error("authentication failed.", e)
            ctx.status(HttpStatus.FORBIDDEN).result(e.message ?: "")
         }
      }
   }

   private fun redirectLogin(ctx: Context) {
      val redirectUrl = setupRedirectURL(ctx, configuration.callbackPath)
      val scopes = "openid profile"
      val responseType = "code"
      val state = listOfNotNull(ctx.path(), ctx.queryString()).joinToString("?")
      val authorizeEndpoint = "${configuration.oidcBaseUrl}authorize?response_type=${responseType}&client_id=${configuration.oidcClientId}&redirect_uri=${redirectUrl}&scope=${scopes}&state=${state}"

      LOG.info("redirecting user to login.")
      ctx.status(HttpStatus.FOUND).header("Location", authorizeEndpoint)
   }

   private fun setupAlgorithm(jwt: DecodedJWT): Algorithm {
      return when (jwt.algorithm) {
         "RS256" ->  Algorithm.RSA256(getPublicKey(jwt) as RSAPublicKey, null)
         "RS384" ->  Algorithm.RSA384(getPublicKey(jwt) as RSAPublicKey, null)
         "RS512" ->  Algorithm.RSA512(getPublicKey(jwt) as RSAPublicKey, null)

         else -> throw IllegalArgumentException("unsupported algorithm: ${jwt.algorithm}")
      }
   }

   private fun getPublicKey(jwt: DecodedJWT): PublicKey =
      jwkProvider.get(jwt.keyId)?.publicKey ?: throw IllegalArgumentException("no public key found for '${jwt.keyId}'")
}

data class TokensResponse(
   @JsonProperty("access_token")
   val accessToken: String,

   @JsonProperty("id_token")
   val idToken: String,

   val scope: String
)
