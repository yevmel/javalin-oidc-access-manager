package de.melnichuk.oidc

import io.javalin.http.Context
import io.javalin.http.Cookie
import io.javalin.http.Handler
import io.javalin.json.jsonMapper
import java.lang.IllegalArgumentException
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets

data class CodeCallbackHandlerConfiguration(
   val oidcClientId: String,
   val oidcClientSecret: String,
   val oidcBaseUrl: String,
   val callbackPath: String
)

class CodeCallbackHandler(
   private val configuration: CodeCallbackHandlerConfiguration
) : Handler {
   override fun handle(ctx: Context) {
      val code = ctx.queryParam("code") ?: throw IllegalArgumentException("missing 'code' parameter.")
      val origin = ctx.queryParam("state") ?: "/"

      val tokens = HttpClient.newHttpClient().use {
         val response = it.send(setupRequest(
            ctx,
            code,
            configuration.oidcClientId,
            configuration.oidcClientSecret,
            configuration.oidcBaseUrl
         ), HttpResponse.BodyHandlers.ofString())

         ctx.jsonMapper().fromJsonString<TokensResponse>(response.body(), TokensResponse::class.java)
      }

      ctx.cookie(Cookie(
         name = "id",
         value = tokens.idToken,
         secure = isRequestSecure(ctx),
         isHttpOnly = true
      ))

      ctx.redirect(origin)
   }

   private fun setupRequest(
      ctx: Context,
      code: String,
      oidcClientId: String,
      oidcClientSecret: String,
      oidcBaseUrl: String
   ): HttpRequest {
      val form = mapOf(
         "code" to code,
         "client_id" to oidcClientId,
         "client_secret" to oidcClientSecret,
         "grant_type" to "authorization_code",
         "redirect_uri" to setupRedirectURL(ctx, configuration.callbackPath),
      ).map { entry -> URLEncoder.encode(entry.key, StandardCharsets.UTF_8) + "=" + URLEncoder.encode(entry.value, StandardCharsets.UTF_8)}.joinToString("&")

      return HttpRequest.newBuilder(URI("${oidcBaseUrl}oauth/token"))
         .header("Content-Type", "application/x-www-form-urlencoded")
         .POST(HttpRequest.BodyPublishers.ofString(form))
         .build()
   }
}
