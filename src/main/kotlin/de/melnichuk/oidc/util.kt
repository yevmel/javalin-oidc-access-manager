package de.melnichuk.oidc

import io.javalin.http.Context

fun isRequestSecure(ctx: Context) = ctx.req().isSecure || ctx.header("x-arr-ssl") == "true"

fun setupRedirectURL(ctx: Context, path: String): String {
   val protocol = if (isRequestSecure(ctx)) "https" else "http"
   return "${protocol}://${ctx.host()}${path}"
}
