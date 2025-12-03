package at.asitplus.wallet.lib.oauth2

import io.ktor.http.URLBuilder

object OAuth2Utils {

    /** Inserts [path] between the host component and the path component of [publicContext], if any. */
    public fun insertWellKnownPath(publicContext: String, path: List<String>): String =
        URLBuilder(publicContext).apply {
            pathSegments = path + (pathSegments.dropWhile { it == "" })
        }.buildString()

}