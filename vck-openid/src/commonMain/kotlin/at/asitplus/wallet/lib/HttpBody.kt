package at.asitplus.wallet.lib

import at.asitplus.wallet.lib.data.MediaTypes
import io.ktor.http.*

/**
 * An encoded body, e.g. form, JSON or JWT, with its media type, which is sent as `Content-Type` with it. Bodies are
 * always text, as is every body of the protocols covered here.
 */
data class HttpBody(
    val contentType: ContentType,
    val text: String,
)

/** Media types of [HttpBody]s that ktor does not define. */
internal object BodyContentTypes {
    /** `application/jwt` */
    val Jwt = ContentType.parse(MediaTypes.Application.JWT)

    /** `application/oauth-authz-req+jwt` */
    val AuthzReqJwt = ContentType.parse(MediaTypes.Application.AUTHZ_REQ_JWT)

    /** `application/token-introspection+jwt` */
    val TokenIntrospectionJwt = ContentType.parse(MediaTypes.Application.TOKEN_INTROSPECTION_JWT)
}

/** Fails if these headers contain `Content-Type`, which is sent with the [HttpBody] instead. */
internal fun Headers.requireNoContentType() =
    require(!contains(HttpHeaders.ContentType)) { "Content-Type is set with the body, not in the headers" }
