package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JwsCompact

/**
 * Wrapper for [at.asitplus.signum.indispensable.josef.JwsCompact]. Useful when [payload] type is known as part of the contract.
 * All communication to outside parties should use [jws] only!
 */
data class JwsCompactTyped<P>(
    val jws: JwsCompact,
    val payload: P,
) {
    companion object {
        inline operator fun <reified P> invoke(jws: JwsCompact) =
            JwsCompactTyped(jws, jws.getPayload<P>().getOrThrow())

        inline operator fun <reified P> invoke(base64UrlString: String) =
            JwsCompact.Companion.parse<P>(base64UrlString).getOrThrow().let { (jws, payload) -> JwsCompactTyped(jws, payload) }
    }
}