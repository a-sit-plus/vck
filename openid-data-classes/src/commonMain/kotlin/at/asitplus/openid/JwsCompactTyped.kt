package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.serializer

/**
 * Wrapper for [at.asitplus.signum.indispensable.josef.JwsCompact]. Useful when [payload] type is known as part of the contract.
 * All communication to outside parties should use [jws] only!
 *
 * While the constructor can be used the different [invoke]'s are recommended
 */
data class JwsCompactTyped<P>(
    val jws: JwsCompact,
    val payload: P,
) {
    override fun toString(): String = jws.toString()

    companion object {
        inline operator fun <reified P> invoke(jws: JwsCompact) =
            JwsCompactTyped(jws, jws.getPayload<P>().getOrThrow())

        inline operator fun <reified P> invoke(base64UrlString: String) =
            JwsCompact.parse<P>(base64UrlString).getOrThrow()
                .let { (jws, payload) -> JwsCompactTyped(jws, payload) }

        //TODO test if this needs to be changed to vckJsonSerializer or serializersModule works just fine
        suspend inline operator fun <reified P> invoke(
            protectedHeader: JwsHeader,
            payload: P,
            noinline signer: suspend (ByteArray) -> ByteArray
        ): JwsCompactTyped<P> {
            val plainPayload =
                joseCompliantSerializer.encodeToString(joseCompliantSerializer.serializersModule.serializer(), protectedHeader).encodeToByteArray()
            return JwsCompactTyped<P>(
                JwsCompact.invoke(protectedHeader = protectedHeader, payload = plainPayload, signer = signer),
                payload
            )
        }
    }
}