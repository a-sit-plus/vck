@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.wallet.ios

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.internals.toByteArray
import at.asitplus.signum.internals.toNSData
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import platform.Foundation.NSData

/**
 * Encodes and decodes any serializable VC-K or Signum type as JSON, the way JOSE and OpenID require, so Swift needs no
 * adapter per type. Swift keeps the type argument of this class, e.g.
 * `JoseCodec<IssuerMetadata>(serializer: IssuerMetadata.companion.serializer())`.
 *
 * Decoding throws `SerializationException` for malformed input, and `IllegalArgumentException` for input that the type
 * rejects, e.g. in its `init` block.
 */
class JoseCodec<T : Any>(private val serializer: KSerializer<T>) {

    @Throws(IllegalArgumentException::class)
    fun decode(data: NSData): T = decodeFromString(data.toByteArray().decodeToString())

    @Throws(IllegalArgumentException::class)
    fun decodeFromString(string: String): T = joseCompliantSerializer.decodeFromString(serializer, string)

    @Throws(IllegalArgumentException::class)
    fun encode(value: T): NSData = encodeToString(value).encodeToByteArray().toNSData()

    @Throws(IllegalArgumentException::class)
    fun encodeToString(value: T): String = joseCompliantSerializer.encodeToString(serializer, value)
}

/**
 * Encodes and decodes any serializable VC-K or Signum type as CBOR, the way COSE and ISO mDoc require, e.g.
 * `CoseCodec<IssuerSigned>(serializer: IssuerSigned.companion.serializer())`. Throws like [JoseCodec].
 */
class CoseCodec<T : Any>(private val serializer: KSerializer<T>) {

    @Throws(IllegalArgumentException::class)
    fun decode(data: NSData): T = coseCompliantSerializer.decodeFromByteArray(serializer, data.toByteArray())

    @Throws(IllegalArgumentException::class)
    fun encode(value: T): NSData = coseCompliantSerializer.encodeToByteArray(serializer, value).toNSData()
}

/**
 * Parses a compact JWS and decodes its payload as JSON, e.g. a key attestation for `JwtProofCreator`'s
 * `loadKeyAttestation` with `JwsCompactCodec<KeyAttestationJwt>(serializer: KeyAttestationJwt.companion.serializer())`,
 * or a Wallet Instance Attestation with `JwsCompactCodec<JsonWebToken>`. Swift can not call the reified factory of
 * [JwsCompactTyped]. Does not verify the signature. Throws like [JoseCodec].
 */
class JwsCompactCodec<P : Any>(private val serializer: KSerializer<P>) {

    @Throws(IllegalArgumentException::class)
    fun decodeFromString(string: String): JwsCompactTyped<P> {
        val jws = JwsCompact(string)
        return JwsCompactTyped(jws, jws.getPayload(serializer).getOrThrow())
    }

    /** The compact serialization, as it was signed. */
    fun encodeToString(value: JwsCompactTyped<P>): String = value.jws.toString()
}
