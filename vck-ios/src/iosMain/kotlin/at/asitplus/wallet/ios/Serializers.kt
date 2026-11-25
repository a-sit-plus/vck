@file:OptIn(ExperimentalObjCName::class)

package at.asitplus.wallet.ios

import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import kotlinx.serialization.SerializationException
import kotlin.experimental.ExperimentalObjCName

/**
 * Parsing that Swift can not do with [JoseCodec] or [CoseCodec], which encode and decode any other serializable type:
 * Swift can not call the reified factory of [JwsCompactTyped]. None of these verify the signature.
 */
object VckSerializer {

    /** Parses a compact JWS of a key attestation, e.g. for `JwtProofCreator`'s `loadKeyAttestation`. */
    @Throws(SerializationException::class, IllegalArgumentException::class)
    fun joseDeserializeKeyAttestationJwt(@ObjCName("_") string: String): JwsCompactTyped<KeyAttestationJwt> =
        JwsCompactTyped<KeyAttestationJwt>(string)

    /** Parses a compact JWT, e.g. a Wallet Instance Attestation for `ClientAttestation`'s `loadInstanceAttestation`. */
    @Throws(SerializationException::class, IllegalArgumentException::class)
    fun joseDeserializeJsonWebTokenJws(@ObjCName("_") string: String): JwsCompactTyped<JsonWebToken> =
        JwsCompactTyped<JsonWebToken>(string)
}
