package at.asitplus.data

import at.asitplus.openid.jwtpayload.KeyAttestationPayload
import at.asitplus.signum.indispensable.asn1.encoding.encodeTo4Bytes
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.typed
import kotlinx.serialization.json.JsonObject

object JwsExtensions {

    /**
     * Prepend `this` with the size as four bytes
     */
    fun ByteArray.prependWith4BytesSize() = this.size.encodeTo4Bytes() + this

}

val JwsHeader.keyAttestationParsed: JwsCompactTyped<KeyAttestationPayload>?
    get() = keyAttestation?.typed()

//TODO find correct payload
val JwsHeader.verifierAttestationParsed: JwsCompactTyped<JsonObject>?
    get() = attestationJwt?.typed()
