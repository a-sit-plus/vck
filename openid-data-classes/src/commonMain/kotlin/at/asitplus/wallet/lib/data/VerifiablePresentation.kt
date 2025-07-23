package at.asitplus.wallet.lib.data

import com.benasher44.uuid.uuid4
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * A Verifiable Presentation (see [W3C VC Data Model](https://w3c.github.io/vc-data-model/)), containing one or more [VerifiableCredential]s.
 */
@Serializable
data class VerifiablePresentation(
    @SerialName("id")
    val id: String,
    @SerialName("type")
    val type: String,
    @SerialName("verifiableCredential")
    val verifiableCredential: Collection<String>,
) {

    constructor(verifiableCredential: Collection<String>) : this(
        id = "urn:uuid:${uuid4()}",
        type = "VerifiablePresentation",
        verifiableCredential = verifiableCredential
    )

    fun toJws(challenge: String, issuerId: String, audienceId: String) = VerifiablePresentationJws(
        vp = this,
        challenge = challenge,
        issuer = issuerId,
        audience = audienceId,
        jwtId = id
    )
}