package at.asitplus.wallet.lib.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

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
    val verifiableCredential: Array<String>,
) {

    constructor(verifiableCredential: Array<String>) : this(
        id = @OptIn(ExperimentalUuidApi::class) "urn:uuid:${Uuid.random()}",
        type = "VerifiablePresentation",
        verifiableCredential = verifiableCredential
    )

    fun toJws(challenge: String, subjectId: String, audienceId: String) = VerifiablePresentationJws(
        vp = this,
        challenge = challenge,
        issuer = subjectId,
        audience = audienceId,
        jwtId = id
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as VerifiablePresentation

        if (id != other.id) return false
        if (type != other.type) return false
        if (!verifiableCredential.contentEquals(other.verifiableCredential)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + type.hashCode()
        result = 31 * result + verifiableCredential.contentHashCode()
        return result
    }

}