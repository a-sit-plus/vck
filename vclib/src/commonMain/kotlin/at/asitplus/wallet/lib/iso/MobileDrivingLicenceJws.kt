package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.data.InstantLongSerializer
import at.asitplus.wallet.lib.data.NullableInstantLongSerializer
import at.asitplus.wallet.lib.data.jsonSerializer
import io.github.aakira.napier.Napier
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * JWS representation of a [MobileDrivingLicence], used e.g. in the payload of a JWS in a single
 * instance of [ServerResponse.documents]
 */
@Serializable
data class MobileDrivingLicenceJws(
    @SerialName("doctype")
    val doctype: String,
    @SerialName("namespaces")
    val namespaces: MobileDrivingLicenceJwsNamespace,
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant,
    @SerialName("exp")
    @Serializable(with = NullableInstantLongSerializer::class)
    val expiration: Instant?,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<MobileDrivingLicenceJws>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }

}