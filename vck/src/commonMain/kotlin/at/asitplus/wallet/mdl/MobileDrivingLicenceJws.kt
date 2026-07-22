package at.asitplus.wallet.mdl

import at.asitplus.signum.indispensable.io.InstantLongSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

/**
 * JWS representation of a [MobileDrivingLicence], used e.g. in the payload of a JWS in a single
 * instance of [at.asitplus.iso.ServerResponse.documentsJws]
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
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant?,
)