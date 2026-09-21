package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Marker type for a token status mechanism.
 * Carries only the URI plus flavor-specific metadata so the resolver can download and
 * interpret the right [RevocationList].
 */
sealed class RevocationListInfo {
    abstract val uri: UniformResourceIdentifier

    /**
     * The identifier_list and status_list in the MSO may contain the Certificate element. If the
     * Certificate element is present, it shall contain a certificate containing the public key that signed the
     * top-level certificate in the x5chain element in the MSO revocation list structure. The mdoc reader shall
     * use that certificate as trust point for verification of the x5chain element in the MSO revocation list
     * structure. If the Certificate element is not present, the top-level certificate in the x5chain element
     * shall be signed by the certificate used to sign the certificate in the x5chain element of the MSO. In the
     * context of an mDL, that is the IACA certificate.
     */
    abstract val certificate: ByteArray?

    /**
     * Wire representation of a referenced token's status object.
     *
     * A status object may contain more than one mechanism. The internal constructor and public type are retained
     * for compatibility with 7.0.1.
     */
    @ConsistentCopyVisibility
    @Serializable
    @SerialName("status")
    data class StatusSurrogate internal constructor(
        @SerialName("status_list")
        val statusList: StatusListInfo? = null,

        @SerialName("identifier_list")
        val identifierList: IdentifierListInfo? = null,
    ) {
        init {
            require(statusList != null || identifierList != null) {
                "At least one token status mechanism must be present"
            }
        }
    }

    /**
     * Serializes [RevocationListInfo] into the status object used by JOSE and COSE credentials.
     * Singleton status objects retain the 7.0.1 leaf type when decoded.
     */
    object StatusSurrogateSerializer : TransformingSerializerTemplate<RevocationListInfo, StatusSurrogate>(
        parent = StatusSurrogate.serializer(),
        encodeAs = {
            when (it) {
                is StatusListInfo -> StatusSurrogate(
                    statusList = it,
                    identifierList = it.identifierListInfo,
                )
                is IdentifierListInfo -> StatusSurrogate(identifierList = it)
            }
        },
        decodeAs = {
            when {
                it.statusList != null && it.identifierList != null ->
                    it.statusList.withIdentifierListInfo(it.identifierList)

                it.statusList != null -> it.statusList
                else -> it.identifierList!!
            }
        },
    )
}
