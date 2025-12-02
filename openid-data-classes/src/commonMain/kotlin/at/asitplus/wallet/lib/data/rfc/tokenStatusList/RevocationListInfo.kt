package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.csc.xor
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Marker type for revocation artefact.
 * Carries only the URI plus flavour-specific metadata so the resolver can download and
 * interpret the right [RevocationList].
 */
sealed class RevocationListInfo {
    abstract val uri: UniformResourceIdentifier

    /**
     * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-06.html#name-status-claim
     *
     * By including a "status" claim in a Referenced Token, the Issuer is referencing a mechanism to
     * retrieve status information about this Referenced Token. The claim contains members used to
     * reference to a Status List Token as defined in this specification. Other members of the "status"
     * object may be defined by other specifications. This is analogous to "cnf" claim in Section 3.1
     * of RFC7800 in which different authenticity confirmation methods can be included.
     *
     * ISO 18013-5 defines new mechanism "IdentifierList". Either the StatusList OR IdentifierList
     * may be used but not both at the same time.
     *
     * Do not use this class directly! Use [RevocationListInfo] in combination with [StatusSurrogateSerializer] instead!
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
            require(statusList xor identifierList)
        }
    }

    /**
     * Serializes a sealed [RevocationListInfo] into the JOSE/COSE field structure defined by the
     * specifications above
     */
    object StatusSurrogateSerializer : TransformingSerializerTemplate<RevocationListInfo, StatusSurrogate>(
        parent = StatusSurrogate.serializer(),
        encodeAs = {
            when (it) {
                is StatusListInfo -> StatusSurrogate(statusList = it)
                is IdentifierListInfo -> StatusSurrogate(identifierList = it)
            }
        },
        decodeAs = {
            require(it.statusList xor it.identifierList) { "Either StatusListInfo or IdentifierListInfo must be present but not both" }
            it.statusList ?: it.identifierList!!
        }
    )
}