package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims

import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimKey
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimName
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtPayloadClaimSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.cbor.CborLabel

/**
 * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-05.html
 *
 *  6.1. Status Claim
 *
 * By including a "status" claim in a Referenced Token, the Issuer is referencing a mechanism to
 * retrieve status information about this Referenced Token. The claim contains members used to
 * reference to a status list as defined in this specification. Other members of the "status" object
 * may be defined by other specifications. This is analogous to "cnf" claim in Section 3.1 of
 * [RFC7800] in which different authenticity confirmation methods can be included.
 *
 * The status claim is encoded as a Status CBOR structure and MUST include at least one data item
 * that refers to a status mechanism. Each data item in the Status CBOR structure comprises a
 * key-value pair, where the key must be a CBOR text string (Major Type 3) specifying the identifier
 * of the status mechanism, and the corresponding value defines its contents. This specification
 * defines the following data items:
 */
data object CwtStatusPayloadClaimSpecification : CwtPayloadClaimSpecification {
    const val NAME = "status"
    const val KEY = 65535L

    override val claimName: CwtClaimName
        get() = CwtClaimName(NAME)
    override val claimKey: CwtClaimKey
        get() = CwtClaimKey(KEY)

    // TODO: is there a way to make this status be of a type like Map<CborTextString, CborElement>?
    interface ClaimProvider<Status: Any> {
        /**
         * Annotations need to be applied to properties of derived classes.
         */
        @SerialName(NAME)
        @CborLabel(KEY)
        val status: Status?
    }

    val CwtPayloadClaimSpecification.Companion.status: CwtStatusPayloadClaimSpecification
        get() = CwtStatusPayloadClaimSpecification
}