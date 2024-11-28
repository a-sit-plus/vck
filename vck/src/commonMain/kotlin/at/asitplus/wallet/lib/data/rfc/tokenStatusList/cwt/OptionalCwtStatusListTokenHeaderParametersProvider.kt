package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt

import at.asitplus.wallet.lib.data.rfc9596.cose.headers.CoseTypeHeaderParameterSpecification
import at.asitplus.wallet.lib.cbor.CoseSignedTypeConstants
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenHeader
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.MissingHeaderParameterException
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtSubjectPayloadClaimSpecification

/**
 * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-05.html
 *
 * The following content applies to the CWT protected header:
 *
 * 16 (type): REQUIRED. The type of the CWT MUST be statuslist+cwt as defined in [RFC9596].
 */
interface OptionalCwtStatusListTokenHeaderParametersProvider : CoseTypeHeaderParameterSpecification.ParameterProvider {
    val containsStatusListTokenHeader: Boolean
        get() = typ == CoseSignedTypeConstants.STATUSLIST_CWT

    fun toStatusListTokenHeader() = if(typ == CoseSignedTypeConstants.STATUSLIST_CWT) {
        StatusListTokenHeader(
            type = typ ?: throw MissingHeaderParameterException(CwtSubjectPayloadClaimSpecification.toNameWithKeyString()),
        )
    } else {
        throw IllegalStateException("Member `${CoseTypeHeaderParameterSpecification.toLabeledName()}` must have the value `${CoseSignedTypeConstants.STATUSLIST_CWT}`.")
    }
}

