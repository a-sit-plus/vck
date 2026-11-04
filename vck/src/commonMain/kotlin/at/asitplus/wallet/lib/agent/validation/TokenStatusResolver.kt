package at.asitplus.wallet.lib.agent.validation

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.extensions.toView
import kotlin.io.encoding.Base64

/**
 * Decompress the Status List with a decompressor that is compatible with DEFLATE
 * from [RFC1951](https://datatracker.ietf.org/doc/html/rfc1951) and
 * ZLIB [RFC1950](https://datatracker.ietf.org/doc/html/rfc1950).
 *
 * Retrieve the status value of the index specified in the Referenced Token as described in
 * Section 4. Fail if the provided index is out of bound of the Status List
 */
internal fun extractTokenStatus(
    revocationList: RevocationList,
    revocationListInfo: RevocationListInfo,
    zlibService: ZlibService = DefaultZlibService(),
): KmmResult<TokenStatus> = RevocationListLookup(revocationList, zlibService).status(revocationListInfo)

/**
 * The statuses in [revocationList], see [extractTokenStatus], for any number of references: a status list is
 * decompressed, and the identifiers of an identifier list are indexed, once, when a status is first looked up.
 */
internal class RevocationListLookup(
    private val revocationList: RevocationList,
    private val zlibService: ZlibService = DefaultZlibService(),
) {
    private val view by lazy { (revocationList as StatusList).toView(zlibService) }
    private val identifiers by lazy {
        (revocationList as IdentifierList).identifiers.keys.mapTo(HashSet()) { Base64.encode(it.value) }
    }

    fun status(revocationListInfo: RevocationListInfo): KmmResult<TokenStatus> = catching {
        if (revocationList is StatusList && revocationListInfo is StatusListInfo) {
            view.getOrNull(revocationListInfo.index)
                ?: throw IndexOutOfBoundsException("The index specified in the status list info is out of bounds of the status list.")
        } else if (revocationList is IdentifierList && revocationListInfo is IdentifierListInfo) {
            if (Base64.encode(revocationListInfo.identifier) in identifiers) TokenStatus.Invalid
            else TokenStatus.Valid
        } else throw IllegalArgumentException("RevocationList / RevocationListInfo mismatch")
    }
}
