package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.RequestOptions
import at.asitplus.wallet.lib.RequestOptionsCredential

data class Iso180137AnnexCRequestOptions(
    /** Requested credentials, should be at least one. */
    override val credentials: Set<RequestOptionsCredential>,
    /** Transaction ID. */
    override val state: String,
) : RequestOptions