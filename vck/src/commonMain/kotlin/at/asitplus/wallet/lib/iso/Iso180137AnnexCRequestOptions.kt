package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.RequestOptions
import at.asitplus.wallet.lib.RequestOptionsCredential
import com.benasher44.uuid.uuid4

data class Iso180137AnnexCRequestOptions(
    /** Requested credentials, should be at least one. */
    override val credentials: Set<RequestOptionsCredential>,
    /** Opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]. */
    override val state: String = uuid4().toString(),
) : RequestOptions {
}