package at.asitplus.wallet.lib.iso

import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.wallet.lib.RequestOptions
import at.asitplus.wallet.lib.RequestOptionsCredential

data class Iso180137AnnexCRequestOptions(
    /**
     * Device request can be built using [CredentialPresentationRequestBuilder]
     */
    val deviceRequest: DeviceRequest,
    /** Transaction ID. */
    override val state: String,
) : RequestOptions