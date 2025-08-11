package at.asitplus.wallet.lib.rqes

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.wallet.lib.openid.RequestOptions

/**
 * RequestOptions which use [QesInputDescriptor]
 * instead of [DifInputDescriptor]
 */
@Deprecated("Module will be removed in the future", ReplaceWith("RequestOptions"))
data class RqesRequestOptions(
    val baseRequestOptions: RequestOptions,
)