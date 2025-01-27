package at.asitplus.wallet.lib.data

import at.asitplus.dif.FormatHolder
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.dcql.DCQLQuery
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable(with = CredentialPresentationRequestSerializer::class)
sealed interface CredentialPresentationRequest {
    @Serializable
    data class PresentationExchangeRequest(
        val presentationDefinition: PresentationDefinition,
        val fallbackFormatHolder: FormatHolder? = null,
    ) : CredentialPresentationRequest

    @Serializable
    @JvmInline
    value class DCQLRequest(val dcqlQuery: DCQLQuery) : CredentialPresentationRequest
}