package at.asitplus.wallet.lib.data

import at.asitplus.dif.FormatHolder
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.dcql.DCQLQuery
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable(with = CredentialPresentationRequestSerializer::class)
sealed interface CredentialPresentationRequest {

    fun toCredentialPresentation(): CredentialPresentation

    @Serializable
    data class PresentationExchangeRequest(
        val presentationDefinition: PresentationDefinition,
        val fallbackFormatHolder: FormatHolder? = null,
    ) : CredentialPresentationRequest {
        override fun toCredentialPresentation(): CredentialPresentation =
            CredentialPresentation.PresentationExchangePresentation(
                presentationRequest = this,
                inputDescriptorSubmissions = null
            )
    }

    @Serializable
    @JvmInline
    value class DCQLRequest(
        val dcqlQuery: DCQLQuery
    ) : CredentialPresentationRequest {
        override fun toCredentialPresentation(): CredentialPresentation =
            CredentialPresentation.DCQLPresentation(
                presentationRequest = this,
                credentialQuerySubmissions = null
            )
    }
}