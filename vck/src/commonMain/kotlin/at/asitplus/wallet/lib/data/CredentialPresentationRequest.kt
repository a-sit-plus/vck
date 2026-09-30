package at.asitplus.wallet.lib.data

import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.PresentationDefinition
import at.asitplus.iso.DeviceRequest
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.wallet.lib.agent.DeviceRequestCredentialDisclosure
import at.asitplus.wallet.lib.agent.PresentationExchangeCredentialDisclosure
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * Query-language-independent representation of a verifier's credential requirements.
 *
 * A request describes what may satisfy the verifier; it does not contain the holder's choice. Match it against the
 * credential store to present candidates to the user, then call the subtype's `toCredentialPresentation` overload
 * with the selected submissions. Calling [toCredentialPresentation] without a selection asks the holder to derive a
 * default submission while creating the response.
 */
@Serializable(with = CredentialPresentationRequestSerializer::class)
sealed interface CredentialPresentationRequest {

    /** Creates a presentation instruction that lets the holder derive a default submission. */
    fun toCredentialPresentation(): CredentialPresentation

    /** Presentation Exchange, formerly used by OpenID4VP, now deprecated. */
    @Suppress("DEPRECATION")
    @Deprecated("Support for Presentation Exchange been removed from OpenID4VP")
    @Serializable
    data class PresentationExchangeRequest(
        val presentationDefinition: PresentationDefinition,
        val fallbackFormatHolder: FormatHolder? = null,
    ) : CredentialPresentationRequest {
        override fun toCredentialPresentation() = toCredentialPresentation(null)

        fun toCredentialPresentation(
            inputDescriptorSubmissions: Map<String, PresentationExchangeCredentialDisclosure<SubjectCredentialStore.StoreEntry>>?
        ): CredentialPresentation = CredentialPresentation.PresentationExchangePresentation(
            presentationRequest = this,
            inputDescriptorSubmissions = inputDescriptorSubmissions
        )

        companion object {
            @Suppress("DEPRECATION")
            @Deprecated("Support for Presentation Exchange been removed from OpenID4VP")
            fun forAttributeNames(vararg attributeName: String) = PresentationExchangeRequest(
                PresentationDefinition(
                    DifInputDescriptor(
                        Constraint(
                            fields = attributeName.map { ConstraintField(path = listOf(it)) }.toSet()
                        )
                    )
                ),
            )
        }
    }

    /** Credential requirements expressed as a DCQL query, as used by OpenID4VP. */
    @Serializable
    @JvmInline
    value class DCQLRequest(
        @SerialName(SerialNames.DCQL_QUERY)
        val dcqlQuery: DCQLQuery
    ) : CredentialPresentationRequest {
        override fun toCredentialPresentation() = toCredentialPresentation(null)

        fun toCredentialPresentation(
            credentialQuerySubmissions: Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<SubjectCredentialStore.StoreEntry>>>?
        ): CredentialPresentation = CredentialPresentation.DCQLPresentation(
            presentationRequest = this,
            credentialQuerySubmissions = credentialQuerySubmissions
        )

        object SerialNames {
            const val DCQL_QUERY = "dcqlQuery"
        }

    }

    /** Device Retrieval according to ISO 18013-5, used for proximity and ISO 18013-7 Annex C over DCAPI. */
    @Serializable
    data class IsoDeviceRetrieval(
        @SerialName(SerialNames.DEVICE_REQUEST)
        val deviceRequest: DeviceRequest
    ) : CredentialPresentationRequest {
        override fun toCredentialPresentation() = toCredentialPresentation(null)

        object SerialNames {
            const val DEVICE_REQUEST = "deviceRequest"
        }

        fun toCredentialPresentation(
            submissions: Collection<DeviceRequestCredentialDisclosure<SubjectCredentialStore.StoreEntry>>? = null,
        ): CredentialPresentation = CredentialPresentation.IsoDeviceRetrievalPresentation(
            presentationRequest = this,
            submissions = submissions
        )
    }
}
