package at.asitplus.iso

import kotlinx.serialization.Serializable

/**
 * A [credential] chosen for a document request, with the data elements to disclose of it, like
 * [at.asitplus.openid.dcql.DCQLCredentialSubmissionOption] for a credential query of DCQL.
 *
 * [disclosedElements] are serialized as `[namespace, dataElementIdentifier]` arrays, see
 * [ElementReference.ArraySerializer].
 */
@Serializable
data class DocRequestSubmissionOption<Credential : Any>(
    val credential: Credential,
    val disclosedElements: List<@Serializable(with = ElementReference.ArraySerializer::class) ElementReference>,
)
