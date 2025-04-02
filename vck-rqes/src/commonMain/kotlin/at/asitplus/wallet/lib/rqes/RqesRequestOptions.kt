package at.asitplus.wallet.lib.rqes

import at.asitplus.dif.*
import at.asitplus.openid.TransactionData
import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.rqes.collection_entries.QCertCreationAcceptance
import at.asitplus.rqes.collection_entries.QesAuthorization
import at.asitplus.wallet.lib.openid.OpenIdRequestOptions
import at.asitplus.wallet.lib.openid.RequestOptions
import com.benasher44.uuid.uuid4

/**
 * RequestOptions which use [QesInputDescriptor]
 * instead of [DifInputDescriptor]
 */
data class RqesRequestOptions(
    val baseRequestOptions: OpenIdRequestOptions,
) : RequestOptions by baseRequestOptions {

    init {
        val transactionIds = transactionData?.mapNotNull { it.credentialIds?.toList() }?.flatten()?.sorted()
        val credentialIds = credentials.map { it.id }.sorted()
        transactionIds?.let { require(it == credentialIds) {"OpenId4VP defines that the credential_ids that must be part of a transaction_data element has to be an ID from InputDescriptor"} }
    }

    override fun toPresentationDefinition(
        containerJwt: FormatContainerJwt,
        containerSdJwt: FormatContainerSdJwt
    ): PresentationDefinition = PresentationDefinition(
        id = uuid4().toString(),
        inputDescriptors = this.toInputDescriptor(containerJwt, containerSdJwt)
    )

    override fun toInputDescriptor(
        containerJwt: FormatContainerJwt,
        containerSdJwt: FormatContainerSdJwt,
    ): List<InputDescriptor> = credentials.map { requestOptionCredential ->
        QesInputDescriptor(
            id = requestOptionCredential.buildId(),
            format = requestOptionCredential.toFormatHolder(containerJwt, containerSdJwt),
            constraints = requestOptionCredential.toConstraint(),
            transactionData = transactionData?.mapNotNull { it.makeUC5compliant() }
        )
    }

    private fun TransactionData.makeUC5compliant(): TransactionData? =
        when (this) {
            is QesAuthorization -> this.copy(
                credentialIds = null,
                transactionDataHashAlgorithms = null
            )

            is QCertCreationAcceptance -> this.copy(
                credentialIds = null,
                transactionDataHashAlgorithms = null
            )

            else -> null
        }
}