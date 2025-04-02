package at.asitplus.wallet.lib.rqes

import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.wallet.lib.openid.OpenIdRequestOptions
import at.asitplus.wallet.lib.openid.RequestOptions
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.openid.TransactionData
import at.asitplus.rqes.collection_entries.QCertCreationAcceptance
import at.asitplus.rqes.collection_entries.QesAuthorization
import com.benasher44.uuid.uuid4

/**
 * RequestOptions which use [QesInputDescriptor]
 * instead of [DifInputDescriptor]
 */
data class RqesRequestOptions(
    val baseRequestOptions: OpenIdRequestOptions,
) : RequestOptions by baseRequestOptions {

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
            transactionData = transactionData?.map { it.makeUC5compliant() }
        )
    }

    private fun TransactionData.makeUC5compliant(): TransactionData =
        when(this) {
            is QesAuthorization -> this.copy(
                signatureQualifier = this.signatureQualifier,
                credentialID = this.credentialID,
                documentDigests = this.documentDigests,
                processID = this.processID,
                credentialIds = null,
                transactionDataHashAlgorithms = null
            )

            is QCertCreationAcceptance -> this.copy(
                qcTermsConditionsUri = this.qcTermsConditionsUri,
                qcHash = this.qcHash,
                qcHashAlgorithmOid = this.qcHashAlgorithmOid,
                credentialIds = null,
                transactionDataHashAlgorithms = null
            )

            else -> throw IllegalArgumentException("Unsupported transaction data type: ${this::class.simpleName}")
        }
}