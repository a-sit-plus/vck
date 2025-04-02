package at.asitplus.wallet.lib.rqes

import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.wallet.lib.openid.OpenIdRequestOptions
import at.asitplus.wallet.lib.openid.RequestOptions
import at.asitplus.dif.DifInputDescriptor
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
            transactionData = transactionData?.toList()
        )
    }
}