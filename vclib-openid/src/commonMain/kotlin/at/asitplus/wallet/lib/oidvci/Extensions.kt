package at.asitplus.wallet.lib.oidvci

import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.crypto.datatypes.jws.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VcDataModelConstants
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidvci.mdl.RequestedCredentialClaimSpecification
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

fun ConstantIndex.CredentialScheme.toSupportedCredentialFormat(cryptoAlgorithms: List<CryptoAlgorithm>) = mapOf(
    this.isoNamespace to SupportedCredentialFormat(
        format = CredentialFormatEnum.MSO_MDOC,
        scope = vcType,
        docType = isoDocType,
        claims = mapOf(
            isoNamespace to claimNames.associateWith { RequestedCredentialClaimSpecification() }
        ),
        supportedBindingMethods = listOf(OpenIdConstants.BINDING_METHOD_COSE_KEY),
        supportedSigningAlgorithms = cryptoAlgorithms.map { it.toJwsAlgorithm().identifier },
    ),
    "$vcType-${CredentialFormatEnum.JWT_VC.text}" to SupportedCredentialFormat(
        format = CredentialFormatEnum.JWT_VC,
        scope = vcType,
        credentialDefinition = SupportedCredentialFormatDefinition(
            types = listOf(VcDataModelConstants.VERIFIABLE_CREDENTIAL, vcType),
            credentialSubject = claimNames.associateWith { CredentialSubjectMetadataSingle() }
        ),
        supportedBindingMethods = listOf(OpenIdConstants.PREFIX_DID_KEY, OpenIdConstants.URN_TYPE_JWK_THUMBPRINT),
        supportedSigningAlgorithms = cryptoAlgorithms.map { it.toJwsAlgorithm().identifier },
    ),
    "$vcType-${CredentialFormatEnum.VC_SD_JWT.text}" to SupportedCredentialFormat(
        format = CredentialFormatEnum.VC_SD_JWT,
        scope = vcType,
        sdJwtVcType = vcType,
        claims = mapOf(
            isoNamespace to claimNames.associateWith { RequestedCredentialClaimSpecification() }
        ),
        supportedBindingMethods = listOf(OpenIdConstants.PREFIX_DID_KEY, OpenIdConstants.URN_TYPE_JWK_THUMBPRINT),
        supportedSigningAlgorithms = cryptoAlgorithms.map { it.toJwsAlgorithm().identifier },
    )
)

fun CredentialFormatEnum.toRepresentation() = when (this) {
    CredentialFormatEnum.JWT_VC_SD_UNOFFICIAL -> ConstantIndex.CredentialRepresentation.SD_JWT
    CredentialFormatEnum.VC_SD_JWT -> ConstantIndex.CredentialRepresentation.SD_JWT
    CredentialFormatEnum.MSO_MDOC -> ConstantIndex.CredentialRepresentation.ISO_MDOC
    else -> ConstantIndex.CredentialRepresentation.PLAIN_JWT
}

fun Issuer.IssuedCredential.toCredentialResponseParameters() = when (this) {
    is Issuer.IssuedCredential.Iso -> CredentialResponseParameters(
        format = CredentialFormatEnum.MSO_MDOC,
        credential = issuerSigned.serialize().encodeToString(Base64UrlStrict),
    )

    is Issuer.IssuedCredential.VcJwt -> CredentialResponseParameters(
        format = CredentialFormatEnum.JWT_VC,
        credential = vcJws,
    )

    is Issuer.IssuedCredential.VcSdJwt -> CredentialResponseParameters(
        format = CredentialFormatEnum.VC_SD_JWT,
        credential = vcSdJwt,
    )
}

class OAuth2Exception(val error: String, val errorDescription: String? = null) : Throwable(error) {

}