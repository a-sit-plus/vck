package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.BINDING_METHOD_COSE_KEY
import at.asitplus.openid.OpenIdConstants.BINDING_METHOD_JWK
import at.asitplus.openid.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.supportsIso
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import at.asitplus.wallet.lib.data.VcDataModelConstants
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

fun ConstantIndex.CredentialScheme.toSupportedCredentialFormat(cryptoAlgorithms: Set<SignatureAlgorithm>? = null)
        : Map<String, SupportedCredentialFormat> {
    val iso = if (supportsIso) {
        isoNamespace!! to SupportedCredentialFormat.forIsoMdoc(
            format = CredentialFormatEnum.MSO_MDOC,
            scope = isoNamespace!!,
            docType = isoDocType!!,
            supportedBindingMethods = setOf(BINDING_METHOD_JWK, BINDING_METHOD_COSE_KEY),
            supportedSigningAlgorithms = cryptoAlgorithms
                ?.mapNotNull { it.toJwsAlgorithm().getOrNull()?.identifier }
                ?.toSet(),
            isoClaims = mapOf(
                isoNamespace!! to claimNames.associateWith { RequestedCredentialClaimSpecification() }
            )
        )
    } else null
    val jwtVc = if (supportsVcJwt) {
        encodeToCredentialIdentifier(vcType!!, CredentialFormatEnum.JWT_VC) to SupportedCredentialFormat.forVcJwt(
            format = CredentialFormatEnum.JWT_VC,
            scope = vcType!!,
            credentialDefinition = SupportedCredentialFormatDefinition(
                types = listOf(VcDataModelConstants.VERIFIABLE_CREDENTIAL, vcType!!),
                credentialSubject = claimNames.associateWith { CredentialSubjectMetadataSingle() }
            ),
            supportedBindingMethods = setOf(BINDING_METHOD_JWK, URN_TYPE_JWK_THUMBPRINT),
            supportedSigningAlgorithms = cryptoAlgorithms
                ?.mapNotNull { it.toJwsAlgorithm().getOrNull()?.identifier }
                ?.toSet(),
        )
    } else null
    val sdJwt = if (supportsSdJwt) {
        encodeToCredentialIdentifier(sdJwtType!!, CredentialFormatEnum.VC_SD_JWT) to SupportedCredentialFormat.forSdJwt(
            format = CredentialFormatEnum.VC_SD_JWT,
            scope = sdJwtType!!,
            sdJwtVcType = sdJwtType!!,
            supportedBindingMethods = setOf(BINDING_METHOD_JWK, URN_TYPE_JWK_THUMBPRINT),
            supportedSigningAlgorithms = cryptoAlgorithms
                ?.mapNotNull { it.toJwsAlgorithm().getOrNull()?.identifier }
                ?.toSet(),
            sdJwtClaims = claimNames.associateWith { RequestedCredentialClaimSpecification() }
        )
    } else null
    return listOfNotNull(iso, jwtVc, sdJwt).toMap()
}

fun ConstantIndex.CredentialScheme.toCredentialIdentifier() =
    listOfNotNull(
        if (supportsIso) isoNamespace!! else null,
        if (supportsVcJwt) encodeToCredentialIdentifier(vcType!!, CredentialFormatEnum.JWT_VC) else null,
        if (supportsSdJwt) encodeToCredentialIdentifier(sdJwtType!!, CredentialFormatEnum.VC_SD_JWT) else null
    )

/**
 * Reverse functionality of [decodeFromCredentialIdentifier],
 * i.e. encodes a credential [type] and [format] to a single string,
 * e.g. from [at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023] and [CredentialFormatEnum.JWT_VC] to
 * `AtomicAttribute2023#jwt_vc_json`
 */
private fun encodeToCredentialIdentifier(type: String, format: CredentialFormatEnum) =
    "$type#${format.text}"

/**
 * Reverse functionality of [encodeToCredentialIdentifier], which can also handle ISO namespaces,
 * i.e. decodes a single string into a credential scheme and format,
 * e.g. from `AtomicAttribute2023#jwt_vc_json` to
 * [at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023] and [CredentialFormatEnum.JWT_VC]
 */
fun decodeFromCredentialIdentifier(input: String): Pair<ConstantIndex.CredentialScheme, CredentialFormatEnum>? {
    if (input.contains("#")) {
        val vcTypeOrSdJwtType = input.substringBeforeLast("#")
        val credentialScheme = AttributeIndex.resolveSdJwtAttributeType(vcTypeOrSdJwtType)
            ?: AttributeIndex.resolveAttributeType(vcTypeOrSdJwtType)
            ?: return null
        val format = CredentialFormatEnum.parse(input.substringAfterLast("#"))
            ?: return null
        return Pair(credentialScheme, format)
    } else {
        return AttributeIndex.resolveIsoNamespace(input)
            ?.let { Pair(it, CredentialFormatEnum.MSO_MDOC) }
    }
}

fun CredentialFormatEnum.toRepresentation() = when (this) {
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
