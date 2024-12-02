package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.BINDING_METHOD_COSE_KEY
import at.asitplus.openid.OpenIdConstants.BINDING_METHOD_JWK
import at.asitplus.openid.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme
import at.asitplus.wallet.lib.data.ConstantIndex.supportsIso
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL

typealias CredentialSchemeInRepresentation = Pair<CredentialScheme, CredentialRepresentation>

interface CredentialSchemeAdapter {
    /**
     * Used to populate [IssuerMetadata.supportedCredentialConfigurations]
     */
    fun getSupportedCredentialConfigurations(
        cryptoAlgorithms: Set<SignatureAlgorithm>,
    ): Map<String, SupportedCredentialFormat>

    /**
     * Used to populate [CredentialOffer.configurationIds]
     */
    fun getConfigurationIds(): Collection<String>

    /**
     * Used to decode the Wallet's request to issue credentials
     */
    fun fromCredentialRequest(params: CredentialRequestParameters): CredentialSchemeInRepresentation?

    /**
     * Used to filter the authorization details in Wallet's token request
     */
    fun supportsAuthorization(details: OpenIdAuthorizationDetails): Boolean
}

class DefaultCredentialSchemeAdapter(
    val credentialSchemes: Set<CredentialScheme>,
) : CredentialSchemeAdapter {

    private val credentialConfigurations: List<Map.Entry<String, SupportedCredentialFormat>> = credentialSchemes
        .flatMap { it.getSupportedCredentialConfigurations().entries }

    override fun getSupportedCredentialConfigurations(
        cryptoAlgorithms: Set<SignatureAlgorithm>,
    ): Map<String, SupportedCredentialFormat> = credentialConfigurations
        .associate {
            it.key to it.value.copyWithSupportedAlgorithms(
                cryptoAlgorithms.mapNotNull { it.toJwsAlgorithm().getOrNull()?.identifier }.toSet()
            )
        }

    override fun getConfigurationIds(): Collection<String> = credentialSchemes.flatMap { it.toCredentialIdentifier() }

    override fun fromCredentialRequest(params: CredentialRequestParameters): CredentialSchemeInRepresentation? =
        params.format?.let { params.extractCredentialScheme(it) }
            ?: params.credentialIdentifier?.let { decodeFromCredentialIdentifier(it) }

    override fun supportsAuthorization(authnDetails: OpenIdAuthorizationDetails): Boolean =
        authnDetails.credentialConfigurationId?.let {
            getConfigurationIds().contains(it)
        } ?: authnDetails.format?.let {
            credentialSchemes.firstOrNull { it.matches(authnDetails) } != null
        } ?: false

}

private fun CredentialScheme.matches(details: OpenIdAuthorizationDetails): Boolean {
    if (details.format == null) return false
    if (!supportedRepresentations.contains(details.format!!.toRepresentation())) return false
    if (details.docType != null) {
        return isoDocType == details.docType
    }
    if (details.sdJwtVcType != null) {
        return sdJwtType == details.sdJwtVcType
    }
    if (details.credentialDefinition?.types != null) {
        return details.credentialDefinition!!.types!!.contains(vcType)
    }
    return false
}

private fun CredentialScheme.getSupportedCredentialConfigurations(): Map<String, SupportedCredentialFormat> {
    val iso = if (supportsIso) {
        toCredentialIdentifier(CredentialRepresentation.ISO_MDOC) to SupportedCredentialFormat.forIsoMdoc(
            scope = isoDocType!!,
            docType = isoDocType!!,
            supportedBindingMethods = setOf(BINDING_METHOD_JWK, BINDING_METHOD_COSE_KEY),
            isoClaims = mapOf(
                isoNamespace!! to claimNames.associateWith { RequestedCredentialClaimSpecification() }
            )
        )
    } else null
    val jwtVc = if (supportsVcJwt) {
        toCredentialIdentifier(CredentialRepresentation.PLAIN_JWT) to SupportedCredentialFormat.forVcJwt(
            scope = vcType!!,
            credentialDefinition = SupportedCredentialFormatDefinition(
                types = setOf(VERIFIABLE_CREDENTIAL, vcType!!),
                credentialSubject = claimNames.associateWith { CredentialSubjectMetadataSingle() }
            ),
            supportedBindingMethods = setOf(BINDING_METHOD_JWK, URN_TYPE_JWK_THUMBPRINT),
        )
    } else null
    val sdJwt = if (supportsSdJwt) {
        toCredentialIdentifier(CredentialRepresentation.SD_JWT) to SupportedCredentialFormat.forSdJwt(
            scope = sdJwtType!!,
            sdJwtVcType = sdJwtType!!,
            supportedBindingMethods = setOf(BINDING_METHOD_JWK, URN_TYPE_JWK_THUMBPRINT),
            sdJwtClaims = claimNames.associateWith { RequestedCredentialClaimSpecification() }
        )
    } else null
    return listOfNotNull(iso, jwtVc, sdJwt).toMap()
}

private fun CredentialScheme.toCredentialIdentifier() = listOfNotNull(
    if (supportsIso) isoNamespace!! else null,
    if (supportsVcJwt) encodeToCredentialIdentifier(vcType!!, CredentialFormatEnum.JWT_VC) else null,
    if (supportsSdJwt) encodeToCredentialIdentifier(sdJwtType!!, CredentialFormatEnum.VC_SD_JWT) else null
)

fun CredentialScheme.toCredentialIdentifier(rep: CredentialRepresentation) = when (rep) {
    CredentialRepresentation.PLAIN_JWT -> encodeToCredentialIdentifier(vcType!!, CredentialFormatEnum.JWT_VC)
    CredentialRepresentation.SD_JWT -> encodeToCredentialIdentifier(sdJwtType!!, CredentialFormatEnum.VC_SD_JWT)
    CredentialRepresentation.ISO_MDOC -> isoNamespace!!
}

private fun CredentialRequestParameters.extractCredentialScheme(format: CredentialFormatEnum) = when (format) {
    CredentialFormatEnum.JWT_VC -> credentialDefinition?.types
        ?.filter { it != VERIFIABLE_CREDENTIAL }
        ?.firstNotNullOf {
            AttributeIndex.resolveAttributeType(it)
                ?.let { it to CredentialRepresentation.PLAIN_JWT }
        }

    CredentialFormatEnum.VC_SD_JWT -> sdJwtVcType
        ?.let { AttributeIndex.resolveSdJwtAttributeType(it) }
        ?.let { it to CredentialRepresentation.SD_JWT }

    CredentialFormatEnum.MSO_MDOC -> docType
        ?.let { AttributeIndex.resolveIsoDoctype(it) }
        ?.let { it to CredentialRepresentation.ISO_MDOC }

    else -> null
}

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
private fun decodeFromCredentialIdentifier(input: String): CredentialSchemeInRepresentation? =
    if (input.contains("#")) {
        val vcTypeOrSdJwtType = input.substringBeforeLast("#")
        val credentialScheme = AttributeIndex.resolveSdJwtAttributeType(vcTypeOrSdJwtType)
            ?: AttributeIndex.resolveAttributeType(vcTypeOrSdJwtType)
            ?: return null
        val format = CredentialFormatEnum.parse(input.substringAfterLast("#"))
            ?.toRepresentation()
            ?: return null
        Pair(credentialScheme, format)
    } else {
        AttributeIndex.resolveIsoNamespace(input)
            ?.let { Pair(it, CredentialRepresentation.ISO_MDOC) }
    }
