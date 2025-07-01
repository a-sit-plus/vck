package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.ClaimDescription
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.CredentialSubjectMetadataSingle
import at.asitplus.openid.OpenIdConstants.BINDING_METHOD_COSE_KEY
import at.asitplus.openid.OpenIdConstants.BINDING_METHOD_JWK
import at.asitplus.openid.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.SupportedCredentialFormatDefinition
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme
import at.asitplus.wallet.lib.data.ConstantIndex.supportsIso
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import at.asitplus.wallet.lib.data.VcDataModelConstants
import at.asitplus.wallet.lib.oidvci.CredentialSchemeMapping.decodeFromCredentialIdentifier
import at.asitplus.wallet.lib.oidvci.CredentialSchemeMapping.encodeToCredentialIdentifier

/**
 * Defines mapping of [CredentialScheme] to identifiers used in OID4VCI in [CredentialIssuer]
 * (keys in [at.asitplus.openid.IssuerMetadata.supportedCredentialConfigurations],
 * and [SupportedCredentialFormat.scope])
 * and [CredentialAuthorizationServiceStrategy]
 * (in [at.asitplus.openid.OpenIdAuthorizationDetails.credentialConfigurationId]).
 */
object CredentialSchemeMapping {

    @Suppress("DEPRECATION")
    fun CredentialScheme.toSupportedCredentialFormat(): Map<String, SupportedCredentialFormat> {
        val iso = if (supportsIso) {
            with(isoNamespace!!) {
                this to SupportedCredentialFormat.forIsoMdoc(
                    format = CredentialFormatEnum.MSO_MDOC,
                    scope = this,
                    docType = isoDocType!!,
                    supportedBindingMethods = setOf(BINDING_METHOD_JWK, BINDING_METHOD_COSE_KEY),
                    isoClaims = claimNames.map {
                        ClaimDescription(path = listOf(isoNamespace!!) + it.split("."))
                    }.toSet()
                )
            }
        } else null
        val jwtVc = if (supportsVcJwt) {
            with(encodeToCredentialIdentifier(vcType!!, CredentialFormatEnum.JWT_VC)) {
                this to SupportedCredentialFormat.forVcJwt(
                    format = CredentialFormatEnum.JWT_VC,
                    scope = this,
                    credentialDefinition = SupportedCredentialFormatDefinition(
                        types = setOf(VcDataModelConstants.VERIFIABLE_CREDENTIAL, vcType!!),
                        credentialSubject = claimNames.associateWith { CredentialSubjectMetadataSingle() }
                    ),
                    supportedBindingMethods = setOf(BINDING_METHOD_JWK, URN_TYPE_JWK_THUMBPRINT),
                )
            }
        } else null
        // Uses "vc+sd-jwt", defined in SD-JWT VC up until draft 06
        val sdJwt = if (supportsSdJwt) {
            with(encodeToCredentialIdentifier(sdJwtType!!, CredentialFormatEnum.VC_SD_JWT)) {
                this to SupportedCredentialFormat.forSdJwt(
                    format = CredentialFormatEnum.VC_SD_JWT,
                    scope = this,
                    sdJwtVcType = sdJwtType!!,
                    supportedBindingMethods = setOf(BINDING_METHOD_JWK, URN_TYPE_JWK_THUMBPRINT),
                    sdJwtClaims = claimNames.map {
                        ClaimDescription(path = it.split("."))
                    }.toSet(),
                )
            }
        } else null
        // Uses "dc+sd-jwt", supported since SD-JWT VC draft 06
        val sdJwtNewIdentifier = if (supportsSdJwt) {
            with(encodeToCredentialIdentifier(sdJwtType!!, CredentialFormatEnum.DC_SD_JWT)) {
                this to SupportedCredentialFormat.forSdJwt(
                    format = CredentialFormatEnum.DC_SD_JWT,
                    scope = this,
                    sdJwtVcType = sdJwtType!!,
                    supportedBindingMethods = setOf(BINDING_METHOD_JWK, URN_TYPE_JWK_THUMBPRINT),
                    sdJwtClaims = claimNames.map {
                        ClaimDescription(path = it.split("."))
                    }.toSet()
                )
            }
        } else null
        return listOfNotNull(iso, jwtVc, sdJwt, sdJwtNewIdentifier).toMap()
    }

    // TODO use DC_SD_JWT >= 6.0.0
    @Suppress("DEPRECATION")
    fun CredentialScheme.toCredentialIdentifier() = listOfNotNull(
        if (supportsIso) isoNamespace!! else null,
        if (supportsVcJwt) encodeToCredentialIdentifier(vcType!!, CredentialFormatEnum.JWT_VC) else null,
        if (supportsSdJwt) encodeToCredentialIdentifier(sdJwtType!!, CredentialFormatEnum.VC_SD_JWT) else null
    )

    // TODO use DC_SD_JWT >= 6.0.0
    @Suppress("DEPRECATION")
    @Deprecated("Use extension method in CredentialSchemeMapping instead")
    fun CredentialScheme.toCredentialIdentifier(rep: CredentialRepresentation) = when (rep) {
        CredentialRepresentation.PLAIN_JWT -> encodeToCredentialIdentifier(vcType!!, CredentialFormatEnum.JWT_VC)
        CredentialRepresentation.SD_JWT -> encodeToCredentialIdentifier(sdJwtType!!, CredentialFormatEnum.VC_SD_JWT)
        CredentialRepresentation.ISO_MDOC -> isoNamespace!!
    }

    /**
     * Reverse functionality of [decodeFromCredentialIdentifier],
     * i.e. encodes a credential [type] and [format] to a single string,
     * e.g. from [at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023] and [CredentialFormatEnum.JWT_VC] to
     * `AtomicAttribute2023#jwt_vc_json`
     */
    fun encodeToCredentialIdentifier(type: String, format: CredentialFormatEnum) =
        "${type.replace(" ", "_")}#${format.text}"

    /**
     * Reverse functionality of [encodeToCredentialIdentifier], which can also handle ISO namespaces,
     * i.e. decodes a single string into a credential scheme and format,
     * e.g. from `AtomicAttribute2023#jwt_vc_json` to
     * [at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023] and [CredentialFormatEnum.JWT_VC]
     */
    fun decodeFromCredentialIdentifier(input: String): Pair<CredentialScheme, CredentialRepresentation>? {
        if (input.contains("#")) {
            val vcTypeOrSdJwtType = input.substringBeforeLast("#")
            val credentialScheme = AttributeIndex.resolveSdJwtAttributeType(vcTypeOrSdJwtType)
                ?: AttributeIndex.resolveAttributeType(vcTypeOrSdJwtType)
                ?: AttributeIndex.resolveSdJwtAttributeType(vcTypeOrSdJwtType.replace("_", " "))
                ?: AttributeIndex.resolveAttributeType(vcTypeOrSdJwtType.replace("_", " "))
                ?: return null
            val format = CredentialFormatEnum.parse(input.substringAfterLast("#"))
                ?: return null
            return Pair(credentialScheme, format.toRepresentation())
        } else {
            return AttributeIndex.resolveIsoNamespace(input)
                ?.let { Pair(it, CredentialRepresentation.ISO_MDOC) }
        }
    }


}