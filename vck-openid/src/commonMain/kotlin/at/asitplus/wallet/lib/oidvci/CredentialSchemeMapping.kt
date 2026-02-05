package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.ClaimDescription
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.CredentialFormatEnum.DC_SD_JWT
import at.asitplus.openid.CredentialFormatEnum.JWT_VC
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

/**
 * Defines mapping of [CredentialScheme] to identifiers used in OID4VCI in [CredentialIssuer]
 * (keys in [at.asitplus.openid.IssuerMetadata.supportedCredentialConfigurations],
 * and [SupportedCredentialFormat.scope])
 * and [CredentialAuthorizationServiceStrategy]
 * (in [at.asitplus.openid.OpenIdAuthorizationDetails.credentialConfigurationId]).
 */
interface CredentialSchemeMapper {

    /**
     * Maps the [scheme] to a map of credential identifiers (see [encodeToCredentialIdentifier])
     * to [SupportedCredentialFormat]s, for use in credential issuer's metadata (see
     * [at.asitplus.openid.IssuerMetadata.supportedCredentialConfigurations])
     */
    fun map(scheme: CredentialScheme): Map<String, SupportedCredentialFormat>

    /**
     * Encodes the [scheme] to a unique identifier,
     * that may be used in [CredentialIssuer.supportedCredentialConfigurations].
     */
    fun toCredentialIdentifier(scheme: CredentialScheme, rep: CredentialRepresentation): String

    /**
     * Reverse functionality of [decodeFromCredentialIdentifier],
     * i.e. encodes a credential [type] and [format] to a single string,
     * e.g. from [at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023] and [CredentialFormatEnum.JWT_VC] to
     * `AtomicAttribute2023#jwt_vc_json`
     */
    fun encodeToCredentialIdentifier(type: String, format: CredentialFormatEnum): String

    /**
     * Reverse functionality of [encodeToCredentialIdentifier], which can also handle ISO namespaces,
     * i.e. decodes a single string into a credential scheme and format,
     * e.g. from `AtomicAttribute2023#jwt_vc_json` to
     * [at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023] and [CredentialFormatEnum.JWT_VC].
     *
     * @return null if this scheme is not registered
     */
    fun decodeFromCredentialIdentifier(input: String): Pair<CredentialScheme, CredentialRepresentation>?
}

class DefaultCredentialSchemeMapper : CredentialSchemeMapper {

    override fun map(scheme: CredentialScheme): Map<String, SupportedCredentialFormat> {
        val iso = with(scheme) {
            if (supportsIso) {
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
        }
        val jwtVc = with(scheme) {
            if (supportsVcJwt) {
                with(encodeToCredentialIdentifier(vcType!!, JWT_VC)) {
                    this to SupportedCredentialFormat.forVcJwt(
                        format = JWT_VC,
                        scope = this,
                        credentialDefinition = SupportedCredentialFormatDefinition(
                            types = setOf(VcDataModelConstants.VERIFIABLE_CREDENTIAL, vcType!!),
                        ),
                        supportedBindingMethods = setOf(BINDING_METHOD_JWK, URN_TYPE_JWK_THUMBPRINT),
                        vcJwtClaims = claimNames.map {
                            ClaimDescription(path = it.split("."))
                        }.toSet()
                    )
                }
            } else null
        }
        val sdJwt = with(scheme) {
            if (supportsSdJwt) {
                with(encodeToCredentialIdentifier(sdJwtType!!, DC_SD_JWT)) {
                    this to SupportedCredentialFormat.forSdJwt(
                        format = DC_SD_JWT,
                        scope = this,
                        sdJwtVcType = sdJwtType!!,
                        supportedBindingMethods = setOf(BINDING_METHOD_JWK, URN_TYPE_JWK_THUMBPRINT),
                        sdJwtClaims = claimNames.map {
                            ClaimDescription(path = it.split("."))
                        }.toSet()
                    )
                }
            } else null
        }
        return listOfNotNull(iso, jwtVc, sdJwt).toMap()
    }

    override fun toCredentialIdentifier(
        scheme: CredentialScheme,
        rep: CredentialRepresentation
    ) = when (rep) {
        CredentialRepresentation.PLAIN_JWT -> encodeToCredentialIdentifier(scheme.vcType!!, JWT_VC)
        CredentialRepresentation.SD_JWT -> encodeToCredentialIdentifier(scheme.sdJwtType!!, DC_SD_JWT)
        CredentialRepresentation.ISO_MDOC -> scheme.isoNamespace!!
    }

    override fun encodeToCredentialIdentifier(type: String, format: CredentialFormatEnum): String =
        "${type.replace(" ", "_")}#${format.text}"

    override fun decodeFromCredentialIdentifier(input: String): Pair<CredentialScheme, CredentialRepresentation>? =
        if (input.contains("#")) {
            val vcTypeOrSdJwtType = input.substringBeforeLast("#")
            val credentialScheme = AttributeIndex.resolveSdJwtAttributeType(vcTypeOrSdJwtType)
                ?: AttributeIndex.resolveAttributeType(vcTypeOrSdJwtType)
                ?: AttributeIndex.resolveSdJwtAttributeType(vcTypeOrSdJwtType.replace("_", " "))
                ?: AttributeIndex.resolveAttributeType(vcTypeOrSdJwtType.replace("_", " "))
                ?: return null
            val format = CredentialFormatEnum.parse(input.substringAfterLast("#"))
                ?: return null
            Pair(credentialScheme, format.toRepresentation())
        } else {
            AttributeIndex.resolveIsoNamespace(input)
                ?.let { Pair(it, CredentialRepresentation.ISO_MDOC) }
        }

}
