package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.CredentialFormatEnum.DC_SD_JWT
import at.asitplus.openid.CredentialFormatEnum.JWT_VC
import at.asitplus.openid.OpenIdConstants.BINDING_METHOD_COSE_KEY
import at.asitplus.openid.OpenIdConstants.BINDING_METHOD_JWK
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.VcJwtCredentialDefinition
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.VcDataModelConstants
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
import at.asitplus.wallet.lib.data.isoQualifiedClaimDescriptions

/**
 * Defines mapping of [CredentialScheme] to identifiers used in OID4VCI in [OpenId4VciServer]
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
     * that may be used in [OpenId4VciServer.supportedCredentialConfigurations].
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

/**
 * Bound to a COSE key only: the `deviceKey` of the MSO is a `COSE_Key` (ISO/IEC 18013-5:2021, 9.1.2.4), which
 * OpenID4VCI 1.0, 12.2.4 identifies as `cose_key`.
 */
fun IsoMdocCredentialScheme.toIsoMdocSupportedCredentialFormat(identifier: String): Pair<String, SupportedCredentialFormat> =
    identifier to SupportedCredentialFormat.forIsoMdoc(
        scope = identifier,
        docType = isoDocType,
        supportedBindingMethods = setOf(BINDING_METHOD_COSE_KEY),
        isoClaims = isoQualifiedClaimDescriptions
    )

/** Bound to a JWK, `jwk` in OpenID4VCI 1.0, 12.2.4. */
fun VcJwtCredentialScheme.toPlainJwtSupportedCredentialFormat(identifier: String): Pair<String, SupportedCredentialFormat> =
    identifier to SupportedCredentialFormat.forVcJwt(
        scope = identifier,
        credentialDefinition = VcJwtCredentialDefinition(
            types = setOf(VcDataModelConstants.VERIFIABLE_CREDENTIAL, vcType),
        ),
        supportedBindingMethods = setOf(BINDING_METHOD_JWK),
        vcJwtClaims = claimDescriptions
    )

/**
 * Bound to a JWK only: the `cnf` claim carries a `jwk` (OpenID4VC HAIP 1.0, 6.1), which OpenID4VCI 1.0, 12.2.4
 * identifies as `jwk`.
 */
fun SdJwtCredentialScheme.toSdJwtSupportedCredentialFormat(identifier: String): Pair<String, SupportedCredentialFormat> =
    identifier to SupportedCredentialFormat.forSdJwt(
        scope = identifier,
        sdJwtVcType = sdJwtType,
        supportedBindingMethods = setOf(BINDING_METHOD_JWK),
        sdJwtClaims = claimDescriptions
    )

class DefaultCredentialSchemeMapper : CredentialSchemeMapper {

    override fun map(scheme: CredentialScheme): Map<String, SupportedCredentialFormat> =
        listOfNotNull(
            if (scheme is IsoMdocCredentialScheme)
                scheme.toIsoMdocSupportedCredentialFormat(toCredentialIdentifier(scheme, ISO_MDOC))
            else null,
            if (scheme is VcJwtCredentialScheme)
                scheme.toPlainJwtSupportedCredentialFormat(toCredentialIdentifier(scheme, PLAIN_JWT))
            else null,
            if (scheme is SdJwtCredentialScheme)
                scheme.toSdJwtSupportedCredentialFormat(toCredentialIdentifier(scheme, SD_JWT))
            else null
        ).toMap()

    override fun toCredentialIdentifier(
        scheme: CredentialScheme,
        rep: CredentialRepresentation,
    ) = when (rep) {
        PLAIN_JWT -> encodeToCredentialIdentifier(scheme.vcType!!, JWT_VC)
        SD_JWT -> encodeToCredentialIdentifier(scheme.sdJwtType!!, DC_SD_JWT)
        ISO_MDOC -> scheme.isoDocType!!
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
            AttributeIndex.resolveIsoDoctype(input)
                ?.let { Pair(it, ISO_MDOC) }
        }

}
