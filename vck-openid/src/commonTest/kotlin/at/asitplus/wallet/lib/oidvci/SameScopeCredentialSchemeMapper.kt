package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.CredentialFormatEnum.DC_SD_JWT
import at.asitplus.openid.CredentialFormatEnum.JWT_VC
import at.asitplus.openid.OpenIdConstants.BINDING_METHOD_COSE_KEY
import at.asitplus.openid.OpenIdConstants.BINDING_METHOD_JWK
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.VcJwtCredentialDefinition
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.VcDataModelConstants
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
import com.benasher44.uuid.uuid4

class SameScopeCredentialSchemeMapper(
    private val scope: String = uuid4().toString(),
) : CredentialSchemeMapper {

    override fun map(scheme: CredentialScheme): Map<String, SupportedCredentialFormat> =
        scheme.toSupportedCredentialFormatWithSameScope(scope)

    override fun decodeFromCredentialIdentifier(input: String): Pair<CredentialScheme, CredentialRepresentation>? =
        DefaultCredentialSchemeMapper().decodeFromCredentialIdentifier(input)

    override fun encodeToCredentialIdentifier(type: String, format: CredentialFormatEnum): String =
        "${type.replace(" ", "_")}#${format.text}"

    override fun toCredentialIdentifier(
        scheme: CredentialScheme,
        rep: CredentialRepresentation
    ) = when (rep) {
        PLAIN_JWT -> encodeToCredentialIdentifier(scheme.vcType!!, JWT_VC)
        SD_JWT -> encodeToCredentialIdentifier(scheme.sdJwtType!!, DC_SD_JWT)
        ISO_MDOC -> scheme.isoDocType!!
    }

    @Suppress("DEPRECATION")
    private fun CredentialScheme.toSupportedCredentialFormatWithSameScope(
        scope: String
    ): Map<String, SupportedCredentialFormat> {
        val iso = if (this is IsoMdocCredentialScheme) {
            with(isoNamespace) {
                this to SupportedCredentialFormat.forIsoMdoc(
                    scope = scope,
                    docType = isoDocType,
                    supportedBindingMethods = setOf(BINDING_METHOD_COSE_KEY),
                    isoClaims = claimDescriptions
                )
            }
        } else null
        val jwtVc = if (this is VcJwtCredentialScheme) {
            with(encodeToCredentialIdentifier(vcType, JWT_VC)) {
                this to SupportedCredentialFormat.forVcJwt(
                    scope = scope,
                    credentialDefinition = VcJwtCredentialDefinition(
                        types = setOf(VcDataModelConstants.VERIFIABLE_CREDENTIAL, vcType),
                    ),
                    supportedBindingMethods = setOf(BINDING_METHOD_JWK),
                    vcJwtClaims = claimDescriptions
                )
            }
        } else null
        val sdJwt = if (this is SdJwtCredentialScheme) {
            with(encodeToCredentialIdentifier(sdJwtType, DC_SD_JWT)) {
                this to SupportedCredentialFormat.forSdJwt(
                    scope = scope,
                    sdJwtVcType = sdJwtType,
                    supportedBindingMethods = setOf(BINDING_METHOD_JWK),
                    sdJwtClaims = claimDescriptions
                )
            }
        } else null
        return listOfNotNull(iso, jwtVc, sdJwt).toMap()
    }
}
