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
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme
import at.asitplus.wallet.lib.data.ConstantIndex.supportsIso
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import at.asitplus.wallet.lib.data.VcDataModelConstants
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
        CredentialRepresentation.PLAIN_JWT -> encodeToCredentialIdentifier(scheme.vcType!!, JWT_VC)
        CredentialRepresentation.SD_JWT -> encodeToCredentialIdentifier(scheme.sdJwtType!!, DC_SD_JWT)
        CredentialRepresentation.ISO_MDOC -> scheme.isoNamespace!!
    }

    @Suppress("DEPRECATION")
    private fun CredentialScheme.toSupportedCredentialFormatWithSameScope(scope: String): Map<String, SupportedCredentialFormat> {
        val iso = if (supportsIso) {
            with(isoNamespace!!) {
                this to SupportedCredentialFormat.forIsoMdoc(
                    format = CredentialFormatEnum.MSO_MDOC,
                    scope = scope,
                    docType = isoDocType!!,
                    supportedBindingMethods = setOf(BINDING_METHOD_JWK, BINDING_METHOD_COSE_KEY),
                    isoClaims = claimNames.map {
                        ClaimDescription(path = listOf(isoNamespace!!) + it.split("."))
                    }.toSet()
                )
            }
        } else null
        val jwtVc = if (supportsVcJwt) {
            with(encodeToCredentialIdentifier(vcType!!, JWT_VC)) {
                this to SupportedCredentialFormat.forVcJwt(
                    format = JWT_VC,
                    scope = scope,
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
        val sdJwt = if (supportsSdJwt) {
            with(encodeToCredentialIdentifier(sdJwtType!!, DC_SD_JWT)) {
                this to SupportedCredentialFormat.forSdJwt(
                    format = DC_SD_JWT,
                    scope = scope,
                    sdJwtVcType = sdJwtType!!,
                    supportedBindingMethods = setOf(BINDING_METHOD_JWK, URN_TYPE_JWK_THUMBPRINT),
                    sdJwtClaims = claimNames.map {
                        ClaimDescription(path = it.split("."))
                    }.toSet()
                )
            }
        } else null
        return listOfNotNull(iso, jwtVc, sdJwt).toMap()
    }
}
