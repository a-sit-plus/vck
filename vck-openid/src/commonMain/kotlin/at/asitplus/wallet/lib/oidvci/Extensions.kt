package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.BINDING_METHOD_COSE_KEY
import at.asitplus.openid.OpenIdConstants.BINDING_METHOD_JWK
import at.asitplus.openid.OpenIdConstants.Errors.ACCESS_DENIED
import at.asitplus.openid.OpenIdConstants.Errors.CREDENTIAL_REQUEST_DENIED
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_CLIENT
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_CODE
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_DPOP_PROOF
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_GRANT
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_NONCE
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_PROOF
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_REQUEST
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_SCOPE
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_TOKEN
import at.asitplus.openid.OpenIdConstants.Errors.REGISTRATION_VALUE_NOT_SUPPORTED
import at.asitplus.openid.OpenIdConstants.Errors.UNSUPPORTED_CREDENTIAL_TYPE
import at.asitplus.openid.OpenIdConstants.Errors.USER_CANCELLED
import at.asitplus.openid.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme
import at.asitplus.wallet.lib.data.ConstantIndex.supportsIso
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import at.asitplus.wallet.lib.data.VcDataModelConstants
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement

@Suppress("DEPRECATION")
fun CredentialScheme.toSupportedCredentialFormat(
    cryptoAlgorithms: Set<SignatureAlgorithm>? = null,
    supportedProofTypes: Map<String, CredentialRequestProofSupported>? = null,
): Map<String, SupportedCredentialFormat> {
    val supportedSigningAlgorithms = cryptoAlgorithms
        ?.mapNotNull { it.toJwsAlgorithm().getOrNull()?.identifier }
        ?.toSet()
    val iso = if (supportsIso) {
        isoNamespace!! to SupportedCredentialFormat.forIsoMdoc(
            format = CredentialFormatEnum.MSO_MDOC,
            scope = isoNamespace!!,
            docType = isoDocType!!,
            supportedBindingMethods = setOf(BINDING_METHOD_JWK, BINDING_METHOD_COSE_KEY),
            supportedSigningAlgorithms = supportedSigningAlgorithms,
            supportedProofTypes = supportedProofTypes,
            isoClaims = claimNames.map {
                ClaimDescription(path = listOf(isoNamespace!!) + it.split("."))
            }.toSet()
        )
    } else null
    val jwtVc = if (supportsVcJwt) {
        encodeToCredentialIdentifier(vcType!!, CredentialFormatEnum.JWT_VC) to SupportedCredentialFormat.forVcJwt(
            format = CredentialFormatEnum.JWT_VC,
            scope = encodeToCredentialIdentifier(vcType!!, CredentialFormatEnum.JWT_VC),
            credentialDefinition = SupportedCredentialFormatDefinition(
                types = setOf(VcDataModelConstants.VERIFIABLE_CREDENTIAL, vcType!!),
                credentialSubject = claimNames.associateWith { CredentialSubjectMetadataSingle() }
            ),
            supportedBindingMethods = setOf(BINDING_METHOD_JWK, URN_TYPE_JWK_THUMBPRINT),
            supportedSigningAlgorithms = supportedSigningAlgorithms,
        )
    } else null
    // Uses "vc+sd-jwt", defined in SD-JWT VC up until draft 06
    val sdJwt = if (supportsSdJwt) {
        encodeToCredentialIdentifier(sdJwtType!!, CredentialFormatEnum.VC_SD_JWT) to SupportedCredentialFormat.forSdJwt(
            format = CredentialFormatEnum.VC_SD_JWT,
            scope = encodeToCredentialIdentifier(sdJwtType!!, CredentialFormatEnum.VC_SD_JWT),
            sdJwtVcType = sdJwtType!!,
            supportedBindingMethods = setOf(BINDING_METHOD_JWK, URN_TYPE_JWK_THUMBPRINT),
            supportedSigningAlgorithms = supportedSigningAlgorithms,
            sdJwtClaims = claimNames.map {
                ClaimDescription(path = it.split("."))
            }.toSet(),
        )
    } else null
    // Uses "dc+sd-jwt", supported since SD-JWT VC draft 06
    val sdJwtNewIdentifier = if (supportsSdJwt) {
        encodeToCredentialIdentifier(sdJwtType!!, CredentialFormatEnum.DC_SD_JWT) to SupportedCredentialFormat.forSdJwt(
            format = CredentialFormatEnum.DC_SD_JWT,
            scope = encodeToCredentialIdentifier(sdJwtType!!, CredentialFormatEnum.DC_SD_JWT),
            sdJwtVcType = sdJwtType!!,
            supportedBindingMethods = setOf(BINDING_METHOD_JWK, URN_TYPE_JWK_THUMBPRINT),
            supportedSigningAlgorithms = supportedSigningAlgorithms,
            sdJwtClaims = claimNames.map {
                ClaimDescription(path = it.split("."))
            }.toSet(),
        )
    } else null
    return listOfNotNull(iso, jwtVc, sdJwt, sdJwtNewIdentifier).toMap()
}

// TODO In 5.4.0, use DC_SD_JWT instead of VC_SD_JWT
@Suppress("DEPRECATION")
fun CredentialScheme.toCredentialIdentifier() = listOfNotNull(
    if (supportsIso) isoNamespace!! else null,
    if (supportsVcJwt) encodeToCredentialIdentifier(vcType!!, CredentialFormatEnum.JWT_VC) else null,
    if (supportsSdJwt) encodeToCredentialIdentifier(sdJwtType!!, CredentialFormatEnum.VC_SD_JWT) else null
)

fun CredentialRepresentation.toFormat(): CredentialFormatEnum = when (this) {
    CredentialRepresentation.PLAIN_JWT -> CredentialFormatEnum.JWT_VC
    CredentialRepresentation.SD_JWT -> CredentialFormatEnum.DC_SD_JWT
    CredentialRepresentation.ISO_MDOC -> CredentialFormatEnum.MSO_MDOC
}

// TODO In 5.4.0, use DC_SD_JWT instead of VC_SD_JWT
@Suppress("DEPRECATION")
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
private fun encodeToCredentialIdentifier(type: String, format: CredentialFormatEnum) =
    "${type.replace(" ", "_")}#${format.text}"

/**
 * Reverse functionality of [encodeToCredentialIdentifier], which can also handle ISO namespaces,
 * i.e. decodes a single string into a credential scheme and format,
 * e.g. from `AtomicAttribute2023#jwt_vc_json` to
 * [at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023] and [CredentialFormatEnum.JWT_VC]
 */
fun decodeFromCredentialIdentifier(input: String): Pair<CredentialScheme, CredentialFormatEnum>? {
    if (input.contains("#")) {
        val vcTypeOrSdJwtType = input.substringBeforeLast("#")
        val credentialScheme = AttributeIndex.resolveSdJwtAttributeType(vcTypeOrSdJwtType)
            ?: AttributeIndex.resolveAttributeType(vcTypeOrSdJwtType)
            ?: AttributeIndex.resolveSdJwtAttributeType(vcTypeOrSdJwtType.replace("_", " "))
            ?: AttributeIndex.resolveAttributeType(vcTypeOrSdJwtType.replace("_", " "))
            ?: return null
        val format = CredentialFormatEnum.parse(input.substringAfterLast("#"))
            ?: return null
        return Pair(credentialScheme, format)
    } else {
        return AttributeIndex.resolveIsoNamespace(input)
            ?.let { Pair(it, CredentialFormatEnum.MSO_MDOC) }
    }
}

@Suppress("DEPRECATION")
fun CredentialFormatEnum.toRepresentation() = when (this) {
    CredentialFormatEnum.VC_SD_JWT -> CredentialRepresentation.SD_JWT
    CredentialFormatEnum.DC_SD_JWT -> CredentialRepresentation.SD_JWT
    CredentialFormatEnum.MSO_MDOC -> CredentialRepresentation.ISO_MDOC
    else -> CredentialRepresentation.PLAIN_JWT
}


/**
 * @param transformer may be used to encrypt the credentials before serializing
 */
suspend fun Issuer.IssuedCredential.toCredentialResponseParameters(
    transformer: (suspend (String) -> String) = { it },
) = when (this) {
    is Issuer.IssuedCredential.Iso -> CredentialResponseParameters(
        credentials = setOf(toCredentialResponseSingleCredential(transformer)),
    )

    is Issuer.IssuedCredential.VcJwt -> CredentialResponseParameters(
        credentials = setOf(toCredentialResponseSingleCredential(transformer)),
    )

    is Issuer.IssuedCredential.VcSdJwt -> CredentialResponseParameters(
        credentials = setOf(toCredentialResponseSingleCredential(transformer)),
    )
}

/**
 * @param transformer may be used to encrypt the credentials before serializing
 */
// TODO In 5.4.0, use DC_SD_JWT instead of VC_SD_JWT
// TODO After 5.5.0, drop "credential", use only "credentials"
@Suppress("DEPRECATION")
suspend fun Collection<Issuer.IssuedCredential>.toCredentialResponseParameters(
    transformer: (suspend (String) -> String) = { it },
) = if (size == 1) {
    first().toCredentialResponseParameters(transformer)
} else {
    CredentialResponseParameters(
        credentials = this.map { it.toCredentialResponseSingleCredential(transformer) }.toSet()
    )
}

/**
 * @param transformer may be used to encrypt the credentials before serializing
 */
suspend fun Issuer.IssuedCredential.toCredentialResponseSingleCredential(
    transformer: (suspend (String) -> String) = { it },
): CredentialResponseSingleCredential = CredentialResponseSingleCredential(
    when (this) {
        is Issuer.IssuedCredential.Iso -> JsonPrimitive(transformer(toBase64UrlStrict()))
        is Issuer.IssuedCredential.VcJwt -> JsonPrimitive(transformer(vcJws))
        is Issuer.IssuedCredential.VcSdJwt -> JsonPrimitive(transformer(vcSdJwt))
    }
)

private fun Issuer.IssuedCredential.Iso.toBase64UrlStrict(): String =
    coseCompliantSerializer.encodeToByteArray(issuerSigned).encodeToString(Base64UrlStrict)

@Serializable
sealed class OAuth2Exception(
    val error: String,
    @Transient val errorDescription: String? = null,
) : Throwable("$error${errorDescription?.let { ": $it" }}") {

    fun serialize() = vckJsonSerializer.encodeToString(OAuth2ExceptionSerializer, this)

    @Serializable
    class InvalidRequest(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_REQUEST, description)

    @Serializable
    class InvalidClient(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_CLIENT, description)

    @Serializable
    class InvalidScope(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_SCOPE, description)

    @Serializable
    class InvalidGrant(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_GRANT, description)

    @Serializable
    class InvalidCode(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_CODE, description)

    @Serializable
    class InvalidToken(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_TOKEN, description)

    @Serializable
    class InvalidProof(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_PROOF, description)

    @Serializable
    class UserCancelled(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(USER_CANCELLED, description)

    @Serializable
    class InvalidDpopProof(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_DPOP_PROOF, description)

    @Serializable
    class UnsupportedCredentialType(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(UNSUPPORTED_CREDENTIAL_TYPE, description)

    @Serializable
    class CredentialRequestDenied(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(CREDENTIAL_REQUEST_DENIED, description)

    @Serializable
    class InvalidNonce(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_NONCE, description)

    @Serializable
    class AccessDenied(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(ACCESS_DENIED, description)

    @Serializable
    class RegistrationValueNotSupported(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(REGISTRATION_VALUE_NOT_SUPPORTED, description)
}

object OAuth2ExceptionSerializer : JsonContentPolymorphicSerializer<OAuth2Exception>(OAuth2Exception::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<OAuth2Exception> {
        throw NotImplementedError("Deserialization not supported")
    }
}
