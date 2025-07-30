package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.CredentialResponseSingleCredential
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.JsonPrimitive

fun CredentialRepresentation.toFormat(): CredentialFormatEnum = when (this) {
    CredentialRepresentation.PLAIN_JWT -> CredentialFormatEnum.JWT_VC
    CredentialRepresentation.SD_JWT -> CredentialFormatEnum.DC_SD_JWT
    CredentialRepresentation.ISO_MDOC -> CredentialFormatEnum.MSO_MDOC
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
        is Issuer.IssuedCredential.VcJwt -> JsonPrimitive(transformer(signedVcJws.serialize()))
        is Issuer.IssuedCredential.VcSdJwt -> JsonPrimitive(transformer(signedSdJwtVc.serialize()))
    }
)

private fun Issuer.IssuedCredential.Iso.toBase64UrlStrict(): String =
    coseCompliantSerializer.encodeToByteArray(issuerSigned).encodeToString(Base64UrlStrict)

