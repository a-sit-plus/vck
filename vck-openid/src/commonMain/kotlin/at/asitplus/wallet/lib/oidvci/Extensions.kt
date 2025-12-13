package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.CredentialResponseSingleCredential
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JwkType
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.JsonPrimitive

fun CredentialRepresentation.toFormat(): CredentialFormatEnum = when (this) {
    CredentialRepresentation.PLAIN_JWT -> CredentialFormatEnum.JWT_VC
    CredentialRepresentation.SD_JWT -> CredentialFormatEnum.DC_SD_JWT
    CredentialRepresentation.ISO_MDOC -> CredentialFormatEnum.MSO_MDOC
}

fun CredentialFormatEnum.toRepresentation() = when (this) {
    CredentialFormatEnum.DC_SD_JWT -> CredentialRepresentation.SD_JWT
    CredentialFormatEnum.MSO_MDOC -> CredentialRepresentation.ISO_MDOC
    else -> CredentialRepresentation.PLAIN_JWT
}

fun Collection<Issuer.IssuedCredential>.toCredentialResponseParameters() =
    CredentialResponseParameters(
        credentials = this.map { it.toCredentialResponseSingleCredential() }.toSet()
    )

fun Issuer.IssuedCredential.toCredentialResponseSingleCredential() = CredentialResponseSingleCredential(
    when (this) {
        is Issuer.IssuedCredential.Iso -> JsonPrimitive(toBase64UrlStrict())
        is Issuer.IssuedCredential.VcJwt -> JsonPrimitive(signedVcJws.serialize())
        is Issuer.IssuedCredential.VcSdJwt -> JsonPrimitive(signedSdJwtVc.serialize())
    }
)

private fun Issuer.IssuedCredential.Iso.toBase64UrlStrict(): String =
    coseCompliantSerializer.encodeToByteArray(issuerSigned).encodeToString(Base64UrlStrict)
