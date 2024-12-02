package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.JsonPrimitive

fun CredentialFormatEnum.toRepresentation() = when (this) {
    CredentialFormatEnum.VC_SD_JWT -> CredentialRepresentation.SD_JWT
    CredentialFormatEnum.MSO_MDOC -> CredentialRepresentation.ISO_MDOC
    else -> CredentialRepresentation.PLAIN_JWT
}

fun Issuer.IssuedCredential.toCredentialResponseJsonPrimitive() = when (this) {
    is Issuer.IssuedCredential.Iso -> JsonPrimitive(issuerSigned.serialize().encodeToString(Base64UrlStrict))
    is Issuer.IssuedCredential.VcJwt -> JsonPrimitive(vcJws)
    is Issuer.IssuedCredential.VcSdJwt -> JsonPrimitive(vcSdJwt)
}

class OAuth2Exception(val error: String, val errorDescription: String? = null) : Throwable(error) {

}
