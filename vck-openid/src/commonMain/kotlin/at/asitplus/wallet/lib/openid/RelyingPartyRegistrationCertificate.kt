package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.openid.VerifierInfo
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.jvm.JvmOverloads

/**
 * The registration certificate (WRPRC) of the relying party, in the encoding of each exchange protocol it requests
 * over, as "The WRPRC shall be formatted as signed JSON Web Token (JWT) [...] or CBOR Web Token (CWT)" (ETSI TS 119 475
 * V1.2.1, GEN-5.2.1-01). Fails if neither is set.
 */
data class RelyingPartyRegistrationCertificate @JvmOverloads constructor(
    /**
     * The compact serialization of the JWT, for OpenID4VP: sent in a `verifier_info` element of the format
     * `registration_cert` without `credential_ids`, as it applies to every requested credential, whose `data` is its
     * base64url encoding (ETSI TS 119 472-2 V1.3.1, OIDFVP-HAIP-COMMON-REQ-RO-15, RO-16), see [verifierInfo].
     */
    val jwt: String? = null,
    /**
     * The CBOR-encoded, COSE-signed CWT, for ISO/IEC 18013-7 Annex C: the `euWrprc` of every document request, see
     * [at.asitplus.iso.DocRequestInfo.euWrprc].
     */
    val cwt: ByteArray? = null,
) {
    init {
        require(jwt != null || cwt != null) { "A registration certificate needs its JWT or its CWT" }
    }

    /** The `verifier_info` element of [jwt], see there, or `null` without one. */
    val verifierInfo: VerifierInfo?
        get() = jwt?.let {
            VerifierInfo(
                format = REGISTRATION_CERT_FORMAT,
                data = it.encodeToByteArray().encodeToString(Base64UrlStrict)
            )
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RelyingPartyRegistrationCertificate) return false
        return jwt == other.jwt && cwt.contentEquals(other.cwt)
    }

    override fun hashCode(): Int = 31 * (jwt?.hashCode() ?: 0) + (cwt?.contentHashCode() ?: 0)
}
