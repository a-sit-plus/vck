package at.asitplus.wallet.lib.openid

import at.asitplus.openid.VerifierInfo
import kotlinx.serialization.Serializable

/**
 * Outcome of authenticating one signature of a multisigned DC API request, i.e. whether its signature verifies and
 * its protected `client_id` is bound to the signing key.
 *
 * Only [authenticated] signatures prove that the verifier they name took part in the request: the protected header of
 * any other signature may have been copied from an unrelated request, so wallets must not display or evaluate trust
 * in its identity as if it were the verifier's.
 */
@Serializable
data class VerifierSignature(
    /** Position of the signature in the JWS General JSON Serialization. */
    val signatureIndex: Int,
    /** Client identifier from the signature's protected header. */
    val clientId: String,
    /** Attestations about the verifier from the signature's protected header. */
    val verifierInfo: List<VerifierInfo>?,
    val status: Status,
    /** Why the signature could not be authenticated, if it was not. */
    val failureReason: String? = null,
) {
    val authenticated: Boolean
        get() = status == Status.AUTHENTICATED

    enum class Status {
        /** The signature verifies, and its client identifier is bound to the signing key. */
        AUTHENTICATED,

        /**
         * The signature does not verify, or the client identifier is not bound to its key, e.g. because the protected
         * header was copied into a forged signature.
         */
        INVALID,

        /**
         * The wallet cannot evaluate the client identifier, e.g. its prefix belongs to a trust framework the wallet
         * does not support. Expected for multisigned requests, which address several trust frameworks at once.
         */
        UNSUPPORTED,

        /** The configured [RelyingPartyTrust] rejected the client identifier. */
        UNTRUSTED,
    }
}
