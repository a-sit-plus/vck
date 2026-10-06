package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.agent.VerifySignature
import at.asitplus.wallet.lib.agent.VerifySignatureFun
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import kotlin.jvm.JvmOverloads

/**
 * The outcome of verifying the signature of a signed object, and the signer material that was used.
 */
data class SignatureVerification(
    val outcome: CheckOutcome,
    /** The certificate chain transported with the signed object, for the trust check, whether or not it verified. */
    val certificateChain: CertificateChain?,
    /** The key the signature verified with, `null` if it did not verify. */
    val key: CryptoPublicKey?,
)

/**
 * Verifies the signature of a JWS or COSE_Sign1 object: cryptographic integrity only, never whether the signer is
 * trusted, which is a separate check on [SignatureVerification.certificateChain].
 *
 * The key is selected strictly:
 *  1. A key the caller passes, e.g. the `cnf` key of a credential for its key binding JWT, is the only one used;
 *     keys the object asserts itself are ignored.
 *  2. Otherwise, the object has to assert exactly one key: the leaf of its `x5c` (JWS) or `x5chain` (COSE), a `jwk`
 *     (JWS), or a `did:key` in `kid`. Different keys fail, so that an asserted key can never stand in for the
 *     certificate the trust check evaluates.
 *
 * A `jku` is never followed: no artifact in scope resolves its key that way, and following a URL the sender chose
 * invites server-side request forgery [RFC8725-3.10]. Where a protocol does resolve keys from a URL, its client
 * retrieves them like any other HTTP request, and passes the key as `key`.
 *
 * Only asymmetric signature algorithms are accepted, never `none` or a MAC.
 */
class SignatureCheck @JvmOverloads constructor(
    private val verifySignature: VerifySignatureFun = VerifySignature(),
) {

    /** Verifies [jws], with [key] if given, otherwise with the single key it asserts, see [SignatureCheck]. */
    @JvmOverloads
    suspend fun verify(
        jws: JwsCompact,
        key: CryptoPublicKey? = null,
    ): SignatureVerification {
        val header = jws.jwsHeader
        val chain = header.certificateChain?.takeIf { it.isNotEmpty() }
        return verified(chain) {
            val algorithm = header.algorithm
            require(algorithm is JwsAlgorithm.Signature) {
                "Algorithm ${algorithm.identifier} is not an asymmetric signature algorithm"
            }
            val signer = key ?: listOfNotNull(
                chain?.leaf?.decodedPublicKey?.getOrThrow(),
                header.jsonWebKey?.toCryptoPublicKey()?.getOrThrow(),
                header.keyId?.toDidKey(),
            ).single() ?: throw IllegalArgumentException("No key to verify the signature with")
            verifySignature(jws.signatureInput, jws.signature, algorithm.algorithm, signer).getOrThrow()
            signer
        }
    }

    /**
     * Verifies [cose], over [externalAad] and, for a detached payload, [detachedPayload], with [key] if given,
     * otherwise with the single key it asserts in its protected or unprotected header, see [SignatureCheck].
     */
    @JvmOverloads
    suspend fun verify(
        cose: CoseSigned<*>,
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
        key: CryptoPublicKey? = null,
    ): SignatureVerification {
        val chain = catching { cose.certificateChain() }.getOrElse {
            return SignatureVerification(Failed(it), certificateChain = null, key = null)
        }
        return verified(chain) {
            val algorithm = cose.protectedHeader.algorithm
            require(algorithm is CoseAlgorithm.Signature) {
                "Algorithm $algorithm is not an asymmetric signature algorithm"
            }
            val signer = key ?: listOfNotNull(
                chain?.leaf?.decodedPublicKey?.getOrThrow(),
                cose.protectedHeader.kid?.decodeToString()?.toDidKey(),
                cose.unprotectedHeader?.kid?.decodeToString()?.toDidKey(),
            ).single() ?: throw IllegalArgumentException("No key to verify the signature with")
            val input = cose.prepareCoseSignatureInput(externalAad, detachedPayload)
            verifySignature(input, cose.signature, algorithm.algorithm, signer).getOrThrow()
            signer
        }
    }

    private suspend fun verified(
        chain: CertificateChain?,
        verification: suspend () -> CryptoPublicKey,
    ): SignatureVerification = catching { verification() }.fold(
        onSuccess = { SignatureVerification(Passed, chain, it) },
        onFailure = { SignatureVerification(Failed(it), chain, key = null) },
    )

    /** The one key all asserted keys agree on, `null` if none is asserted. */
    private fun List<CryptoPublicKey>.single(): CryptoPublicKey? {
        val distinct = distinctBy { it.encodeToDer().toList() }
        require(distinct.size <= 1) { "The signed object asserts different keys" }
        return distinct.firstOrNull()
    }

    /** A `kid` is a key only if it is a `did:key`, otherwise it just names a key. */
    private fun String.toDidKey(): CryptoPublicKey? =
        takeIf { it.startsWith("did:key:") }?.let { CryptoPublicKey.fromDid(it) }

    /** Certificates are transported DER-encoded in COSE headers; both headers have to agree if both carry one. */
    private fun CoseSigned<*>.certificateChain(): CertificateChain? {
        val protectedChain = protectedHeader.certificateChain?.takeIf { it.isNotEmpty() }
        val unprotectedChain = unprotectedHeader?.certificateChain?.takeIf { it.isNotEmpty() }
        if (protectedChain != null && unprotectedChain != null) {
            require(protectedChain.size == unprotectedChain.size &&
                    protectedChain.zip(unprotectedChain).all { (a, b) -> a.contentEquals(b) }) {
                "The protected and unprotected header carry different certificate chains"
            }
        }
        return (protectedChain ?: unprotectedChain)?.map { X509Certificate.decodeFromDer(it) }
    }
}

/*
 * References
 *
 * | Tag          | Source                                                                                         |
 * |--------------|------------------------------------------------------------------------------------------------|
 * | RFC8725-3.10 | RFC 8725 (JSON Web Token Best Current Practices), 3.10 Do Not Trust Received Claims: blindly   |
 * |              | following a `jku` or `x5u` header "could result in server-side request forgery (SSRF) attacks" |
 */
