package at.asitplus.wallet.lib.agent.validation.relyingParty

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.ReaderAuthentication
import at.asitplus.iso.ReaderAuthenticationAll
import at.asitplus.iso.SessionTranscript
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun

/** Authenticates an mdoc request with the reader certificates of its signatures. Chain trust is checked separately. */
class ReaderAuthenticationVerifier(
    private val verifySignature: VerifyCoseSignatureWithKeyFun<ByteArray> = VerifyCoseSignatureWithKey(),
) {
    /**
     * Authenticates the complete mdoc request with one reader certificate, failing if a document request is not
     * covered by reader authentication.
     */
    @Deprecated(
        "Use authenticate, which returns every chain whose readerAuthAll signature verifies, to check the trust of " +
                "each, and the document requests without reader authentication."
    )
    suspend operator fun invoke(
        request: DeviceRequest,
        transcript: SessionTranscript
    ): KmmResult<CertificateChain> = authenticate(request, transcript).mapCatching {
        require(it.unauthenticatedDocRequests.isEmpty()) { "DocRequest is missing readerAuth" }
        it.chains.first()
    }

    /**
     * Authenticates the mdoc [request] over [transcript] (ISO/IEC DIS 18013-5:2025, 12.5.4), which "can be used for
     * each element individually or all at the same time":
     *  - with `readerAuthAll`, which covers every document request, every signature that verifies yields a chain,
     *    e.g. one per trust framework of the reader, and the `readerAuth` of document requests is ignored; if none
     *    verifies, the request is not authenticated;
     *  - otherwise, every `readerAuth` of a document request has to verify, all with one reader certificate, and
     *    document requests without one are [AuthenticatedReader.unauthenticatedDocRequests].
     *
     * Fails for a request without any reader authentication.
     */
    suspend fun authenticate(
        request: DeviceRequest,
        transcript: SessionTranscript,
    ): KmmResult<AuthenticatedReader> = catching {
        require(request.docRequests.isNotEmpty()) { "DeviceRequest contains no document requests" }

        val readerAuthAll = request.readerAuthAll.orEmpty()
        if (readerAuthAll.isNotEmpty()) {
            val payload = ReaderAuthenticationAll.detachedPayload(request, transcript)
            val results = readerAuthAll.map { verify(it, payload) }
            val chains = results.mapNotNull { it.getOrNull() }
            if (chains.isEmpty()) {
                throw IllegalArgumentException(
                    "No readerAuthAll signature verifies",
                    results.last().exceptionOrNull(),
                )
            }
            return@catching AuthenticatedReader(chains, emptyList())
        }

        val chains = request.docRequests.mapNotNull { docRequest ->
            docRequest.readerAuth?.let {
                verify(it, ReaderAuthentication.detachedPayload(docRequest, transcript)).getOrThrow()
            }
        }
        require(chains.isNotEmpty()) { "The request has no reader authentication" }
        val first = chains.first()
        val leafDer = first.first().encodeToDer()
        require(chains.all { it.first().encodeToDer().contentEquals(leafDer) }) {
            "DocRequests are not signed by one reader certificate"
        }
        AuthenticatedReader(
            chains = listOf(first),
            unauthenticatedDocRequests = request.docRequests.indices.filter { request.docRequests[it].readerAuth == null },
        )
    }

    private suspend fun verify(
        signature: CoseSigned<ByteArray>,
        detachedPayload: ByteArray
    ): KmmResult<CertificateChain> = catching {
        require(signature.payload == null) { "Reader authentication must use a detached payload" }
        val encodedChain = signature.protectedHeader.certificateChain
            ?: signature.unprotectedHeader?.certificateChain
            ?: throw IllegalArgumentException("Reader authentication has no x5chain")
        require(encodedChain.isNotEmpty()) { "Reader authentication has an empty x5chain" }
        val chain = encodedChain.map { bytes ->
            X509Certificate.decodeFromDerSafe(bytes).getOrElse { cause ->
                throw IllegalArgumentException("Invalid reader authentication certificate", cause)
            }
        }
        val signer = chain.first().decodedPublicKey.getOrThrow().toCoseKey().getOrThrow()
        verifySignature(signature, signer, byteArrayOf(), detachedPayload).getOrThrow()
        chain
    }
}

/** The result of [ReaderAuthenticationVerifier.authenticate]. */
data class AuthenticatedReader(
    /**
     * The certificate chains whose signatures over the request verify, in the order of the request, not empty: one
     * per `readerAuthAll` signature that verifies, or the one of the `readerAuth` of document requests.
     */
    val chains: List<CertificateChain>,
    /** The indices of the document requests no signature covers, which are not bound to the reader. */
    val unauthenticatedDocRequests: List<Int>,
)
