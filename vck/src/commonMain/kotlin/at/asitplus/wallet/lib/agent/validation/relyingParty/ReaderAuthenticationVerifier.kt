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

/** Authenticates the complete mdoc request with one WRPAC leaf certificate. Chain trust is checked separately. */
class ReaderAuthenticationVerifier(
    private val verifySignature: VerifyCoseSignatureWithKeyFun<ByteArray> = VerifyCoseSignatureWithKey(),
) {
    suspend operator fun invoke(
        request: DeviceRequest,
        transcript: SessionTranscript
    ): KmmResult<CertificateChain> = catching {
        require(request.docRequests.isNotEmpty()) { "DeviceRequest contains no document requests" }

        request.readerAuthAll.orEmpty().forEach { signature ->
            verify(signature, ReaderAuthenticationAll.detachedPayload(request, transcript)).getOrNull()
                ?.let { return@catching it }
        }

        val chains = request.docRequests.map { docRequest ->
            val signature = requireNotNull(docRequest.readerAuth) { "DocRequest is missing readerAuth" }
            verify(signature, ReaderAuthentication.detachedPayload(docRequest, transcript)).getOrThrow()
        }
        val first = chains.first()
        val leafDer = first.first().encodeToDer()
        require(chains.all { it.first().encodeToDer().contentEquals(leafDer) }) {
            "DocRequests are not signed by one WRPAC"
        }
        first
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
