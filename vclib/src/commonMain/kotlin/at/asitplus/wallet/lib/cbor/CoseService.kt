package at.asitplus.wallet.lib.cbor

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultVerifierCryptoService
import at.asitplus.wallet.lib.agent.VerifierCryptoService
import at.asitplus.wallet.lib.jws.JwsExtensions.extractSignatureValues
import io.github.aakira.napier.Napier
import kotlinx.serialization.cbor.ByteStringWrapper

/**
 * Creates and parses COSE objects.
 */
interface CoseService {

    /**
     * Creates and signs a new [CoseSigned] object,
     * appends correct value for [CoseHeader.algorithm] into [protectedHeader].
     *
     * @param addKeyId whether to set [CoseHeader.kid] in [protectedHeader]
     * @param addCertificate whether to set [CoseHeader.certificateChain] in [unprotectedHeader]
     *
     */
    suspend fun createSignedCose(
        protectedHeader: CoseHeader,
        unprotectedHeader: CoseHeader? = null,
        payload: ByteArray? = null,
        addKeyId: Boolean = true,
        addCertificate: Boolean = false,
    ): KmmResult<CoseSigned>
}

interface VerifierCoseService {

    fun verifyCose(coseSigned: CoseSigned, signer: CoseKey): KmmResult<Boolean>

}

/**
 * Constant from RFC 9052 - CBOR Object Signing and Encryption (COSE)
 */
private const val SIGNATURE1_STRING = "Signature1"

class DefaultCoseService(private val cryptoService: CryptoService) : CoseService {

    override suspend fun createSignedCose(
        protectedHeader: CoseHeader,
        unprotectedHeader: CoseHeader?,
        payload: ByteArray?,
        addKeyId: Boolean,
        addCertificate: Boolean,
    ): KmmResult<CoseSigned> {
        var copyProtectedHeader = protectedHeader.copy(algorithm = cryptoService.coseAlgorithm)
        if (addKeyId)
            copyProtectedHeader = copyProtectedHeader.copy(kid = cryptoService.identifier.encodeToByteArray())

        val copyUnprotectedHeader = if (addCertificate) {
            (unprotectedHeader ?: CoseHeader()).copy(certificateChain = cryptoService.certificate)
        } else {
            unprotectedHeader
        }

        val signatureInput = CoseSignatureInput(
            contextString = SIGNATURE1_STRING,
            protectedHeader = ByteStringWrapper(copyProtectedHeader),
            externalAad = byteArrayOf(),
            payload = payload,
        ).serialize()

        val signature = cryptoService.sign(signatureInput).getOrElse {
            Napier.w("No signature from native code", it)
            return KmmResult.failure(it)
        }
        val rawSignature = signature.extractSignatureValues(cryptoService.coseAlgorithm.signatureValueLength)
        return KmmResult.success(
            CoseSigned(ByteStringWrapper(copyProtectedHeader), copyUnprotectedHeader, payload, rawSignature)
        )
    }
}

class DefaultVerifierCoseService(
    private val cryptoService: VerifierCryptoService = DefaultVerifierCryptoService()
) : VerifierCoseService {

    /**
     * Verifiers the signature of [coseSigned] by using [signer].
     */
    override fun verifyCose(coseSigned: CoseSigned, signer: CoseKey): KmmResult<Boolean> {
        val signatureInput = CoseSignatureInput(
            contextString = SIGNATURE1_STRING,
            protectedHeader = ByteStringWrapper(coseSigned.protectedHeader.value),
            externalAad = byteArrayOf(),
            payload = coseSigned.payload,
        ).serialize()

        val algorithm = coseSigned.protectedHeader.value.algorithm
            ?: return KmmResult.failure(IllegalArgumentException("Algorithm not specified"))
        val verified = cryptoService.verify(signatureInput, coseSigned.signature, algorithm, signer)
        val result = verified.getOrElse {
            Napier.w("No verification from native code", it)
            return KmmResult.failure(it)
        }
        return KmmResult.success(result)
    }
}



