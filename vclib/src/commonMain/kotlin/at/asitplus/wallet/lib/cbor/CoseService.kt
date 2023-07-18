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
     * Appends correct values for [CoseHeader.kid], [CoseHeader.algorithm],
     * if the corresponding options are set
     */
    suspend fun createSignedCose(
        protectedHeader: CoseHeader,
        unprotectedHeader: CoseHeader,
        payload: ByteArray,
        addKeyId: Boolean = true,
    ): KmmResult<CoseSigned>
}

interface VerifierCoseService {

    fun verifyCose(coseSigned: CoseSigned, signer: CoseKey): KmmResult<Boolean>

}

class DefaultCoseService(private val cryptoService: CryptoService) : CoseService {

    override suspend fun createSignedCose(
        protectedHeader: CoseHeader,
        unprotectedHeader: CoseHeader,
        payload: ByteArray,
        addKeyId: Boolean,
    ): KmmResult<CoseSigned> {
        var copy = protectedHeader.copy(algorithm = cryptoService.coseAlgorithm)
        if (addKeyId)
            copy = copy.copy(kid = cryptoService.identifier)

        val signatureInput = CoseSignatureInput(
            contextString = "Signature1",
            protectedHeader = ByteStringWrapper(copy),
            payload = payload,
        ).serialize()

        val signature = cryptoService.sign(signatureInput).getOrElse {
            Napier.w("No signature from native code", it)
            return KmmResult.failure(it)
        }
        val rawSignature = signature.extractSignatureValues(cryptoService.coseAlgorithm.signatureValueLength)
        return KmmResult.success(
            CoseSigned(ByteStringWrapper(copy), unprotectedHeader, payload, rawSignature)
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
            contextString = "Signature1",
            protectedHeader = ByteStringWrapper(coseSigned.protectedHeader.value),
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



