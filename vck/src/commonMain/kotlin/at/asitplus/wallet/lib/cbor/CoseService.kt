package at.asitplus.wallet.lib.cbor

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultVerifierCryptoService
import at.asitplus.wallet.lib.agent.VerifierCryptoService
import io.github.aakira.napier.Napier

/**
 * Creates and parses COSE objects.
 */
interface CoseService {

    /**
     * Algorithm which will be used to sign COSE in [createSignedCose].
     */
    val algorithm: CoseAlgorithm

    /**
     * Creates and signs a new [CoseSigned] object,
     * appends correct value for [CoseHeader.algorithm] into [protectedHeader].
     *
     * @param addKeyId whether to set [CoseHeader.kid] in [protectedHeader]
     * @param addCertificate whether to set [CoseHeader.certificateChain] in [unprotectedHeader]
     *
     */
    suspend fun createSignedCose(
        protectedHeader: CoseHeader? = null,
        unprotectedHeader: CoseHeader? = null,
        payload: ByteArray? = null,
        addKeyId: Boolean = true,
        addCertificate: Boolean = false,
    ): KmmResult<CoseSigned>
}

interface VerifierCoseService {

    fun verifyCose(coseSigned: CoseSigned, signer: CoseKey): KmmResult<Verifier.Success>

}

class DefaultCoseService(private val cryptoService: CryptoService) : CoseService {

    override val algorithm: CoseAlgorithm = cryptoService.keyMaterial.signatureAlgorithm.toCoseAlgorithm().getOrThrow()

    override suspend fun createSignedCose(
        protectedHeader: CoseHeader?,
        unprotectedHeader: CoseHeader?,
        payload: ByteArray?,
        addKeyId: Boolean,
        addCertificate: Boolean,
    ): KmmResult<CoseSigned> = catching {
        var copyProtectedHeader = protectedHeader?.copy(algorithm = algorithm)
            ?: CoseHeader(algorithm = algorithm)
        if (addKeyId) {
            copyProtectedHeader = copyProtectedHeader
                .copy(kid = cryptoService.keyMaterial.publicKey.didEncoded.encodeToByteArray())
        }

        val certificate = cryptoService.keyMaterial.getCertificate()
        val copyUnprotectedHeader = if (addCertificate && certificate != null) {
            (unprotectedHeader ?: CoseHeader())
                .copy(certificateChain = certificate.encodeToDer())
        } else {
            unprotectedHeader
        }

        val signatureInput = CoseSigned.prepareCoseSignatureInput(copyProtectedHeader, payload)

        val signature = cryptoService.sign(signatureInput).asKmmResult().getOrElse {
            Napier.w("No signature from native code", it)
            throw it
        }

        CoseSigned(
            protectedHeader = ByteStringWrapper(value = copyProtectedHeader),
            unprotectedHeader = copyUnprotectedHeader,
            payload = payload,
            signature = signature
        )
    }
}

class DefaultVerifierCoseService(
    private val cryptoService: VerifierCryptoService = DefaultVerifierCryptoService()
) : VerifierCoseService {

    /**
     * Verifiers the signature of [coseSigned] by using [signer].
     */
    override fun verifyCose(coseSigned: CoseSigned, signer: CoseKey) = catching {
        val signatureInput = CoseSigned.prepareCoseSignatureInput(coseSigned.protectedHeader.value, coseSigned.payload)

        val algorithm = coseSigned.protectedHeader.value.algorithm
            ?: throw IllegalArgumentException("Algorithm not specified")
        val publicKey = signer.toCryptoPublicKey().getOrElse { ex ->
            throw IllegalArgumentException("Signer not convertible")
                .also { Napier.w("Could not convert signer to public key: $signer", ex) }
        }
        cryptoService.verify(
            input = signatureInput,
            signature = coseSigned.signature,
            algorithm = algorithm.toX509SignatureAlgorithm().getOrThrow(),
            publicKey = publicKey
        ).getOrThrow()
    }
}



