package at.asitplus.wallet.lib.cbor

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultVerifierCryptoService
import at.asitplus.wallet.lib.agent.VerifierCryptoService
import at.asitplus.wallet.lib.iso.wrapInCborTag
import io.github.aakira.napier.Napier
import kotlinx.serialization.SerializationStrategy

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
     */
    suspend fun createSignedCose(
        protectedHeader: CoseHeader? = null,
        unprotectedHeader: CoseHeader? = null,
        payload: ByteArray? = null,
        addKeyId: Boolean = true,
        addCertificate: Boolean = false,
    ): KmmResult<CoseSigned<ByteArray>>

    /**
     * Creates and signs a new [CoseSigned] object,
     * appends correct value for [CoseHeader.algorithm] into [protectedHeader].
     *
     * @param addKeyId whether to set [CoseHeader.kid] in [protectedHeader]
     * @param addCertificate whether to set [CoseHeader.certificateChain] in [unprotectedHeader]
     */
    suspend fun <P : Any> createSignedCose(
        protectedHeader: CoseHeader? = null,
        unprotectedHeader: CoseHeader? = null,
        payload: P,
        serializationStrategy: SerializationStrategy<P>,
        addKeyId: Boolean = true,
        addCertificate: Boolean = false,
    ): KmmResult<CoseSigned<P>>
}

interface VerifierCoseService {

    fun verifyCose(coseSigned: CoseSigned<*>, signer: CoseKey): KmmResult<Verifier.Success>

}

class DefaultCoseService(private val cryptoService: CryptoService) : CoseService {

    override val algorithm: CoseAlgorithm = cryptoService.keyMaterial.signatureAlgorithm.toCoseAlgorithm().getOrThrow()

    override suspend fun createSignedCose(
        protectedHeader: CoseHeader?,
        unprotectedHeader: CoseHeader?,
        payload: ByteArray?,
        addKeyId: Boolean,
        addCertificate: Boolean,
    ): KmmResult<CoseSigned<ByteArray>> = catching {
        protectedHeader.withAlgorithmAndKeyId(addKeyId).let { coseHeader ->
            CoseSigned(
                protectedHeader = coseHeader,
                unprotectedHeader = unprotectedHeader.withCertificateIfExists(addCertificate),
                payload = payload,
                signature = calcSignature(coseHeader, payload)
            )
        }
    }

    override suspend fun <P : Any> createSignedCose(
        protectedHeader: CoseHeader?,
        unprotectedHeader: CoseHeader?,
        payload: P,
        serializationStrategy: SerializationStrategy<P>,
        addKeyId: Boolean,
        addCertificate: Boolean,
    ): KmmResult<CoseSigned<P>> = catching {
        protectedHeader.withAlgorithmAndKeyId(addKeyId).let { coseHeader ->
            coseCompliantSerializer.encodeToByteArray(serializationStrategy, payload)
                .let { if (payload is ByteStringWrapper<*>) it.wrapInCborTag(24) else it }
                .let { rawPayload ->
                    CoseSigned(
                        protectedHeader = coseHeader,
                        unprotectedHeader = unprotectedHeader.withCertificateIfExists(addCertificate),
                        payload = rawPayload,
                        signature = calcSignature(coseHeader, rawPayload)
                    )
                }
        }

    }

    private suspend fun CoseHeader?.withCertificateIfExists(addCertificate: Boolean): CoseHeader? =
        if (addCertificate) {
            withCertificate(cryptoService.keyMaterial.getCertificate())
        } else {
            this
        }

    private fun CoseHeader?.withCertificate(certificate: X509Certificate?) =
        (this ?: CoseHeader()).copy(certificateChain = certificate?.encodeToDer())

    private fun CoseHeader?.withAlgorithmAndKeyId(addKeyId: Boolean): CoseHeader =
        if (addKeyId) {
            withAlgorithm(algorithm).withKeyId()
        } else {
            withAlgorithm(algorithm)
        }

    private fun CoseHeader.withKeyId(): CoseHeader =
        copy(kid = cryptoService.keyMaterial.publicKey.didEncoded.encodeToByteArray())

    private fun CoseHeader?.withAlgorithm(coseAlgorithm: CoseAlgorithm): CoseHeader =
        this?.copy(algorithm = coseAlgorithm)
            ?: CoseHeader(algorithm = coseAlgorithm)

    private suspend fun calcSignature(
        protectedHeader: CoseHeader,
        payload: ByteArray?
    ): CryptoSignature.RawByteEncodable =
        cryptoService.sign(CoseSigned.prepareCoseSignatureInput(protectedHeader, payload))
            .asKmmResult().getOrElse {
                Napier.w("No signature from native code", it)
                throw it
            }

}

class DefaultVerifierCoseService(
    private val cryptoService: VerifierCryptoService = DefaultVerifierCryptoService()
) : VerifierCoseService {

    /**
     * Verifiers the signature of [coseSigned] by using [signer].
     */
    override fun verifyCose(coseSigned: CoseSigned<*>, signer: CoseKey) = catching {
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



