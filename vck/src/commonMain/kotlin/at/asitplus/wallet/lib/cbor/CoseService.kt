package at.asitplus.wallet.lib.cbor

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultVerifierCryptoService
import at.asitplus.wallet.lib.agent.VerifierCryptoService
import io.github.aakira.napier.Napier
import kotlinx.serialization.KSerializer

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
    suspend fun <P : Any> createSignedCose(
        protectedHeader: CoseHeader? = null,
        unprotectedHeader: CoseHeader? = null,
        payload: P? = null,
        serializer: KSerializer<P>,
        addKeyId: Boolean = true,
        addCertificate: Boolean = false,
    ): KmmResult<CoseSigned<P>>
}

interface VerifierCoseService {

    fun <P : Any> verifyCose(
        coseSigned: CoseSigned<P>,
        signer: CoseKey,
        externalAad: ByteArray = byteArrayOf(),
    ): KmmResult<Verifier.Success>

    fun <P : Any> verifyCose(
        coseSigned: CoseSigned<P>,
        serializer: KSerializer<P>,
    ): KmmResult<Verifier.Success>
}

class DefaultCoseService(private val cryptoService: CryptoService) : CoseService {

    override val algorithm: CoseAlgorithm =
        cryptoService.keyMaterial.signatureAlgorithm.toCoseAlgorithm().getOrThrow()

    override suspend fun <P : Any> createSignedCose(
        protectedHeader: CoseHeader?,
        unprotectedHeader: CoseHeader?,
        payload: P?,
        serializer: KSerializer<P>,
        addKeyId: Boolean,
        addCertificate: Boolean,
    ): KmmResult<CoseSigned<P>> = catching {
        protectedHeader.withAlgorithmAndKeyId(addKeyId).let { coseHeader ->
            calcSignature(coseHeader, payload, serializer).let { signature ->
                CoseSigned.create(
                    protectedHeader = coseHeader,
                    unprotectedHeader = unprotectedHeader.withCertificateIfExists(addCertificate),
                    payload = payload,
                    signature = signature,
                    payloadSerializer = serializer,
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

    /**
     * @return payload to calculated signature
     */
    @Throws(Throwable::class)
    private suspend fun <P : Any> calcSignature(
        protectedHeader: CoseHeader,
        payload: P?,
        serializer: KSerializer<P>,
    ): CryptoSignature.RawByteEncodable =
        CoseSigned.prepare<P>(
            protectedHeader = protectedHeader,
            externalAad = byteArrayOf(),
            payload = payload,
            payloadSerializer = serializer
        ).let { signatureInput ->
            cryptoService.sign(signatureInput.serialize()).asKmmResult().getOrElse {
                Napier.w("No signature from native code", it)
                throw it
            }
        }
}

class DefaultVerifierCoseService(
    private val cryptoService: VerifierCryptoService = DefaultVerifierCryptoService(),
    /** Need to implement if valid keys for CoseSigned are transported somehow out-of-band, e.g. provided by a trust store */
    private val publicKeyLookup: PublicCoseKeyLookup = { null },
) : VerifierCoseService {

    /**
     * Verifiers the signature of [coseSigned] by using [signer].
     */
    override fun <P : Any> verifyCose(
        coseSigned: CoseSigned<P>,
        signer: CoseKey,
        externalAad: ByteArray,
    ) = catching {
        val signatureInput = coseSigned.prepareCoseSignatureInput(externalAad = externalAad)
        val algorithm = coseSigned.protectedHeader.algorithm
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

    /**
     * Verifiers the signature of [coseSigned] by extracting the coseSigned public key, or by using
     * [publicKeyLookup].
     */
    override fun <P : Any> verifyCose(
        coseSigned: CoseSigned<P>,
        serializer: KSerializer<P>
    ): KmmResult<Verifier.Success> = catching {
        coseSigned.loadPublicKeys().also {
            Napier.d("Public keys available: ${it.size}")
        }.firstNotNullOf { coseKey ->
            verifyCose(coseSigned, coseKey).getOrNull()
        }
    }

    fun CoseSigned<*>.loadPublicKeys(): Set<CoseKey> =
        (protectedHeader.publicKey ?: unprotectedHeader?.publicKey)?.let { setOf(it) }
            ?: publicKeyLookup(this) ?: setOf()
}

typealias PublicCoseKeyLookup = (CoseSigned<*>) -> Set<CoseKey>?

/**
 * Tries to compute a public key in order from [coseKey], [kid] or
 * [certificateChain], and takes the first success or null.
 */
val CoseHeader.publicKey: CoseKey?
    get() = coseKey?.let { CoseKey.deserialize(it).getOrNull() }
        ?: kid?.let { CoseKey.fromDid(it.decodeToString()) }?.getOrNull()
        ?: certificateChain?.let {
            runCatching {
                X509Certificate.decodeFromDer(it)
            }.getOrNull()?.publicKey?.toCoseKey()?.getOrThrow()
        }