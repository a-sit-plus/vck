package at.asitplus.wallet.lib.cbor

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultVerifierCryptoService
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.VerifierCryptoService
import at.asitplus.wallet.lib.agent.VerifySignature
import at.asitplus.wallet.lib.agent.VerifySignatureFun
import at.asitplus.wallet.lib.cbor.CoseUtils.calcSignature
import at.asitplus.wallet.lib.cbor.CoseUtils.withCertificateIfExists
import at.asitplus.wallet.lib.cbor.CoseUtils.withKeyId
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlin.byteArrayOf

/**
 * Creates and parses COSE objects.
 */
@Deprecated("Use SignCose, SignCoseDetached instead")
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
    @Deprecated("Use SignCose instead")
    suspend fun <P : Any> createSignedCose(
        protectedHeader: CoseHeader? = null,
        unprotectedHeader: CoseHeader? = null,
        payload: P? = null,
        serializer: KSerializer<P>,
        addKeyId: Boolean = true,
        addCertificate: Boolean = false,
    ): KmmResult<CoseSigned<P>>

    /**
     * Creates and signs a new [CoseSigned] object with detached payload,
     * meaning the signature is calculated over the signature, but not included in the [CoseSigned] structure.
     * It will set the correct value for [CoseHeader.algorithm] in [protectedHeader].
     *
     * @param addKeyId whether to set [CoseHeader.kid] in [protectedHeader]
     * @param addCertificate whether to set [CoseHeader.certificateChain] in [unprotectedHeader]
     */
    @Deprecated("Use SignCoseDetached instead")
    suspend fun <P : Any> createSignedCoseWithDetachedPayload(
        protectedHeader: CoseHeader? = null,
        unprotectedHeader: CoseHeader? = null,
        payload: P,
        serializer: KSerializer<P>,
        addKeyId: Boolean = false,
        addCertificate: Boolean = false,
    ): KmmResult<CoseSigned<P>>
}

/** How to identify the key material in a [CoseHeader] */
typealias CoseHeaderIdentifierFun = suspend (CoseHeader?, KeyMaterial) -> CoseHeader?

/** Don't identify [KeyMaterial] in [CoseHeader]. */
object CoseHeaderNone {
    operator fun invoke(): CoseHeaderIdentifierFun = { it, keyMaterial -> it }
}

/** Identify [KeyMaterial] with it's [KeyMaterial.identifier] in (protected) [CoseHeader.keyId]. */
object CoseHeaderKeyId {
    operator fun invoke(): CoseHeaderIdentifierFun = { it, keyMaterial ->
        it?.copy(kid = keyMaterial.identifier.encodeToByteArray())
    }
}

/** Identify [KeyMaterial] with it's [KeyMaterial.getCertificate] in (unprotected) [CoseHeader.certificateChain]. */
object CoseHeaderCertificate {
    operator fun invoke(): CoseHeaderIdentifierFun = { it, keyMaterial ->
        it?.copy(certificateChain = keyMaterial.getCertificate()?.let { listOf(it.encodeToDer()) })
    }
}

typealias SignCoseFun<P> = suspend (
    protectedHeader: CoseHeader?,
    unprotectedHeader: CoseHeader?,
    payload: P?,
    serializer: KSerializer<P>,
) -> KmmResult<CoseSigned<P>>

/** Create a [CoseSigned], setting protected and unprotected headers, and applying [CoseHeaderIdentifierFun]. */
object SignCose {
    operator fun <P : Any> invoke(
        keyMaterial: KeyMaterial,
        protectedHeaderModifier: CoseHeaderIdentifierFun? = null,
        unprotectedHeaderModifier: CoseHeaderIdentifierFun? = null,
    ): SignCoseFun<P> = { protectedHeader, unprotectedHeader, payload, serializer ->
        catching {
            val algorithm = keyMaterial.signatureAlgorithm.toCoseAlgorithm().getOrThrow()
            val headerWithAlg = (protectedHeader ?: CoseHeader()).copy(algorithm = algorithm)
            val protectedHeader = protectedHeaderModifier?.invoke(headerWithAlg, keyMaterial) ?: headerWithAlg
            val unprotectedHeader = unprotectedHeaderModifier?.invoke(unprotectedHeader ?: CoseHeader(), keyMaterial)
                ?: unprotectedHeader
            calcSignature(keyMaterial, protectedHeader, payload, serializer).let { signature ->
                CoseSigned.create(
                    protectedHeader = protectedHeader,
                    unprotectedHeader = unprotectedHeader,
                    payload = payload,
                    signature = signature,
                    payloadSerializer = serializer,
                )
            }
        }
    }
}

typealias SignCoseDetachedFun<P> = suspend (
    protectedHeader: CoseHeader?,
    unprotectedHeader: CoseHeader?,
    payload: P?,
    serializer: KSerializer<P>,
) -> KmmResult<CoseSigned<P>>

/**
 * Create a [CoseSigned] with detached payload,
 * setting protected and unprotected headers, and applying [CoseHeaderIdentifierFun]. */
object SignCoseDetached {
    operator fun <P : Any> invoke(
        keyMaterial: KeyMaterial,
        protectedHeaderModifier: CoseHeaderIdentifierFun? = null,
        unprotectedHeaderModifier: CoseHeaderIdentifierFun? = null,
    ): SignCoseDetachedFun<P> = { protectedHeader, unprotectedHeader, payload, serializer ->
        catching {
            val algorithm = keyMaterial.signatureAlgorithm.toCoseAlgorithm().getOrThrow()
            val headerWithAlg = (protectedHeader ?: CoseHeader()).copy(algorithm = algorithm)
            val protectedHeader = protectedHeaderModifier?.invoke(headerWithAlg, keyMaterial) ?: headerWithAlg
            val unprotectedHeader = unprotectedHeaderModifier?.invoke(unprotectedHeader ?: CoseHeader(), keyMaterial)
                ?: unprotectedHeader
            calcSignature(keyMaterial, protectedHeader, payload, serializer).let { signature ->
                CoseSigned.create(
                    protectedHeader = protectedHeader,
                    unprotectedHeader = unprotectedHeader,
                    payload = null,
                    signature = signature,
                    payloadSerializer = serializer,
                )
            }
        }
    }
}

interface VerifierCoseService {

    /**
     * Verifiers the signature of [coseSigned] by using [signer].
     *
     * @param externalAad optional authenticated data
     * @param detachedPayload optional payload, if it has been transported seperately, and [coseSigned.payload] is null
     */
    fun <P : Any> verifyCose(
        coseSigned: CoseSigned<P>,
        signer: CoseKey,
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
    ): KmmResult<Verifier.Success>

    /**
     * Verifiers the signature of [coseSigned] by extracting the public key from it's headers,
     * or by using [publicKeyLookup].
     *
     * @param externalAad optional authenticated data
     * @param detachedPayload optional payload, if it has been transported seperately, and [coseSigned.payload] is null
     */
    fun <P : Any> verifyCose(
        coseSigned: CoseSigned<P>,
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
    ): KmmResult<Verifier.Success>
}

@Deprecated("Use SignCose, SignCoseDetached instead")
class DefaultCoseService(private val cryptoService: CryptoService) : CoseService {

    override val algorithm: CoseAlgorithm =
        cryptoService.keyMaterial.signatureAlgorithm.toCoseAlgorithm().getOrThrow()

    @Deprecated("Use SignCose instead")
    override suspend fun <P : Any> createSignedCose(
        protectedHeader: CoseHeader?,
        unprotectedHeader: CoseHeader?,
        payload: P?,
        serializer: KSerializer<P>,
        addKeyId: Boolean,
        addCertificate: Boolean,
    ): KmmResult<CoseSigned<P>> = catching {
        protectedHeader.withAlgorithmAndKeyId(addKeyId).let { coseHeader ->
            calcSignature(cryptoService.keyMaterial, coseHeader, payload, serializer).let { signature ->
                CoseSigned.create(
                    protectedHeader = coseHeader,
                    unprotectedHeader = unprotectedHeader.withCertificateIfExists(
                        cryptoService.keyMaterial,
                        addCertificate
                    ),
                    payload = payload,
                    signature = signature,
                    payloadSerializer = serializer,
                )
            }
        }
    }

    @Deprecated("Use SignCoseDetached instead")
    override suspend fun <P : Any> createSignedCoseWithDetachedPayload(
        protectedHeader: CoseHeader?,
        unprotectedHeader: CoseHeader?,
        payload: P,
        serializer: KSerializer<P>,
        addKeyId: Boolean,
        addCertificate: Boolean,
    ): KmmResult<CoseSigned<P>> = catching {
        protectedHeader.withAlgorithmAndKeyId(addKeyId).let { coseHeader ->
            calcSignature(cryptoService.keyMaterial, coseHeader, payload, serializer).let { signature ->
                CoseSigned.create(
                    protectedHeader = coseHeader,
                    unprotectedHeader = unprotectedHeader.withCertificateIfExists(
                        cryptoService.keyMaterial,
                        addCertificate
                    ),
                    payload = null,
                    signature = signature,
                    payloadSerializer = serializer,
                )
            }
        }
    }

    private fun CoseHeader?.withAlgorithmAndKeyId(addKeyId: Boolean): CoseHeader =
        if (addKeyId) {
            withAlgorithm(algorithm).withKeyId(cryptoService.keyMaterial)
        } else {
            withAlgorithm(algorithm)
        }

    private fun CoseHeader?.withAlgorithm(coseAlgorithm: CoseAlgorithm): CoseHeader =
        this?.copy(algorithm = coseAlgorithm)
            ?: CoseHeader(algorithm = coseAlgorithm)
}

object CoseUtils {

    suspend fun CoseHeader?.withCertificateIfExists(
        keyMaterial: KeyMaterial,
        addCertificate: Boolean,
    ): CoseHeader? =
        if (addCertificate) {
            withCertificate(keyMaterial.getCertificate())
        } else {
            this
        }

    fun CoseHeader?.withCertificate(certificate: X509Certificate?) =
        (this ?: CoseHeader()).copy(certificateChain = certificate?.let { listOf(it.encodeToDer()) })

    fun CoseHeader.withKeyId(keyMaterial: KeyMaterial): CoseHeader =
        copy(kid = keyMaterial.publicKey.didEncoded.encodeToByteArray())

    /**
     * @return payload to calculated signature
     */
    @Throws(Throwable::class)
    suspend fun <P : Any> calcSignature(
        keyMaterial: KeyMaterial,
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
            Napier.d("COSE Signature input is ${signatureInput.serialize().encodeToString(Base16())}")
            keyMaterial.sign(signatureInput.serialize()).asKmmResult().getOrElse {
                Napier.w("No signature from native code", it)
                throw it
            }
        }

}

typealias VerifyCoseSignatureFun<P> = (
    coseSigned: CoseSigned<P>,
    externalAad: ByteArray,
    detachedPayload: ByteArray?,
) -> KmmResult<Verifier.Success>

object VerifyCoseSignature {
    operator fun <P : Any> invoke(
        verifyCoseSignature: VerifyCoseSignatureWithKeyFun<P> = VerifyCoseSignatureWithKey<P>(),
        /** Need to implement if valid keys for CoseSigned are transported somehow out-of-band, e.g. provided by a trust store */
        publicKeyLookup: PublicCoseKeyLookup = { null },
    ): VerifyCoseSignatureFun<P> = { coseSigned, externalAad, detachedPayload ->
        catching {
            coseSigned.loadPublicKeys(publicKeyLookup).also {
                Napier.d("Public keys available: ${it.size}")
            }.firstNotNullOf { coseKey ->
                verifyCoseSignature(coseSigned, coseKey, externalAad, detachedPayload).getOrNull()
            }
        }
    }

    fun CoseSigned<*>.loadPublicKeys(
        publicKeyLookup: PublicCoseKeyLookup = { null },
    ): Set<CoseKey> = (protectedHeader.publicKey ?: unprotectedHeader?.publicKey)?.let { setOf(it) }
        ?: publicKeyLookup(this) ?: setOf()
}

typealias VerifyCoseSignatureWithKeyFun<P> = (
    coseSigned: CoseSigned<P>,
    signer: CoseKey,
    externalAad: ByteArray,
    detachedPayload: ByteArray?,
) -> KmmResult<Verifier.Success>

object VerifyCoseSignatureWithKey {
    operator fun <P : Any> invoke(
        verifySignature: VerifySignatureFun = VerifySignature(),
    ): VerifyCoseSignatureWithKeyFun<P> = { coseSigned, signer, externalAad, detachedPayload ->
        catching {
            val signatureInput = coseSigned.prepareCoseSignatureInput(externalAad, detachedPayload)
                .also { Napier.d("verifyCose input is ${it.encodeToString(Base16())}") }
            val algorithm = coseSigned.protectedHeader.algorithm
                ?: throw IllegalArgumentException("Algorithm not specified")
            val publicKey = signer.toCryptoPublicKey().getOrElse { ex ->
                throw IllegalArgumentException("Signer not convertible", ex)
                    .also { Napier.w("Could not convert signer to public key: $signer", ex) }
            }
            verifySignature(
                signatureInput,
                coseSigned.signature,
                algorithm.algorithm,
                publicKey
            ).getOrThrow()
        }
    }
}

class DefaultVerifierCoseService(
    @Suppress("DEPRECATION") @Deprecated("Use verifySignature")
    private val cryptoService: VerifierCryptoService = DefaultVerifierCryptoService(),
    /** Need to implement if valid keys for CoseSigned are transported somehow out-of-band, e.g. provided by a trust store */
    private val publicKeyLookup: PublicCoseKeyLookup = { null },
    private val verifySignature: VerifySignatureFun = VerifySignature(),
    private val verifyCoseSignatureWithKey: VerifyCoseSignatureWithKeyFun<Any> = VerifyCoseSignatureWithKey<Any>(
        verifySignature
    ),
    private val verifyCoseSignature: VerifyCoseSignatureFun<Any> = VerifyCoseSignature<Any>(
        verifyCoseSignatureWithKey,
        publicKeyLookup
    ),
) : VerifierCoseService {

    /**
     * Verifiers the signature of [coseSigned] by using [signer].
     *
     * @param externalAad optional authenticated data
     * @param detachedPayload optional payload, if it has been transported seperately, and [coseSigned.payload] is null
     */
    override fun <P : Any> verifyCose(
        coseSigned: CoseSigned<P>,
        signer: CoseKey,
        externalAad: ByteArray,
        detachedPayload: ByteArray?,
    ) = verifyCoseSignatureWithKey(coseSigned as CoseSigned<Any>, signer, externalAad, detachedPayload)

    /**
     * Verifiers the signature of [coseSigned] by extracting the public key from it's headers,
     * or by using [publicKeyLookup].
     *
     * @param externalAad optional authenticated data
     * @param detachedPayload optional payload, if it has been transported seperately, and [coseSigned.payload] is null
     */
    override fun <P : Any> verifyCose(
        coseSigned: CoseSigned<P>,
        externalAad: ByteArray,
        detachedPayload: ByteArray?,
    ) = verifyCoseSignature(coseSigned as CoseSigned<Any>, externalAad, detachedPayload)

}

// TODO should be suspend
typealias PublicCoseKeyLookup = (CoseSigned<*>) -> Set<CoseKey>?

/**
 * Tries to compute a public key in order from [coseKey], [kid] or
 * [certificateChain], and takes the first success or null.
 */
val CoseHeader.publicKey: CoseKey?
    get() = kid?.let { CoseKey.fromDid(it.decodeToString()) }?.getOrNull()
        ?: certificateChain?.firstOrNull()?.let {
            runCatching {
                X509Certificate.decodeFromDer(it)
            }.getOrNull()?.publicKey?.toCoseKey()?.getOrThrow()
        }
