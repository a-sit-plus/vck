package at.asitplus.wallet.lib.cbor

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.signum.supreme.mac.mac
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.VerifyMac
import at.asitplus.wallet.lib.agent.VerifyMacFun
import at.asitplus.wallet.lib.agent.VerifySignature
import at.asitplus.wallet.lib.agent.VerifySignatureFun
import at.asitplus.wallet.lib.cbor.CoseUtils.calcMac
import at.asitplus.wallet.lib.cbor.CoseUtils.calcSignature
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.encodeToByteArray

/** How to identify the key material in a [CoseHeader] */
fun interface CoseHeaderIdentifierFun<T> {
    suspend operator fun invoke(
        it: CoseHeader?,
        keyMaterial: T,
    ): CoseHeader?
}

/** Don't identify [KeyMaterial] in [CoseHeader]. */
class CoseHeaderNone<T> : CoseHeaderIdentifierFun<T> {
    override suspend fun invoke(
        it: CoseHeader?,
        keyMaterial: T,
    ): CoseHeader? = it
}

/** Identify [KeyMaterial] with it's [KeyMaterial.identifier] in (protected) [CoseHeader.keyId]. */
class CoseHeaderKeyIdForKeyMaterial : CoseHeaderIdentifierFun<KeyMaterial> {
    override suspend operator fun invoke(
        it: CoseHeader?,
        keyMaterial: KeyMaterial,
    ): CoseHeader? = it?.copy(kid = keyMaterial.identifier.encodeToByteArray())
}

class CoseHeaderKeyIdForCoseKey : CoseHeaderIdentifierFun<CoseKey> {
    override suspend operator fun invoke(
        it: CoseHeader?,
        keyMaterial: CoseKey,
    ): CoseHeader? = it?.copy(kid = keyMaterial.keyId)
}

/** Identify [KeyMaterial] with it's [KeyMaterial.getCertificate] in (unprotected) [CoseHeader.certificateChain]. */
class CoseHeaderCertificate : CoseHeaderIdentifierFun<KeyMaterial> {
    override suspend operator fun invoke(
        it: CoseHeader?,
        keyMaterial: KeyMaterial,
    ) = it?.copy(certificateChain = keyMaterial.getCertificate()?.let { listOf(it.encodeToDer()) })
}

fun interface SignCoseFun<P> {
    suspend operator fun invoke(
        protectedHeader: CoseHeader?,
        unprotectedHeader: CoseHeader?,
        payload: P?,
        serializer: KSerializer<P>,
    ): KmmResult<CoseSigned<P>>
}

/** Create a [CoseSigned], setting protected and unprotected headers, and applying [CoseHeaderIdentifierFun]. */
class SignCose<P : Any>(
    val keyMaterial: KeyMaterial,
    val protectedHeaderModifier: CoseHeaderIdentifierFun<KeyMaterial>? = null,
    val unprotectedHeaderModifier: CoseHeaderIdentifierFun<KeyMaterial>? = null,
) : SignCoseFun<P> {
    override suspend operator fun invoke(
        protectedHeader: CoseHeader?,
        unprotectedHeader: CoseHeader?,
        payload: P?,
        serializer: KSerializer<P>,
    ): KmmResult<CoseSigned<P>> = catching {
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

fun interface MacCoseFun<P> {
    suspend operator fun invoke(
        protectedHeader: CoseHeader?,
        unprotectedHeader: CoseHeader?,
        payload: P?,
        serializer: KSerializer<P>,
    ): KmmResult<CoseMac<P>>
}

class MacCose<P : Any>(
    val keyMaterial: CoseKey,
    val protectedHeaderModifier: CoseHeaderIdentifierFun<CoseKey>? = null,
    val unprotectedHeaderModifier: CoseHeaderIdentifierFun<CoseKey>? = null,
) : MacCoseFun<P> {
    override suspend fun invoke(
        protectedHeader: CoseHeader?,
        unprotectedHeader: CoseHeader?,
        payload: P?,
        serializer: KSerializer<P>
    ): KmmResult<CoseMac<P>> = catching {
        val algorithm = keyMaterial.algorithm
        val headerWithAlg = (protectedHeader ?: CoseHeader()).copy(algorithm = algorithm)
        val protectedHeader = protectedHeaderModifier?.invoke(headerWithAlg, keyMaterial) ?: headerWithAlg
        val unprotectedHeader = unprotectedHeaderModifier?.invoke(unprotectedHeader ?: CoseHeader(), keyMaterial)
            ?: unprotectedHeader
        calcMac(keyMaterial, protectedHeader, payload, serializer).let { mac ->
            CoseMac.create(
                protectedHeader = protectedHeader,
                unprotectedHeader = unprotectedHeader,
                payload = payload,
                tag = mac,
                payloadSerializer = serializer,
            )
        }
    }
}

fun interface SignCoseDetachedFun<P> {
    suspend operator fun invoke(
        protectedHeader: CoseHeader?,
        unprotectedHeader: CoseHeader?,
        payload: P?,
        serializer: KSerializer<P>,
    ): KmmResult<CoseSigned<P>>
}

/**
 * Create a [CoseSigned] with detached payload,
 * setting protected and unprotected headers, and applying [CoseHeaderIdentifierFun]. */
class SignCoseDetached<P : Any>(
    val keyMaterial: KeyMaterial,
    val protectedHeaderModifier: CoseHeaderIdentifierFun<KeyMaterial>? = null,
    val unprotectedHeaderModifier: CoseHeaderIdentifierFun<KeyMaterial>? = null,
) : SignCoseDetachedFun<P> {
    override suspend operator fun invoke(
        protectedHeader: CoseHeader?,
        unprotectedHeader: CoseHeader?,
        payload: P?,
        serializer: KSerializer<P>,
    ) = catching {
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

fun interface MacCoseDetachedFun<P> {
    suspend operator fun invoke(
        protectedHeader: CoseHeader?,
        unprotectedHeader: CoseHeader?,
        payload: P?,
        serializer: KSerializer<P>,
    ): KmmResult<CoseMac<P>>
}

class MacCoseDetached<P : Any>(
    val keyMaterial: CoseKey,
    val protectedHeaderModifier: CoseHeaderIdentifierFun<CoseKey>? = null,
    val unprotectedHeaderModifier: CoseHeaderIdentifierFun<CoseKey>? = null,
) : MacCoseDetachedFun<P> {
    override suspend fun invoke(
        protectedHeader: CoseHeader?,
        unprotectedHeader: CoseHeader?,
        payload: P?,
        serializer: KSerializer<P>
    ): KmmResult<CoseMac<P>> = catching {
        val algorithm = keyMaterial.algorithm
        val headerWithAlg = (protectedHeader ?: CoseHeader()).copy(algorithm = algorithm)
        val protectedHeader = protectedHeaderModifier?.invoke(headerWithAlg, keyMaterial) ?: headerWithAlg
        val unprotectedHeader = unprotectedHeaderModifier?.invoke(unprotectedHeader ?: CoseHeader(), keyMaterial)
            ?: unprotectedHeader
        calcMac(keyMaterial, protectedHeader, payload, serializer).let { mac ->
            CoseMac.create(
                protectedHeader = protectedHeader,
                unprotectedHeader = unprotectedHeader,
                payload = null,
                tag = mac,
                payloadSerializer = serializer,
            )
        }
    }
}

object CoseUtils {

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
            val serialized = coseCompliantSerializer.encodeToByteArray(signatureInput)
            Napier.d("COSE Signature input is ${serialized.encodeToString(Base16())}")
            keyMaterial.sign(serialized).asKmmResult().getOrElse {
                Napier.w("No signature from native code", it)
                throw it
            }
        }

    /**
     * @return payload to calculated MAC
     */
    @Throws(Throwable::class)
    suspend fun <P : Any> calcMac(
        keyMaterial: CoseKey,
        protectedHeader: CoseHeader,
        payload: P?,
        serializer: KSerializer<P>,
    ): ByteArray =
        CoseMac.prepare<P>(
            protectedHeader = protectedHeader,
            externalAad = byteArrayOf(),
            payload = payload,
            payloadSerializer = serializer
        ).let { macInput ->
            val serialized = coseCompliantSerializer.encodeToByteArray(macInput)
            Napier.d("COSE Mac input is ${serialized.encodeToString(Base16())}")
            val key = (keyMaterial.keyParams as CoseKeyParams.SymmKeyParams).k
            (keyMaterial.algorithm as CoseAlgorithm.MAC).algorithm.mac(key, serialized).getOrThrow()
        }

}

fun interface VerifyCoseSignatureFun<P> {
    suspend operator fun invoke(
        coseSigned: CoseSigned<P>,
        externalAad: ByteArray,
        detachedPayload: ByteArray?,
    ): KmmResult<Verifier.Success>
}

class VerifyCoseSignature<P : Any>(
    val verifyCoseSignature: VerifyCoseSignatureWithKeyFun<P> = VerifyCoseSignatureWithKey<P>(),
    /** Need to implement if valid keys for CoseSigned are transported somehow out-of-band, e.g. provided by a trust store */
    val publicKeyLookup: PublicCoseKeyLookup = PublicCoseKeyLookup { null },
) : VerifyCoseSignatureFun<P> {
    override suspend operator fun invoke(
        coseSigned: CoseSigned<P>,
        externalAad: ByteArray,
        detachedPayload: ByteArray?,
    ) = catching {
        coseSigned.loadPublicKeys().also {
            Napier.d("Public keys available: ${it.size}")
        }.firstNotNullOf { coseKey ->
            verifyCoseSignature(coseSigned, coseKey, externalAad, detachedPayload).getOrNull()
        }
    }

    suspend fun CoseSigned<*>.loadPublicKeys(): Set<CoseKey> =
        (protectedHeader.publicKey ?: unprotectedHeader?.publicKey)?.let { setOf(it) }
            ?: publicKeyLookup(this) ?: setOf()
}

fun interface VerifyCoseSignatureWithKeyFun<P> {
    suspend operator fun invoke(
        coseSigned: CoseSigned<P>,
        signer: CoseKey,
        externalAad: ByteArray,
        detachedPayload: ByteArray?,
    ): KmmResult<Verifier.Success>
}

class VerifyCoseSignatureWithKey<P : Any>(
    val verifySignature: VerifySignatureFun = VerifySignature(),
) : VerifyCoseSignatureWithKeyFun<P> {
    override suspend operator fun invoke(
        coseSigned: CoseSigned<P>,
        signer: CoseKey,
        externalAad: ByteArray,
        detachedPayload: ByteArray?,
    ) = catching {
        val signatureInput = coseSigned.prepareCoseSignatureInput(externalAad, detachedPayload)
            .also { Napier.d("verifyCose input is ${it.encodeToString(Base16())}") }
        val algorithm = coseSigned.protectedHeader.algorithm
            ?: throw IllegalArgumentException("Algorithm not specified")
        require(algorithm is CoseAlgorithm.Signature) { "CoseAlgorithm not supported: $algorithm" }
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

fun interface VerifyCoseMacWithKeyFun<P> {
    suspend operator fun invoke(
        coseMac: CoseMac<P>,
        coseKey: CoseKey,
        externalAad: ByteArray,
        detachedPayload: ByteArray?,
    ): KmmResult<VerifyMacFun.Success>
}

class VerifyCoseMacWithKey<P : Any>(
    val verifyMac: VerifyMacFun = VerifyMac(),
) : VerifyCoseMacWithKeyFun<P> {
    override suspend fun invoke(
        coseMac: CoseMac<P>,
        coseKey: CoseKey,
        externalAad: ByteArray,
        detachedPayload: ByteArray?
    ) = catching {
        val macInput = coseMac.prepareCoseMacInput(externalAad, detachedPayload)
            .also { Napier.d("verifyCose input is ${it.encodeToString(Base16())}") }
        val algorithm = coseMac.protectedHeader.algorithm
            ?: throw IllegalArgumentException("Algorithm not specified")
        require(algorithm is CoseAlgorithm.MAC) { "CoseAlgorithm not supported: ${algorithm}" }
        val key = (coseKey.keyParams as CoseKeyParams.SymmKeyParams).k
        verifyMac(
            macInput,
            coseMac.tag,
            algorithm.algorithm,
            key
        ).getOrThrow()
    }

}

fun interface PublicCoseKeyLookup {
    suspend operator fun invoke(
        coseSigned: CoseSigned<*>,
    ): Set<CoseKey>?
}

/**
 * Tries to compute a public key in order from [coseKey], [kid] or
 * [certificateChain], and takes the first success or null.
 */
val CoseHeader.publicKey: CoseKey?
    get() = kid?.let { CoseKey.fromDid(it.decodeToString()) }?.getOrNull()
        ?: certificateChain?.firstOrNull()?.let {
            catchingUnwrapped {
                X509Certificate.decodeFromDer(it)
            }.getOrNull()?.decodedPublicKey?.getOrNull()?.toCoseKey()?.getOrThrow()
        }


