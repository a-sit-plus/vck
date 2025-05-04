package at.asitplus.wallet.lib.cbor

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.VerifySignature
import at.asitplus.wallet.lib.agent.VerifySignatureFun
import at.asitplus.wallet.lib.cbor.CoseUtils.calcSignature
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlin.byteArrayOf

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
