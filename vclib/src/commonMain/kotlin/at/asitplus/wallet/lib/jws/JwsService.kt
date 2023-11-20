package at.asitplus.wallet.lib.jws

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.JwsAlgorithm
import at.asitplus.crypto.datatypes.asn1.encodeTo4Bytes
import at.asitplus.crypto.datatypes.jws.*
import at.asitplus.crypto.datatypes.jws.JwsExtensions.prependWith4BytesSize
import at.asitplus.crypto.datatypes.jws.JwsExtensions.extractSignatureValues
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultVerifierCryptoService
import at.asitplus.wallet.lib.agent.VerifierCryptoService
import at.asitplus.wallet.lib.data.Base64Strict
import at.asitplus.wallet.lib.data.Base64UrlStrict
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.random.Random

/**
 * Creates and parses JWS and JWE objects.
 */
interface JwsService {

    suspend fun createSignedJwt(
        type: String,
        payload: ByteArray,
        contentType: String? = null
    ): String?

    suspend fun createSignedJws(header: JwsHeader, payload: ByteArray): String?

    /**
     * Appends correct values for [JweHeader.keyId], [JwsHeader.algorithm] and [JwsHeader.jsonWebKey],
     * if the corresponding options are set
     */
    suspend fun createSignedJwsAddingParams(
        header: JwsHeader,
        payload: ByteArray,
        addKeyId: Boolean = true,
        addJsonWebKey: Boolean = true
    ): String?

    fun encryptJweObject(
        type: String,
        payload: ByteArray,
        recipientKey: JsonWebKey,
        contentType: String? = null,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption
    ): String?

    suspend fun decryptJweObject(jweObject: JweEncrypted, serialized: String): JweDecrypted?

}

interface VerifierJwsService {

    fun verifyJwsObject(jwsObject: JwsSigned, serialized: String? = null): Boolean

    fun verifyJws(jwsObject: JwsSigned, signer: JsonWebKey): Boolean

}

class DefaultJwsService(private val cryptoService: CryptoService) : JwsService {

    override suspend fun createSignedJwt(
        type: String,
        payload: ByteArray,
        contentType: String?
    ): String? {
        val jwsHeader = JwsHeader(
            algorithm = cryptoService.jwsAlgorithm,
            keyId = cryptoService.toPublicKey().keyId,
            type = type,
            contentType = contentType
        )
        return createSignedJws(jwsHeader, payload)
    }

    override suspend fun createSignedJws(header: JwsHeader, payload: ByteArray): String? {
        if (header.algorithm != cryptoService.jwsAlgorithm
            || header.keyId?.let { it != cryptoService.toPublicKey().keyId } == true
            || header.jsonWebKey?.let { it != cryptoService.toJsonWebKey() } == true
        ) {
            return null.also { Napier.w("Algorithm or keyId not matching to cryptoService") }
        }
        val signatureInput = header.serialize().encodeToByteArray().encodeToString(Base64UrlStrict) +
                "." + payload.encodeToString(Base64UrlStrict)
        val signatureInputBytes = signatureInput.encodeToByteArray()
        val signature = cryptoService.sign(signatureInputBytes).getOrElse {
            Napier.w("No signature from native code", it)
            return null
        }
        val rawSignature = when (cryptoService.jwsAlgorithm) {
            JwsAlgorithm.ES256, JwsAlgorithm.ES384, JwsAlgorithm.ES512 -> signature.extractSignatureValues(
                (cryptoService.toPublicKey() as CryptoPublicKey.Ec).curve.signatureLengthBytes / 2u
            )
            else -> signature
        }
        return JwsSigned(header, payload, rawSignature, signatureInput).serialize()
    }

    override suspend fun createSignedJwsAddingParams(
        header: JwsHeader,
        payload: ByteArray,
        addKeyId: Boolean,
        addJsonWebKey: Boolean
    ): String? {
        var copy = header.copy(algorithm = cryptoService.jwsAlgorithm)
        if (addKeyId)
            copy = copy.copy(keyId = cryptoService.toPublicKey().keyId)
        if (addJsonWebKey)
            copy = copy.copy(jsonWebKey = cryptoService.toPublicKey().toJsonWebKey().getOrNull()!!)
        return createSignedJws(copy, payload)
    }

    override suspend fun decryptJweObject(
        jweObject: JweEncrypted,
        serialized: String
    ): JweDecrypted? {
        val header = jweObject.header ?: return null
            .also { Napier.w("Could not parse JWE header") }
        val alg = header.algorithm ?: return null.also { Napier.w("No algorithm in JWE header") }
        val enc = header.encryption ?: return null.also { Napier.w("No encryption in JWE header") }
        val z = cryptoService.performKeyAgreement(header.ephemeralKeyPair!!, alg)
            .getOrElse {
                Napier.w("No Z value from native code", it)
                return null
            }
        val kdfInput = prependWithAdditionalInfo(
            z,
            enc,
            header.agreementPartyUInfo,
            header.agreementPartyVInfo
        )
        val key = cryptoService.messageDigest(kdfInput, Digest.SHA256).getOrElse {
            Napier.w("No digest from native code", it)
            return null
        }
        val iv = jweObject.iv
        val aad = jweObject.headerAsParsed.encodeToByteArray(Base64UrlStrict)
        val ciphertext = jweObject.ciphertext
        val authTag = jweObject.authTag
        val plaintext =
            cryptoService.decrypt(key, iv, aad, ciphertext, authTag, enc).getOrElse {
                Napier.w("No plaintext from native code", it)
                return null
            }
        return JweDecrypted(header, plaintext)
    }

    override fun encryptJweObject(
        type: String,
        payload: ByteArray,
        recipientKey: JsonWebKey,
        contentType: String?,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption
    ): String? {
        val crv = recipientKey.curve
            ?: return null.also { Napier.w("No curve in recipient key") }
        val ephemeralKeyPair =
            cryptoService.generateEphemeralKeyPair(crv).getOrElse {
                Napier.w("No ephemeral key pair from native code", it)
                return null
            }
        val jweHeader = JweHeader(
            algorithm = jweAlgorithm,
            encryption = jweEncryption,
            jsonWebKey = cryptoService.toJsonWebKey(),
            type = type,
            contentType = contentType,
            ephemeralKeyPair = ephemeralKeyPair.toPublicJsonWebKey()
        )
        val z = cryptoService.performKeyAgreement(ephemeralKeyPair, recipientKey, jweAlgorithm)
            .getOrElse {
                Napier.w("No Z value from native code", it)
                return null
            }
        val kdf = prependWithAdditionalInfo(z, jweEncryption, null, null)
        val key = cryptoService.messageDigest(kdf, Digest.SHA256).getOrElse {
            Napier.w("No digest from native code", it)
            return null
        }
        val iv = Random.Default.nextBytes(jweEncryption.ivLengthBits / 8)
        val headerSerialized = jweHeader.serialize()
        val aad = headerSerialized.encodeToByteArray()
        val aadForCipher = aad.encodeToByteArray(Base64UrlStrict)
        val ciphertext =
            cryptoService.encrypt(key, iv, aadForCipher, payload, jweEncryption).getOrElse {
                Napier.w("No ciphertext from native code", it)
                return null
            }
        return JweEncrypted(aad, null, iv, ciphertext.ciphertext, ciphertext.authtag).serialize()
    }

    private fun prependWithAdditionalInfo(
        z: ByteArray,
        jweEncryption: JweEncryption,
        apu: ByteArray?,
        apv: ByteArray?
    ): ByteArray {
        val counterValue = 1.encodeTo4Bytes() // it depends ...
        val algId = jweEncryption.text.encodeToByteArray().prependWith4BytesSize()
        val apuEncoded = apu?.prependWith4BytesSize() ?: 0.encodeTo4Bytes()
        val apvEncoded = apv?.prependWith4BytesSize() ?: 0.encodeTo4Bytes()
        val keyLength = jweEncryption.encryptionKeyLength.encodeTo4Bytes()
        val otherInfo = algId + apuEncoded + apvEncoded + keyLength + byteArrayOf()
        return counterValue + z + otherInfo
    }

}

class DefaultVerifierJwsService(
    private val cryptoService: VerifierCryptoService = DefaultVerifierCryptoService()
) : VerifierJwsService {

    /**
     * Verifies the signature of [jwsObject], by extracting the public key from [JwsHeader.keyId] (`kid`),
     * or from [JwsHeader.jsonWebKey] (`jwk`), or from [JwsHeader.certificateChain] (`x5c`).
     */
    override fun verifyJwsObject(jwsObject: JwsSigned, serialized: String?): Boolean {
        val header = jwsObject.header
//        val publicKey = header.jsonKey?.toCryptoPublicKey()?.getOrNull()
//            ?: return false
//                .also { Napier.w("Could not extract PublicKey from header: $header") }
        val publicKey = header.publicKey
            ?: return false
                .also { Napier.w("Could not extract PublicKey from header: $header") }
        val verified = cryptoService.verify(
            input = jwsObject.plainSignatureInput.encodeToByteArray(),
            signature = jwsObject.signature,
            algorithm = header.algorithm,
            publicKey = publicKey,
        )
        val falseVar = false //workaround kotlin bug for linking xcframework
        return verified.getOrElse {
            Napier.w("No verification from native code")
            falseVar
        }
    }

    /**
     * Verifiers the signature of [jwsObject] by using [signer].
     */
    override fun verifyJws(jwsObject: JwsSigned, signer: JsonWebKey): Boolean {
        val publicKey = signer.toCryptoPublicKey().getOrNull()
            ?: return false
                .also { Napier.w("Could not convert signer to public key: $signer") }
        val verified = cryptoService.verify(
            jwsObject.plainSignatureInput.encodeToByteArray(),
            jwsObject.signature,
            jwsObject.header.algorithm,
            publicKey,
        )
        val falseVar = false //workaround kotlin bug for linking xcframework
        return verified.getOrElse {
            Napier.w("No verification from native code")
            return falseVar
        }
    }

}



