package at.asitplus.wallet.lib.jws

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultVerifierCryptoService
import at.asitplus.wallet.lib.agent.Digest
import at.asitplus.wallet.lib.agent.VerifierCryptoService
import at.asitplus.wallet.lib.jws.JwsExtensions.encodeToByteArray
import at.asitplus.wallet.lib.jws.JwsExtensions.encodeWithLength
import at.asitplus.wallet.lib.jws.JwsExtensions.extractSignatureValues
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.random.Random

/**
 * Creates and parses JWS and JWE objects.
 */
interface JwsService {

    suspend fun createSignedJwt(
        type: JwsContentType,
        payload: ByteArray,
        contentType: JwsContentType? = null
    ): String?

    suspend fun createSignedJws(header: JwsHeader, payload: ByteArray): String?

    /**
     * Appends correct values for [JweHeader.keyId], [JwsHeader.algorithm] and [JwsHeader.jsonWebKey]
     */
    suspend fun createSignedJwsAddingParams(header: JwsHeader, payload: ByteArray): String?

    fun encryptJweObject(
        type: JwsContentType,
        payload: ByteArray,
        recipientKey: JsonWebKey,
        contentType: JwsContentType? = null,
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
        type: JwsContentType,
        payload: ByteArray,
        contentType: JwsContentType?
    ): String? {
        val jwsHeader =
            JwsHeader(cryptoService.jwsAlgorithm, cryptoService.keyId, type, contentType)
        return createSignedJws(jwsHeader, payload)
    }

    override suspend fun createSignedJws(header: JwsHeader, payload: ByteArray): String? {
        if (header.algorithm != cryptoService.jwsAlgorithm || header.keyId?.let { it != cryptoService.keyId } == true) {
            return null.also { Napier.w("Algorithm or keyId not matching to cryptoService") }
        }
        val signatureInput = header.serialize().encodeToByteArray()
            .encodeToString(Base64UrlNoPad) + "." + payload.encodeToString(Base64UrlNoPad)
        val signatureInputBytes = signatureInput.encodeToByteArray()
        val signature = cryptoService.sign(signatureInputBytes).getOrElse {
            Napier.w("No signature from native code", it)
            return null
        }
        val rawSignature = signature.extractSignatureValues(header.algorithm.signatureValueLength)
        return JwsSigned(header, payload, rawSignature, signatureInput).serialize()
    }

    override suspend fun createSignedJwsAddingParams(header: JwsHeader, payload: ByteArray): String? {
        val copy = header.copy(
            algorithm = cryptoService.jwsAlgorithm,
            keyId = cryptoService.keyId,
            jsonWebKey = cryptoService.toJsonWebKey()
        )
        return createSignedJws(copy, payload)
    }

    override suspend fun decryptJweObject(
        jweObject: JweEncrypted,
        serialized: String
    ): JweDecrypted? {
        val header = jweObject.header ?: return null
            .also { Napier.w("Could not parse JWE header") }
        if (header.algorithm == null) return null.also { Napier.w("No algorithm in JWE header") }
        if (header.encryption == null) return null.also { Napier.w("No encryption in JWE header") }
        val z = cryptoService.performKeyAgreement(header.ephemeralKeyPair!!, header.algorithm)
            .getOrElse {
                Napier.w("No Z value from native code", it)
                return null
            }
        val kdfInput =
            prependWithAdditionalInfo(
                z,
                header.encryption,
                header.agreementPartyUInfo,
                header.agreementPartyVInfo
            )
        val key = cryptoService.messageDigest(kdfInput, Digest.SHA256).getOrElse {
            Napier.w("No digest from native code", it)
            return null
        }
        val iv = jweObject.iv
        val aad = jweObject.headerAsParsed.encodeToByteArray(Base64UrlNoPad)
        val ciphertext = jweObject.ciphertext
        val authTag = jweObject.authTag
        val plaintext =
            cryptoService.decrypt(key, iv, aad, ciphertext, authTag, header.encryption).getOrElse {
                Napier.w("No plaintext from native code", it)
                return null
            }
        return JweDecrypted(header, plaintext)
    }

    override fun encryptJweObject(
        type: JwsContentType,
        payload: ByteArray,
        recipientKey: JsonWebKey,
        contentType: JwsContentType?,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption
    ): String? {
        if (recipientKey.curve == null)
            return null.also { Napier.w("No curve in recipient key") }
        val ephemeralKeyPair =
            cryptoService.generateEphemeralKeyPair(recipientKey.curve).getOrElse {
                Napier.w("No ephemeral key pair from native code", it)
                return null
            }
        val jweHeader = JweHeader(
            algorithm = jweAlgorithm,
            encryption = jweEncryption,
            keyId = cryptoService.keyId,
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
        val aadForCipher = aad.encodeToByteArray(Base64UrlNoPad)
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
        val counterValue = 1.encodeToByteArray() // it depends ...
        val algId = jweEncryption.text.encodeToByteArray().encodeWithLength()
        val apuEncoded = apu.encodeWithLength()
        val apvEncoded = apv.encodeWithLength()
        val keyLength = jweEncryption.encryptionKeyLength.encodeToByteArray()
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
        val publicKey = header.keyId?.let { JsonWebKey.fromKeyId(it) }
            ?: header.jsonWebKey
            ?: header.certificateChain?.first()?.let { cryptoService.extractPublicKeyFromX509Cert(it) }
            ?: return false
                .also { Napier.w("Could not extract PublicKey from header: $header") }
        val verified = cryptoService.verify(
            jwsObject.plainSignatureInput.encodeToByteArray(),
            jwsObject.signature,
            header.algorithm,
            publicKey
        )
        return verified.getOrElse {
            Napier.w("No verification from native code")
            false
        }
    }

    /**
     * Verifiers the signature of [jwsObject] by using [signer].
     */
    override fun verifyJws(jwsObject: JwsSigned, signer: JsonWebKey): Boolean {
        val verified = cryptoService.verify(
            jwsObject.plainSignatureInput.encodeToByteArray(),
            jwsObject.signature,
            jwsObject.header.algorithm,
            signer
        )
        return verified.getOrElse {
            Napier.w("No verification from native code")
            return false
        }
    }

}



