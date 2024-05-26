package at.asitplus.wallet.lib.jws

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.asn1.encodeTo4Bytes
import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.crypto.datatypes.jws.JsonWebKey
import at.asitplus.crypto.datatypes.jws.JsonWebKeySet
import at.asitplus.crypto.datatypes.jws.JweAlgorithm
import at.asitplus.crypto.datatypes.jws.JweDecrypted
import at.asitplus.crypto.datatypes.jws.JweEncrypted
import at.asitplus.crypto.datatypes.jws.JweEncryption
import at.asitplus.crypto.datatypes.jws.JweHeader
import at.asitplus.crypto.datatypes.jws.JwsAlgorithm
import at.asitplus.crypto.datatypes.jws.JwsExtensions.prependWith4BytesSize
import at.asitplus.crypto.datatypes.jws.JwsHeader
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.JwsSigned.Companion.prepareJwsSignatureInput
import at.asitplus.crypto.datatypes.jws.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultVerifierCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyHolder
import at.asitplus.wallet.lib.agent.VerifierCryptoService
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToByteArray
import kotlin.random.Random

/**
 * Creates and parses JWS and JWE objects.
 */
interface JwsService {

    /**
     * Algorithm which will be used to sign JWS in [createSignedJws], [createSignedJwt], [createSignedJwsAddingParams].
     */
    val algorithm: JwsAlgorithm

    /**
     * Algorithm which can be used to encrypt JWE, that can be decrypted with [decryptJweObject].
     */
    val encryptionAlgorithm: JweAlgorithm

    /**
     * Encoding which can be used to encrypt JWE, that can be decrypted with [decryptJweObject].
     */
    val encryptionEncoding: JweEncryption

    suspend fun createSignedJwt(
        type: String,
        payload: ByteArray,
        contentType: String? = null
    ): KmmResult<JwsSigned>

    suspend fun createSignedJws(header: JwsHeader, payload: ByteArray): KmmResult<JwsSigned>

    /**
     * Appends correct values for  [JwsHeader.algorithm],
     * [JweHeader.keyId] (if `addKeyId` is `true`),
     * and [JwsHeader.jsonWebKey] (if `addJsonWebKey` is `true`).
     */
    suspend fun createSignedJwsAddingParams(
        header: JwsHeader? = null,
        payload: ByteArray,
        addKeyId: Boolean = true,
        addJsonWebKey: Boolean = true,
        addX5c: Boolean = false
    ): KmmResult<JwsSigned>

    suspend fun encryptJweObject(
        header: JweHeader? = null,
        payload: ByteArray,
        recipientKey: JsonWebKey,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption
    ): KmmResult<JweEncrypted>

    fun encryptJweObject(
        type: String,
        payload: ByteArray,
        recipientKey: JsonWebKey,
        contentType: String? = null,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption
    ): KmmResult<JweEncrypted>

    suspend fun decryptJweObject(jweObject: JweEncrypted, serialized: String): KmmResult<JweDecrypted>

}

interface VerifierJwsService {

    val supportedAlgorithms: List<JwsAlgorithm>

    fun verifyJwsObject(jwsObject: JwsSigned): Boolean

    fun verifyJws(jwsObject: JwsSigned, signer: JsonWebKey): Boolean

}

class DefaultJwsService(private val cryptoService: CryptoService) : JwsService {

    override val algorithm: JwsAlgorithm = cryptoService.algorithm.toJwsAlgorithm()

    // TODO: Get from crypto service
    override val encryptionAlgorithm: JweAlgorithm = JweAlgorithm.ECDH_ES

    // TODO: Get from crypto service
    override val encryptionEncoding: JweEncryption = JweEncryption.A256GCM

    override suspend fun createSignedJwt(
        type: String,
        payload: ByteArray,
        contentType: String?
    ): KmmResult<JwsSigned> = createSignedJws(
        JwsHeader(
            algorithm = cryptoService.algorithm.toJwsAlgorithm(),
            keyId = cryptoService.publicKey.didEncoded,
            type = type,
            contentType = contentType
        ), payload
    )

    override suspend fun createSignedJws(header: JwsHeader, payload: ByteArray): KmmResult<JwsSigned> {
        if (header.algorithm != cryptoService.algorithm.toJwsAlgorithm()
            || header.jsonWebKey?.let { it != cryptoService.jsonWebKey } == true
        ) {
            return KmmResult.failure(IllegalArgumentException("Algorithm or JSON Web Key not matching to cryptoService"))
        }

        val plainSignatureInput = prepareJwsSignatureInput(header, payload)
        val signature = cryptoService.sign(plainSignatureInput.encodeToByteArray()).getOrElse {
            Napier.w("No signature from native code", it)
            return KmmResult.failure(it)
        }
        return KmmResult.success(JwsSigned(header, payload, signature, plainSignatureInput))
    }

    override suspend fun createSignedJwsAddingParams(
        header: JwsHeader?,
        payload: ByteArray,
        addKeyId: Boolean,
        addJsonWebKey: Boolean,
        addX5c: Boolean
    ): KmmResult<JwsSigned> {
        var copy = header?.copy(algorithm = cryptoService.algorithm.toJwsAlgorithm())
            ?: JwsHeader(algorithm = cryptoService.algorithm.toJwsAlgorithm())
        if (addKeyId)
            copy = copy.copy(keyId = cryptoService.jsonWebKey.keyId)
        if (addJsonWebKey)
            copy = copy.copy(jsonWebKey = cryptoService.jsonWebKey)
        if (addX5c)
            copy = copy.copy(certificateChain = listOf(cryptoService!!.certificate!!)) //TODO cleanup/nullchecks
        return createSignedJws(copy, payload)
    }

    override suspend fun decryptJweObject(
        jweObject: JweEncrypted,
        serialized: String
    ): KmmResult<JweDecrypted> {
        val header = jweObject.header
            ?: return KmmResult.failure(IllegalArgumentException("Could not parse JWE header"))
        val alg = header.algorithm
            ?: return KmmResult.failure(IllegalArgumentException("No algorithm in JWE header"))
        val enc = header.encryption
            ?: return KmmResult.failure(IllegalArgumentException("No encryption in JWE header"))
        val epk = header.ephemeralKeyPair
            ?: return KmmResult.failure(IllegalArgumentException("No epk in JWE header"))
        val z = cryptoService.performKeyAgreement(epk, alg).getOrElse {
            Napier.w("No Z value from native code", it)
            return KmmResult.failure(it)
        }
        val kdfInput = prependWithAdditionalInfo(z, enc, header.agreementPartyUInfo, header.agreementPartyVInfo)
        val key = cryptoService.messageDigest(kdfInput, Digest.SHA256).getOrElse {
            Napier.w("No digest from native code", it)
            return KmmResult.failure(it)
        }
        val iv = jweObject.iv
        val aad = jweObject.headerAsParsed.encodeToByteArray(Base64UrlStrict)
        val ciphertext = jweObject.ciphertext
        val authTag = jweObject.authTag
        val plaintext = cryptoService.decrypt(key, iv, aad, ciphertext, authTag, enc).getOrElse {
            Napier.w("No plaintext from native code", it)
            return KmmResult.failure(it)
        }
        return KmmResult.success(JweDecrypted(header, plaintext))
    }

    override suspend fun encryptJweObject(
        header: JweHeader?,
        payload: ByteArray,
        recipientKey: JsonWebKey,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption,
    ): KmmResult<JweEncrypted> {
        val crv = recipientKey.curve
            ?: return KmmResult.failure(IllegalArgumentException("No curve in recipient key"))
        val ephemeralKeyPair = cryptoService.generateEphemeralKeyPair(crv).getOrElse {
            Napier.w("No ephemeral key pair from native code", it)
            return KmmResult.failure(it)
        }
        val jweHeader = (header ?: JweHeader(jweAlgorithm, jweEncryption, type = null)).copy(
            algorithm = jweAlgorithm,
            encryption = jweEncryption,
            jsonWebKey = cryptoService.jsonWebKey,
            ephemeralKeyPair = ephemeralKeyPair.publicJsonWebKey
        )
        return encryptJwe(ephemeralKeyPair, recipientKey, jweAlgorithm, jweEncryption, jweHeader, payload)
    }

    override fun encryptJweObject(
        type: String,
        payload: ByteArray,
        recipientKey: JsonWebKey,
        contentType: String?,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption
    ): KmmResult<JweEncrypted> {
        val crv = recipientKey.curve
            ?: return KmmResult.failure(IllegalArgumentException("No curve in recipient key"))
        val ephemeralKeyPair = cryptoService.generateEphemeralKeyPair(crv).getOrElse {
            Napier.w("No ephemeral key pair from native code", it)
            return KmmResult.failure(it)
        }
        val jweHeader = JweHeader(
            algorithm = jweAlgorithm,
            encryption = jweEncryption,
            jsonWebKey = cryptoService.jsonWebKey,
            type = type,
            contentType = contentType,
            ephemeralKeyPair = ephemeralKeyPair.publicJsonWebKey
        )
        return encryptJwe(ephemeralKeyPair, recipientKey, jweAlgorithm, jweEncryption, jweHeader, payload)
    }

    private fun encryptJwe(
        ephemeralKeyPair: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption,
        jweHeader: JweHeader,
        payload: ByteArray
    ): KmmResult<JweEncrypted> {
        val z = cryptoService.performKeyAgreement(ephemeralKeyPair, recipientKey, jweAlgorithm).getOrElse {
            Napier.w("No Z value from native code", it)
            return KmmResult.failure(it)
        }
        val kdf =
            prependWithAdditionalInfo(z, jweEncryption, jweHeader.agreementPartyUInfo, jweHeader.agreementPartyVInfo)
        val key = cryptoService.messageDigest(kdf, Digest.SHA256).getOrElse {
            Napier.w("No digest from native code", it)
            return KmmResult.failure(it)
        }
        val iv = Random.nextBytes(jweEncryption.ivLengthBits / 8)
        val headerSerialized = jweHeader.serialize()
        val aad = headerSerialized.encodeToByteArray()
        val aadForCipher = aad.encodeToByteArray(Base64UrlStrict)
        val ciphertext = cryptoService.encrypt(key, iv, aadForCipher, payload, jweEncryption).getOrElse {
            Napier.w("No ciphertext from native code", it)
            return KmmResult.failure(it)
        }
        return KmmResult.success(JweEncrypted(jweHeader, aad, null, iv, ciphertext.ciphertext, ciphertext.authtag))
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
/**
 * Clients need to retrieve the URL passed in as the only argument, and parse the content to [JsonWebKeySet].
 */
typealias JwkSetRetrieverFunction = (String) -> JsonWebKeySet?

class DefaultVerifierJwsService(
    private val cryptoService: VerifierCryptoService = DefaultVerifierCryptoService(),
    /**
     * Need to implement if JSON web keys in JWS headers are referenced by a `kid`, and need to be retrieved from
     * the `jku`.
     */
    private val jwkSetRetriever: JwkSetRetrieverFunction = { null },
) : VerifierJwsService {

    override val supportedAlgorithms: List<JwsAlgorithm> = cryptoService.supportedAlgorithms.map { it.toJwsAlgorithm() }

    /**
     * Verifies the signature of [jwsObject], by extracting the public key from [JwsHeader.publicKey],
     * or by using [jwkSetRetriever] if [JwsHeader.jsonWebKeySetUrl] is set.
     */
    override fun verifyJwsObject(jwsObject: JwsSigned): Boolean {
        val header = jwsObject.header
        val publicKey = header.publicKey
            ?: header.jsonWebKeySetUrl?.let { jku -> retrieveJwkFromKeySetUrl(jku, header) }
            ?: return false
                .also { Napier.w("Could not extract PublicKey from header: $header") }
        return verify(jwsObject, publicKey)
    }

    private fun retrieveJwkFromKeySetUrl(jku: String, header: JwsHeader) =
        jwkSetRetriever(jku)?.keys?.firstOrNull { it.keyId == header.keyId }?.toCryptoPublicKey()?.getOrNull()

    /**
     * Verifiers the signature of [jwsObject] by using [signer].
     */
    override fun verifyJws(jwsObject: JwsSigned, signer: JsonWebKey): Boolean {
        val publicKey = signer.toCryptoPublicKey().getOrNull()
            ?: return false
                .also { Napier.w("Could not convert signer to public key: $signer") }
        return verify(jwsObject, publicKey)
    }

    private fun verify(jwsObject: JwsSigned, publicKey: CryptoPublicKey): Boolean {
        val verified = cryptoService.verify(
            input = jwsObject.plainSignatureInput.encodeToByteArray(),
            signature = jwsObject.signature,
            algorithm = jwsObject.header.algorithm.toCryptoAlgorithm(),
            publicKey = publicKey,
        )
        val falseVar = false // workaround kotlin bug for linking xcframework
        return verified.getOrElse {
            Napier.w("No verification from native code", it)
            return falseVar
        }
    }
}



