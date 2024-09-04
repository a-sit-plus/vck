package at.asitplus.wallet.lib.jws

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.encodeTo4Bytes
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweDecrypted
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsExtensions.prependWith4BytesSize
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.JwsSigned.Companion.prepareJwsSignatureInput
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.asKmmResult
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

    suspend fun decryptJweObject(
        jweObject: JweEncrypted,
        serialized: String
    ): KmmResult<JweDecrypted>

}

interface VerifierJwsService {

    val supportedAlgorithms: List<JwsAlgorithm>

    fun verifyJwsObject(jwsObject: JwsSigned): Boolean

    fun verifyJws(jwsObject: JwsSigned, signer: JsonWebKey): Boolean

}

class DefaultJwsService(private val cryptoService: CryptoService) : JwsService {

    override val algorithm: JwsAlgorithm =
        cryptoService.keyWithCert.signatureAlgorithm.toJwsAlgorithm().getOrThrow()

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
            algorithm = cryptoService.keyWithCert.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
            keyId = cryptoService.keyWithCert.publicKey.didEncoded,
            type = type,
            contentType = contentType
        ), payload
    )

    override suspend fun createSignedJws(header: JwsHeader, payload: ByteArray) = catching {
        if (header.algorithm != cryptoService.keyWithCert.signatureAlgorithm.toJwsAlgorithm()
                .getOrThrow()
            || header.jsonWebKey?.let { it != cryptoService.keyWithCert.jsonWebKey } == true
        ) {
            throw IllegalArgumentException("Algorithm or JSON Web Key not matching to cryptoService")
        }

        val plainSignatureInput = prepareJwsSignatureInput(header, payload)
        val signature =
            cryptoService.sign(plainSignatureInput.encodeToByteArray()).asKmmResult().getOrThrow()
        JwsSigned(header, payload, signature, plainSignatureInput)
    }

    override suspend fun createSignedJwsAddingParams(
        header: JwsHeader?,
        payload: ByteArray,
        addKeyId: Boolean,
        addJsonWebKey: Boolean,
        addX5c: Boolean
    ): KmmResult<JwsSigned> = catching {
        var copy = header?.copy(
            algorithm = cryptoService.keyWithCert.signatureAlgorithm.toJwsAlgorithm().getOrThrow()
        )
            ?: JwsHeader(
                algorithm = cryptoService.keyWithCert.signatureAlgorithm.toJwsAlgorithm()
                    .getOrThrow()
            )
        if (addKeyId)
            copy = copy.copy(keyId = cryptoService.keyWithCert.jsonWebKey.keyId)
        if (addJsonWebKey)
            copy = copy.copy(jsonWebKey = cryptoService.keyWithCert.jsonWebKey)
        if (addX5c)
            copy =
                copy.copy(certificateChain = listOf(cryptoService.keyWithCert.getCertificate()!!)) //TODO cleanup/nullchecks
        createSignedJws(copy, payload).getOrThrow()
    }

    override suspend fun decryptJweObject(
        jweObject: JweEncrypted,
        serialized: String
    ): KmmResult<JweDecrypted> = catching {
        val header = jweObject.header
        val alg = header.algorithm
            ?: throw IllegalArgumentException("No algorithm in JWE header")
        val enc = header.encryption
            ?: throw IllegalArgumentException("No encryption in JWE header")
        val epk = header.ephemeralKeyPair
            ?: throw IllegalArgumentException("No epk in JWE header")
        val z = cryptoService.performKeyAgreement(epk, alg).getOrThrow()
        val kdfInput = prependWithAdditionalInfo(
            z,
            enc,
            header.agreementPartyUInfo,
            header.agreementPartyVInfo
        )
        val key = cryptoService.messageDigest(kdfInput, Digest.SHA256)
        val iv = jweObject.iv
        val aad = jweObject.headerAsParsed.encodeToByteArray(Base64UrlStrict)
        val ciphertext = jweObject.ciphertext
        val authTag = jweObject.authTag
        val plaintext = cryptoService.decrypt(key, iv, aad, ciphertext, authTag, enc).getOrThrow()
        JweDecrypted(header, plaintext)
    }

    override suspend fun encryptJweObject(
        header: JweHeader?,
        payload: ByteArray,
        recipientKey: JsonWebKey,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption,
    ): KmmResult<JweEncrypted> = catching {
        val crv = recipientKey.curve
            ?: throw IllegalArgumentException("No curve in recipient key")
        val ephemeralKeyPair = cryptoService.generateEphemeralKeyPair(crv)
        val jweHeader = (header ?: JweHeader(jweAlgorithm, jweEncryption, type = null)).copy(
            algorithm = jweAlgorithm,
            encryption = jweEncryption,
            jsonWebKey = cryptoService.keyWithCert.jsonWebKey,
            ephemeralKeyPair = ephemeralKeyPair.publicJsonWebKey
        )
        encryptJwe(ephemeralKeyPair, recipientKey, jweAlgorithm, jweEncryption, jweHeader, payload)
    }

    override fun encryptJweObject(
        type: String,
        payload: ByteArray,
        recipientKey: JsonWebKey,
        contentType: String?,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption
    ): KmmResult<JweEncrypted> = catching {
        val crv = recipientKey.curve
            ?: throw IllegalArgumentException("No curve in recipient key")
        val ephemeralKeyPair = cryptoService.generateEphemeralKeyPair(crv)
        val jweHeader = JweHeader(
            algorithm = jweAlgorithm,
            encryption = jweEncryption,
            jsonWebKey = cryptoService.keyWithCert.jsonWebKey,
            type = type,
            contentType = contentType,
            ephemeralKeyPair = ephemeralKeyPair.publicJsonWebKey
        )
        encryptJwe(ephemeralKeyPair, recipientKey, jweAlgorithm, jweEncryption, jweHeader, payload)
    }

    private fun encryptJwe(
        ephemeralKeyPair: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption,
        jweHeader: JweHeader,
        payload: ByteArray
    ): JweEncrypted {
        val z = cryptoService.performKeyAgreement(ephemeralKeyPair, recipientKey, jweAlgorithm)
            .getOrThrow()
        val kdf =
            prependWithAdditionalInfo(
                z,
                jweEncryption,
                jweHeader.agreementPartyUInfo,
                jweHeader.agreementPartyVInfo
            )
        val key = cryptoService.messageDigest(kdf, Digest.SHA256)
        val iv = Random.nextBytes(jweEncryption.ivLengthBits / 8)
        val headerSerialized = jweHeader.serialize()
        val aad = headerSerialized.encodeToByteArray()
        val aadForCipher = aad.encodeToByteArray(Base64UrlStrict)
        val ciphertext =
            cryptoService.encrypt(key, iv, aadForCipher, payload, jweEncryption).getOrThrow()
        return JweEncrypted(jweHeader, aad, null, iv, ciphertext.ciphertext, ciphertext.authtag)
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

    override val supportedAlgorithms: List<JwsAlgorithm> =
        cryptoService.supportedAlgorithms.map { it.toJwsAlgorithm().getOrThrow() }

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
        jwkSetRetriever(jku)?.keys?.firstOrNull { it.keyId == header.keyId }?.toCryptoPublicKey()
            ?.getOrNull()

    /**
     * Verifiers the signature of [jwsObject] by using [signer].
     */
    override fun verifyJws(jwsObject: JwsSigned, signer: JsonWebKey): Boolean {
        val publicKey = signer.toCryptoPublicKey().getOrNull()
            ?: return false
                .also { Napier.w("Could not convert signer to public key: $signer") }
        return verify(jwsObject, publicKey)
    }

    private fun verify(jwsObject: JwsSigned, publicKey: CryptoPublicKey): Boolean = catching {
        cryptoService.verify(
            input = jwsObject.plainSignatureInput.encodeToByteArray(),
            signature = jwsObject.signature,
            algorithm = jwsObject.header.algorithm.toX509SignatureAlgorithm().getOrThrow(),
            publicKey = publicKey,
        ).getOrThrow()
    }.fold(onSuccess = { true }, onFailure = {
        Napier.w("No verification from native code", it)
        false
    })
}



