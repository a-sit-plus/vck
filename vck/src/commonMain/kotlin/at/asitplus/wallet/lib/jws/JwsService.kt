package at.asitplus.wallet.lib.jws

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.encoding.encodeTo4Bytes
import at.asitplus.signum.indispensable.asn1.encoding.encodeTo8Bytes
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.signum.indispensable.josef.JweEncryption.*
import at.asitplus.signum.indispensable.josef.JwsExtensions.prependWith4BytesSize
import at.asitplus.signum.indispensable.josef.JwsSigned.Companion.prepareJwsSignatureInput
import at.asitplus.signum.supreme.SecretExposure
import at.asitplus.signum.supreme.agree.keyAgreement
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.JweUtils.compositeKey
import at.asitplus.wallet.lib.jws.JweUtils.concatKdf
import at.asitplus.wallet.lib.jws.JweUtils.hmacInput
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToByteArray
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationStrategy
import kotlin.random.Random


/**
 * Creates and parses JWS and JWE objects.
 */
@Deprecated("Replaced with separate functions, e.g. SignJwtFun")
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

    /**
     * Key material used for signing
     */
    val keyMaterial: KeyMaterial

    @Deprecated("Use SignJwtFun instead")
    suspend fun <T : Any> createSignedJwt(
        type: String,
        payload: T,
        serializer: SerializationStrategy<T>,
        contentType: String? = null,
    ): KmmResult<JwsSigned<T>>

    @Deprecated("Use SignJwtFun instead")
    suspend fun <T : Any> createSignedJws(
        header: JwsHeader,
        payload: T,
        serializer: SerializationStrategy<T>,
    ): KmmResult<JwsSigned<T>>

    /**
     * Appends (or sets) correct value for  [JwsHeader.algorithm].
     *
     * Precedence of flags:
     * 1. [addX5c] setting certificate chain
     * 2. [addJsonWebKey] setting JWK
     * 3. [addKeyId] setting keyId
     *
     * @param addX5c sets [JwsHeader.certificateChain] from [KeyMaterial.getCertificate]
     * @param addJsonWebKey sets [JwsHeader.jsonWebKey] from [KeyMaterial.jsonWebKey]
     * @param addKeyId sets [JwsHeader.keyId] from [KeyMaterial.identifier]
     */
    @Deprecated("Use SignJwtFun instead")
    suspend fun <T : Any> createSignedJwsAddingParams(
        header: JwsHeader? = null,
        payload: T,
        serializer: SerializationStrategy<T>,
        addKeyId: Boolean = true,
        addJsonWebKey: Boolean = true,
        addX5c: Boolean = false,
    ): KmmResult<JwsSigned<T>>

    @Deprecated("Use EncryptJweFun instead")
    suspend fun <T : Any> encryptJweObject(
        header: JweHeader? = null,
        payload: T,
        serializer: SerializationStrategy<T>,
        recipientKey: JsonWebKey,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption,
    ): KmmResult<JweEncrypted>

    @Deprecated("Use EncryptJweFun instead")
    suspend fun <T : Any> encryptJweObject(
        type: String,
        payload: T,
        serializer: SerializationStrategy<T>,
        recipientKey: JsonWebKey,
        contentType: String? = null,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption,
    ): KmmResult<JweEncrypted>

    @Deprecated("Use DecryptJweFun instead")
    suspend fun <T : Any> decryptJweObject(
        jweObject: JweEncrypted,
        serialized: String,
        deserializer: DeserializationStrategy<T>,
    ): KmmResult<JweDecrypted<T>>

}

/** How to identify the key material in a [JwsHeader] */
typealias JwsHeaderIdentifierFun = suspend (JwsHeader, KeyMaterial) -> JwsHeader

/** Identify [KeyMaterial] with it's [KeyMaterial.identifier] in [JwsHeader.keyId]. */
object JwsHeaderKeyId {
    operator fun invoke(): JwsHeaderIdentifierFun = { it, keyMaterial ->
        it.copy(keyId = keyMaterial.identifier)
    }
}

/**
 * Identify [KeyMaterial] with it's [KeyMaterial.getCertificate] in [JwsHeader.certificateChain] if it exists,
 * or [KeyMaterial.jsonWebKey] in [JwsHeader.jsonWebKey]. */
object JwsHeaderCertOrJwk {
    operator fun invoke(): JwsHeaderIdentifierFun = { it, keyMaterial ->
        keyMaterial.getCertificate()?.let { x5c ->
            it.copy(certificateChain = listOf(x5c))
        } ?: it.copy(jsonWebKey = keyMaterial.jsonWebKey)
    }
}

/** Identify [KeyMaterial] with it's [KeyMaterial.jsonWebKey] in [JwsHeader.jsonWebKey]. */
object JwsHeaderJwk {
    operator fun invoke(): JwsHeaderIdentifierFun = { it, keyMaterial ->
        it.copy(jsonWebKey = keyMaterial.jsonWebKey)
    }
}

/**
 * Identify [KeyMaterial] with it's [KeyMaterial.identifier] set in [JwsHeader.keyId],
 * and URL set in[JwsHeader.jsonWebKeySetUrl].
 */
object JwsHeaderJwksUrl {
    operator fun invoke(jsonWebKeySetUrl: String): JwsHeaderIdentifierFun = { it, keyMaterial ->
        it.copy(keyId = keyMaterial.identifier, jsonWebKeySetUrl = jsonWebKeySetUrl)
    }
}

/** Don't identify [KeyMaterial] at all in a [JwsHeader], used for SD-JWT KB-JWS. */
object JwsHeaderNone {
    operator fun invoke(): JwsHeaderIdentifierFun = { it, keyMaterial -> it }
}

/** Create a [JwsSigned], setting [JwsHeader.type] to the specified value */
typealias SignJwtFun<P> = suspend (
    type: String?,
    payload: P,
    serializer: SerializationStrategy<P>,
) -> KmmResult<JwsSigned<P>>

/** Create a [JwsSigned], setting [JwsHeader.type] to the specified value and applying [JwsHeaderIdentifierFun]. */
object SignJwt {
    operator fun <P : Any> invoke(
        keyMaterial: KeyMaterial,
        headerModifier: JwsHeaderIdentifierFun,
    ): SignJwtFun<P> = { type, payload, serializer ->
        catching {
            val header = JwsHeader(
                algorithm = keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                type = type,
            ).let { headerModifier(it, keyMaterial) }
            val plainSignatureInput = prepareJwsSignatureInput(header, payload, serializer, vckJsonSerializer)
            val signature = keyMaterial.sign(plainSignatureInput).asKmmResult().getOrThrow()
            JwsSigned(header, payload, signature, plainSignatureInput)
        }
    }
}


/** Create a [JweEncrypted], setting values for [JweHeader]. */
typealias EncryptJweFun = suspend (
    header: JweHeader,
    payload: String,
    recipientKey: JsonWebKey,
) -> KmmResult<JweEncrypted>

/** Create a [JweEncrypted], setting values for [JweHeader]. */
object EncryptJwe {
    operator fun invoke(
        keyMaterial: KeyMaterial,
        platformCryptoShim: PlatformCryptoShim = PlatformCryptoShim(),
    ): EncryptJweFun = { header, payload, recipientKey ->
        catching {
            val crv = recipientKey.curve
                ?: throw IllegalArgumentException("No curve in recipient key")
            val ephemeralKeyPair = DefaultEphemeralKeyHolder(crv)
            val jweEncryption = header.encryption
                ?: throw IllegalArgumentException("No encryption in JWE header")
            val jweAlgorithm = header.algorithm
                ?: throw IllegalArgumentException("No algorithm in JWE header")
            val jweHeader = header.copy(
                jsonWebKey = keyMaterial.jsonWebKey,
                ephemeralKeyPair = ephemeralKeyPair.publicJsonWebKey
            )
            val z = performKeyAgreement(ephemeralKeyPair, recipientKey).getOrThrow()
            val intermediateKey = concatKdf(
                z,
                jweEncryption,
                jweHeader.agreementPartyUInfo,
                jweHeader.agreementPartyVInfo,
                jweEncryption.encryptionKeyLength
            )
            val key = compositeKey(jweEncryption, intermediateKey)
            // Pending fix in signum
            val ivLengthBits = when (jweEncryption) {
                A128GCM, A192GCM, A256GCM -> 96
                else -> 128
            }
            val iv = Random.nextBytes(ivLengthBits / 8)
            val headerSerialized = jweHeader.serialize()
            val aad = headerSerialized.encodeToByteArray()
            val aadForCipher = aad.encodeToByteArray(Base64UrlStrict)
            val bytes = payload.encodeToByteArray()
            val ciphertext = platformCryptoShim.encrypt(key.aesKey, iv, aadForCipher, bytes, jweEncryption).getOrThrow()
            val authTag = key.hmacKey?.let { hmacKey ->
                platformCryptoShim.hmac(hmacKey, jweEncryption, hmacInput(aadForCipher, iv, ciphertext.ciphertext))
                    .getOrThrow()
                    .take(jweEncryption.macLength!!).toByteArray()
            } ?: ciphertext.authtag
            JweEncrypted(jweHeader, aad, null, iv, ciphertext.ciphertext, authTag)
        }
    }


    private suspend fun performKeyAgreement(
        ephemeralKey: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
    ): KmmResult<ByteArray> = catching {
        //this is temporary until we refactor the JWS service and both key agreement functions get merged
        @OptIn(SecretExposure::class)
        (recipientKey.toCryptoPublicKey()
            .getOrThrow() as CryptoPublicKey.EC).keyAgreement(
            ephemeralKey.key.exportPrivateKey().getOrThrow() as CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC>
        ).getOrThrow()
    }

}


object JweUtils {

    /**
     * Derives the key, for use in content encryption in JWE,
     * per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1)
     */
    fun compositeKey(jweEncryption: JweEncryption, key: ByteArray) =
        if (jweEncryption.macLength != null) {
            CompositeKey(key.drop(key.size / 2).toByteArray(), key.take(key.size / 2).toByteArray())
        } else {
            CompositeKey(key)
        }

    /**
     * Input for HMAC calculation in JWE, when not using authenticated encryption,
     * per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1)
     */
    fun hmacInput(
        aadForCipher: ByteArray,
        iv: ByteArray,
        ciphertext: ByteArray,
    ) = aadForCipher + iv + ciphertext + (aadForCipher.size * 8L).encodeTo8Bytes()

    /**
     * Concat KDF for use in ECDH-ES in JWE,
     * per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-4.6),
     * and [NIST.800-56A](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf)
     */
    fun concatKdf(
        z: ByteArray,
        jweEncryption: JweEncryption,
        apu: ByteArray?,
        apv: ByteArray?,
        encryptionKeyLengthBits: Int,
    ): ByteArray {
        val digest = Digest.SHA256
        val repetitions = (encryptionKeyLengthBits.toUInt() + digest.outputLength.bits - 1U) / digest.outputLength.bits
        val algId = jweEncryption.text.encodeToByteArray().prependWith4BytesSize()
        val apuEncoded = apu?.prependWith4BytesSize() ?: 0.encodeTo4Bytes()
        val apvEncoded = apv?.prependWith4BytesSize() ?: 0.encodeTo4Bytes()
        val keyLength = jweEncryption.encryptionKeyLength.encodeTo4Bytes()
        val otherInfo = algId + apuEncoded + apvEncoded + keyLength + byteArrayOf()
        val output = (1..repetitions.toInt()).fold(byteArrayOf()) { acc, step ->
            acc + digest.digest(sequenceOf(step.encodeTo4Bytes() + z + otherInfo))
        }
        return output.take(encryptionKeyLengthBits / 8).toByteArray()
    }
}

/** Decrypt a [JweEncrypted] object*/
typealias DecryptJweFun = suspend (
    jweObject: JweEncrypted,
) -> KmmResult<JweDecrypted<String>>

object DecryptJwe {
    operator fun invoke(
        keyMaterial: KeyMaterial,
        platformCryptoShim: PlatformCryptoShim = PlatformCryptoShim(),
    ): DecryptJweFun = { jweObject ->
        catching {
            val header = jweObject.header
            val alg = header.algorithm
                ?: throw IllegalArgumentException("No algorithm in JWE header")
            val enc = header.encryption
                ?: throw IllegalArgumentException("No encryption in JWE header")
            val epk = header.ephemeralKeyPair
                ?: throw IllegalArgumentException("No epk in JWE header")
            val z = performKeyAgreement(keyMaterial, epk).getOrThrow()
            val intermediateKey = concatKdf(
                z,
                enc,
                header.agreementPartyUInfo,
                header.agreementPartyVInfo,
                enc.encryptionKeyLength
            )
            val key = compositeKey(enc, intermediateKey)
            val iv = jweObject.iv
            val aad = jweObject.headerAsParsed.encodeToByteArray(Base64UrlStrict)
            val ciphertext = jweObject.ciphertext
            val authTag = jweObject.authTag
            val plaintext = platformCryptoShim.decrypt(key.aesKey, iv, aad, ciphertext, authTag, enc).getOrThrow()
            val plainObject = plaintext.decodeToString()
            key.hmacKey?.let { hmacKey ->
                val expectedAuthTag = platformCryptoShim.hmac(hmacKey, enc, hmacInput(aad, iv, ciphertext))
                    .getOrThrow()
                    .take(enc.macLength!!).toByteArray()
                if (!expectedAuthTag.contentEquals(authTag)) {
                    throw IllegalArgumentException("Authtag mismatch")
                }
            }
            JweDecrypted(header, plainObject)
        }
    }

    private suspend fun performKeyAgreement(
        keyMaterial: KeyMaterial,
        ephemeralKey: JsonWebKey,
    ): KmmResult<ByteArray> = catching {
        val publicKey = ephemeralKey.toCryptoPublicKey().getOrThrow() as CryptoPublicKey.EC
        //this is temporary until we refactor the JWS service and both key agreement functions get merged
        (keyMaterial.getUnderLyingSigner() as Signer.ECDSA).keyAgreement(publicKey).getOrThrow()
    }

}

interface VerifierJwsService {

    val supportedAlgorithms: List<JwsAlgorithm>

    suspend fun verifyJwsObject(jwsObject: JwsSigned<*>): Boolean

    suspend fun verifyJws(jwsObject: JwsSigned<*>, signer: JsonWebKey): Boolean

    suspend fun verifyJws(jwsObject: JwsSigned<*>, cnf: ConfirmationClaim): Boolean

}

@Deprecated("Replaced with separate functions, e.g. SignJwtFun")
class DefaultJwsService(private val cryptoService: CryptoService) : JwsService {

    override val algorithm: JwsAlgorithm =
        cryptoService.keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow()

    override val keyMaterial: KeyMaterial = cryptoService.keyMaterial

    override val encryptionAlgorithm: JweAlgorithm = JweAlgorithm.ECDH_ES

    override val encryptionEncoding: JweEncryption = JweEncryption.A256GCM

    @Deprecated("Use SignJwtFun instead")
    override suspend fun <T : Any> createSignedJwt(
        type: String,
        payload: T,
        serializer: SerializationStrategy<T>,
        contentType: String?,
    ): KmmResult<JwsSigned<T>> = createSignedJws(
        JwsHeader(
            algorithm = cryptoService.keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
            keyId = cryptoService.keyMaterial.identifier,
            type = type,
            contentType = contentType
        ),
        payload,
        serializer,
    )

    @Deprecated("Use SignJwtFun instead")
    override suspend fun <T : Any> createSignedJws(
        header: JwsHeader,
        payload: T,
        serializer: SerializationStrategy<T>,
    ) = catching {
        if (header.algorithm != cryptoService.keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow()
            || header.jsonWebKey?.let { it != cryptoService.keyMaterial.jsonWebKey } == true
        ) {
            throw IllegalArgumentException("Algorithm or JSON Web Key not matching to cryptoService")
        }

        val plainSignatureInput = prepareJwsSignatureInput(header, payload, serializer, vckJsonSerializer)
        val signature = cryptoService.sign(plainSignatureInput).asKmmResult().getOrThrow()
        JwsSigned(header, payload, signature, plainSignatureInput)
    }

    @Deprecated("Use SignJwtFun instead")
    override suspend fun <T : Any> createSignedJwsAddingParams(
        header: JwsHeader?,
        payload: T,
        serializer: SerializationStrategy<T>,
        addKeyId: Boolean,
        addJsonWebKey: Boolean,
        addX5c: Boolean,
    ): KmmResult<JwsSigned<T>> = catching {
        var copy = header?.copy(
            algorithm = cryptoService.keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow()
        ) ?: JwsHeader(
            algorithm = cryptoService.keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow()
        )
        if (addX5c && cryptoService.keyMaterial.getCertificate() != null)
            copy = copy.copy(certificateChain = listOf(cryptoService.keyMaterial.getCertificate()!!))
        else if (addJsonWebKey)
            copy = copy.copy(jsonWebKey = cryptoService.keyMaterial.jsonWebKey)
        else if (addKeyId)
            copy = copy.copy(keyId = cryptoService.keyMaterial.jsonWebKey.keyId)

        createSignedJws(copy, payload, serializer).getOrThrow()
    }

    @Deprecated("Use DecryptJweFun instead")
    override suspend fun <T : Any> decryptJweObject(
        jweObject: JweEncrypted,
        serialized: String,
        deserializer: DeserializationStrategy<T>,
    ): KmmResult<JweDecrypted<T>> = catching {
        val header = jweObject.header
        val alg = header.algorithm
            ?: throw IllegalArgumentException("No algorithm in JWE header")
        val enc = header.encryption
            ?: throw IllegalArgumentException("No encryption in JWE header")
        val epk = header.ephemeralKeyPair
            ?: throw IllegalArgumentException("No epk in JWE header")
        val z = cryptoService.performKeyAgreement(epk, alg).getOrThrow()
        val intermediateKey = concatKdf(
            z,
            enc,
            header.agreementPartyUInfo,
            header.agreementPartyVInfo,
            enc.encryptionKeyLength
        )
        val key = compositeKey(enc, intermediateKey)
        val iv = jweObject.iv
        val aad = jweObject.headerAsParsed.encodeToByteArray(Base64UrlStrict)
        val ciphertext = jweObject.ciphertext
        val authTag = jweObject.authTag
        val plaintext = cryptoService.decrypt(key.aesKey, iv, aad, ciphertext, authTag, enc).getOrThrow()
        val plainObject = vckJsonSerializer.decodeFromString(deserializer, plaintext.decodeToString())
        key.hmacKey?.let { hmacKey ->
            val expectedAuthTag = cryptoService.hmac(hmacKey, enc, hmacInput(aad, iv, ciphertext))
                .getOrThrow()
                .take(enc.macLength!!).toByteArray()
            if (!expectedAuthTag.contentEquals(authTag)) {
                throw IllegalArgumentException("Authtag mismatch")
            }
        }
        JweDecrypted(header, plainObject)
    }

    @Deprecated("Use EncryptJweFun instead")
    override suspend fun <T : Any> encryptJweObject(
        header: JweHeader?,
        payload: T,
        serializer: SerializationStrategy<T>,
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
            jsonWebKey = cryptoService.keyMaterial.jsonWebKey,
            ephemeralKeyPair = ephemeralKeyPair.publicJsonWebKey
        )
        encryptJwe(ephemeralKeyPair, recipientKey, jweAlgorithm, jweEncryption, jweHeader, payload, serializer)
    }

    @Deprecated("Use EncryptJweFun instead")
    override suspend fun <T : Any> encryptJweObject(
        type: String,
        payload: T,
        serializer: SerializationStrategy<T>,
        recipientKey: JsonWebKey,
        contentType: String?,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption,
    ): KmmResult<JweEncrypted> = catching {
        val crv = recipientKey.curve
            ?: throw IllegalArgumentException("No curve in recipient key")
        val ephemeralKeyPair = cryptoService.generateEphemeralKeyPair(crv)
        val jweHeader = JweHeader(
            algorithm = jweAlgorithm,
            encryption = jweEncryption,
            jsonWebKey = cryptoService.keyMaterial.jsonWebKey,
            type = type,
            contentType = contentType,
            ephemeralKeyPair = ephemeralKeyPair.publicJsonWebKey
        )
        encryptJwe(ephemeralKeyPair, recipientKey, jweAlgorithm, jweEncryption, jweHeader, payload, serializer)
    }

    private suspend fun <T : Any> encryptJwe(
        ephemeralKeyPair: EphemeralKeyHolder,
        recipientKey: JsonWebKey,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption,
        jweHeader: JweHeader,
        payload: T,
        serializer: SerializationStrategy<T>,
    ): JweEncrypted {
        val z = cryptoService.performKeyAgreement(ephemeralKeyPair, recipientKey, jweAlgorithm)
            .getOrThrow()
        val intermediateKey = concatKdf(
            z,
            jweEncryption,
            jweHeader.agreementPartyUInfo,
            jweHeader.agreementPartyVInfo,
            jweEncryption.encryptionKeyLength
        )
        val key = compositeKey(jweEncryption, intermediateKey)
        // Pending fix in signum
        val ivLengthBits = when (jweEncryption) {
            A128GCM, A192GCM, A256GCM -> 96
            else -> 128
        }
        val iv = Random.nextBytes(ivLengthBits / 8)
        val headerSerialized = jweHeader.serialize()
        val aad = headerSerialized.encodeToByteArray()
        val aadForCipher = aad.encodeToByteArray(Base64UrlStrict)
        val bytes = vckJsonSerializer.encodeToString(serializer, payload).encodeToByteArray()
        val ciphertext = cryptoService.encrypt(key.aesKey, iv, aadForCipher, bytes, jweEncryption).getOrThrow()
        val authTag = key.hmacKey?.let { hmacKey ->
            cryptoService.hmac(hmacKey, jweEncryption, hmacInput(aadForCipher, iv, ciphertext.ciphertext))
                .getOrThrow()
                .take(jweEncryption.macLength!!).toByteArray()
        } ?: ciphertext.authtag
        return JweEncrypted(jweHeader, aad, null, iv, ciphertext.ciphertext, authTag)
    }


}
/**
 * Clients need to retrieve the URL passed in as the only argument, and parse the content to [JsonWebKeySet].
 */
typealias JwkSetRetrieverFunction = suspend (String) -> JsonWebKeySet?

/**
 * Clients get the parsed [JwsSigned] and need to provide a set of keys, which will be used for verification one-by-one.
 */
typealias PublicJsonWebKeyLookup = suspend (JwsSigned<*>) -> Set<JsonWebKey>?

typealias VerifyJwsSignatureFun = suspend (jwsObject: JwsSigned<*>, publicKey: CryptoPublicKey) -> Boolean

object VerifyJwsSignature {
    operator fun invoke(
        verifySignature: VerifySignatureFun = VerifySignature(),
    ): VerifyJwsSignatureFun = { jwsObject, publicKey ->
        catching {
            verifySignature(
                jwsObject.plainSignatureInput,
                jwsObject.signature,
                jwsObject.header.algorithm.algorithm,
                publicKey,
            ).getOrThrow()
        }.fold(
            onSuccess = { true },
            onFailure = {
                Napier.w("No verification from native code", it)
                false
            })
    }
}

typealias VerifyJwsSignatureWithKeyFun = suspend (jwsObject: JwsSigned<*>, signer: JsonWebKey) -> Boolean

object VerifyJwsSignatureWithKey {
    operator fun invoke(
        verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(),
    ): VerifyJwsSignatureWithKeyFun = { jwsObject, signer ->
        signer.toCryptoPublicKey().getOrNull()?.let {
            verifyJwsSignature(jwsObject, it)
        } ?: false.also { Napier.w("Could not convert signer to public key: $signer") }
    }
}

typealias VerifyJwsSignatureWithCnfFun = suspend (jwsObject: JwsSigned<*>, cnf: ConfirmationClaim) -> Boolean

object VerifyJwsSignatureWithCnf {
    operator fun invoke(
        verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(),
        /**
         * Need to implement if JSON web keys in JWS headers are referenced by a `kid`, and need to be retrieved from
         * the `jku`.
         */
        jwkSetRetriever: JwkSetRetrieverFunction = { null },
    ): VerifyJwsSignatureWithCnfFun = { jwsObject, cnf ->
        cnf.loadPublicKeys(jwkSetRetriever).any { verifyJwsSignature(jwsObject, it) }
    }

    /**
     * Loads all referenced [JsonWebKey]s, i.e. from [ConfirmationClaim.jsonWebKey] and [ConfirmationClaim.jsonWebKeySetUrl].
     */
    private suspend fun ConfirmationClaim.loadPublicKeys(
        jwkSetRetriever: JwkSetRetrieverFunction = { null },
    ): Set<CryptoPublicKey> =
        setOfNotNull(
            jsonWebKey?.toCryptoPublicKey()?.getOrNull(),
            jsonWebKeySetUrl?.let { retrieveJwkFromKeySetUrl(jwkSetRetriever, it, keyId) }
        )

    /**
     * Either take the single key from the JSON Web Key Set, or the one matching the keyId
     */
    private suspend fun retrieveJwkFromKeySetUrl(
        jwkSetRetriever: JwkSetRetrieverFunction = { null },
        jku: String,
        keyId: String?,
    ): CryptoPublicKey? =
        jwkSetRetriever(jku)?.keys?.let { keys ->
            (keys.firstOrNull { it.keyId == keyId } ?: keys.singleOrNull())
        }?.toCryptoPublicKey()?.getOrNull()

}

typealias VerifyJwsObjectFun = suspend (jwsObject: JwsSigned<*>) -> Boolean

object VerifyJwsObject {
    operator fun invoke(
        verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(),
        /**
         * Need to implement if JSON web keys in JWS headers are referenced by a `kid`, and need to be retrieved from
         * the `jku`.
         */
        jwkSetRetriever: JwkSetRetrieverFunction = { null },
        /** Need to implement if valid keys for JWS are transported somehow out-of-band, e.g. provided by a trust store */
        publicKeyLookup: PublicJsonWebKeyLookup = { null },
    ): VerifyJwsObjectFun = { jwsObject ->
        jwsObject.loadPublicKeys(jwkSetRetriever, publicKeyLookup).any { verifyJwsSignature(jwsObject, it) }
    }

    /**
     * Returns a list of public keys that may have been used to sign this [JwsSigned]
     * by evaluating its header values (see [JwsHeader.jsonWebKey], [JwsHeader.jsonWebKeySetUrl])
     * as well as out-of-band transmitted keys from [publicKeyLookup].
     */
    private suspend fun JwsSigned<*>.loadPublicKeys(
        /**
         * Need to implement if JSON web keys in JWS headers are referenced by a `kid`, and need to be retrieved from
         * the `jku`.
         */
        jwkSetRetriever: JwkSetRetrieverFunction = { null },
        /** Need to implement if valid keys for JWS are transported somehow out-of-band, e.g. provided by a trust store */
        publicKeyLookup: PublicJsonWebKeyLookup = { null },
    ): Set<CryptoPublicKey> =
        header.publicKey?.let { setOf(it) }
            ?: header.jsonWebKeySetUrl?.let {
                retrieveJwkFromKeySetUrl(jwkSetRetriever, it, header.keyId)?.let { setOf(it) }
            } ?: publicKeyLookup(this)?.mapNotNull { jwk -> jwk.toCryptoPublicKey().getOrNull() }?.toSet()
            ?: setOf()

    /**
     * Either take the single key from the JSON Web Key Set, or the one matching the keyId
     */
    private suspend fun retrieveJwkFromKeySetUrl(
        jwkSetRetriever: JwkSetRetrieverFunction = { null },
        jku: String,
        keyId: String?,
    ): CryptoPublicKey? =
        jwkSetRetriever(jku)?.keys?.let { keys ->
            (keys.firstOrNull { it.keyId == keyId } ?: keys.singleOrNull())
        }?.toCryptoPublicKey()?.getOrNull()

}

class DefaultVerifierJwsService(
    @Suppress("DEPRECATION") @Deprecated("Use verifySignature and supportedAlgorithms")
    private val cryptoService: VerifierCryptoService = DefaultVerifierCryptoService(),
    private val verifySignature: VerifySignatureFun = VerifySignature(),
    override val supportedAlgorithms: List<JwsAlgorithm> = listOf(JwsAlgorithm.ES256),
    private val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(verifySignature),
    private val verifyJwsSignatureObject: VerifyJwsObjectFun = VerifyJwsObject(verifyJwsSignature),
    private val verifyJwsSignatureWithKey: VerifyJwsSignatureWithKeyFun = VerifyJwsSignatureWithKey(
        verifyJwsSignature
    ),
    private val verifyJwsSignatureWithCnf: VerifyJwsSignatureWithCnfFun = VerifyJwsSignatureWithCnf(
        verifyJwsSignature
    ),
    /**
     * Need to implement if JSON web keys in JWS headers are referenced by a `kid`, and need to be retrieved from
     * the `jku`.
     */
    private val jwkSetRetriever: JwkSetRetrieverFunction = { null },
    /** Need to implement if valid keys for JWS are transported somehow out-of-band, e.g. provided by a trust store */
    @Deprecated("Use verifyJwsSignatureObject and pass publicKeyLookup there")
    private val publicKeyLookup: PublicJsonWebKeyLookup = { null },
) : VerifierJwsService {

    /**
     * Verifies the signature of [jwsObject], by extracting the public key from [JwsHeader.publicKey],
     * or by using [jwkSetRetriever] if [JwsHeader.jsonWebKeySetUrl] is set.
     */
    override suspend fun verifyJwsObject(jwsObject: JwsSigned<*>): Boolean = verifyJwsSignatureObject(jwsObject)

    /**
     * Either take the single key from the JSON Web Key Set, or the one matching the keyId
     */
    private suspend fun retrieveJwkFromKeySetUrl(jku: String, keyId: String?): CryptoPublicKey? =
        retrieveFromKeySetUrl(jku, keyId)?.toCryptoPublicKey()?.getOrNull()

    /**
     * Either take the single key from the JSON Web Key Set, or the one matching the keyId
     */
    private suspend fun retrieveFromKeySetUrl(jku: String, keyId: String?): JsonWebKey? =
        jwkSetRetriever(jku)?.keys?.let { keys ->
            (keys.firstOrNull { it.keyId == keyId } ?: keys.singleOrNull())
        }

    /**
     * Verifiers the signature of [jwsObject] by using [signer].
     */
    override suspend fun verifyJws(jwsObject: JwsSigned<*>, signer: JsonWebKey): Boolean =
        verifyJwsSignatureWithKey(jwsObject, signer)

    /**
     * Verifiers the signature of [jwsObject] by using keys from [cnf].
     */
    override suspend fun verifyJws(jwsObject: JwsSigned<*>, cnf: ConfirmationClaim): Boolean =
        verifyJwsSignatureWithCnf(jwsObject, cnf)

}


data class CompositeKey(
    val aesKey: ByteArray,
    val hmacKey: ByteArray? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CompositeKey

        if (!aesKey.contentEquals(other.aesKey)) return false
        if (hmacKey != null) {
            if (other.hmacKey == null) return false
            if (!hmacKey.contentEquals(other.hmacKey)) return false
        } else if (other.hmacKey != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = aesKey.contentHashCode()
        result = 31 * result + (hmacKey?.contentHashCode() ?: 0)
        return result
    }
}
