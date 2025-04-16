package at.asitplus.wallet.lib.jws

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.asn1.encoding.encodeTo4Bytes
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.signum.indispensable.josef.JwsExtensions.prependWith4BytesSize
import at.asitplus.signum.indispensable.josef.JwsSigned.Companion.prepareJwsSignatureInput
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.agree.Ephemeral
import at.asitplus.signum.supreme.agree.keyAgreement
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToByteArray
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationStrategy


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

    /**
     * Key material used for signing
     */
    val keyMaterial: KeyMaterial

    suspend fun <T : Any> createSignedJwt(
        type: String,
        payload: T,
        serializer: SerializationStrategy<T>,
        contentType: String? = null,
    ): KmmResult<JwsSigned<T>>

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
    // TODO Refactor in next major release (with functions) the flags into an enum
    suspend fun <T : Any> createSignedJwsAddingParams(
        header: JwsHeader? = null,
        payload: T,
        serializer: SerializationStrategy<T>,
        addKeyId: Boolean = true,
        addJsonWebKey: Boolean = true,
        addX5c: Boolean = false,
    ): KmmResult<JwsSigned<T>>

    suspend fun <T : Any> encryptJweObject(
        header: JweHeader? = null,
        payload: T,
        serializer: SerializationStrategy<T>,
        recipientKey: JsonWebKey,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption,
    ): KmmResult<JweEncrypted>

    suspend fun <T : Any> encryptJweObject(
        type: String,
        payload: T,
        serializer: SerializationStrategy<T>,
        recipientKey: JsonWebKey,
        contentType: String? = null,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption,
    ): KmmResult<JweEncrypted>

    suspend fun <T : Any> decryptJweObject(
        jweObject: JweEncrypted,
        serialized: String,
        deserializer: DeserializationStrategy<T>,
    ): KmmResult<JweDecrypted<T>>

}

interface VerifierJwsService {

    val supportedAlgorithms: List<JwsAlgorithm>

    suspend fun verifyJwsObject(jwsObject: JwsSigned<*>): Boolean

    suspend fun verifyJws(jwsObject: JwsSigned<*>, signer: JsonWebKey): Boolean

    suspend fun verifyJws(jwsObject: JwsSigned<*>, cnf: ConfirmationClaim): Boolean

}

class DefaultJwsService(private val cryptoService: CryptoService) : JwsService {

    override val algorithm: JwsAlgorithm =
        cryptoService.keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow()

    override val keyMaterial: KeyMaterial = cryptoService.keyMaterial

    // TODO: Get from crypto service
    override val encryptionAlgorithm: JweAlgorithm = JweAlgorithm.ECDH_ES

    // TODO: Get from crypto service
    override val encryptionEncoding: JweEncryption = JweEncryption.A256GCM

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
        val z =
            cryptoService.performKeyAgreement(epk.toCryptoPublicKey().getOrThrow() as CryptoPublicKey.EC).getOrThrow()
        val intermediateKey = concatKdf(
            z,
            enc,
            header.agreementPartyUInfo,
            header.agreementPartyVInfo
        )
        require(alg == JweAlgorithm.ECDH_ES)
        val algorithm = enc.algorithm
        require(algorithm.requiresNonce())
        require(algorithm.isAuthenticated())
        val key = algorithm.keyFromIntermediate(intermediateKey)
        val iv = jweObject.iv
        val aad = jweObject.headerAsParsed.encodeToByteArray(Base64UrlStrict)
        val ciphertext = jweObject.ciphertext
        val authTag = jweObject.authTag
        val plaintext = cryptoService.decrypt(key, iv, aad, ciphertext, authTag).getOrThrow()
        val plainObject = vckJsonSerializer.decodeFromString(deserializer, plaintext.decodeToString())

        JweDecrypted(header, plainObject)
    }

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
        val ephemeralKeyPair = KeyAgreementPrivateValue.ECDH.Ephemeral(crv).getOrThrow()
        val jweHeader = (header ?: JweHeader(jweAlgorithm, jweEncryption, type = null)).copy(
            algorithm = jweAlgorithm,
            encryption = jweEncryption,
            jsonWebKey = cryptoService.keyMaterial.jsonWebKey,
            ephemeralKeyPair = ephemeralKeyPair.publicValue.asCryptoPublicKey().toJsonWebKey()
        )
        encryptJwe(ephemeralKeyPair, recipientKey, jweAlgorithm, jweEncryption, jweHeader, payload, serializer)
    }

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
        val ephemeralKeyPair = KeyAgreementPrivateValue.ECDH.Ephemeral(crv).getOrThrow()
        val jweHeader = JweHeader(
            algorithm = jweAlgorithm,
            encryption = jweEncryption,
            jsonWebKey = cryptoService.keyMaterial.jsonWebKey,
            type = type,
            contentType = contentType,
            ephemeralKeyPair = ephemeralKeyPair.publicValue.asCryptoPublicKey().toJsonWebKey()
        )
        encryptJwe(ephemeralKeyPair, recipientKey, jweAlgorithm, jweEncryption, jweHeader, payload, serializer)
    }

    private suspend fun <T : Any> encryptJwe(
        ephemeralKeyPair: KeyAgreementPrivateValue.ECDH,
        recipientKey: JsonWebKey,
        jweAlgorithm: JweAlgorithm,
        jweEncryption: JweEncryption,
        jweHeader: JweHeader,
        payload: T,
        serializer: SerializationStrategy<T>,
    ): JweEncrypted {

        val cryptoPublicKey = recipientKey.toCryptoPublicKey().getOrThrow()
        require(cryptoPublicKey is CryptoPublicKey.EC)


        val z = ephemeralKeyPair.keyAgreement(cryptoPublicKey).getOrThrow()
        val intermediateKey = concatKdf(
            z,
            jweEncryption,
            jweHeader.agreementPartyUInfo,
            jweHeader.agreementPartyVInfo,
        )

        val algorithm = jweEncryption.algorithm
        require(algorithm.requiresNonce())
        require(algorithm.isAuthenticated())
        val key = algorithm.keyFromIntermediate(intermediateKey)

        val headerSerialized = jweHeader.serialize()
        val aad = headerSerialized.encodeToByteArray()
        val aadForCipher = aad.encodeToByteArray(Base64UrlStrict)
        val bytes = vckJsonSerializer.encodeToString(serializer, payload).encodeToByteArray()
        val sealedBox = cryptoService.encrypt(key, bytes, aad = aadForCipher).getOrThrow()

        return JweEncrypted(jweHeader, aad, null, sealedBox.nonce, sealedBox.encryptedData, sealedBox.authTag)
    }

    /**
     * Derives the key, for use in content encryption in JWE,
     * per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1)
     */
    private inline fun SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<*>, NonceTrait.Required, *>.keyFromIntermediate(
        jweKeyBytes: ByteArray
    ): SymmetricKey<AuthCapability.Authenticated<*>, NonceTrait.Required, *> {
        return ((if (hasDedicatedMac())
            keyFrom(
                jweKeyBytes.drop(jweKeyBytes.size / 2).toByteArray(),
                jweKeyBytes.take(jweKeyBytes.size / 2).toByteArray()
            ).getOrThrow()
        else
            keyFrom(jweKeyBytes).getOrThrow()) as SymmetricKey<AuthCapability.Authenticated<*>, NonceTrait.Required, *>)
    }


    /**
     * Concat KDF for use in ECDH-ES in JWE,
     * per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-4.6),
     * and [NIST.800-56A](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf)
     */
    private fun concatKdf(
        z: ByteArray,
        jweEncryption: JweEncryption,
        apu: ByteArray?,
        apv: ByteArray?,
    ): ByteArray {
        val digest = Digest.SHA256
        val repetitions =
            (jweEncryption.combinedEncryptionKeyLength.bits + digest.outputLength.bits - 1U) / digest.outputLength.bits
        val algId = jweEncryption.identifier.encodeToByteArray().prependWith4BytesSize()
        val apuEncoded = apu?.prependWith4BytesSize() ?: 0.encodeTo4Bytes()
        val apvEncoded = apv?.prependWith4BytesSize() ?: 0.encodeTo4Bytes()
        val keyLength = jweEncryption.combinedEncryptionKeyLength.bits.toInt().encodeTo4Bytes()
        val otherInfo = algId + apuEncoded + apvEncoded + keyLength + byteArrayOf()
        val output = (1..repetitions.toInt()).fold(byteArrayOf()) { acc, step ->
            acc + digest.digest(step.encodeTo4Bytes() + z + otherInfo)
        }
        return output.take(jweEncryption.combinedEncryptionKeyLength.bytes.toInt()).toByteArray()
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

            val jwsAlgorithm = jwsObject.header.algorithm
            require(jwsAlgorithm is JwsAlgorithm.Signature) { "Algorithm not supported: $jwsAlgorithm" }
            verifySignature(
                jwsObject.plainSignatureInput,
                jwsObject.signature,
                jwsAlgorithm.algorithm,
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
            } ?: publicKeyLookup(this)?.mapNotNull { jwk -> jwk.toCryptoPublicKey().getOrNull() }?.toSet() ?: setOf()

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
    override val supportedAlgorithms: List<JwsAlgorithm.Signature> = listOf(JwsAlgorithm.Signature.ES256),
    private val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(verifySignature),
    private val verifyJwsSignatureObject: VerifyJwsObjectFun = VerifyJwsObject(verifyJwsSignature),
    private val verifyJwsSignatureWithKey: VerifyJwsSignatureWithKeyFun = VerifyJwsSignatureWithKey(verifyJwsSignature),
    private val verifyJwsSignatureWithCnf: VerifyJwsSignatureWithCnfFun = VerifyJwsSignatureWithCnf(verifyJwsSignature),
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


private data class CompositeKey(
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
