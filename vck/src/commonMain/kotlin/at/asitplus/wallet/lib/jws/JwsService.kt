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
import kotlinx.serialization.SerializationStrategy
import kotlin.random.Random


/** How to identify the key material in a [JwsHeader] */
fun interface JwsHeaderIdentifierFun {
    suspend operator fun invoke(it: JwsHeader, keyMaterial: KeyMaterial): JwsHeader
}

/** Identify [KeyMaterial] with it's [KeyMaterial.identifier] in [JwsHeader.keyId]. */
class JwsHeaderKeyId : JwsHeaderIdentifierFun {
    override suspend operator fun invoke(it: JwsHeader, keyMaterial: KeyMaterial) =
        it.copy(keyId = keyMaterial.identifier)
}

/**
 * Identify [KeyMaterial] with it's [KeyMaterial.getCertificate] in [JwsHeader.certificateChain] if it exists,
 * or [KeyMaterial.jsonWebKey] in [JwsHeader.jsonWebKey]. */
class JwsHeaderCertOrJwk : JwsHeaderIdentifierFun {
    override suspend operator fun invoke(it: JwsHeader, keyMaterial: KeyMaterial) =
        keyMaterial.getCertificate()?.let { x5c ->
            it.copy(certificateChain = listOf(x5c))
        } ?: it.copy(jsonWebKey = keyMaterial.jsonWebKey)
}

/** Identify [KeyMaterial] with it's [KeyMaterial.jsonWebKey] in [JwsHeader.jsonWebKey]. */
class JwsHeaderJwk : JwsHeaderIdentifierFun {
    override suspend operator fun invoke(it: JwsHeader, keyMaterial: KeyMaterial) =
        it.copy(jsonWebKey = keyMaterial.jsonWebKey)
}

/**
 * Identify [KeyMaterial] with it's [KeyMaterial.identifier] set in [JwsHeader.keyId],
 * and URL set in[JwsHeader.jsonWebKeySetUrl].
 */
class JwsHeaderJwksUrl(val jsonWebKeySetUrl: String) : JwsHeaderIdentifierFun {
    override suspend operator fun invoke(
        it: JwsHeader,
        keyMaterial: KeyMaterial,
    ) = it.copy(keyId = keyMaterial.identifier, jsonWebKeySetUrl = jsonWebKeySetUrl)
}

/** Don't identify [KeyMaterial] at all in a [JwsHeader], used for SD-JWT KB-JWS. */
class JwsHeaderNone : JwsHeaderIdentifierFun {
    override suspend operator fun invoke(
        it: JwsHeader,
        keyMaterial: KeyMaterial,
    ) = it
}

/** Create a [JwsSigned], setting [JwsHeader.type] to the specified value */
fun interface SignJwtFun<P : Any> {
    suspend operator fun invoke(
        type: String?,
        payload: P,
        serializer: SerializationStrategy<P>,
    ): KmmResult<JwsSigned<P>>
}

/** Create a [JwsSigned], setting [JwsHeader.type] to the specified value and applying [JwsHeaderIdentifierFun]. */
class SignJwt<P : Any>(
    val keyMaterial: KeyMaterial,
    val headerModifier: JwsHeaderIdentifierFun,
) : SignJwtFun<P> {
    override suspend operator fun invoke(
        type: String?,
        payload: P,
        serializer: SerializationStrategy<P>,
    ): KmmResult<JwsSigned<P>> = catching {
        val header = JwsHeader(
            algorithm = keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
            type = type,
        ).let {
            headerModifier(it, keyMaterial)
        }
        val plainSignatureInput = prepareJwsSignatureInput(header, payload, serializer, vckJsonSerializer)
        val signature = keyMaterial.sign(plainSignatureInput).asKmmResult().getOrThrow()
        JwsSigned(header, payload, signature, plainSignatureInput)
    }
}

/** Create a [JweEncrypted], setting values for [JweHeader]. */
fun interface EncryptJweFun {
    suspend operator fun invoke(
        header: JweHeader,
        payload: String,
        recipientKey: JsonWebKey,
    ): KmmResult<JweEncrypted>
}


/** Create a [JweEncrypted], setting values for [JweHeader]. */
class EncryptJwe(
    val keyMaterial: KeyMaterial,
    val platformCryptoShim: PlatformCryptoShim = PlatformCryptoShim(),
) : EncryptJweFun {
    override suspend operator fun invoke(
        header: JweHeader,
        payload: String, recipientKey: JsonWebKey,
    ) = catching {
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
fun interface DecryptJweFun {
    suspend operator fun invoke(
        jweObject: JweEncrypted,
    ): KmmResult<JweDecrypted<String>>
}

class DecryptJwe(
    val keyMaterial: KeyMaterial,
    val platformCryptoShim: PlatformCryptoShim = PlatformCryptoShim(),
) : DecryptJweFun {
    override suspend operator fun invoke(
        jweObject: JweEncrypted,
    ) = catching {
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

    private suspend fun performKeyAgreement(
        keyMaterial: KeyMaterial,
        ephemeralKey: JsonWebKey,
    ): KmmResult<ByteArray> = catching {
        val publicKey = ephemeralKey.toCryptoPublicKey().getOrThrow() as CryptoPublicKey.EC
        //this is temporary until we refactor the JWS service and both key agreement functions get merged
        (keyMaterial.getUnderLyingSigner() as Signer.ECDSA).keyAgreement(publicKey).getOrThrow()
    }

}


/**
 * Clients need to retrieve the URL passed in as the only argument, and parse the content to [JsonWebKeySet].
 */
fun interface JwkSetRetrieverFunction {
    suspend operator fun invoke(
        url: String,
    ): JsonWebKeySet?
}

/**
 * Clients get the parsed [JwsSigned] and need to provide a set of keys, which will be used for verification one-by-one.
 */
fun interface PublicJsonWebKeyLookup {
    suspend operator fun invoke(
        jwsObject: JwsSigned<*>,
    ): Set<JsonWebKey>?
}

fun interface VerifyJwsSignatureFun {
    operator fun invoke(
        jwsObject: JwsSigned<*>,
        publicKey: CryptoPublicKey,
    ): Boolean
}

class VerifyJwsSignature(
    val verifySignature: VerifySignatureFun = VerifySignature(),
) : VerifyJwsSignatureFun {
    override operator fun invoke(
        jwsObject: JwsSigned<*>,
        publicKey: CryptoPublicKey,
    ) = catching {
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

fun interface VerifyJwsSignatureWithKeyFun {
    operator fun invoke(
        jwsObject: JwsSigned<*>,
        signer: JsonWebKey,
    ): Boolean
}

class VerifyJwsSignatureWithKey(
    val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(),
) : VerifyJwsSignatureWithKeyFun {
    override operator fun invoke(
        jwsObject: JwsSigned<*>,
        signer: JsonWebKey,
    ) = signer.toCryptoPublicKey().getOrNull()?.let {
        verifyJwsSignature(jwsObject, it)
    } ?: false.also { Napier.w("Could not convert signer to public key: $signer") }
}

fun interface VerifyJwsSignatureWithCnfFun {
    suspend operator fun invoke(
        jwsObject: JwsSigned<*>,
        cnf: ConfirmationClaim,
    ): Boolean
}

class VerifyJwsSignatureWithCnf(
    val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(),
    /**
     * Need to implement if JSON web keys in JWS headers are referenced by a `kid`, and need to be retrieved from
     * the `jku`.
     */
    val jwkSetRetriever: JwkSetRetrieverFunction = nullJwkSetRetrieverFunction(),
) : VerifyJwsSignatureWithCnfFun {
    override suspend operator fun invoke(
        jwsObject: JwsSigned<*>,
        cnf: ConfirmationClaim,
    ) = cnf.loadPublicKeys().any { verifyJwsSignature(jwsObject, it) }

    /**
     * Loads all referenced [JsonWebKey]s, i.e. from [ConfirmationClaim.jsonWebKey] and [ConfirmationClaim.jsonWebKeySetUrl].
     */
    private suspend fun ConfirmationClaim.loadPublicKeys(): Set<CryptoPublicKey> =
        setOfNotNull(
            jsonWebKey?.toCryptoPublicKey()?.getOrNull(),
            jsonWebKeySetUrl?.let { retrieveJwkFromKeySetUrl(it, keyId) }
        )

    /**
     * Either take the single key from the JSON Web Key Set, or the one matching the keyId
     */
    private suspend fun retrieveJwkFromKeySetUrl(
        jku: String,
        keyId: String?,
    ): CryptoPublicKey? =
        jwkSetRetriever(jku)?.keys?.let { keys ->
            (keys.firstOrNull { it.keyId == keyId } ?: keys.singleOrNull())
        }?.toCryptoPublicKey()?.getOrNull()

}

private fun nullJwkSetRetrieverFunction(): JwkSetRetrieverFunction = object : JwkSetRetrieverFunction {
    override suspend operator fun invoke(url: String): JsonWebKeySet? = null
}

private fun nullPublicJsonWebKeyLookup(): PublicJsonWebKeyLookup = object : PublicJsonWebKeyLookup {
    override suspend operator fun invoke(jwsObject: JwsSigned<*>) = null
}

fun interface VerifyJwsObjectFun {
    suspend operator fun invoke(jwsObject: JwsSigned<*>): Boolean
}

class VerifyJwsObject(
    val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(),
    /**
     * Need to implement if JSON web keys in JWS headers are referenced by a `kid`, and need to be retrieved from
     * the `jku`.
     */
    val jwkSetRetriever: JwkSetRetrieverFunction = nullJwkSetRetrieverFunction(),
    /** Need to implement if valid keys for JWS are transported somehow out-of-band, e.g. provided by a trust store */
    val publicKeyLookup: PublicJsonWebKeyLookup = nullPublicJsonWebKeyLookup(),
) : VerifyJwsObjectFun {
    override suspend operator fun invoke(jwsObject: JwsSigned<*>) =
        jwsObject.loadPublicKeys().any { verifyJwsSignature(jwsObject, it) }

    /**
     * Returns a list of public keys that may have been used to sign this [JwsSigned]
     * by evaluating its header values (see [JwsHeader.jsonWebKey], [JwsHeader.jsonWebKeySetUrl])
     * as well as out-of-band transmitted keys from [publicKeyLookup].
     */
    private suspend fun JwsSigned<*>.loadPublicKeys(): Set<CryptoPublicKey> =
        header.publicKey?.let { setOf(it) }
            ?: header.jsonWebKeySetUrl?.let {
                retrieveJwkFromKeySetUrl(it, header.keyId)?.let { setOf(it) }
            } ?: publicKeyLookup(this)?.mapNotNull { jwk -> jwk.toCryptoPublicKey().getOrNull() }?.toSet()
            ?: setOf()

    /**
     * Either take the single key from the JSON Web Key Set, or the one matching the keyId
     */
    private suspend fun retrieveJwkFromKeySetUrl(
        jku: String,
        keyId: String?,
    ): CryptoPublicKey? =
        jwkSetRetriever(jku)?.keys?.let { keys ->
            (keys.firstOrNull { it.keyId == keyId } ?: keys.singleOrNull())
        }?.toCryptoPublicKey()?.getOrNull()

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
