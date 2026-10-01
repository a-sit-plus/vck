package at.asitplus.wallet.lib.jws

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.asn1.encoding.encodeTo4Bytes
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweDecrypted
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsExtensions.prependWith4BytesSize
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.jsonWebKeyBytes
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.signum.indispensable.symmetric.AuthCapability
import at.asitplus.signum.indispensable.symmetric.KeyType
import at.asitplus.signum.indispensable.symmetric.NonceTrait
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricKey
import at.asitplus.signum.indispensable.symmetric.authTag
import at.asitplus.signum.indispensable.symmetric.hasDedicatedMac
import at.asitplus.signum.indispensable.symmetric.hasNonce
import at.asitplus.signum.indispensable.symmetric.isAuthenticated
import at.asitplus.signum.indispensable.symmetric.isIntegrated
import at.asitplus.signum.indispensable.symmetric.keyFrom
import at.asitplus.signum.indispensable.symmetric.nonce
import at.asitplus.signum.indispensable.symmetric.randomKey
import at.asitplus.signum.indispensable.symmetric.requiresNonce
import at.asitplus.signum.supreme.agree.Ephemeral
import at.asitplus.signum.supreme.agree.keyAgreement
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.signum.supreme.symmetric.decrypt
import at.asitplus.signum.supreme.symmetric.encrypt
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.PublishedKeyMaterial
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.VerifySignature
import at.asitplus.wallet.lib.agent.VerifySignatureFun
import at.asitplus.wallet.lib.agent.requireTrustedSigningCertificate
import at.asitplus.wallet.lib.etsi.isIssuerOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import kotlin.io.encoding.Base64
import kotlin.jvm.JvmOverloads


/** Modify the [JwsHeader] before it being signed. */
fun interface JwsHeaderModifierFun {
    suspend operator fun invoke(it: JwsHeader): JwsHeader
}

/** How to identify the key material in a [JwsHeader] */
fun interface JwsHeaderIdentifierFun {
    suspend operator fun invoke(it: JwsHeader, keyMaterial: KeyMaterial): JwsHeader
}

/** Identify [KeyMaterial] with it's [KeyMaterial.jsonWebKey] in [JwsHeader.jsonWebKey]. */
class JwsHeaderJwk : JwsHeaderIdentifierFun {
    override suspend operator fun invoke(it: JwsHeader, keyMaterial: KeyMaterial) =
        it.copy(jsonWebKey = keyMaterial.jsonWebKey)
}

/**
 * Identify [KeyMaterial] with it's [KeyMaterial.getCertificate] in [JwsHeader.certificateChain] if it exists,
 * or [KeyMaterial.jsonWebKey] in [JwsHeader.jsonWebKey]. */
class JwsHeaderCertOrJwk : JwsHeaderIdentifierFun {
    override suspend operator fun invoke(it: JwsHeader, keyMaterial: KeyMaterial) =
        when (keyMaterial) {
            is PublishedKeyMaterial -> it.copy(
                keyId = keyMaterial.identifier,
                jsonWebKeySetUrl = keyMaterial.keySetUrl
            )

            else -> keyMaterial.getCertificate()?.let { x5c ->
                it.copy(certificateChain = listOf(x5c))
            } ?: it.copy(jsonWebKey = keyMaterial.jsonWebKey)
        }
}

/** Don't identify [KeyMaterial] at all in a [JwsHeader], used for SD-JWT KB-JWS. */
class JwsHeaderNone : JwsHeaderIdentifierFun {
    override suspend operator fun invoke(
        it: JwsHeader,
        keyMaterial: KeyMaterial,
    ) = it
}

/** Create a [JwsCompact], setting [JwsHeader.type] to the specified value */
fun interface SignJwtFun<P : Any> {
    suspend operator fun invoke(
        type: String?,
        payload: P,
        serializer: SerializationStrategy<P>,
    ): KmmResult<JwsCompactTyped<P>>
}

/** Create a [JwsCompact], setting [JwsHeader.type] to the specified value, applying the header modifier. */
fun interface SignJwtExtFun<P : Any> {
    suspend operator fun invoke(
        type: String?,
        payload: P,
        serializer: SerializationStrategy<P>,
        additionalHeaderModifier: JwsHeaderModifierFun,
    ): KmmResult<JwsCompactTyped<P>>
}

/** Create a [JwsCompact], setting [JwsHeader.type] to the specified value and applying [JwsHeaderIdentifierFun]. */
class SignJwt<P : Any>(
    val keyMaterial: KeyMaterial,
    val headerModifier: JwsHeaderIdentifierFun,
) : SignJwtFun<P> {
    override suspend operator fun invoke(
        type: String?,
        payload: P,
        serializer: SerializationStrategy<P>,
    ): KmmResult<JwsCompactTyped<P>> = catching {
        val header = JwsHeader(
            algorithm = keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
            type = type,
        ).let {
            headerModifier(it, keyMaterial)
        }
        JwsCompactTyped(
            JwsCompact(
                protectedHeader = header,
                payload = joseCompliantSerializer.encodeToString(serializer, payload).encodeToByteArray(),
                signer = { keyMaterial.sign(it).asKmmResult().getOrThrow().rawByteArray }
            ),
            payload
        )
    }
}

/** Create a [JwsCompact], setting [JwsHeader.type] to the specified value and applying [JwsHeaderIdentifierFun]. */
class SignJwtExt<P : Any>(
    val keyMaterial: KeyMaterial,
    val headerModifier: JwsHeaderIdentifierFun,
) : SignJwtExtFun<P> {
    override suspend operator fun invoke(
        type: String?,
        payload: P,
        serializer: SerializationStrategy<P>,
        additionalHeaderModifier: JwsHeaderModifierFun,
    ): KmmResult<JwsCompactTyped<P>> = catching {
        val header = JwsHeader(
            algorithm = keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
            type = type,
        ).let {
            headerModifier(it, keyMaterial)
        }.let {
            additionalHeaderModifier(it)
        }
        JwsCompactTyped(
            JwsCompact(
                protectedHeader = header,
                payload = joseCompliantSerializer.encodeToString(serializer, payload).encodeToByteArray(),
                signer = { keyMaterial.sign(it).asKmmResult().getOrThrow().rawByteArray }
            ),
            payload
        )
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


/** Create a [JweEncrypted], setting values for [JweHeader], uses ephemeral private keys. */
class EncryptJwe : EncryptJweFun {
    override suspend operator fun invoke(
        header: JweHeader,
        payload: String,
        recipientKey: JsonWebKey,
    ) = catching {
        val crv = recipientKey.curve
            ?: throw IllegalArgumentException("No curve in recipient key")
        val ephemeralKeyPair = KeyAgreementPrivateValue.ECDH.Ephemeral(crv).getOrThrow()
        val jweEncryption = header.encryption
            ?: throw IllegalArgumentException("No encryption in JWE header")
        val jweHeader = header.copy(
            jsonWebKey = recipientKey,
            ephemeralKeyPair = ephemeralKeyPair.publicValue.asCryptoPublicKey().toJsonWebKey()
        )
        JweUtils.encryptJwe(ephemeralKeyPair, recipientKey, jweEncryption, jweHeader, payload)
    }
}

/** Create a [JweEncrypted], setting values for [JweHeader]. */
fun interface EncryptJweSymmetricFun {
    suspend operator fun invoke(
        header: JweHeader,
        payload: String,
    ): KmmResult<JweEncrypted>
}

/** Create a [JweEncrypted], setting values for [JweHeader]. */
class EncryptJweSymmetric(
    val keyMaterial: SymmetricKey<AuthCapability<out KeyType>, NonceTrait, out KeyType>,
) : EncryptJweSymmetricFun {
    override suspend operator fun invoke(
        header: JweHeader,
        payload: String,
    ) = catching {
        val jweEncryption = header.encryption
            ?: throw IllegalArgumentException("No encryption in JWE header")
        val algorithm = jweEncryption.algorithm
        require(algorithm.requiresNonce())
        require(algorithm.isAuthenticated())

        JweUtils.encryptJwe(keyMaterial, header, payload)
    }
}

object JweUtils {
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

    internal suspend fun encryptJwe(
        ephemeralKeyPair: KeyAgreementPrivateValue.ECDH,
        recipientKey: JsonWebKey,
        jweEncryption: JweEncryption,
        jweHeader: JweHeader,
        payload: String,
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

        val headerSerialized = joseCompliantSerializer.encodeToString(jweHeader)
        val aad = headerSerialized.encodeToByteArray()
        val aadForCipher = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encodeToByteArray(aad)
        val bytes = payload.encodeToByteArray()
        val sealedBox = key.encrypt(data = bytes, authenticatedData = aadForCipher).getOrThrow()

        return JweEncrypted(jweHeader, aad, null, sealedBox.nonce, sealedBox.encryptedData, sealedBox.authTag)
    }

    internal suspend fun decryptJwe(
        keyMaterial: KeyMaterial,
        header: JweHeader,
        jweObject: JweEncrypted,
    ): JweDecrypted<String> {
        val z = (keyMaterial.getUnderLyingSigner() as Signer.ECDSA)
            .keyAgreement(header.ephemeralKeyPair?.toCryptoPublicKey()?.getOrThrow() as CryptoPublicKey.EC)
            .getOrThrow()
        val intermediateKey = concatKdf(
            z,
            header.encryption!!,
            header.agreementPartyUInfo,
            header.agreementPartyVInfo
        )
        require(header.algorithm == JweAlgorithm.ECDH_ES)
        val algorithm = header.encryption!!.algorithm
        require(algorithm.requiresNonce())
        require(algorithm.isAuthenticated())
        val key = algorithm.keyFromIntermediate(intermediateKey)
        val iv = jweObject.iv
        val aad = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encodeToByteArray(jweObject.headerAsParsed)
        val ciphertext = jweObject.ciphertext
        val authTag = jweObject.authTag
        val plaintext = key.decrypt(iv, ciphertext, authTag, aad).getOrThrow()
        val plainObject = plaintext.decodeToString()

        return JweDecrypted(header, plainObject)
    }

    internal suspend fun encryptJwe(
        key: SymmetricKey<AuthCapability<out KeyType>, NonceTrait, out KeyType>,
        jweHeader: JweHeader,
        payload: String,
    ): JweEncrypted {
        require(jweHeader.algorithm is JweAlgorithm.Symmetric)
        val keyAlgorithm = (jweHeader.algorithm as JweAlgorithm.Symmetric).algorithm
        if (key.algorithm != keyAlgorithm)
            throw IllegalArgumentException("Key algorithm mismatch: $keyAlgorithm != ${key.algorithm}")

        val contentAlgorithm = jweHeader.encryption!!.algorithm
        require(contentAlgorithm.requiresNonce())
        require(contentAlgorithm.isAuthenticated())
        val contentKey = contentAlgorithm.randomKey()
        val encryptedKey = key.encrypt(contentKey.jsonWebKeyBytes.getOrThrow()).getOrThrow()

        val headerWithContentKeyParams = jweHeader.copy(
            initializationVector = if (encryptedKey.hasNonce()) encryptedKey.nonce else null,
            authenticationTag = if (encryptedKey.isAuthenticated()) encryptedKey.authTag else null,
        )
        val headerSerialized = joseCompliantSerializer.encodeToString(headerWithContentKeyParams)
        val aad = headerSerialized.encodeToByteArray()
        val aadForCipher = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encodeToByteArray(aad)
        val bytes = payload.encodeToByteArray()
        val sealedBox = contentKey.encrypt(bytes, aadForCipher).getOrThrow()

        return JweEncrypted(
            headerWithContentKeyParams,
            aad,
            encryptedKey.encryptedData,
            sealedBox.nonce,
            sealedBox.encryptedData,
            sealedBox.authTag
        )
    }

    internal suspend fun decryptJwe(
        key: SymmetricKey<AuthCapability<out KeyType>, NonceTrait, out KeyType>,
        jweObject: JweEncrypted,
        header: JweHeader,
    ): JweDecrypted<String> {
        val keyAlgorithm = (header.algorithm as JweAlgorithm.Symmetric).algorithm
        if (key.algorithm != keyAlgorithm)
            throw IllegalArgumentException("Key algorithm mismatch: $keyAlgorithm != ${key.algorithm}")
        require(key is SymmetricKey.Integrated)

        // TODO Can we simplify this?
        val contentKeyBytes = if (key is SymmetricKey.Integrated.Authenticating.RequiringNonce) {
            key.decrypt(
                nonce = header.initializationVector!!,
                encryptedData = jweObject.encryptedKey!!,
                authTag = header.authenticationTag!!,
            ).getOrThrow()
        } else if (key is SymmetricKey.Integrated.Authenticating.WithoutNonce) {
            key.decrypt(
                encryptedData = jweObject.encryptedKey!!,
                authTag = header.authenticationTag!!,
            ).getOrThrow()
        } else if (key is SymmetricKey.Integrated.NonAuthenticating.WithoutNonce) {
            key.decrypt(
                encryptedData = jweObject.encryptedKey!!,
            ).getOrThrow()
        } else if (key is SymmetricKey.Integrated.NonAuthenticating.RequiringNonce) {
            key.decrypt(
                nonce = header.initializationVector!!,
                encryptedData = jweObject.encryptedKey!!,
            ).getOrThrow()
        } else {
            throw IllegalArgumentException("Unsupported key type: $key")
        }
        val contentAlgorithm = header.encryption!!.algorithm
        require(contentAlgorithm.requiresNonce())
        require(contentAlgorithm.isAuthenticated())

        // does not work as the method called doesn't guarantee the contract?
        //val contentKey = header.encryption!!.symmetricKeyFromJsonWebKeyBytes(contentKeyBytes).getOrThrow()
        val contentKey = if (contentAlgorithm.isIntegrated()) {
            contentAlgorithm.keyFrom(contentKeyBytes).getOrThrow()
        } else {
            contentAlgorithm.keyFrom(
                contentKeyBytes.drop(contentKeyBytes.size / 2).toByteArray(),
                contentKeyBytes.take(contentKeyBytes.size / 2).toByteArray()
            ).getOrThrow()
        }

        val iv = jweObject.iv
        val aad = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encodeToByteArray(jweObject.headerAsParsed)
        val ciphertext = jweObject.ciphertext
        val authTag = jweObject.authTag
        val plaintext = contentKey.decrypt(iv, ciphertext, authTag, aad).getOrThrow()
        val plainObject = plaintext.decodeToString()

        return JweDecrypted(header, plainObject)
    }
}

/** Decrypt a [JweEncrypted] object*/
fun interface DecryptJweFun {
    suspend operator fun invoke(
        jweObject: JweEncrypted,
    ): KmmResult<JweDecrypted<String>>
}

/**
 * Decrypts JWE payloads using the recipient's key material.
 * Use when handling encrypted messages targeted at the holder's key.
 */
class DecryptJwe(
    val keyMaterial: KeyMaterial,
) : DecryptJweFun {
    override suspend operator fun invoke(
        jweObject: JweEncrypted,
    ) = catching {
        val header = jweObject.header
        val alg = header.algorithm
            ?: throw IllegalArgumentException("No algorithm in JWE header")
        require(alg == JweAlgorithm.ECDH_ES)
        val enc = header.encryption
            ?: throw IllegalArgumentException("No encryption in JWE header")
        require(enc.algorithm.requiresNonce())
        require(enc.algorithm.isAuthenticated())
        val epk = header.ephemeralKeyPair
            ?: throw IllegalArgumentException("No epk in JWE header")
        require(epk.toCryptoPublicKey().getOrThrow() is CryptoPublicKey.EC)
        JweUtils.decryptJwe(keyMaterial, header, jweObject)
    }

}

/**
 * Decrypts JWE payloads with the ephemeral key referenced by the JWE's `kid` header, as per
 * [OpenID4VP 1.0, 8.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-encrypted-responses).
 *
 * *Note that this function only loads the key but does not consume it from [ephemeralEncryptionKeyService]!*
 */
class DecryptJweWithEphemeralKey(
    private val ephemeralEncryptionKeyService: EphemeralEncryptionKeyService,
    /** Long-lived key to fall back to, for client identifier schemes without client metadata in the request. */
    private val fallbackKeyMaterial: KeyMaterial? = null,
) : DecryptJweFun {
    override suspend operator fun invoke(
        jweObject: JweEncrypted,
    ) = catching {
        val keyId = jweObject.header.keyId
        val keyMaterial = keyId?.let { ephemeralEncryptionKeyService.consumeKey(it) }
            ?: fallbackKeyMaterial?.takeIf { keyId == null || it.identifier == keyId }
            ?: throw IllegalArgumentException("No decryption key for kid ${jweObject.header.keyId}")
        DecryptJwe(keyMaterial)(jweObject).getOrThrow()
    }
}

/**
 * Decrypts JWE payloads using a shared symmetric key.
 * Use when the content is encrypted for a pre-shared secret between parties.
 */
class DecryptJweSymmetric(
    val keyMaterial: SymmetricKey<AuthCapability<out KeyType>, NonceTrait, out KeyType>,
) : DecryptJweFun {
    override suspend operator fun invoke(
        jweObject: JweEncrypted,
    ) = catching {
        val header = jweObject.header
        header.algorithm
            ?: throw IllegalArgumentException("No algorithm in JWE header")
        val enc = header.encryption
            ?: throw IllegalArgumentException("No encryption in JWE header")
        val algorithm = enc.algorithm
        require(algorithm.requiresNonce())
        require(algorithm.isAuthenticated())

        JweUtils.decryptJwe(keyMaterial, jweObject, header)
    }
}


/**
 * Clients need to retrieve the URL passed in as the only argument, and parse the content to [JsonWebKeySet].
 */
fun interface JwkSetRetrieverFunction {
    suspend operator fun invoke(url: String): JsonWebKeySet?
}

/**
 * Clients get the parsed [JwsCompact] and need to provide a set of keys, which will be used for verification one-by-one.
 */
fun interface PublicJsonWebKeyLookup {
    suspend operator fun invoke(
        jwsObject: JwsCompact,
    ): Set<JsonWebKey>?
}

/**
 * Assumes that truststore is populated by x509 certificates
 */
@Deprecated(
    "Trusted certificates are not selected per signed object, use TrustedCertificates instead",
    ReplaceWith("at.asitplus.wallet.lib.agent.TrustedCertificates")
)
fun interface TrustStoreLookup {
    suspend operator fun invoke(
        jwsObject: JwsCompact,
    ): Set<X509Certificate>?
}

fun interface VerifyJwsSignatureFun {
    suspend operator fun invoke(
        jwsObject: JwsCompact,
        publicKey: CryptoPublicKey,
    ): KmmResult<Verifier.Success>
}

/**
 * Verifies a JWS signature against a provided public key.
 * Use when the verification key is already resolved out of band.
 */
class VerifyJwsSignature @JvmOverloads constructor(
    val verifySignature: VerifySignatureFun = VerifySignature(),
) : VerifyJwsSignatureFun {
    override suspend operator fun invoke(
        jwsObject: JwsCompact,
        publicKey: CryptoPublicKey,
    ) = catching {
        val jwsAlgorithm = jwsObject.jwsHeader.algorithm
        require(jwsAlgorithm is JwsAlgorithm.Signature) { "Algorithm not supported: $jwsAlgorithm" }
        verifySignature(
            jwsObject.signatureInput,
            jwsObject.signature,
            jwsAlgorithm.algorithm,
            publicKey,
        ).getOrThrow()
    }
}

fun interface VerifyJwsSignatureWithKeyFun {
    suspend operator fun invoke(
        jwsObject: JwsCompact,
        signer: JsonWebKey,
    ): KmmResult<Verifier.Success>
}

/**
 * Verifies a JWS signature using a JSON Web Key.
 * Use when the signer key is available in JWK form.
 */
class VerifyJwsSignatureWithKey @JvmOverloads constructor(
    val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(),
) : VerifyJwsSignatureWithKeyFun {
    override suspend operator fun invoke(
        jwsObject: JwsCompact,
        signer: JsonWebKey,
    ) = verifyJwsSignature(jwsObject, signer.toCryptoPublicKey().getOrThrow())
}

fun interface VerifyJwsSignatureWithCnfFun {
    suspend operator fun invoke(
        jwsObject: JwsCompact,
        cnf: ConfirmationClaim,
    ): Boolean
}

/**
 * Verifies a JWS signature using the confirmation claim (cnf) key material.
 * Use when tokens bind signatures to a subject key in the payload.
 */
class VerifyJwsSignatureWithCnf @JvmOverloads constructor(
    val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(),
    /**
     * Need to implement if JSON web keys in JWS headers are referenced by a `kid`, and need to be retrieved from
     * the `jku`.
     */
    val jwkSetRetriever: JwkSetRetrieverFunction = JwkSetRetrieverFunction { null },
) : VerifyJwsSignatureWithCnfFun {
    override suspend operator fun invoke(
        jwsObject: JwsCompact,
        cnf: ConfirmationClaim,
    ) = cnf.loadPublicKeys().any { verifyJwsSignature(jwsObject, it).isSuccess }

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

/**
 * The public key used to validate the signature on the Status List Token
 * defined in [I-D.ietf-oauth-status-list] MUST be included in the x5c JOSE header of the Token.
 * The X.509 certificate of the trust anchor MUST NOT be included in the x5c JOSE header of the Status List Token.
 * The X.509 certificate signing the request MUST NOT be self-signed.
 */
class VerifyStatusListTokenHAIP @JvmOverloads constructor(
    val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(),
    /** Certificates of trusted issuers of status list tokens, if trust in the issuer shall be evaluated */
    val trustedIssuers: TrustedCertificates? = null,
) : VerifyJwsObjectFun {

    override suspend operator fun invoke(jwsObject: JwsCompact) = catching {
        val certChain: CertificateChain = jwsObject.jwsHeader.certificateChain
            ?: throw IllegalArgumentException("Certificate Chain MUST not be empty")
        // HAIP requires the signing certificate to be issued by a trust anchor, so direct trust is not an option
        val signingCert = trustedIssuers
            ?.let { certChain.requireTrustedSigningCertificate(it, allowDirectTrust = false) }
            ?: certChain.leaf.also {
                require(it.isIssuerOf(it).isFailure) {
                    "The certificate signing the request MUST NOT be self-signed"
                }
            }
        verifyJwsSignature(jwsObject, signingCert.decodedPublicKey.getOrThrow()).getOrThrow()
    }
}

/**
 * Verifies a JWS against a fixed list of certificates of trusted issuers, supplied by [trustedIssuers], e.g.
 * extracted from an ETSI trust list.
 *
 * The certificate transported in [JwsHeader.certificateChain] has to be signed by one of those certificates,
 * see [requireTrustedSigningCertificate] for the exact rules. Any other key material asserted by the JWS
 * ([JwsHeader.jsonWebKey], [JwsHeader.keyId], [JwsHeader.jsonWebKeySetUrl]) is ignored, a JWS without `x5c`
 * can never be verified by this.
 *
 * Use this to verify issuer signatures on credentials, i.e. the SD-JWT or VC-JWS signed by the issuer. Note
 * that holder signatures (key binding, proof of possession, a signed presentation) are self-asserted by design,
 * so [VerifyJwsObject] is the correct choice for those.
 */
class VerifyJwsObjectTrustedCertificate @JvmOverloads constructor(
    val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(),
    val trustedIssuers: TrustedCertificates,
) : VerifyJwsObjectFun {
    override suspend operator fun invoke(jwsObject: JwsCompact) = catching {
        val signingCertificate = jwsObject.jwsHeader.certificateChain
            .requireTrustedSigningCertificate(trustedIssuers)
        verifyJwsSignature(jwsObject, signingCertificate.decodedPublicKey.getOrThrow()).getOrThrow()
    }
}

fun interface VerifyJwsObjectFun {
    suspend operator fun invoke(
        jwsObject: JwsCompact,
    ): KmmResult<Verifier.Success>
}

/**
 * Verifies a JWS against the key material asserted by the JWS itself, i.e. its header values
 * (see [JwsHeader.jsonWebKey], [JwsHeader.keyId], [JwsHeader.certificateChain]) or a JSON web key set
 * referenced by [JwsHeader.jsonWebKeySetUrl].
 *
 * This makes **no trust decision**: it only establishes that the JWS is internally consistent, i.e. signed by
 * whoever the JWS claims signed it. Use it where a self-asserted key is the correct input (holder key binding,
 * proof of possession, DPoP). Where the signer needs to be an entity from a trust list, use
 * [VerifyJwsObjectTrusted] instead.
 */
class VerifyJwsObject @JvmOverloads constructor(
    val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(),
    /**
     * Need to implement if JSON web keys in JWS headers are referenced by a `kid`, and need to be retrieved from
     * the `jku`.
     */
    val jwkSetRetriever: JwkSetRetrieverFunction = JwkSetRetrieverFunction { null },
) : VerifyJwsObjectFun {

    /** Set only by the deprecated constructor taking a [PublicJsonWebKeyLookup]. */
    private var trustedDelegate: VerifyJwsObjectFun? = null

    @Deprecated(
        "A key lookup used to be ignored whenever the JWS header asserted a key itself, so it could not " +
                "enforce anything. Use VerifyJwsObjectTrusted to treat the keys as a trust list, or drop the " +
                "parameter to keep verifying against the key asserted by the JWS.",
        ReplaceWith("VerifyJwsObjectTrusted(verifyJwsSignature, publicKeyLookup)")
    )
    constructor(
        verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(),
        jwkSetRetriever: JwkSetRetrieverFunction = JwkSetRetrieverFunction { null },
        publicKeyLookup: PublicJsonWebKeyLookup,
    ) : this(verifyJwsSignature, jwkSetRetriever) {
        trustedDelegate = VerifyJwsObjectTrusted(verifyJwsSignature, publicKeyLookup)
    }

    override suspend operator fun invoke(jwsObject: JwsCompact) = trustedDelegate?.invoke(jwsObject) ?: catching {
        require(jwsObject.loadPublicKeys().any { verifyJwsSignature(jwsObject, it).isSuccess }) {
            "Invalid Signature"
        }
        Verifier.Success
    }

    /**
     * Returns a list of public keys that may have been used to sign this [JwsCompact]
     * by evaluating its header values (see [JwsHeader.jsonWebKey], [JwsHeader.jsonWebKeySetUrl]).
     */
    private suspend fun JwsCompact.loadPublicKeys(): Set<CryptoPublicKey> =
        jwsHeader.publicKey?.let { setOf(it) }
            ?: jwsHeader.jsonWebKeySetUrl?.let {
                retrieveJwkFromKeySetUrl(it, jwsHeader.keyId)?.let { setOf(it) }
            } ?: setOf()

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

/**
 * Verifies a JWS against a fixed set of trusted keys, e.g. entries of a trust list, supplied by [trustedKeys].
 *
 * Those keys are the *only* accepted signers: key material asserted by the JWS itself
 * ([JwsHeader.jsonWebKey], [JwsHeader.keyId], [JwsHeader.certificateChain], [JwsHeader.jsonWebKeySetUrl])
 * never supplies a verification key. If the header does assert a key, it must be contained in [trustedKeys],
 * otherwise verification fails.
 *
 * Note that this does not build a certificate path to a trust anchor, it compares public keys.
 */
class VerifyJwsObjectTrusted @JvmOverloads constructor(
    val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(),
    val trustedKeys: PublicJsonWebKeyLookup,
) : VerifyJwsObjectFun {
    override suspend operator fun invoke(jwsObject: JwsCompact) = catching {
        val trusted = trustedKeys(jwsObject)
            ?.mapNotNull { it.toCryptoPublicKey().getOrNull() }
            ?.toSet() ?: setOf()
        require(trusted.isNotEmpty()) { "No trusted keys" }
        // If the JWS names its signer, that signer has to be trusted, we don't fall back to the other entries
        val candidates = jwsObject.jwsHeader.publicKey?.let { headerKey ->
            require(headerKey in trusted) { "Signer asserted in JWS header is not trusted" }
            setOf(headerKey)
        } ?: trusted
        require(candidates.any { verifyJwsSignature(jwsObject, it).isSuccess }) {
            "Invalid Signature"
        }
        Verifier.Success
    }
}

/**
 * Verifies a JWS object and additionally validates JAdES-B-B requirements.
 * Ensures that the JWS signature is valid using `VerifyJwsObject` and further enforces
 * the integrity of the signing certificate chain by validating the `x5t#o`
 * (X.509 certificate thumbprint) header parameter against the leaf certificate
 * in the `x5c` chain
 */
class VerifyJwsObjectJades @JvmOverloads constructor(
    val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
) : VerifyJwsObjectFun {

    @Serializable
    private data class JadesX5tO(
        @SerialName("digAlg") val digAlg: String,
        @SerialName("digVal") val digVal: String
    )

    override suspend operator fun invoke(jwsObject: JwsCompact): KmmResult<Verifier.Success> = catching {
        verifyJwsObject(jwsObject).getOrThrow()
        validateX5tO(jwsObject).getOrThrow()
        Verifier.Success
    }

    /**
     * Validates the 'x5t#o' parameter against the leaf certificate of the 'x5c' chain.
     * The calculated thumbprint of the leaf certificate must match the value from `x5t#o`
     */
    private fun validateX5tO(jwsObject: JwsCompact): KmmResult<Unit> = catching {
        val headerJsonStr = jwsObject.plainProtectedHeader.decodeToString()
        val rawHeaderJson = joseCompliantSerializer.parseToJsonElement(headerJsonStr).jsonObject
        val x5tOElement = rawHeaderJson["x5t#o"] ?: return@catching
        val x5tO = joseCompliantSerializer.decodeFromJsonElement<JadesX5tO>(x5tOElement)

        val certChain = jwsObject.jwsHeader.certificateChain
            ?: throw IllegalArgumentException("JAdES Compliance Failure: 'x5t#o' parameter requires an 'x5c' certificate chain.")

        val digestAlgorithm = parseJadesDigestAlgorithm(x5tO.digAlg)

        val certBytes = certChain.leaf.encodeToDer()
        val calculatedHash = digestAlgorithm.digest(certBytes)
        val calculatedB64Url = calculatedHash.encodeToString(Base64UrlStrict)

        require(calculatedB64Url == x5tO.digVal) {
            "JAdES Integrity Violation: The calculated certificate thumbprint does not match 'x5t#o'."
        }
    }

    /**
     * Parses the JAdES digest algorithm string into a [Digest] instance.
     * Throws [IllegalArgumentException] if the algorithm is forbidden (like SHA-256 in x5t#o) or unsupported.
     */
    private fun parseJadesDigestAlgorithm(alg: String): Digest {
        return when (alg.lowercase()) {
            "sha-256", "s256" -> throw IllegalArgumentException(
                "JAdES Compliance Failure: 'sha-256' is forbidden in 'x5t#o'. Use 'x5t#256' instead."
            )

            "sha-384", "s384" -> Digest.SHA384
            "sha-512", "s512" -> Digest.SHA512
            else -> throw IllegalArgumentException(
                "Unsupported JAdES digest algorithm: '$alg'. System supports 'sha-384' or 'sha-512'."
            )
        }
    }
}

/**
 * Derives the key, for use in content encryption in JWE,
 * per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1)
 */
@Suppress("UNCHECKED_CAST")
private fun SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<*>, NonceTrait.Required, *>.keyFromIntermediate(
    jweKeyBytes: ByteArray,
): SymmetricKey<AuthCapability.Authenticated<*>, NonceTrait.Required, *> = ((if (hasDedicatedMac())
    keyFrom(
        jweKeyBytes.drop(jweKeyBytes.size / 2).toByteArray(),
        jweKeyBytes.take(jweKeyBytes.size / 2).toByteArray()
    ).getOrThrow()
else
    keyFrom(jweKeyBytes).getOrThrow()) as SymmetricKey<AuthCapability.Authenticated<*>, NonceTrait.Required, *>)
