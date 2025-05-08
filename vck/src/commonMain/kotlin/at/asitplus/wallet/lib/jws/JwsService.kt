package at.asitplus.wallet.lib.jws

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.asn1.encoding.encodeTo4Bytes
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweEncryption.*
import at.asitplus.signum.indispensable.josef.JwsExtensions.prependWith4BytesSize
import at.asitplus.signum.indispensable.josef.JwsSigned.Companion.prepareJwsSignatureInput
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.agree.Ephemeral
import at.asitplus.signum.supreme.agree.keyAgreement
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.symmetric.decrypt
import at.asitplus.signum.supreme.symmetric.encrypt
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToByteArray
import kotlinx.serialization.SerializationStrategy


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
) : EncryptJweFun {
    override suspend operator fun invoke(
        header: JweHeader,
        payload: String, recipientKey: JsonWebKey,
    ) = catching {
        val cryptoPublicKey = recipientKey.toCryptoPublicKey().getOrThrow()
        require(cryptoPublicKey is CryptoPublicKey.EC)
        val crv = recipientKey.curve
            ?: throw IllegalArgumentException("No curve in recipient key")
        val ephemeralKeyPair = KeyAgreementPrivateValue.ECDH.Ephemeral(crv).getOrThrow()
        val jweEncryption = header.encryption
            ?: throw IllegalArgumentException("No encryption in JWE header")
        val jweHeader = header.copy(
            jsonWebKey = keyMaterial.jsonWebKey,
            ephemeralKeyPair = ephemeralKeyPair.publicValue.asCryptoPublicKey().toJsonWebKey()
        )
        JweUtils.encryptJwe(ephemeralKeyPair, recipientKey, jweEncryption, jweHeader, payload)
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

        val headerSerialized = jweHeader.serialize()
        val aad = headerSerialized.encodeToByteArray()
        val aadForCipher = aad.encodeToByteArray(Base64UrlStrict)
        val bytes = payload.encodeToByteArray()
        val sealedBox = key.encrypt(data = bytes, authenticatedData = aadForCipher).getOrThrow()

        return JweEncrypted(jweHeader, aad, null, sealedBox.nonce, sealedBox.encryptedData, sealedBox.authTag)
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
        val z = (keyMaterial.getUnderLyingSigner() as Signer.ECDSA)
            .keyAgreement(epk.toCryptoPublicKey().getOrThrow() as CryptoPublicKey.EC)
            .getOrThrow()
        val intermediateKey = JweUtils.concatKdf(
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
        val plaintext = key.decrypt(iv, ciphertext, authTag, aad).getOrThrow()
        val plainObject = plaintext.decodeToString()

        JweDecrypted(header, plainObject)
    }
}


/**
 * Clients need to retrieve the URL passed in as the only argument, and parse the content to [JsonWebKeySet].
 */
fun interface JwkSetRetrieverFunction {
    operator fun invoke(url: String): JsonWebKeySet?
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
    val jwkSetRetriever: JwkSetRetrieverFunction = JwkSetRetrieverFunction { null },
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

fun interface VerifyJwsObjectFun {
    suspend operator fun invoke(jwsObject: JwsSigned<*>): Boolean
}

class VerifyJwsObject(
    val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(),
    /**
     * Need to implement if JSON web keys in JWS headers are referenced by a `kid`, and need to be retrieved from
     * the `jku`.
     */
    val jwkSetRetriever: JwkSetRetrieverFunction = JwkSetRetrieverFunction { null },
    /** Need to implement if valid keys for JWS are transported somehow out-of-band, e.g. provided by a trust store */
    val publicKeyLookup: PublicJsonWebKeyLookup = PublicJsonWebKeyLookup { null },
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

/**
 * Derives the key, for use in content encryption in JWE,
 * per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1)
 */
private inline fun SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<*>, NonceTrait.Required, *>.keyFromIntermediate(
    jweKeyBytes: ByteArray,
): SymmetricKey<AuthCapability.Authenticated<*>, NonceTrait.Required, *> {
    return ((if (hasDedicatedMac())
        keyFrom(
            jweKeyBytes.drop(jweKeyBytes.size / 2).toByteArray(),
            jweKeyBytes.take(jweKeyBytes.size / 2).toByteArray()
        ).getOrThrow()
    else
        keyFrom(jweKeyBytes).getOrThrow()) as SymmetricKey<AuthCapability.Authenticated<*>, NonceTrait.Required, *>)
}
