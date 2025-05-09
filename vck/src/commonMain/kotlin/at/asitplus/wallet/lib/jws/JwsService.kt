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
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.symmetric.decrypt
import at.asitplus.signum.supreme.symmetric.encrypt
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToByteArray
import kotlinx.serialization.SerializationStrategy
import kotlin.random.Random


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

fun interface SignJwtFun<P : Any> {
    suspend operator fun invoke(
        type: String?,
        payload: P,
        serializer: SerializationStrategy<P>,
    ): KmmResult<JwsSigned<P>>
}

data class SignJwt<P : Any>(
    val keyMaterial: KeyMaterial,
    val headerModifier: JwsHeaderIdentifierFun,
) : SignJwtFun<P> {
    override suspend operator fun invoke(
        type: String?,
        payload: P,
        serializer: SerializationStrategy<P>,
    ) = catching {
        val header = JwsHeader(
            algorithm = keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
            type = type,
        ).let { headerModifier(it, keyMaterial) }
        val plainSignatureInput = prepareJwsSignatureInput(header, payload, serializer, vckJsonSerializer)
        val signature = keyMaterial.sign(plainSignatureInput).asKmmResult().getOrThrow()
        JwsSigned(header, payload, signature, plainSignatureInput)
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
    ): EncryptJweFun = { header, payload, recipientKey ->
        catching {

            val cryptoPublicKey = recipientKey.toCryptoPublicKey().getOrThrow()
            require(cryptoPublicKey is CryptoPublicKey.EC)
            val crv = recipientKey.curve
                ?: throw IllegalArgumentException("No curve in recipient key")
            val ephemeralKeyPair = KeyAgreementPrivateValue.ECDH.Ephemeral(crv).getOrThrow()
            val enc = header.encryption
            require(enc != null)

            val jweHeader = header.copy(
                jsonWebKey = keyMaterial.jsonWebKey,
                ephemeralKeyPair = ephemeralKeyPair.publicValue.asCryptoPublicKey().toJsonWebKey()
            )

            JweUtils.encryptJwe(ephemeralKeyPair, recipientKey, enc, jweHeader, payload)
        }
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
        val sealedBox =key.encrypt(data= bytes, authenticatedData = aadForCipher).getOrThrow()

        return JweEncrypted(jweHeader, aad, null, sealedBox.nonce, sealedBox.encryptedData, sealedBox.authTag)
    }

}

/** Decrypt a [JweEncrypted] object*/
typealias DecryptJweFun = suspend (
    jweObject: JweEncrypted,
) -> KmmResult<JweDecrypted<String>>

object DecryptJwe {
    operator fun invoke(
        keyMaterial: KeyMaterial,
    ): DecryptJweFun = { jweObject ->
        catching {
            val header = jweObject.header
            val alg = header.algorithm
                ?: throw IllegalArgumentException("No algorithm in JWE header")
            val enc = header.encryption
                ?: throw IllegalArgumentException("No encryption in JWE header")
            val epk = header.ephemeralKeyPair
                ?: throw IllegalArgumentException("No epk in JWE header")
            val z = (keyMaterial.getUnderLyingSigner() as Signer.ECDSA).keyAgreement(epk.toCryptoPublicKey().getOrThrow() as CryptoPublicKey.EC).getOrThrow()
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
            val plaintext =  key.decrypt(iv, ciphertext, authTag, aad).getOrThrow()
            val plainObject = plaintext.decodeToString()

            JweDecrypted(header, plainObject)
        }
    }

    internal suspend fun performKeyAgreement(
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