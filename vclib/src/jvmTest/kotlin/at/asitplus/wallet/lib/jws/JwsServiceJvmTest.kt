package at.asitplus.wallet.lib.jws

import at.asitplus.crypto.datatypes.JwsAlgorithm
import at.asitplus.crypto.datatypes.jws.*
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.data.jsonSerializer
import com.benasher44.uuid.uuid4
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.mpp.timeInMillis
import kotlinx.serialization.encodeToString
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

class JwsServiceJvmTest : FreeSpec({

    lateinit var cryptoService: CryptoService
    lateinit var jwsService: JwsService
    lateinit var verifierJwsService: VerifierJwsService
    lateinit var randomPayload: String
    lateinit var publicKeyDesc: List<Pair<KeyPair, JwsAlgorithm>>

    "EC" - {
        withData(256, 384, 521) { bits ->
            publicKeyDesc = List<Pair<KeyPair, JwsAlgorithm>>(5) {
                val keyPair = KeyPairGenerator.getInstance("EC").apply {
                    initialize(bits)
                }.genKeyPair()
                val algo = when (bits) {
                    256 -> JwsAlgorithm.ES256
                    384 -> JwsAlgorithm.ES384
                    521 -> JwsAlgorithm.ES512
                    else -> JwsAlgorithm.NON_JWS_SHA1_WITH_RSA.also { throw IllegalArgumentException("Unknown EC Curve size") } // necessary(compiler), but redundant else-branch
                }
                Pair(keyPair, algo)
            }
            withData(publicKeyDesc) { (keyPair, algorithm) ->
                cryptoService = DefaultCryptoService(keyPair, algorithm)
                jwsService = DefaultJwsService(cryptoService)
                verifierJwsService = DefaultVerifierJwsService()
                randomPayload = uuid4().toString()

                withData("signed object from ext. library can be verified: $algorithm", Pair(keyPair, algorithm)) {
                    val stringPayload = jsonSerializer.encodeToString(randomPayload)
//                    if (algorithm == JwsAlgorithm.ES512){
//                        print(stringPayload)
//                    }
                    val libHeader = JWSHeader.Builder(JWSAlgorithm(algorithm.name)).type(JOSEObjectType("JWT"))
                        .keyID(cryptoService.jsonWebKey.keyId).build()
                    val libObject = JWSObject(libHeader, Payload(stringPayload)).also {
                        it.sign(ECDSASigner(keyPair.private as ECPrivateKey))
                    }
                    libObject.verify(ECDSAVerifier(keyPair.public as ECPublicKey)) shouldBe true

                    // Parsing to our structure verifying payload
                    val signedLibObject = libObject.serialize()
                    val parsedJwsSigned = JwsSigned.parse(signedLibObject)
                    parsedJwsSigned.shouldNotBeNull()
                    parsedJwsSigned.payload.decodeToString() shouldBe stringPayload
                    val parsedSig = parsedJwsSigned.signature.serialize()
                    // verifying external JWT with our service
                    val result = verifierJwsService.verifyJwsObject(parsedJwsSigned)
                    result shouldBe true
                }

                withData("signed object can be verified with ext. library: $algorithm", Pair(keyPair, algorithm)) {
                    val stringPayload = jsonSerializer.encodeToString(randomPayload)
                    val signed = jwsService.createSignedJwt(JwsContentTypeConstants.JWT, stringPayload.encodeToByteArray())

                    verifierJwsService.verifyJwsObject(signed!!) shouldBe true
                    val parsed = JWSObject.parse(signed.serialize())
                    parsed.shouldNotBeNull()
                    parsed.payload.toString() shouldBe stringPayload
                    val result = parsed.verify(ECDSAVerifier(keyPair.public as ECPublicKey))
                    result shouldBe true
                }

                withData("encrypted object from ext. library can be decrypted: $algorithm", Pair(keyPair, algorithm)) {
                    val stringPayload = jsonSerializer.encodeToString(randomPayload)
                    val libJweHeader = JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                        .type(JOSEObjectType(JwsContentTypeConstants.DIDCOMM_ENCRYPTED_JSON))
                        .contentType(JwsContentTypeConstants.DIDCOMM_PLAIN_JSON).keyID(cryptoService.jsonWebKey.keyId)
                        .build()
                    val libJweObject = JWEObject(libJweHeader, Payload(stringPayload)).also {
                        it.encrypt(ECDHEncrypter(keyPair.public as ECPublicKey))
                    }
                    val encryptedJwe = libJweObject.serialize()

                    val parsedJwe = JweEncrypted.parse(encryptedJwe)
                    parsedJwe.shouldNotBeNull()

                    jwsService.decryptJweObject(
                        parsedJwe, encryptedJwe
                    )?.payload?.decodeToString() shouldBe stringPayload
                }

                withData("encrypted object can be decrypted with ext. library: $algorithm", Pair(keyPair, algorithm)) {
                    val stringPayload = jsonSerializer.encodeToString(randomPayload)
                    val encrypted = jwsService.encryptJweObject(
                        JwsContentTypeConstants.DIDCOMM_ENCRYPTED_JSON,
                        stringPayload.encodeToByteArray(),
                        cryptoService.jsonWebKey,
                        JwsContentTypeConstants.DIDCOMM_PLAIN_JSON,
                        JweAlgorithm.ECDH_ES,
                        JweEncryption.A256GCM,
                    )

                    val parsed = JWEObject.parse(encrypted)
                    parsed.shouldNotBeNull()
                    parsed.payload.shouldBeNull()

                    parsed.decrypt(ECDHDecrypter(keyPair.private as ECPrivateKey))
                    parsed.payload.toString() shouldBe stringPayload
                }
            }
        }
    }
})
