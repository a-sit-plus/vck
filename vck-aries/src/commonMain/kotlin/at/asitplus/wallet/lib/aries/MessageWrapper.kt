package at.asitplus.wallet.lib.aries

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.jws.*
import at.asitplus.wallet.lib.msg.JsonWebMessage
import io.github.aakira.napier.Napier

class MessageWrapper(
    private val keyMaterial: KeyMaterial,
    private val jwsService: JwsService = DefaultJwsService(DefaultCryptoService(keyMaterial)),
    private val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(),
) {

    suspend fun parseMessage(it: String): ReceivedMessage {
        val jwsSigned = JwsSigned.deserialize(it).getOrNull()
        if (jwsSigned != null) {
            return parseJwsMessage(jwsSigned)
        }
        val jweEncrypted = JweEncrypted.deserialize(it).getOrNull()
        if (jweEncrypted != null)
            return parseJweMessage(jweEncrypted, it)
        return ReceivedMessage.Error
            .also { Napier.w("Could not parse message: $it") }
    }

    private suspend fun parseJweMessage(
        jweObject: JweEncrypted,
        serialized: String
    ): ReceivedMessage {
        Napier.d("Parsing JWE ${jweObject.serialize()}")
        val joseObject = jwsService.decryptJweObject(jweObject, serialized).getOrElse {
            Napier.w("Could not parse JWE", it)
            return ReceivedMessage.Error
        }
        val payloadString = joseObject.payload.decodeToString()
        if (joseObject.header.contentType == JwsContentTypeConstants.DIDCOMM_SIGNED_JSON) {
            val parsed = JwsSigned.deserialize(payloadString).getOrNull()
                ?: return ReceivedMessage.Error
                    .also { Napier.w("Could not parse inner JWS") }
            return parseJwsMessage(parsed)
        }
        if (joseObject.header.contentType == JwsContentTypeConstants.DIDCOMM_PLAIN_JSON) {
            val message = JsonWebMessage.deserialize(payloadString).getOrElse { ex ->
                return ReceivedMessage.Error
                    .also { Napier.w("Could not parse plain message", ex) }
            }
            return ReceivedMessage.Success(message, joseObject.header.publicKey)
        }
        return ReceivedMessage.Error
            .also { Napier.w("ContentType not matching") }
    }

    private fun parseJwsMessage(joseObject: JwsSigned): ReceivedMessage {
        Napier.d("Parsing JWS ${joseObject.serialize()}")
        if (!verifierJwsService.verifyJwsObject(joseObject))
            return ReceivedMessage.Error
                .also { Napier.w("Signature invalid") }
        if (joseObject.header.contentType == JwsContentTypeConstants.DIDCOMM_PLAIN_JSON) {
            val payloadString = joseObject.payload.decodeToString()
            val message = JsonWebMessage.deserialize(payloadString).getOrElse { ex ->
                return ReceivedMessage.Error
                    .also { Napier.w("Could not parse plain message", ex) }
            }
            return ReceivedMessage.Success(message, joseObject.header.publicKey?.toJsonWebKey())
        }
        return ReceivedMessage.Error
            .also { Napier.w("ContentType not matching") }
    }

    suspend fun createSignedAndEncryptedJwe(jwm: JsonWebMessage, recipientKey: JsonWebKey) = catching {
        val jwt = createSignedJwt(jwm).getOrElse {
            Napier.w("Can not create signed JWT for encryption", it)
            throw it
        }
        jwsService.encryptJweObject(
            JwsContentTypeConstants.DIDCOMM_ENCRYPTED_JSON,
            jwt.serialize().encodeToByteArray(),
            recipientKey,
            JwsContentTypeConstants.DIDCOMM_SIGNED_JSON,
            JweAlgorithm.ECDH_ES,
            JweEncryption.A256GCM,
        ).getOrThrow()
    }

    suspend fun createSignedJwt(jwm: JsonWebMessage): KmmResult<JwsSigned> = jwsService.createSignedJwt(
        JwsContentTypeConstants.DIDCOMM_SIGNED_JSON,
        jwm.serialize().encodeToByteArray(),
        JwsContentTypeConstants.DIDCOMM_PLAIN_JSON
    )

}