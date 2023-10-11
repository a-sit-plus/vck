package at.asitplus.wallet.lib.aries

import at.asitplus.crypto.datatypes.jws.*
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.msg.JsonWebMessage
import io.github.aakira.napier.Napier

class MessageWrapper(
    private val cryptoService: CryptoService,
    private val jwsService: JwsService = DefaultJwsService(cryptoService),
    private val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(),
) {

    suspend fun parseMessage(it: String): ReceivedMessage {
        val jwsSigned = JwsSigned.parse(it)
        if (jwsSigned != null) {
            return parseJwsMessage(jwsSigned, it)
        }
        val jweEncrypted = JweEncrypted.parse(it)
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
        val joseObject = jwsService.decryptJweObject(jweObject, serialized)
            ?: return ReceivedMessage.Error
                .also { Napier.w("Could not parse JWE") }
        val payloadString = joseObject.payload.decodeToString()
        if (joseObject.header.contentType == JwsContentTypeConstants.DIDCOMM_SIGNED_JSON) {
            val parsed = JwsSigned.parse(payloadString)
                ?: return ReceivedMessage.Error
                    .also { Napier.w("Could not parse inner JWS") }
            return parseJwsMessage(parsed, payloadString)
        }
        if (joseObject.header.contentType == JwsContentTypeConstants.DIDCOMM_PLAIN_JSON) {
            val message = JsonWebMessage.deserialize(payloadString)
                ?: return ReceivedMessage.Error
                    .also { Napier.w("Could not parse plain message") }
            return ReceivedMessage.Success(message, joseObject.header.publicKey)
        }
        return ReceivedMessage.Error
            .also { Napier.w("ContentType not matching") }
    }

    private fun parseJwsMessage(joseObject: JwsSigned, serialized: String): ReceivedMessage {
        Napier.d("Parsing JWS ${joseObject.serialize()}")
        if (!verifierJwsService.verifyJwsObject(joseObject, serialized))
            return ReceivedMessage.Error
                .also { Napier.w("Signature invalid") }
        if (joseObject.header.contentType == JwsContentTypeConstants.DIDCOMM_PLAIN_JSON) {
            val payloadString = joseObject.payload.decodeToString()
            val message = JsonWebMessage.deserialize(payloadString)
                ?: return ReceivedMessage.Error
                    .also { Napier.w("Could not parse plain message") }
            return ReceivedMessage.Success(message, joseObject.header.publicKey)
        }
        return ReceivedMessage.Error
            .also { Napier.w("ContentType not matching") }
    }

    fun createEncryptedJwe(jwm: JsonWebMessage, recipientKey: JsonWebKey): String? {
        val jwePayload = jwm.serialize().encodeToByteArray()
        return jwsService.encryptJweObject(
            JwsContentTypeConstants.DIDCOMM_ENCRYPTED_JSON,
            jwePayload,
            recipientKey,
            JwsContentTypeConstants.DIDCOMM_PLAIN_JSON,
            JweAlgorithm.ECDH_ES,
            JweEncryption.A256GCM,
        )
    }

    suspend fun createSignedAndEncryptedJwe(jwm: JsonWebMessage, recipientKey: JsonWebKey): String? {
        val jwePayload = createSignedJwt(jwm)?.encodeToByteArray()
            ?: return null
                .also { Napier.w("Can not create signed JWT for encryption") }
        return jwsService.encryptJweObject(
            JwsContentTypeConstants.DIDCOMM_ENCRYPTED_JSON,
            jwePayload,
            recipientKey,
            JwsContentTypeConstants.DIDCOMM_SIGNED_JSON,
            JweAlgorithm.ECDH_ES,
            JweEncryption.A256GCM,
        )
    }

    suspend fun createSignedJwt(jwm: JsonWebMessage): String? {
        return jwsService.createSignedJwt(
            JwsContentTypeConstants.DIDCOMM_SIGNED_JSON,
            jwm.serialize().encodeToByteArray(),
            JwsContentTypeConstants.DIDCOMM_PLAIN_JSON
        )
    }

}