package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.DCAPIHandover.Companion.TYPE_DCAPI
import at.asitplus.dcapi.DCAPIInfo
import at.asitplus.dcapi.EncryptedResponse
import at.asitplus.dcapi.EncryptedResponseData
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.serializeOrigin
import at.asitplus.iso.sha256
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.supreme.asymmetric.HPKE
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.PresentationResponseParameters
import at.asitplus.wallet.lib.cbor.CoseHeaderNone
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.cbor.SignCoseDetachedFun
import at.asitplus.wallet.lib.data.CredentialPresentation
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToByteArray

/** Low-level ISO/IEC 18013-7 Annex C device-response construction used by [Iso180137AnnexCHolder]. */
object IsoMdocDcapiResponseBuilder {

    private val hpke = HPKE(
        HPKE.KEM.DHKEM_P256_HKDF_SHA256,
        HPKE.KDF.HKDF_SHA256,
        HPKE.AEAD.AES_128_GCM,
    )

    /** Builds the DC API session transcript bound to the request encryption information and calling origin. */
    fun sessionTranscriptFor(isoMdocWalletRequest: RequestParametersFrom.IsoMdocDcApi): SessionTranscript {
        val isoMdocRequest = isoMdocWalletRequest.parameters.isoMdocRequest
        val callingOrigin = isoMdocWalletRequest.callingOrigin.serializeOrigin()
            ?: throw IllegalArgumentException("Invalid calling origin")
        val hash = coseCompliantSerializer.encodeToByteArray(
            DCAPIInfo(isoMdocRequest.encryptionInfo, callingOrigin)
        ).sha256()
        val handover = DCAPIHandover(type = TYPE_DCAPI, hash = hash)
        return SessionTranscript.forDcApi(handover)
    }

    /** Creates the device response, applies device authentication, and HPKE-encrypts it for the verifier. */
    suspend fun buildEncryptedResponse(
        credentialPresentation: CredentialPresentation.IsoDeviceRetrievalPresentation,
        isoMdocWalletRequest: RequestParametersFrom.IsoMdocDcApi,
        holder: Holder,
    ): EncryptedResponse {
        val sessionTranscript = sessionTranscriptFor(isoMdocWalletRequest)
        val isoMdocRequest = isoMdocWalletRequest.parameters.isoMdocRequest
        val callingOrigin = isoMdocWalletRequest.callingOrigin.serializeOrigin()
            ?: throw IllegalArgumentException("Invalid calling origin")

        val presentationResult = holder.createPresentation(
            request = PresentationRequestParameters(
                nonce = isoMdocRequest.encryptionInfo.encryptionParameters.nonce
                    ?.encodeToString(Base64UrlStrict) ?: throw IllegalArgumentException("no nonce"),
                audience = callingOrigin,
                calcIsoSessionTranscript = { sessionTranscript },
                returnOneDeviceResponse = true,
            ),
            credentialPresentation = credentialPresentation,
        )

        val result = presentationResult.getOrThrow()
        require(result is PresentationResponseParameters.DeviceRetrievalParameters) {
            "Result is not DeviceRetrievalParameters"
        }
        val deviceResponseSerialized = coseCompliantSerializer.encodeToByteArray(result.deviceResponse)

        val encryptionParameters = isoMdocRequest.encryptionInfo.encryptionParameters
        val publicKey = encryptionParameters.recipientPublicKey.toCryptoPublicKey().getOrThrow()
        require(publicKey is CryptoPublicKey.EC) {
            "Could not extract EC public key"
        }

        val encodedSessionTranscript = coseCompliantSerializer.encodeToByteArray(sessionTranscript)
        val sealed = hpke.SealBase(
            pkR = publicKey,
            info = encodedSessionTranscript,
            aad = ByteArray(0),
            pt = deviceResponseSerialized,
        )
        val encryptedResponseData = EncryptedResponseData(
            enc = sealed.encapsulatedSecret,
            cipherText = sealed.ciphertext
        )
        return EncryptedResponse(TYPE_DCAPI, encryptedResponseData)
    }

    @Deprecated(
        message = "signDeviceAuthDetached and keyMaterial are no longer needed and have been removed" +
                " because Iso DeviceSignature computation has been moved into Holder's presentation creation.",
        replaceWith = ReplaceWith(
            expression = "buildEncryptedResponse(credentialPresentation, isoMdocWalletRequest, holder)",
        )
    )
    suspend fun buildEncryptedResponse(
        credentialPresentation: CredentialPresentation.IsoDeviceRetrievalPresentation,
        isoMdocWalletRequest: RequestParametersFrom.IsoMdocDcApi,
        keyMaterial: KeyMaterial,
        holder: Holder,
        signDeviceAuthDetached: SignCoseDetachedFun<ByteArray> =
            SignCoseDetached(keyMaterial, CoseHeaderNone(), CoseHeaderNone()),
    ) = buildEncryptedResponse(credentialPresentation, isoMdocWalletRequest, holder)
}
