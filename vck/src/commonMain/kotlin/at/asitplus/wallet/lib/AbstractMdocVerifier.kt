package at.asitplus.wallet.lib

import at.asitplus.dcapi.SessionTranscriptContentHashable
import at.asitplus.iso.DeviceAuthentication
import at.asitplus.iso.Document
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.wrapInCborTag
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToByteArray

abstract class AbstractMdocVerifier {
    /** Creates challenges in authentication requests. */
    protected abstract val nonceService: NonceService
    /** Used for encrypted responses. */
    protected abstract val decryptionKeyMaterial: KeyMaterial
    /** Used to verify session transcripts from mDoc responses. */
    protected abstract val verifyCoseSignature: VerifyCoseSignatureWithKeyFun<ByteArray>

    /**
     * Performs calculation of the [at.asitplus.iso.SessionTranscript] for DC API
     */
    protected abstract fun createDcApiSessionTranscript(
        toBeHashed: SessionTranscriptContentHashable,
    ): SessionTranscript

    /**
     * Performs verification of the [at.asitplus.iso.SessionTranscript] and [at.asitplus.iso.DeviceAuthentication],
     * acc. to ISO/IEC 18013-5:2021 and ISO/IEC 18013-7:2024, if required (i.e. response is encrypted)
     */
    @Throws(IllegalArgumentException::class, IllegalStateException::class)
    protected fun verifyDocument(
        sessionTranscript: SessionTranscript
    ): suspend (MobileSecurityObject, Document) -> Boolean = { mso, document ->
        val deviceSignature = document.deviceSigned.deviceAuth.deviceSignature
            ?: throw IllegalArgumentException("deviceSignature is null")

        val expected = document.calcDeviceAuthenticationOpenId4VpFinal(
            sessionTranscript = sessionTranscript,
        ).wrapAsExpectedPayload()

        verifyCoseSignature(
            coseSigned = deviceSignature,
            signer = mso.deviceKeyInfo.deviceKey,
            externalAad = byteArrayOf(),
            detachedPayload = expected
        ).onFailure {
            throw IllegalArgumentException("deviceSignature not matching ${expected.encodeToString(Base16())}", it)
        }
        true
    }

    private fun DeviceAuthentication.wrapAsExpectedPayload(): ByteArray = coseCompliantSerializer
        .encodeToByteArray(coseCompliantSerializer.encodeToByteArray(this))
        .wrapInCborTag(24)


    /**
     * Performs calculation of the [at.asitplus.iso.DeviceAuthentication],
     * acc. to ISO 18013. Can take session transcripts acc. to ISO 18013 or OpenID4VP 1.0
     */
    private fun Document.calcDeviceAuthenticationOpenId4VpFinal(
        sessionTranscript: SessionTranscript,
    ) = DeviceAuthentication(
        type = DeviceAuthentication.TYPE,
        sessionTranscript = sessionTranscript,
        docType = docType,
        namespaces = deviceSigned.namespaces
    )

}