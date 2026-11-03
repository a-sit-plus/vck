package at.asitplus.wallet.lib

import at.asitplus.iso.DeviceAuthentication
import at.asitplus.iso.Document
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.wrapInCborTag
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToByteArray
import kotlin.jvm.JvmOverloads

/** Verifies the mdoc device signature against a session transcript, acc. to ISO/IEC 18013-5/-7. */
class MdocDeviceSignatureVerifier @JvmOverloads constructor(
    private val verifyCoseSignature: VerifyCoseSignatureWithKeyFun<ByteArray> = VerifyCoseSignatureWithKey(),
) {
    /**
     * Performs verification of the [at.asitplus.iso.SessionTranscript] and [at.asitplus.iso.DeviceAuthentication],
     * acc. to ISO/IEC 18013-5:2021 and ISO/IEC 18013-7:2024, if required (i.e. response is encrypted)
     */
    @Throws(IllegalArgumentException::class, IllegalStateException::class)
    fun verifyDocument(
        sessionTranscript: SessionTranscript
    ): suspend (MobileSecurityObject, Document) -> Boolean = { mso, document ->
        val deviceSignature = document.deviceSigned.deviceAuth.deviceSignature
            ?: throw IllegalArgumentException("deviceSignature is null")

        val expectedDetachedPayload = document.deviceAuthenticationBytes(sessionTranscript)

        verifyCoseSignature(
            coseSigned = deviceSignature,
            signer = mso.deviceKeyInfo.deviceKey,
            externalAad = byteArrayOf(),
            detachedPayload = expectedDetachedPayload
        ).onFailure {
            throw IllegalArgumentException(
                "deviceSignature not matching ${expectedDetachedPayload.encodeToString(Base16())}",
                it
            )
        }
        true
    }

}

/**
 * The detached payload the device signature of this document signs, `DeviceAuthenticationBytes`, i.e. the
 * `DeviceAuthentication` over [sessionTranscript], wrapped in CBOR tag 24 (ISO/IEC 18013-5:2021, 9.1.3.4).
 */
internal fun Document.deviceAuthenticationBytes(sessionTranscript: SessionTranscript): ByteArray =
    coseCompliantSerializer.encodeToByteArray(
        coseCompliantSerializer.encodeToByteArray(
            DeviceAuthentication(
                type = DeviceAuthentication.TYPE,
                sessionTranscript = sessionTranscript,
                docType = docType,
                namespaces = deviceSigned.namespaces,
            )
        )
    ).wrapInCborTag(24)