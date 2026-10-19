package at.asitplus.wallet.lib

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.Document
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.wrapInCborTag
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.HMAC
import at.asitplus.signum.indispensable.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseMac
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.kdf.HKDF
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.supreme.agree.keyAgreement
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.kdf.deriveKey
import at.asitplus.signum.supreme.mac.mac
import kotlinx.serialization.encodeToByteArray

/**
 * Verifies the [deviceMac] of this document, i.e. mdoc MAC authentication acc. to ISO/IEC 18013-5:2021, 9.1.3.5, as the
 * mdoc reader: `EMacKey` is derived with HKDF-SHA-256 from the ECDH shared secret of the reader's ephemeral private key
 * [eReaderKey] and the [deviceKey] the MSO binds, with `SHA-256(SessionTranscriptBytes)` as salt, and `"EMacKey"` as
 * info. The `COSE_Mac0` has to authenticate the detached `DeviceAuthenticationBytes` with HMAC 256/256.
 */
internal suspend fun Document.verifyDeviceMac(
    deviceMac: CoseMac<ByteArray>,
    deviceKey: CryptoPublicKey,
    eReaderKey: KeyAgreementPrivateValue.ECDH,
    sessionTranscript: SessionTranscript,
): KmmResult<Unit> = catching {
    require(deviceMac.protectedHeader.algorithm == CoseAlgorithm.MAC.HS256) {
        "deviceMac has to use HMAC 256/256, not ${deviceMac.protectedHeader.algorithm}"
    }
    require(deviceMac.payload == null) { "deviceMac has to authenticate the detached DeviceAuthenticationBytes" }
    require(deviceKey is CryptoPublicKey.EC) { "MAC authentication requires an EC device key, not $deviceKey" }
    val readerCurve = eReaderKey.publicValue.asCryptoPublicKey().curve
    require(readerCurve == deviceKey.curve) {
        "The device key on ${deviceKey.curve} does not match the reader's ephemeral key on $readerCurve"
    }
    val sharedSecret = eReaderKey.keyAgreement(deviceKey).getOrThrow()
    val eMacKey = HKDF.SHA256(info = "EMacKey".encodeToByteArray())
        .deriveKey(
            salt = Digest.SHA256.digest(sessionTranscript.sessionTranscriptBytes()),
            ikm = sharedSecret,
            derivedKeyLength = 256.bit,
        ).getOrThrow()
    val macInput = deviceMac.prepareCoseMacInput(detachedPayload = deviceAuthenticationBytes(sessionTranscript))
    val expectedTag = HMAC.SHA256.mac(eMacKey, macInput).getOrThrow()
    require(expectedTag.contentEqualsConstantTime(deviceMac.tag)) { "deviceMac does not match" }
}

/** `SessionTranscriptBytes`, i.e. the encoded [SessionTranscript] wrapped in CBOR tag 24 (ISO/IEC 18013-5:2021, 9.1.5.1). */
internal fun SessionTranscript.sessionTranscriptBytes(): ByteArray =
    coseCompliantSerializer.encodeToByteArray(coseCompliantSerializer.encodeToByteArray(this)).wrapInCborTag(24)

private fun ByteArray.contentEqualsConstantTime(other: ByteArray): Boolean {
    if (size != other.size) return false
    var difference = 0
    for (i in indices) difference = difference or (this[i].toInt() xor other[i].toInt())
    return difference == 0
}
