package at.asitplus.wallet.lib

import at.asitplus.iso.DeviceAuthentication
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.SessionTranscript
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.supreme.agree.Ephemeral
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.cbor.iso18013AnnexDDeviceResponse
import at.asitplus.wallet.lib.iso.iso18013AnnexDDeviceAuthenticationBytes
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.decodeFromByteArray
import kotlin.random.Random

/** The ephemeral reader key of ISO/IEC 18013-5:2021(E), D.5.1. */
private fun iso18013AnnexDEReaderKey(): KeyAgreementPrivateValue.ECDH = CryptoPrivateKey.EC.WithPublicKey(
    privateKey = BigInteger.fromByteArray(
        "de3b4b9e5f72dd9b58406ae3091434da48a6f9fd010d88fcb0958e2cebec947c".decodeToByteArray(Base16),
        Sign.POSITIVE
    ),
    curve = ECCurve.SECP_256_R_1,
    encodeCurve = true,
    encodePublicKey = true,
)

val MdocDeviceMacVerifierTest by matrixSuite {

    val document = coseCompliantSerializer.decodeFromByteArray<DeviceResponse>(
        iso18013AnnexDDeviceResponse.decodeToByteArray(Base16(true))
    ).documents.shouldNotBeNull().single()
    val deviceMac = document.deviceSigned.deviceAuth.deviceMac.shouldNotBeNull()
    val deviceKey = document.issuerSigned.issuerAuth.payload.shouldNotBeNull()
        .deviceKeyInfo.deviceKey.toCryptoPublicKey().getOrThrow()
    val deviceAuthenticationBytes = iso18013AnnexDDeviceAuthenticationBytes.decodeToByteArray(Base16)
    val sessionTranscript = coseCompliantSerializer.decodeFromByteArray<DeviceAuthentication>(
        coseCompliantSerializer.decodeFromByteArray<ByteArray>(deviceAuthenticationBytes.drop(2).toByteArray())
    ).sessionTranscript

    "DeviceAuthenticationBytes of ISO 18013-5 D.5.3 are those of the decoded session transcript" {
        document.deviceAuthenticationBytes(sessionTranscript) shouldBe deviceAuthenticationBytes
    }

    "device MAC of ISO 18013-5 D.5.3 verifies with the ephemeral reader key" {
        document.verifyDeviceMac(deviceMac, deviceKey, iso18013AnnexDEReaderKey(), sessionTranscript)
            .getOrThrow()
    }

    "device MAC fails with another ephemeral reader key" {
        val otherKey = KeyAgreementPrivateValue.ECDH.Ephemeral().getOrThrow()

        document.verifyDeviceMac(deviceMac, deviceKey, otherKey, sessionTranscript)
            .isFailure shouldBe true
    }

    "device MAC fails over another session transcript" {
        val otherTranscript = SessionTranscript.Qr(Random.nextBytes(32), Random.nextBytes(32))

        document.verifyDeviceMac(deviceMac, deviceKey, iso18013AnnexDEReaderKey(), otherTranscript)
            .isFailure shouldBe true
    }

    "device MAC fails with a reader key on another curve" {
        val otherKey = KeyAgreementPrivateValue.ECDH.Ephemeral(ECCurve.SECP_384_R_1).getOrThrow()

        document.verifyDeviceMac(deviceMac, deviceKey, otherKey, sessionTranscript)
            .isFailure shouldBe true
    }
}
