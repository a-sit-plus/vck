package at.asitplus.wallet.lib.cbor

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.wallet.lib.iso.*
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlin.random.Random
import kotlin.random.nextUInt

class DeviceSignedItemSerializationTest : FreeSpec({

    "serialization with String" {
        val namespace = uuid4().toString()
        val elementIdentifier = uuid4().toString()
        val item = DeviceSignedItem(
            key = elementIdentifier,
            value = uuid4().toString(),
        )
        val deviceNameSpaces = DeviceNameSpaces(mapOf(namespace to DeviceSignedItemList(listOf(item))))

        val serialized = deviceNameSpaces.serialize()
        serialized.encodeToString(Base16(true)).shouldNotContain("D903EC")

        val parsed = DeviceNameSpaces.deserialize(serialized).getOrThrow()

        parsed shouldBe deviceNameSpaces
    }

    "document serialization with ByteArray" {
        val elementId = uuid4().toString()
        val namespace = uuid4().toString()
        CborCredentialSerializer.register(mapOf(elementId to ByteArraySerializer()), namespace)
        val issuerSignedItem = IssuerSignedItem(
            digestId = Random.nextUInt(),
            random = Random.nextBytes(16),
            elementIdentifier = elementId,
            elementValue = Random.nextBytes(32),
        )
        val deviceSignedItem = DeviceSignedItem(
            key = elementId,
            value = Random.nextBytes(32),
        )
        val protectedHeader = CoseHeader()
        val issuerAuth = CoseSigned<MobileSecurityObject>(protectedHeader, null, null, CryptoSignature.RSAorHMAC(byteArrayOf()))
        val deviceAuth = CoseSigned<ByteArray>(protectedHeader, null, null, CryptoSignature.RSAorHMAC(byteArrayOf()))

        val doc = Document(
            docType = uuid4().toString(),
            issuerSigned = IssuerSigned.fromIssuerSignedItems(
                mapOf(namespace to listOf(issuerSignedItem)),
                issuerAuth
            ),
            deviceSigned = DeviceSigned.fromDeviceSignedItems(
                mapOf(namespace to listOf(deviceSignedItem)),
                deviceAuth
            )
        )
        val serialized = doc.serialize()
        serialized.encodeToString(Base16(true)).shouldNotContain("D903EC")

        val parsed = Document.deserialize(serialized).getOrThrow()

        parsed shouldBe doc
    }
})
