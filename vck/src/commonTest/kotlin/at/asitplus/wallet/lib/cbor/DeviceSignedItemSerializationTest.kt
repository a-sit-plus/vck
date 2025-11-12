package at.asitplus.wallet.lib.cbor

import at.asitplus.iso.CborCredentialSerializer
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.DeviceSignedItem
import at.asitplus.iso.DeviceSignedItemList
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.invoke
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.random.Random
import kotlin.random.nextUInt

val DeviceSignedItemSerializationTest by testSuite {

    "serialization with String" {
        val namespace = uuid4().toString()
        val elementIdentifier = uuid4().toString()
        val item = DeviceSignedItem(
            key = elementIdentifier,
            value = uuid4().toString(),
        )
        val deviceNameSpaces = DeviceNameSpaces(mapOf(namespace to DeviceSignedItemList(listOf(item))))

        val serialized = coseCompliantSerializer.encodeToByteArray(deviceNameSpaces)
        serialized.encodeToString(Base16(true)).shouldNotContain("D903EC")

        val parsed = coseCompliantSerializer.decodeFromByteArray<DeviceNameSpaces>(serialized)

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
        val protectedHeader = CoseHeader(algorithm = CoseAlgorithm.Signature.RS256)
        val issuerAuth = CoseSigned.create(
            protectedHeader,
            null,
            null,
            CryptoSignature.RSA(byteArrayOf()),
            MobileSecurityObject.serializer()
        )
        val deviceAuth = CoseSigned.create(
            protectedHeader,
            null,
            null,
            CryptoSignature.RSA(byteArrayOf()),
            ByteArraySerializer()
        )

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
        val serialized = coseCompliantSerializer.encodeToByteArray(doc)
        serialized.encodeToString(Base16(true)).shouldNotContain("D903EC")

        coseCompliantSerializer.decodeFromByteArray<Document>(serialized) shouldBe doc
    }
}