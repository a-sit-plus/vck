package at.asitplus.wallet.lib.iso

import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldStartWith
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.random.Random

/**
 * Test correct appending tag 24 (in hex `D818`) for certain data structures,
 * as defined by ISO/IEC 18013-5:2021
 */
@OptIn(ExperimentalSerializationApi::class)
class Tag24SerializationTest : FreeSpec({

    "DeviceSigned" {
        val input = DeviceSigned(
            namespaces = ByteStringWrapper(
                DeviceNameSpaces(
                    mapOf(
                        "iso.namespace" to DeviceSignedItemList(
                            listOf(
                                DeviceSignedItem("name", "foo"),
                                DeviceSignedItem("date", "bar")
                            )
                        )
                    )
                )
            ),
            deviceAuth = DeviceAuth(
                deviceSignature = issuerAuth()
            )
        )

        val serialized = vckCborSerializer.encodeToByteArray(input)
            .also { println(it.encodeToString(Base16(true))) }

        serialized.encodeToString(Base16(true)).shouldContain("D818")
        vckCborSerializer.decodeFromByteArray<DeviceSigned>(serialized) shouldBe input
    }

    "DocRequest" {
        val input = DocRequest(
            itemsRequest = ByteStringWrapper(ItemsRequest("docType", mapOf(), null)),
        )

        val serialized = vckCborSerializer.encodeToByteArray(input)
            .also { println(it.encodeToString(Base16(true))) }

        serialized.encodeToString(Base16(true)).shouldContain("D818")
        vckCborSerializer.decodeFromByteArray<DocRequest>(serialized) shouldBe input
    }

    "IssuerSigned" {
        val input = IssuerSigned(
            namespacedItems = mapOf(
                "org.iso.something" to listOf(issuerSignedItem())
            ),
            issuerAuth = issuerAuth()
        )

        val serialized = vckCborSerializer.encodeToByteArray(input)
            .also { println(it.encodeToString(Base16(true))) }

        serialized.encodeToString(Base16(true)).shouldContain("D818")
        vckCborSerializer.decodeFromByteArray<IssuerSigned>(serialized) shouldBe input
    }

    "IssuerAuth" {
        val mso = MobileSecurityObject(
            version = "1.0",
            digestAlgorithm = "SHA-256",
            valueDigests = mapOf("foo" to ValueDigestList(listOf(ValueDigest(0U, byteArrayOf())))),
            deviceKeyInfo = deviceKeyInfo(),
            docType = "docType",
            validityInfo = ValidityInfo(Clock.System.now(), Clock.System.now(), Clock.System.now())
        )
        // todo should not be an explicit function
        val serializedMso = mso.serializeForIssuerAuth()
            .also { println(it.encodeToString(Base16(true))) }
        val input = CoseSigned(
            protectedHeader = ByteStringWrapper(CoseHeader()),
            unprotectedHeader = null,
            payload = serializedMso,
            rawSignature = byteArrayOf()
        )

        val serialized = vckCborSerializer.encodeToByteArray(input)
            .also { println(it.encodeToString(Base16(true))) }

        serialized.encodeToString(Base16(true)).shouldContain("D818")
        serializedMso.encodeToString(Base16(true)).shouldStartWith("D818")
        vckCborSerializer.decodeFromByteArray<CoseSigned>(serialized) shouldBe input
        MobileSecurityObject.deserializeFromIssuerAuth(serializedMso).getOrThrow() shouldBe mso
    }


})

private fun deviceKeyInfo() =
    DeviceKeyInfo(CoseKey(CoseKeyType.EC2, keyParams = CoseKeyParams.EcYBoolParams(CoseEllipticCurve.P256)))

private fun issuerAuth() = CoseSigned(
    protectedHeader = ByteStringWrapper(CoseHeader()),
    unprotectedHeader = null,
    payload = byteArrayOf(),
    rawSignature = byteArrayOf()
)

private fun issuerSignedItem() = IssuerSignedItem(0u, Random.nextBytes(16), "identifier", "value")
