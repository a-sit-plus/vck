package at.asitplus.wallet.lib.iso

import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.ConstantIndex
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.maps.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContainOnlyOnce
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf
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

        serialized.encodeToString(Base16(true)).shouldContainOnlyOnce("D818")
        vckCborSerializer.decodeFromByteArray<DeviceSigned>(serialized) shouldBe input
    }

    "DocRequest" {
        val input = DocRequest(
            itemsRequest = ByteStringWrapper(ItemsRequest("docType", mapOf(), null)),
        )

        val serialized = vckCborSerializer.encodeToByteArray(input)

        serialized.encodeToString(Base16(true)).shouldContainOnlyOnce("D818")
        vckCborSerializer.decodeFromByteArray<DocRequest>(serialized) shouldBe input
    }

    "IssuerSigned" {
        val input = IssuerSigned.fromIssuerSignedItems(
            namespacedItems = mapOf(
                "org.iso.something" to listOf(issuerSignedItem())
            ),
            issuerAuth = issuerAuth()
        )

        val serialized = vckCborSerializer.encodeToByteArray(input)

        serialized.encodeToString(Base16(true)).shouldContainOnlyOnce("D818")
        vckCborSerializer.decodeFromByteArray<IssuerSigned>(serialized) shouldBe input
    }

    "IssuerSigned from IssuerAgent" {
        val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
        val issuedCredential = IssuerAgent().issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.ISO_MDOC
            ).getOrThrow()
        ).getOrThrow().shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()

        issuedCredential.issuerSigned.namespaces!!.shouldNotBeEmpty()
        val numberOfClaims = issuedCredential.issuerSigned.namespaces!!.entries.fold(0) { acc, entry ->
            acc + entry.value.entries.size
        }
        val serialized = issuedCredential.issuerSigned.serialize().encodeToString(Base16(true))
        "D818".toRegex().findAll(serialized).toList().shouldHaveSize(numberOfClaims + 1)
        // add 1 for MSO in IssuerAuth
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
        val serializedMso = mso.serializeForIssuerAuth()
        val input = CoseSigned<ByteArray>(
            protectedHeader = ByteStringWrapper(CoseHeader()),
            unprotectedHeader = null,
            payload = serializedMso,
            rawSignature = byteArrayOf()
        )

        val serialized = vckCborSerializer.encodeToByteArray(input)

        serialized.encodeToString(Base16(true)).shouldContainOnlyOnce("D818")
        serializedMso.encodeToString(Base16(true)).shouldStartWith("D818")
        vckCborSerializer.decodeFromByteArray<CoseSigned<ByteArray>>(serialized) shouldBe input
        MobileSecurityObject.deserializeFromIssuerAuth(serializedMso).getOrThrow() shouldBe mso
    }


})

private fun deviceKeyInfo() =
    DeviceKeyInfo(CoseKey(CoseKeyType.EC2, keyParams = CoseKeyParams.EcYBoolParams(CoseEllipticCurve.P256)))

private fun issuerAuth() = CoseSigned<ByteArray>(
    protectedHeader = ByteStringWrapper(CoseHeader()),
    unprotectedHeader = null,
    payload = byteArrayOf(),
    rawSignature = byteArrayOf()
)

private fun issuerSignedItem() = IssuerSignedItem(0u, Random.nextBytes(16), "identifier", "value")
