package at.asitplus.wallet.lib.iso

import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceKeyInfo
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.DocRequest
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.IssuerSignedList
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.iso.ValidityInfo
import at.asitplus.iso.ValueDigest
import at.asitplus.iso.ValueDigestList
import at.asitplus.iso.sha256
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.cbor.CoseHeaderCertificate
import at.asitplus.wallet.lib.cbor.CoseHeaderNone
import at.asitplus.wallet.lib.cbor.SignCose
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlin.random.Random
import kotlin.time.Clock

val IsoProcessTest by testSuite {

    "issue, store, present, verify" {
        val wallet = Wallet()
        val verifier = Verifier()
        val issuer = Issuer()

        val deviceResponse = issuer.buildDeviceResponse(wallet.deviceKeyInfo)
        wallet.storeMdl(deviceResponse)

        val verifierRequest = verifier.buildDeviceRequest()
        val walletResponse = wallet.buildDeviceResponse(verifierRequest)
        verifier.verifyResponse(walletResponse, issuer.keyMaterial.publicKey.toCoseKey().getOrThrow())
    }

}
class Wallet {

    private val keyMaterial = EphemeralKeyWithoutCert()
    private val signCose = SignCose<ByteArray>(keyMaterial)

    val deviceKeyInfo = DeviceKeyInfo(keyMaterial.publicKey.toCoseKey().getOrThrow())
    private var storedIssuerAuth: CoseSigned<MobileSecurityObject>? = null
    private var storedMdlItems: IssuerSignedList? = null

    fun storeMdl(deviceResponse: DeviceResponse) {
        val document = deviceResponse.documents?.first().shouldNotBeNull()
        document.docType shouldBe ConstantIndex.AtomicAttribute2023.isoDocType
        val issuerAuth = document.issuerSigned.issuerAuth
        this.storedIssuerAuth = issuerAuth

        issuerAuth.payload.shouldNotBeNull()
        val mso = document.issuerSigned.issuerAuth
            .payload.shouldNotBeNull()

        val mdlItems = document.issuerSigned.namespaces?.get(ConstantIndex.AtomicAttribute2023.isoNamespace)
            .shouldNotBeNull()
        this.storedMdlItems = mdlItems
        mso.valueDigests[ConstantIndex.AtomicAttribute2023.isoNamespace].shouldNotBeNull()

        extractDataString(mdlItems, CLAIM_GIVEN_NAME).shouldNotBeNull()
        extractDataString(mdlItems, CLAIM_FAMILY_NAME).shouldNotBeNull()
    }

    suspend fun buildDeviceResponse(verifierRequest: DeviceRequest): DeviceResponse {
        val itemsRequest = verifierRequest.docRequests[0].itemsRequest
        val isoNamespace = itemsRequest.value.namespaces[ConstantIndex.AtomicAttribute2023.isoNamespace]
            .shouldNotBeNull()
        val requestedKeys = isoNamespace.entries.filter { it.intentToRetain }.map { it.dataElementIdentifier }
        return DeviceResponse(
            version = "1.0",
            documents = arrayOf(
                Document(
                    docType = ConstantIndex.AtomicAttribute2023.isoDocType,
                    issuerSigned = IssuerSigned.fromIssuerSignedItems(
                        namespacedItems = mapOf(
                            ConstantIndex.AtomicAttribute2023.isoNamespace to storedMdlItems!!.entries.filter {
                                it.value.elementIdentifier in requestedKeys
                            }.map { it.value }
                        ),
                        issuerAuth = storedIssuerAuth!!
                    ),
                    deviceSigned = DeviceSigned(
                        namespaces = ByteStringWrapper(DeviceNameSpaces(mapOf())),
                        deviceAuth = DeviceAuth(
                            deviceSignature = signCose(null, null, null, ByteArraySerializer()).getOrThrow()
                        )
                    )
                )
            ),
            status = 0U,
        )
    }

}

class Issuer {

    val keyMaterial = EphemeralKeyWithoutCert()
    private val signCose = SignCose<MobileSecurityObject>(keyMaterial, CoseHeaderNone(), CoseHeaderCertificate())

    suspend fun buildDeviceResponse(walletKeyInfo: DeviceKeyInfo): DeviceResponse {
        val issuerSigned = listOf(
            buildIssuerSignedItem(CLAIM_FAMILY_NAME, "Meier", 0U),
            buildIssuerSignedItem(CLAIM_GIVEN_NAME, "Susanne", 1U),
        )

        val mso = MobileSecurityObject(
            version = "1.0",
            digestAlgorithm = "SHA-256",
            valueDigests = mapOf(
                ConstantIndex.AtomicAttribute2023.isoNamespace to ValueDigestList(entries = issuerSigned.map {
                    ValueDigest.fromIssuerSignedItem(it, ConstantIndex.AtomicAttribute2023.isoNamespace)
                })
            ),
            deviceKeyInfo = walletKeyInfo,
            docType = ConstantIndex.AtomicAttribute2023.isoDocType,
            validityInfo = ValidityInfo(
                signed = Clock.System.now(),
                validFrom = Clock.System.now(),
                validUntil = Clock.System.now(),
            )
        )

        return DeviceResponse(
            version = "1.0",
            documents = arrayOf(
                Document(
                    docType = ConstantIndex.AtomicAttribute2023.isoDocType,
                    issuerSigned = IssuerSigned.fromIssuerSignedItems(
                        namespacedItems = mapOf(
                            ConstantIndex.AtomicAttribute2023.isoNamespace to issuerSigned
                        ),
                        issuerAuth = signCose(null, null, mso, MobileSecurityObject.serializer()).getOrThrow()
                    ),
                    deviceSigned = DeviceSigned(
                        namespaces = ByteStringWrapper(DeviceNameSpaces(mapOf())),
                        deviceAuth = DeviceAuth()
                    )
                )
            ),
            status = 0U,
        )
    }
}

class Verifier {

    private val keyMaterial = EphemeralKeyWithoutCert()
    private val signCose = SignCose<ByteArray>(keyMaterial)
    private val verifyCoseSignatureMso = VerifyCoseSignatureWithKey<MobileSecurityObject>()
    private val verifyCoseSignatureBytes = VerifyCoseSignatureWithKey<ByteArray>()

    suspend fun buildDeviceRequest() = DeviceRequest(
        version = "1.0",
        docRequests = arrayOf(
            DocRequest(
                itemsRequest = ByteStringWrapper(
                    value = ItemsRequest(
                        docType = ConstantIndex.AtomicAttribute2023.isoDocType,
                        namespaces = mapOf(
                            ConstantIndex.AtomicAttribute2023.isoNamespace to ItemsRequestList(
                                listOf(
                                    SingleItemsRequest(CLAIM_FAMILY_NAME, true),
                                    SingleItemsRequest(CLAIM_GIVEN_NAME, true),
                                )
                            )
                        )
                    )
                ),
                readerAuth = signCose(
                    protectedHeader = null,
                    unprotectedHeader = CoseHeader(),
                    payload = null,
                    serializer = ByteArraySerializer()
                ).getOrThrow()
            )
        )
    )

    suspend fun verifyResponse(deviceResponse: DeviceResponse, issuerKey: CoseKey) {
        val documents = deviceResponse.documents.shouldNotBeNull()
        val doc = documents.first()
        doc.docType shouldBe ConstantIndex.AtomicAttribute2023.isoDocType
        doc.errors.shouldBeNull()
        val issuerSigned = doc.issuerSigned
        val issuerAuth = issuerSigned.issuerAuth
        verifyCoseSignatureMso(issuerAuth, issuerKey, byteArrayOf(), null).isSuccess shouldBe true
        issuerAuth.payload.shouldNotBeNull()
        val mso = issuerAuth.payload.shouldNotBeNull()

        mso.docType shouldBe ConstantIndex.AtomicAttribute2023.isoDocType
        val mdlItems = mso.valueDigests[ConstantIndex.AtomicAttribute2023.isoNamespace].shouldNotBeNull()

        val walletKey = mso.deviceKeyInfo.deviceKey
        val deviceSignature = doc.deviceSigned.deviceAuth.deviceSignature.shouldNotBeNull()
        verifyCoseSignatureBytes(deviceSignature, walletKey, byteArrayOf(), null).isSuccess shouldBe true
        val namespaces = issuerSigned.namespaces.shouldNotBeNull()
        val issuerSignedItems = namespaces[ConstantIndex.AtomicAttribute2023.isoNamespace].shouldNotBeNull()

        extractAndVerifyData(issuerSignedItems, mdlItems, CLAIM_FAMILY_NAME)
        extractAndVerifyData(issuerSignedItems, mdlItems, CLAIM_GIVEN_NAME)
    }

    private fun extractAndVerifyData(
        issuerSignedItems: IssuerSignedList,
        mdlItems: ValueDigestList,
        key: String,
    ) {
        val issuerSignedItem = issuerSignedItems.entries.first { it.value.elementIdentifier == key }
        //val elementValue = issuerSignedItem.value.elementValue.toString().shouldNotBeNull()
        val issuerHash = mdlItems.entries.first { it.key == issuerSignedItem.value.digestId }.shouldNotBeNull().value
        val verifierHash = issuerSignedItem.serialized.sha256()
        verifierHash.encodeToString(Base16(true)) shouldBe issuerHash.encodeToString(Base16(true))
    }
}

private fun extractDataString(
    mdlItems: IssuerSignedList,
    key: String,
): String {
    val element = mdlItems.entries.first { it.value.elementIdentifier == key }
    return element.value.elementValue.toString().shouldNotBeNull()
}

fun buildIssuerSignedItem(elementIdentifier: String, elementValue: Any, digestId: UInt) = IssuerSignedItem(
    digestId = digestId,
    random = Random.nextBytes(16),
    elementIdentifier = elementIdentifier,
    elementValue = elementValue
)
