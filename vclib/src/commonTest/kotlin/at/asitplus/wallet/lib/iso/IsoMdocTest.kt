package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.cbor.CoseAlgorithm
import at.asitplus.wallet.lib.cbor.CoseHeader
import at.asitplus.wallet.lib.cbor.CoseKey
import at.asitplus.wallet.lib.cbor.CoseSigned
import at.asitplus.wallet.lib.cbor.DefaultCoseService
import at.asitplus.wallet.lib.cbor.DefaultVerifierCoseService
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DOC_TYPE_MDL
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.DOCUMENT_NUMBER
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.DRIVING_PRIVILEGES
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.EXPIRY_DATE
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.FAMILY_NAME
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.GIVEN_NAME
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.ISSUE_DATE
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements.PORTRAIT
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.NAMESPACE_MDL
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.component.encoding.base16.encodeBase16
import kotlinx.datetime.Clock
import kotlinx.datetime.LocalDate
import kotlinx.serialization.cbor.ByteStringWrapper
import kotlin.random.Random

class IsoMdocTest : FreeSpec({

    beforeSpec {
        Napier.base(DebugAntilog())
    }

    "issue, store, present, verify" {
        val wallet = Wallet()
        val verifier = Verifier()
        val issuer = Issuer()

        // TODO Wallet needs to prove posession of key
        val deviceResponse = issuer.buildDeviceResponse(wallet.deviceKeyInfo)
        wallet.storeMdl(deviceResponse)

        val verifierRequest = verifier.buildDeviceRequest()
        val walletResponse = wallet.buildDeviceResponse(verifierRequest)
        verifier.verifyResponse(walletResponse, issuer.cryptoService.toCoseKey())
    }

})

class Wallet {

    val cryptoService = DefaultCryptoService()
    val coseService = DefaultCoseService(cryptoService)

    val deviceKeyInfo = DeviceKeyInfo(
        deviceKey = cryptoService.toCoseKey(),
        // specify optional parameters as workaround for definite length encoding in CBOR
        keyAuthorizations = KeyAuthorization(namespaces = arrayOf("a"), dataElements = mapOf("b" to arrayOf("c"))),
        keyInfo = mapOf(0 to "bar")
    )

    var storedMdl: MobileDrivingLicence? = null
    var storedIssuerAuth: CoseSigned? = null
    var storedMdlItems: IssuerSignedList? = null

    fun storeMdl(deviceResponse: DeviceResponse) {
        val document = deviceResponse.documents?.firstOrNull()
        document.shouldNotBeNull()
        document.docType shouldBe DOC_TYPE_MDL
        val issuerAuth = document.issuerSigned.issuerAuth
        this.storedIssuerAuth = issuerAuth
        println("Wallet stored IssuerAuth: $issuerAuth")
        val issuerAuthPayload = issuerAuth.payload
        issuerAuthPayload.shouldNotBeNull()
        val mso = MobileSecurityObject.deserialize(issuerAuthPayload.stripCborTag(24))
        mso.shouldNotBeNull()
        val mdlItems = document.issuerSigned.namespaces?.get(NAMESPACE_MDL)
        mdlItems.shouldNotBeNull()
        this.storedMdlItems = mdlItems
        val valueDigests = mso.valueDigests[NAMESPACE_MDL]
        valueDigests.shouldNotBeNull()

        val givenNameValue = extractDataString(mdlItems, GIVEN_NAME)
        val familyNameValue = extractDataString(mdlItems, FAMILY_NAME)
        val licenceNumberValue = extractDataString(mdlItems, DOCUMENT_NUMBER)
        val issueDateValue = extractDataString(mdlItems, ISSUE_DATE)
        val expiryDateValue = extractDataString(mdlItems, EXPIRY_DATE)
        val drivingPrivilegesValue = extractDataDrivingPrivileges(mdlItems, DRIVING_PRIVILEGES)

        storedMdl = MobileDrivingLicence(
            familyName = familyNameValue,
            givenName = givenNameValue,
            licenceNumber = licenceNumberValue,
            portrait = byteArrayOf(),
            issueDate = LocalDate.parse(issueDateValue),
            expiryDate = LocalDate.parse(expiryDateValue),
            drivingPrivileges = drivingPrivilegesValue,
        )
        println("Wallet stored MDL: $storedMdl")
    }

    suspend fun buildDeviceResponse(verifierRequest: DeviceRequest): DeviceResponse {
        val isoNamespace = verifierRequest.docRequests[0].itemsRequest.value.namespaces[NAMESPACE_MDL]
        isoNamespace.shouldNotBeNull()
        val requestedKeys = isoNamespace.entries.filter { it.value }.map { it.key }
        return DeviceResponse(
            version = "1.0",
            documents = arrayOf(
                Document(
                    docType = DOC_TYPE_MDL,
                    issuerSigned = IssuerSigned(
                        namespaces = mapOf(
                            NAMESPACE_MDL to IssuerSignedList(storedMdlItems!!.entries.filter {
                                it.value.elementIdentifier in requestedKeys
                            })
                        ),
                        issuerAuth = storedIssuerAuth!!
                    ),
                    deviceSigned = DeviceSigned(
                        namespaces = byteArrayOf(),
                        deviceAuth = DeviceAuth(
                            deviceSignature = coseService.createSignedCose(
                                protectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
                                unprotectedHeader = null,
                                payload = null,
                                addKeyId = false
                            ).getOrThrow()
                        )
                    )
                )
            ),
            status = 0U,
        )
    }

}

class Issuer {

    val cryptoService = DefaultCryptoService()
    val coseService = DefaultCoseService(cryptoService)

    suspend fun buildDeviceResponse(walletKeyInfo: DeviceKeyInfo): DeviceResponse {
        val drivingPrivilege = DrivingPrivilege(
            vehicleCategoryCode = "B",
            issueDate = LocalDate.parse("2023-01-01"),
            expiryDate = LocalDate.parse("2033-01-31"),
            codes = arrayOf(
                DrivingPrivilegeCode(code = "B", sign = "sign", value = "value")
            )
        )
        val issuerSigned = listOf(
            buildIssuerSignedItem(FAMILY_NAME, "Mustermann", 0U),
            buildIssuerSignedItem(GIVEN_NAME, "Max", 1U),
            buildIssuerSignedItem(DOCUMENT_NUMBER, "123456789", 2U),
            buildIssuerSignedItem(ISSUE_DATE, "2023-01-01", 3U),
            buildIssuerSignedItem(EXPIRY_DATE, "2033-01-31", 4U),
            buildIssuerSignedItem(DRIVING_PRIVILEGES, drivingPrivilege, 4U),
        )

        val mso = MobileSecurityObject(
            version = "1.0",
            digestAlgorithm = "SHA-256",
            valueDigests = mapOf(
                NAMESPACE_MDL to ValueDigestList(entries = issuerSigned.map {
                    ValueDigest.fromIssuerSigned(it)
                })
            ),
            deviceKeyInfo = walletKeyInfo,
            docType = DOC_TYPE_MDL,
            validityInfo = ValidityInfo(
                signed = Clock.System.now(),
                validFrom = Clock.System.now(),
                validUntil = Clock.System.now(),
                // specify optional parameters as workaround for definite length encoding in CBOR
                expectedUpdate = Clock.System.now(),
            )
        )

        return DeviceResponse(
            version = "1.0",
            documents = arrayOf(
                Document(
                    docType = DOC_TYPE_MDL,
                    issuerSigned = IssuerSigned(
                        namespaces = mapOf(
                            NAMESPACE_MDL to IssuerSignedList.withItems(issuerSigned)
                        ),
                        issuerAuth = coseService.createSignedCose(
                            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
                            unprotectedHeader = null, // TODO transport issuer certificate
                            payload = mso.serialize().wrapInCborTag(24),
                            addKeyId = false,
                        ).getOrThrow()
                    ),
                    deviceSigned = DeviceSigned(
                        namespaces = byteArrayOf(),
                        deviceAuth = DeviceAuth()
                    )
                )
            ),
            status = 0U,
        )
    }
}

class Verifier {

    val cryptoService = DefaultCryptoService()
    val coseService = DefaultCoseService(cryptoService)
    val verifierCoseService = DefaultVerifierCoseService()

    suspend fun buildDeviceRequest() = DeviceRequest(
        version = "1.0",
        docRequests = arrayOf(
            DocRequest(
                itemsRequest = ByteStringWrapper(
                    value = ItemsRequest(
                        docType = DOC_TYPE_MDL,
                        namespaces = mapOf(
                            NAMESPACE_MDL to ItemsRequestList(
                                listOf(
                                    SingleItemsRequest(FAMILY_NAME, true),
                                    SingleItemsRequest(GIVEN_NAME, true),
                                    SingleItemsRequest(PORTRAIT, false)
                                )
                            )
                        )
                    )
                ),
                readerAuth = coseService.createSignedCose(
                    protectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
                    unprotectedHeader = CoseHeader(),
                    payload = null,
                    addKeyId = false
                ).getOrThrow()
            )
        )
    )

    fun verifyResponse(deviceResponse: DeviceResponse, issuerKey: CoseKey) {
        val documents = deviceResponse.documents
        documents.shouldNotBeNull()
        val doc = documents.first()
        doc.docType shouldBe DOC_TYPE_MDL
        doc.errors.shouldBeNull()
        val issuerSigned = doc.issuerSigned
        val issuerAuth = issuerSigned.issuerAuth
        verifierCoseService.verifyCose(issuerAuth, issuerKey).getOrThrow().shouldBe(true)
        val issuerAuthPayload = issuerAuth.payload
        issuerAuthPayload.shouldNotBeNull()
        val mso = MobileSecurityObject.deserialize(issuerAuthPayload.stripCborTag(24))
        mso.shouldNotBeNull()
        mso.docType shouldBe DOC_TYPE_MDL
        val mdlItems = mso.valueDigests[NAMESPACE_MDL]
        mdlItems.shouldNotBeNull()

        val walletKey = mso.deviceKeyInfo.deviceKey
        val deviceSignature = doc.deviceSigned.deviceAuth.deviceSignature
        deviceSignature.shouldNotBeNull()
        verifierCoseService.verifyCose(deviceSignature, walletKey).getOrThrow().shouldBe(true)
        val namespaces = issuerSigned.namespaces
        namespaces.shouldNotBeNull()
        val issuerSignedItems = namespaces[NAMESPACE_MDL]
        issuerSignedItems.shouldNotBeNull()

        extractAndVerifyData(issuerSignedItems, mdlItems, FAMILY_NAME)
        extractAndVerifyData(issuerSignedItems, mdlItems, GIVEN_NAME)
    }

    private fun extractAndVerifyData(
        issuerSignedItems: IssuerSignedList,
        mdlItems: ValueDigestList,
        key: String
    ) {
        val issuerSignedItem = issuerSignedItems.entries.first { it.value.elementIdentifier == key }
        val elementValue = issuerSignedItem.value.elementValue.string
        elementValue.shouldNotBeNull()
        val issuerHash = mdlItems.entries.first { it.key == issuerSignedItem.value.digestId }
        issuerHash.shouldNotBeNull()
        val verifierHash = issuerSignedItem.serialized.sha256()
        verifierHash.encodeBase16() shouldBe issuerHash.value.encodeBase16()
        println("Verifier got $key with value $elementValue and correct hash ${verifierHash.encodeBase16()}")
    }
}

private fun extractDataString(
    mdlItems: IssuerSignedList,
    key: String
): String {
    val element = mdlItems.entries.first { it.value.elementIdentifier == key }
    val value = element.value.elementValue.string
    value.shouldNotBeNull()
    return value
}

private fun extractDataDrivingPrivileges(
    mdlItems: IssuerSignedList,
    key: String
): List<DrivingPrivilege> {
    val element = mdlItems.entries.first { it.value.elementIdentifier == key }
    val value = element.value.elementValue.drivingPrivilege
    value.shouldNotBeNull()
    return value
}


fun buildIssuerSignedItem(elementIdentifier: String, elementValue: String, digestId: UInt) = IssuerSignedItem(
    digestId = digestId,
    random = Random.nextBytes(16),
    elementIdentifier = elementIdentifier,
    elementValue = ElementValue(string = elementValue)
)

fun buildIssuerSignedItem(elementIdentifier: String, elementValue: DrivingPrivilege, digestId: UInt) = IssuerSignedItem(
    digestId = digestId,
    random = Random.nextBytes(16),
    elementIdentifier = elementIdentifier,
    elementValue = ElementValue(drivingPrivilege = listOf(elementValue))
)
