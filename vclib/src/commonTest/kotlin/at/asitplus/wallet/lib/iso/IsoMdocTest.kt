package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.cbor.CoseAlgorithm
import at.asitplus.wallet.lib.cbor.CoseHeader
import at.asitplus.wallet.lib.cbor.DefaultCoseService
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.ktor.utils.io.core.toByteArray
import io.matthewnelson.component.encoding.base16.encodeBase16
import kotlinx.datetime.Clock
import kotlinx.datetime.LocalDate
import kotlinx.serialization.cbor.ByteStringWrapper
import kotlin.random.Random

class IsoMdocTest : FreeSpec({

    beforeSpec {
        Napier.base(DebugAntilog())
    }

    "issue and verify" {
        val deviceCryptoService = DefaultCryptoService()
        val deviceKeyInfo = DeviceKeyInfo(
            deviceKey = deviceCryptoService.toCoseKey(),
            keyAuthorizations = KeyAuthorization(namespaces = arrayOf("foo"), dataElements = mapOf("foo" to arrayOf("bar"))),
            keyInfo = mapOf(0 to "bar")
        )
        val deviceRequest = buildDeviceRequest(deviceCryptoService)
        //println(deviceRequest)
        // Wallet sends deviceRequest to Issuer

        val deviceResponse = buildDeviceResponse(deviceKeyInfo)
        //println(deviceResponse)
        // Issuer sends deviceResponse to Wallet

        val document = deviceResponse.documents?.firstOrNull()
        document.shouldNotBeNull()
        println(document)
        document.docType shouldBe "org.iso.18013.5.1.mDL"
        val issuerAuth = document.issuerSigned.issuerAuth.payload
        issuerAuth.shouldNotBeNull()
        val mso = MobileSecurityObject.deserialize(issuerAuth.stripTag(24))
        mso.shouldNotBeNull()

        val mdlItems = document.issuerSigned.namespaces?.get("org.iso.18013.5.1")
        mdlItems.shouldNotBeNull()
        val valueDigests = mso.valueDigests["org.iso.18013.5.1"]
        valueDigests.shouldNotBeNull()

        val givenName = mdlItems.first { it.value.elementIdentifier == "given_name" }.value
        val givenNameValue = givenName.elementValue.string
        val givenNameHash = valueDigests[givenName.digestId]?.encodeBase16()
        val familyName = mdlItems.first { it.value.elementIdentifier == "family_name" }.value
        val familyNameValue = familyName.elementValue.string
        val familyNameHash = valueDigests[familyName.digestId]?.encodeBase16()

        println("Given name: $givenNameValue with hash $givenNameHash")
        println("Family name: $familyNameValue with hash $familyNameHash")
    }

})


private suspend fun buildDeviceRequest(deviceCryptoService: DefaultCryptoService): DeviceRequest {
    val deviceCoseService = DefaultCoseService(deviceCryptoService)
    return DeviceRequest(
        version = "1.0",
        docRequests = arrayOf(
            DocRequest(
                itemsRequest = ByteStringWrapper(
                    value = ItemsRequest(
                        docType = "org.iso.18013.5.1.mDL",
                        namespaces = mapOf(
                            // TODO is this necessary?
                            "org.iso.18013.5.1" to mapOf(
                                "family_name" to true,
                                "portrait" to false
                            )
                        )
                    )
                ),
                readerAuth = deviceCoseService.createSignedCose(
                    protectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
                    unprotectedHeader = CoseHeader(),
                    payload = null,
                    addKeyId = false
                ).getOrThrow()
            )
        )
    )
}

private suspend fun buildDeviceResponse(deviceKeyInfo: DeviceKeyInfo): DeviceResponse {
    val mdl = MobileDrivingLicence(
        familyName = "Mustermann",
        givenName = "Max",
        dateOfBirth = LocalDate.parse("1970-01-01"),
        issueDate = LocalDate.parse("2018-08-09"),
        expiryDate = LocalDate.parse("2024-10-20"),
        issuingCountry = "AT",
        issuingAuthority = "LPD Steiermark",
        licenceNumber = "A/3f984/019",
        portrait = "foo".toByteArray(),
        drivingPrivileges = arrayOf(
            DrivingPrivilege(
                vehicleCategoryCode = "A",
                issueDate = LocalDate.parse("2018-08-09"),
                expiryDate = LocalDate.parse("2024-10-20")
            )
        ),
        unDistinguishingSign = "AT"
    )
    val familyNameIssuerSigned = IssuerSignedItem(
        digestId = 0U,
        random = Random.nextBytes(16),
        elementIdentifier = "family_name",
        elementValue = ElementValue(string = mdl.familyName)
    )
    val givenNameIssuerSigned = IssuerSignedItem(
        digestId = 1U,
        random = Random.nextBytes(16),
        elementIdentifier = "given_name",
        elementValue = ElementValue(string = mdl.givenName)
    )
    val mso = MobileSecurityObject(
        version = "1.0",
        digestAlgorithm = "SHA-256",
        valueDigests = mapOf(
            "org.iso.18013.5.1" to mapOf(
                0U to familyNameIssuerSigned.toValueDigest(),
                1U to givenNameIssuerSigned.toValueDigest()
            )
        ),
        deviceKeyInfo = deviceKeyInfo,
        docType = "org.iso.18013.5.1.mDL",
        validityInfo = ValidityInfo(
            signed = Clock.System.now(),
            validFrom = Clock.System.now(),
            validUntil = Clock.System.now(),
            expectedUpdate = Clock.System.now(),
        )
    )

    val issuerCryptoService = DefaultCryptoService()
    val issuerCoseService = DefaultCoseService(issuerCryptoService)
    return DeviceResponse(
        version = "1.0",
        documents = arrayOf(
            Document(
                docType = "org.iso.18013.5.1.mDL",
                issuerSigned = IssuerSigned(
                    namespaces = mapOf(
                        "org.iso.18013.5.1" to listOf(
                            ByteStringWrapper(familyNameIssuerSigned),
                            ByteStringWrapper(givenNameIssuerSigned),
                        )
                    ),
                    issuerAuth = issuerCoseService.createSignedCose(
                        protectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
                        unprotectedHeader = null,
                        payload = mso.serialize().wrapInCborTag(24),
                        addKeyId = false,
                    ).getOrThrow()
                ),
                deviceSigned = DeviceSigned(
                    namespaces = byteArrayOf(),
                    deviceAuth = DeviceAuth(

                    )
                )
            )
        ),
        status = 0U,
    )
}

private fun ByteArray.stripTag(tag: Byte) = this.dropWhile { it == 0xd8.toByte() }.dropWhile { it == tag }.toByteArray()

private fun ByteArray.wrapInCborTag(tag: Byte) = byteArrayOf(0xd8.toByte()) + byteArrayOf(tag) + this

private fun IssuerSignedItem.toValueDigest() = this.serialize().wrapInCborTag(24).sha256()

// TODO actually hash it
private fun ByteArray.sha256(): ByteArray = this
