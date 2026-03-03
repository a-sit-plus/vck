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
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.io.Base64UrlStrict
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
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.decodeFromHexString
import kotlin.random.Random
import kotlin.time.Clock

val IsoProcessTest by testSuite {

    "deserializing issuer signed" {
        val input = """
            ompuYW1lU3BhY2VzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMZbYGFhTpGhkaWdlc3RJRABmcmFuZG9tUIWpJITQCaJFh0M2bwu87mlxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWVsZWxlbWVudFZhbHVlZE5lYWzYGFhTpGhkaWdlc3RJRAFmcmFuZG9tUFChMXh6R-CF8ZLw1X2rWdpxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVlVHlsZXLYGFhbpGhkaWdlc3RJRAJmcmFuZG9tUNtlN778rsODe_3V4-yxC6txZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZWxlbGVtZW50VmFsdWXZA-xqMTk1NS0wNC0xMtgYWHKkaGRpZ2VzdElEA2ZyYW5kb21QpyJicZzLBwp7uwhfTTCfi3FlbGVtZW50SWRlbnRpZmllcm5wbGFjZV9vZl9iaXJ0aGxlbGVtZW50VmFsdWWiZ2NvdW50cnliQVRobG9jYWxpdHlrMTAxIFRyYXVuZXLYGFhSpGhkaWdlc3RJRARmcmFuZG9tUI-EfFubIYRqGI7hcRNxv9RxZWxlbWVudElkZW50aWZpZXJrbmF0aW9uYWxpdHlsZWxlbWVudFZhbHVlgWJBVNgYWFakaGRpZ2VzdElEBWZyYW5kb21Q_HfMZR-_jWEhAqTlBW2nDXFlbGVtZW50SWRlbnRpZmllcnByZXNpZGVudF9jb3VudHJ5bGVsZW1lbnRWYWx1ZWJBVNgYWF-kaGRpZ2VzdElEBmZyYW5kb21Q2tMWpmfuI6avih2sFDb8M3FlbGVtZW50SWRlbnRpZmllcm5yZXNpZGVudF9zdGF0ZWxlbGVtZW50VmFsdWVtTG93ZXIgQXVzdHJpYdgYWGOkaGRpZ2VzdElEB2ZyYW5kb21Qn1QekU65KvJJOrGVNaR_P3FlbGVtZW50SWRlbnRpZmllcm1yZXNpZGVudF9jaXR5bGVsZW1lbnRWYWx1ZXJHZW1laW5kZSBCaWJlcmJhY2jYGFhcpGhkaWdlc3RJRAhmcmFuZG9tUKRoJFLbL1iA7Kx5JJT5HW9xZWxlbWVudElkZW50aWZpZXJ0cmVzaWRlbnRfcG9zdGFsX2NvZGVsZWxlbWVudFZhbHVlZDMzMzHYGFhapGhkaWdlc3RJRAlmcmFuZG9tUDnyYB_JFvi2yy2P7DjaS3hxZWxlbWVudElkZW50aWZpZXJvcmVzaWRlbnRfc3RyZWV0bGVsZW1lbnRWYWx1ZWdUcmF1bmVy2BhYXKRoZGlnZXN0SUQKZnJhbmRvbVAnkVl7G05ZdexIAMp7qJdfcWVsZW1lbnRJZGVudGlmaWVydXJlc2lkZW50X2hvdXNlX251bWJlcmxlbGVtZW50VmFsdWVjMTAx2BhYWaRoZGlnZXN0SUQLZnJhbmRvbVAHUWhjKkj7Z4gnDEw32rk9cWVsZW1lbnRJZGVudGlmaWVycWZhbWlseV9uYW1lX2JpcnRobGVsZW1lbnRWYWx1ZWROZWFs2BhYWaRoZGlnZXN0SUQMZnJhbmRvbVAQkoP84o47NFz8lofKugD1cWVsZW1lbnRJZGVudGlmaWVycGdpdmVuX25hbWVfYmlydGhsZWxlbWVudFZhbHVlZVR5bGVy2BhYR6RoZGlnZXN0SUQNZnJhbmRvbVBWodC7mMpZjwLDd5SmUffdcWVsZW1lbnRJZGVudGlmaWVyY3NleGxlbGVtZW50VmFsdWUB2BhYZ6RoZGlnZXN0SUQOZnJhbmRvbVDOfpqDlv6E-CCsqFW9DZD8cWVsZW1lbnRJZGVudGlmaWVybWVtYWlsX2FkZHJlc3NsZWxlbWVudFZhbHVldnR5bGVyLm5lYWxAZXhhbXBsZS5jb23YGFiIpGhkaWdlc3RJRA9mcmFuZG9tUNXu6IgdQVip91iahL_dPYxxZWxlbWVudElkZW50aWZpZXJ4HnBlcnNvbmFsX2FkbWluaXN0cmF0aXZlX251bWJlcmxlbGVtZW50VmFsdWV4JDU4MDI4YTJiLWMyZWQtNDU1Yi04ZjU0LTlkZmYzYzk1ZWIwZdgYWFykaGRpZ2VzdElEEGZyYW5kb21QRxDQXWjJbr2ZoyNBy9iVKHFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZWxlbGVtZW50VmFsdWXZA-xqMjAyNi0wNi0xMdgYWHGkaGRpZ2VzdElEEWZyYW5kb21Q4HWgwCb-OtgnQyAW9OKTm3FlbGVtZW50SWRlbnRpZmllcnFpc3N1aW5nX2F1dGhvcml0eWxlbGVtZW50VmFsdWV4G0dSIEFkbWluaXN0cmF0aXZlIGF1dGhvcml0edgYWFWkaGRpZ2VzdElEEmZyYW5kb21QQY24DUAsXKbK2rDTOPUtUHFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlYkdS2BhYeKRoZGlnZXN0SUQTZnJhbmRvbVClMzYsbtX9-8rrtcwMDZ-rcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWV4JDFiMDUzM2MxLTVkNDYtNDE3OS05MmI5LTgwMmE3NGY3ZTA4MtgYWFykaGRpZ2VzdElEFGZyYW5kb21QACsS5etpBItEd6uEZzuAB3FlbGVtZW50SWRlbnRpZmllcnRpc3N1aW5nX2p1cmlzZGljdGlvbmxlbGVtZW50VmFsdWVkR1ItSdgYWF6kaGRpZ2VzdElEFWZyYW5kb21Q-XETNSAAc1xUnggKrmEFFHFlbGVtZW50SWRlbnRpZmllcm1pc3N1YW5jZV9kYXRlbGVsZW1lbnRWYWx1ZdkD7GoyMDI2LTAzLTAzamlzc3VlckF1dGiEQ6EBJqEYIVkBSzCCAUcwge6gAwIBAgIIYa1XJAzJfNswCgYIKoZIzj0EAwIwKjEoMCYGA1UEAxMfcGlkLWlzc3Vlci5kZXYuZXVkaS55b3VuaXF4LmNvbTAeFw0yNjAzMDMxMzA5NDlaFw0yNzAzMDMxMzA5NDlaMCoxKDAmBgNVBAMTH3BpZC1pc3N1ZXIuZGV2LmV1ZGkueW91bmlxeC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATHXpdSqJ5vJDFrb7P5r04re_7gbLB6kZS3b2YYkqe_bdLXt0jrqoMqKjwf5xNdQt2m7yMp4_KlmLOgbULThmWlMAoGCCqGSM49BAMCA0gAMEUCIQDVSFZGOT0swZ5loHSagpLwL5OSpCNlBdOtpUKeMJOiVQIgVu9_V2DKFmzevKXfsdLBevpDrORZZfT0N2XMBAPWiapZBGTYGFkEX6ZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMbYAWCBtqt4DV-e-ZNTtOYKvuqIX2-bIvpHIONmL6r1ifgzURwFYIG2-C-y3ZF-z4suFUmrVTYhBVT5Z5iqG0xnFdZdIDMUwAlggT-0sLDkzF_qnmCaVfDK6wJ-5YqRBEuBkvbnyrUqhfE8DWCAaDJfVGXS1ssl0a07iWDAJcAf80SJYgDOFzacfjQ02tQRYIE5NvfAPT4rs6BB-DwWIh-XWjJIoyYzi_jf4uKLVeDuiBVggXGgmVVySlBN9UvI--w6Z3Fsw3E1uBmmAfvd9cEBSLm4GWCBzhaNNvm1bz0bKsEb1R0zCXV7LzO6CP5lO_bMjk7LXlwdYIH6-E788aovJJi77hrl9qZ9dAjVnJ-g8WczFGe9u_66pCFggGQ0Y90d2ZuTIa3UfOmbDItCVwO3lBm6n6NQncsyRVlIJWCCKfGQFTUU1RyRs-FdxW5DtWQP6FlriYDP-HM5FDgKatwpYIOfIZMV7CAWsbyObGDzTVWiYELmWJzz8IdExyhlUWDqVC1ggkF7ZxoEoM4DHAiJnu77O2TCv0EJ8Bk8E1z_QkhuEmbMMWCDPRcBmaCqGwogxhkfdxqwpsmsWCbS4z1CHOSqQR1rE0A1YIL1Tp7oj2W_HD5fJZnvbzyz3JUZGfZK4o0X3vyg3XjYUDlggnGWNJwBPMnQ6K9yS_5WfYABKptC-ytFrf_0ESW7Bd6cPWCA1Qd4QI4VGRiHFdz8alXZ0yFmQfqciYjA4QnLTzSuT0hBYIOe1nPxRc4vRXQqWrlWQslFBOW8UIkIPIzVezXe81nCpEVggBWMyNIs13ad8PblVn5lcK8vdOMW7-SQxMveHVl9qAzYSWCAfd_8VGY2rnfTSGcfhhZXXvrtFjMv_vsZeWyU2BeLW9BNYIJoWfKyTTocDHxKgi44r8CAviVLFcpBQwNPsBEkHASL_FFggstKjH2lRSWI5UPp_pID9TlaE3jcEmng15FGgI2jnV9UVWCDB8vTNXgRJ28xGDW4XF2Jvb9sv6NOzu4APqqfVby1NMm1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIOZQTDafveCzJWtDqHQbbT1TdF1GLspw3AnmsO5YBFmvIlggG5fjP89tVjP6nrCEgdlQTgbeH0TGBIjw4j6H5zvYLAVnZG9jVHlwZXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMWx2YWxpZGl0eUluZm-jZnNpZ25lZMB4HjIwMjYtMDMtMDNUMTM6Mjc6MTMuMzg2ODE5ODQyWml2YWxpZEZyb23AeB4yMDI2LTAzLTAzVDEzOjI3OjEzLjM4NjgxOTg0MlpqdmFsaWRVbnRpbMB4HjIwMjYtMDQtMDJUMTM6Mjc6MTMuMzg2ODE5ODQyWlhAU6ivtLx-ZUiGR1ReCXarw_SC6NB2leGjODeJY096YkdpFBZFq9Q2Y17wkdYlCiubwezbNZvZ6C6XG243bzJaQQ==
        """.trimIndent()

        coseCompliantSerializer.decodeFromByteArray<IssuerSigned>(input.decodeToByteArray(Base64UrlStrict)).shouldNotBeNull()
            .also { println(it) }
    }

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
