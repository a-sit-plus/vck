package at.asitplus.wallet.lib.cbor

import at.asitplus.iso.CborCredentialSerializer
import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceKeyInfo
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.IssuerSignedItemSerializer
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.ValidityInfo
import at.asitplus.iso.ValueDigest
import at.asitplus.iso.ValueDigestList
import at.asitplus.iso.sha256
import at.asitplus.iso.wrapInCborTag
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseEllipticCurve
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.CoseKeyParams
import at.asitplus.signum.indispensable.cosef.CoseKeyType
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.data.LocalDateOrInstant
import at.asitplus.wallet.lib.data.LocalDateOrInstantSerializer
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.aroundEach
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.LocalDate
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.random.Random
import kotlin.random.nextUInt
import kotlin.time.Clock
import kotlin.time.Instant

@OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)
val IssuerSignedItemSerializationTest by testSuite {

    lateinit var elementId: String
    lateinit var namespace: String

    testConfig= TestConfig.aroundEach {
        namespace = uuid4().toString()
        elementId = uuid4().toString()
        it()
    }

    "serialization with String" {
        val item = IssuerSignedItem(
            digestId = Random.nextUInt(),
            random = Random.nextBytes(16),
            elementIdentifier = elementId,
            elementValue = uuid4().toString(),
        )
        val serialized =
            coseCompliantSerializer.encodeToByteArray(IssuerSignedItemSerializer(namespace, elementId), item)
        serialized.encodeToString(Base16()).shouldNotContain("D903EC")

        coseCompliantSerializer.decodeFromByteArray(IssuerSignedItemSerializer("", elementId), serialized) shouldBe item
    }

    "serialization with Instant" {
        CborCredentialSerializer.register(mapOf(elementId to Instant.serializer()), namespace)
        val item = IssuerSignedItem(
            digestId = Random.nextUInt(),
            random = Random.nextBytes(16),
            elementIdentifier = elementId,
            elementValue = Clock.System.now(),
        )

        val serialized =
            coseCompliantSerializer.encodeToByteArray(IssuerSignedItemSerializer(namespace, elementId), item)
            .also {
                it.encodeToString(Base16()).shouldContain(
                    "elementValue".toHex()
                            + "C0" // tag(0)
                            + "78" // text(..)
                )
            }

        coseCompliantSerializer.decodeFromByteArray(
            IssuerSignedItemSerializer(namespace, elementId),
            serialized
        ) shouldBe item
    }

    "serialization with LocalDate" {
        CborCredentialSerializer.register(mapOf(elementId to LocalDate.serializer()), namespace)
        val item = IssuerSignedItem(
            digestId = Random.nextUInt(),
            random = Random.nextBytes(16),
            elementIdentifier = elementId,
            elementValue = LocalDate.fromEpochDays(Random.nextInt(32768))
        )

        val serialized =
            coseCompliantSerializer.encodeToByteArray(IssuerSignedItemSerializer(namespace, elementId), item)
            .also {
                it.encodeToString(Base16()).shouldContain(
                    "elementValue".toHex()
                            + "D903EC" // tag(1004)
                            + "6A" // text(10)
                )
            }

        coseCompliantSerializer.decodeFromByteArray(
            IssuerSignedItemSerializer(namespace, elementId),
            serialized
        ) shouldBe item
    }

    "document serialization with ByteArray" {
        CborCredentialSerializer.register(mapOf(elementId to ByteArraySerializer()), namespace)
        val digestId = 13u
        val item = IssuerSignedItem(
            digestId = digestId,
            random = Random.nextBytes(16),
            elementIdentifier = elementId,
            elementValue = Random.nextBytes(32),
        )
        val protectedHeader = CoseHeader(algorithm = CoseAlgorithm.Signature.RS256)
        val mso = MobileSecurityObject(
            version = "1.0",
            digestAlgorithm = "SHA-256",
            valueDigests = mapOf(
                namespace to ValueDigestList(
                    listOf(ValueDigest.fromIssuerSignedItem(item, namespace))
                )
            ),
            deviceKeyInfo = DeviceKeyInfo(
                CoseKey(
                    CoseKeyType.EC2,
                    keyParams = CoseKeyParams.EcYBoolParams(CoseEllipticCurve.P256)
                )
            ),
            docType = namespace,
            validityInfo = ValidityInfo(Clock.System.now(), Clock.System.now(), Clock.System.now()),
        )
        val issuerAuth = CoseSigned.create(
            protectedHeader,
            null,
            mso,
            CryptoSignature.RSA(byteArrayOf()),
            MobileSecurityObject.serializer()
        )
        val doc = Document(
            docType = uuid4().toString(),
            issuerSigned = IssuerSigned.fromIssuerSignedItems(
                mapOf(namespace to listOf(item)),
                issuerAuth
            ),
            deviceSigned = DeviceSigned(
                ByteStringWrapper(DeviceNameSpaces(mapOf())),
                DeviceAuth()
            )
        )
        val serialized = coseCompliantSerializer.encodeToByteArray(doc).also {
            it.encodeToString(Base16()).also {
                it.shouldNotContain("D903EC")
                val itemSerialized = coseCompliantSerializer.encodeToByteArray(
                    IssuerSignedItemSerializer(namespace, item.elementIdentifier), item
                )
                val itemBytes = coseCompliantSerializer.encodeToByteArray(ByteArraySerializer(), itemSerialized)
                it.shouldContain( // inside the document
                    "nameSpaces".toHex()
                            + "A1" // map(1)
                            + "7824" // text(36)
                            + namespace.toHex()
                            + "81" // array(1)
                            + "D818" // tag(24)
                            + itemBytes.encodeToString(Base16())
                )
                // important here is wrapping in D818 before hashing it!
                val itemHash = itemBytes.wrapInCborTag(24).sha256()
                it.shouldContain( // inside the mso
                    namespace.toHex()
                            + "A1" // map(1)
                            + "0D" // unsigned 13, the digestId
                            + "5820" // bytes(32)
                            + itemHash.encodeToString(Base16())
                )
            }
        }

        coseCompliantSerializer.decodeFromByteArray<Document>(serialized) shouldBe doc
    }

    // Contains LocalDates instead of Instants, as we expected, so we'll handle this with LocalDateOrInstantSerializer
    "deserialize DeviceResponse from EUDI Ref Impl" {
        CborCredentialSerializer.register(
            serializerMap = mapOf(
                "expiry_date" to LocalDateOrInstantSerializer,
                "birth_date" to LocalDateOrInstantSerializer
            ),
            isoNamespace = "eu.europa.ec.eudi.pid.1"
        )
        val input = """
            o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBld2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xbGlzc3VlclNpZ25lZKJqbmFtZVNwYWNl
            c6F3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjGI2BhYbKRmcmFuZG9tWCAYEd2zTYDimiBjUeC_955trB4a2hZlPCQF5NPKX9uGB2hkaWdlc3RJ
            RAhsZWxlbWVudFZhbHVl2QPsajE5NjUtMDEtMDFxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWG2kZnJhbmRvbVggkqce2jGkon0M
            48b7qIKlc0tcztcoBvVLbO1fSnniZXloZGlnZXN0SUQEbGVsZW1lbnRWYWx1ZdkD7GoyMDI1LTA4LTI1cWVsZW1lbnRJZGVudGlmaWVya2V4
            cGlyeV9kYXRl2BhYZqRmcmFuZG9tWCD1d1Oi7UwmN5EPBRcMhTe9BEv1wWu6EEbof8u_6tDbyWhkaWdlc3RJRAJsZWxlbWVudFZhbHVlZkdh
            cmNpYXFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWGWkZnJhbmRvbVggjBx-y1fceuQod-KSt9varklC4YV45dsoqJPIzyEceEpo
            ZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZWZqYXZpZXJxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZdgYWHWkZnJhbmRvbVggXSfcSWd04t-Y
            pALvhp00pGQrHk948yhJl1mLW1AuM2VoZGlnZXN0SUQBbGVsZW1lbnRWYWx1ZW9UZXN0IFBJRCBpc3N1ZXJxZWxlbWVudElkZW50aWZpZXJx
            aXNzdWluZ19hdXRob3JpdHnYGFhvpGZyYW5kb21YIEXxSYm4G04mADNQRuGixci-Fv1JA6cfpQvGZLLz9B6taGRpZ2VzdElEB2xlbGVtZW50
            VmFsdWXZA-xqMjAyNS0wNS0yN3FlbGVtZW50SWRlbnRpZmllcm1pc3N1YW5jZV9kYXRl2BhYZqRmcmFuZG9tWCAWvlEqzjYIda5q8KADpkfm
            AUOAKGt8Iq1R5X7_blAHE2hkaWdlc3RJRABsZWxlbWVudFZhbHVlYkVVcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyedgYWGOk
            ZnJhbmRvbVggxfPLvhC9UFMZyEKtSh5ERT6r78nUZW2KoCf4qLASZNZoZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZYFiRVVxZWxlbWVudElkZW50
            aWZpZXJrbmF0aW9uYWxpdHlqaXNzdWVyQXV0aIRDoQEmoRghWQLeMIIC2jCCAoCgAwIBAgIUf2vrQ0pb13kmYuW1dsLV85EnOAswCgYIKoZI
            zj0EAwIwVzEZMBcGA1UEAwwQUElEIElzc3VlciBDQSAwMjEtMCsGA1UECgwkRVVESSBXYWxsZXQgUmVmZXJlbmNlIEltcGxlbWVudGF0aW9u
            MQswCQYDVQQGEwJFVTAeFw0yNTA0MTAxNDM0MTFaFw0yNjA3MDQxNDM0MTBaMFIxFDASBgNVBAMMC1BJRCBEUyAtIDAxMS0wKwYDVQQKDCRF
            VURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAkVVMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbtpdDGfZ
            r2pafe15Qo02ImcCSgmB30OdgaaO8_TFpUtR3MbVStda2Mz17DRVFtadtqHKSSSad7ke42LemkjamqOCAS0wggEpMB8GA1UdIwQYMBaAFEJQ
            UL4QuBDwnURcjb-rEAjuJ9xJMBsGA1UdEQQUMBKCEGlzc3Vlci5ldWRpdy5kZXYwFgYDVR0lAQH_BAwwCgYIK4ECAgAAAQIwQwYDVR0fBDww
            OjA4oDagNIYyaHR0cHM6Ly9wcmVwcm9kLnBraS5ldWRpdy5kZXYvY3JsL3BpZF9DQV9FVV8wMi5jcmwwHQYDVR0OBBYEFFABcwEd7yXSDl5I
            yCs7OJHEnJnxMA4GA1UdDwEB_wQEAwIHgDBdBgNVHRIEVjBUhlJodHRwczovL2dpdGh1Yi5jb20vZXUtZGlnaXRhbC1pZGVudGl0eS13YWxs
            ZXQvYXJjaGl0ZWN0dXJlLWFuZC1yZWZlcmVuY2UtZnJhbWV3b3JrMAoGCCqGSM49BAMCA0gAMEUCICqWEEilBF9oPJ4bBZQw2Ekz1hU8-aOZ
            WpHT2w__0IWNAiEAyOM2_D2-WFvlrOP2gQmLhWxkClDagbhvElQCjPIqSwVZA4_YGFkDiqdmc3RhdHVzomtzdGF0dXNfbGlzdKJjaWR4GRMR
            Y3VyaXhqaHR0cHM6Ly9pc3N1ZXIuZXVkaXcuZGV2L3Rva2VuX3N0YXR1c19saXN0L0VVL2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xL2JiMTEz
            N2UwLWZlMWUtNDRkYi05Mjg1LWRlN2VkOGMyZDEwZW9pZGVudGlmaWVyX2xpc3SiYmlkZDQ4ODFjdXJpeGhodHRwczovL2lzc3Vlci5ldWRp
            dy5kZXYvaWRlbnRpZmllcl9saXN0L0VVL2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xL2JiMTEzN2UwLWZlMWUtNDRkYi05Mjg1LWRlN2VkOGMy
            ZDEwZWdkb2NUeXBld2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI1LTA1LTI3
            VDA4OjEzOjIxWml2YWxpZEZyb23AdDIwMjUtMDUtMjdUMDg6MTM6MjFaanZhbGlkVW50aWzAdDIwMjUtMDgtMjVUMDA6MDA6MDBabHZhbHVl
            RGlnZXN0c6F3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjGpAFggwG5NkzwZiLZMD62mdmwvFjv7aTQt1We8iyH-fMbWO8sBWCCKAOnJaNlolxsK
            x-Qi-LoeU9vjl9vdGG7g4vhyyQUHWAJYIL9LlzaBrcdI9jzH2wCEuEXf8qQV6su28rwucz6iw7YHA1ggQkJUF8m34q1KQ2z9mD5hA9K3DNVl
            b5i7oVwOCFl3oIAEWCAtkHp9sgW3gUwiKyfN_rd87NPLEtH2nuoRGW8KzTQUWgVYIADp4Ty9opglXbQUQ30H7FFqC216q9s3IF3GgU7ywmEg
            Blggz-gl9y3r34GxowWRe6CzenwZ3hV3OsFnmMfIy83xxIAHWCC95VWgMCakOg_pmBX4VMLw1FVbejAMYo4WHMVminYe4QhYILvkcUWw01Er
            IDrvKdqJ7gxOqALLL6hTKI3N-ibW0yfGbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggUVFDZDIPLJLjMcpeZbYgU4ahAGglIGcu
            Je34Rk_gV-IiWCA4P6VbgKeKQMl3WGFaaHFXMpcgQlzQF_eW9Yuk1ho0im9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAi-IYBBTdONaATnXY
            4jcS9Wg32A72OZ9zRKBHrzd2MFq9Gk1HPBQFkL5n3SWtb9-nPeJZAfk_nScMkpcYY844r2xkZXZpY2VTaWduZWSiam5hbWVTcGFjZXPYGEGg
            amRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQAdF3jbal7_uvhXIxuKV9ZE_9Dja-3dkzH5OUFJ5fug7CfxtYIWyQXmBb-0s
            VeJakU_LiF4mJwXG4JRLiu3htGtmc3RhdHVzAA
        """.trimIndent()

        input.decodeToByteArray(Base64UrlStrict)
            .let { coseCompliantSerializer.decodeFromByteArray<DeviceResponse>(it) }
            .apply {
                documents.shouldNotBeNull().first().apply {
                    issuerSigned.namespaces.shouldNotBeNull().values.first().apply {
                        entries.shouldHaveSize(8)
                        entries.first { it.value.elementIdentifier == "expiry_date" }
                            .value.elementValue shouldBe LocalDateOrInstant.LocalDate(LocalDate.parse("2025-08-25"))
                        entries.first { it.value.elementIdentifier == "birth_date" }
                            .value.elementValue shouldBe LocalDateOrInstant.LocalDate(LocalDate.parse("1965-01-01"))
                    }
                }
            }
    }

    "deserialize IssuerSigned from EUDI Ref Impl" {
        CborCredentialSerializer.register(mapOf("birth_date" to LocalDate.serializer()), "eu.europa.ec.eudi.pid.1")
        val input = """
            A26A697373756572417574688443A10126A118215902E9308202E53082026AA003020102021419040C2598027AD6AC99063EE39AB8C3
            6FA6DAE4300A06082A8648CE3D040302305C311E301C06035504030C1550494420497373756572204341202D204555203031312D302B
            060355040A0C24455544492057616C6C6574205265666572656E636520496D706C656D656E746174696F6E310B300906035504061302
            4555301E170D3233303930323137333932385A170D3234313132353137333932375A30543116301406035504030C0D50494420445320
            2D2030303031312D302B060355040A0C24455544492057616C6C6574205265666572656E636520496D706C656D656E746174696F6E31
            0B30090603550406130245553059301306072A8648CE3D020106082A8648CE3D0301070342000464DF85FAA25CB3830A6F83ED10FDAD
            6A2068540205349D71DBB0B84B2BC32E6B178E5F3F698808922EAD03B60A359AE914042CCA0513E5D51F34AB0209605F99A382011030
            82010C301F0603551D23041830168014418B6176E18C81DC3FB25F563FFE6CB20681E01130160603551D250101FF040C300A06082B81
            02020000010230430603551D1F043C303A3038A036A034863268747470733A2F2F70726570726F642E706B692E65756469772E646576
            2F63726C2F7069645F43415F45555F30312E63726C301D0603551D0E041604146035E1769A8317A5D92E2FFBEF492992ED0F4418300E
            0603551D0F0101FF040403020780305D0603551D1204563054865268747470733A2F2F6769746875622E636F6D2F65752D6469676974
            616C2D6964656E746974792D77616C6C65742F6172636869746563747572652D616E642D7265666572656E63652D6672616D65776F72
            6B300A06082A8648CE3D0403020369003066023100CF75AD412DD8A9365701BB85EB844617952682D53E93181B4C66C621D99D58BED4
            32C074040219AE599E924B7A5224EE023100903B1BDCF9AF87AD3CF63EB68119D4C0AD8FD2C9F8F9314D0A504C4E3DB5018540656132
            389397AFD615A43826B70A2A590259D818590254A667646F63547970657765752E6575726F70612E65632E657564692E7069642E3167
            76657273696F6E63312E306C76616C6964697479496E666FA3667369676E6564C074323032342D31302D32335431343A32343A32355A
            6976616C696446726F6DC074323032342D31302D32335431343A32343A32355A6A76616C6964556E74696CC074323032352D30312D32
            315430303A30303A30305A6C76616C756544696765737473A17765752E6575726F70612E65632E657564692E7069642E31A8005820B7
            FAC61165B43D7088E504E05332E544FD05A7944865ED1D84CAFB3F8CB98CA2015820B314A01D1963184513EC7D28CE76FE4D112308D7
            B6059B50352AC4337E8E33D00258207580DBF64DDCB633C52C898103D546533C5F8F3FD4DB93874C219BCF51CE1912035820ABD56C84
            EE00E01C88C1EE9C71BEFCD1B3E22890EC0A28193BD0FC8D60662B5804582087065EA6E65356C14DCD2523F13BA27D7932C075DD3455
            29E5621C2E80C6919405582092D5D5435000AF5BACFD16259AC88CA26F949D945B43F55986F4A921549166330658207741AD9D5E0805
            A378B7EE837749C61539DA9A38BF5F7222C8A380C2AAF2C8CC075820BAE6B7B63C4F107216465DF1EFE817A10F3AE9D0AF4FB827DEAD
            D188351CF5FE6D6465766963654B6579496E666FA1696465766963654B6579A4010220012158205B6FD9E2B13EB0E5687C2668281BA2
            E00B74A4AD878FB89125F3489C5F6E4BED225820B5C87386D05EBFEE6FE1DA7AF3530E8E659A70154F91C594D0F953D176430F9D6F64
            6967657374416C676F726974686D675348412D32353658404DDD44CCC2761226F02391F45A23189A7C53A5B9ADA080A23DED77A93988
            DC5AF59A67EC936F594AF86AE188CDC667573E377DB23657618B9FB6A24F01BF99A06A6E616D65537061636573A17765752E6575726F
            70612E65632E657564692E7069642E3188D818586CA46672616E646F6D5820A0A2A777A503F660A157C7B09008F606D42D353CC5A86D
            CB51051F02EDA1D4AA686469676573744944006C656C656D656E7456616C7565D903EC6A313936352D30312D303171656C656D656E74
            4964656E7469666965726A62697274685F64617465D818586FA46672616E646F6D5820F41ABFAFE91CFBA92E78C249C4C92F63C60D23
            47B3B74D21C2A3FEFEA2DF9569686469676573744944016C656C656D656E7456616C7565D903EC6A323032342D31302D323371656C65
            6D656E744964656E7469666965726D69737375616E63655F64617465D8185865A46672616E646F6D5820105A81F2B0F3835025EC5C8A
            FC1C5C55D08AC7F91BB175E858F03FE1E8BA5395686469676573744944026C656C656D656E7456616C7565666A617669657271656C65
            6D656E744964656E7469666965726A676976656E5F6E616D65D818586DA46672616E646F6D5820C58F218133297B5413268A51F4245D
            06F497E189BBCD63FF5B8F04D5B75321DE686469676573744944036C656C656D656E7456616C7565D903EC6A323032352D30312D3231
            71656C656D656E744964656E7469666965726B6578706972795F64617465D8185860A46672616E646F6D58202B27AC89B308044EA57A
            26CE02388C005C34E415F0E8E1F259D51999915E958B686469676573744944046C656C656D656E7456616C7565F571656C656D656E74
            4964656E7469666965726B6167655F6F7665725F3138D8185866A46672616E646F6D582051BFD38D542495BE08327AC2064A05846836
            B35FBAC4F0C467DE0338072DA30B686469676573744944056C656C656D656E7456616C75656647617263696171656C656D656E744964
            656E7469666965726B66616D696C795F6E616D65D8185866A46672616E646F6D58203DA715C789DE91788ACD9A6A919CE82DB180C1F7
            D3AEB41AE81A0F0027349C29686469676573744944066C656C656D656E7456616C756562455571656C656D656E744964656E74696669
            65726F69737375696E675F636F756E747279D8185875A46672616E646F6D58207A17BCCBCA82615A3CB1321343CB963287482156C2C8
            E8563C35B8E0A3825CF0686469676573744944076C656C656D656E7456616C75656F54657374205049442069737375657271656C656D
            656E744964656E7469666965727169737375696E675F617574686F72697479
        """.trimIndent().replace("\n", "")

        val parsed = coseCompliantSerializer.decodeFromByteArray<IssuerSigned>(input.decodeToByteArray(Base16()))

        val namespaces = parsed.namespaces
            .shouldNotBeNull()
        val issuerSignedList = namespaces.values.first()
        val issuerSignedItems = issuerSignedList.entries.map { it.value }
        issuerSignedItems.first { it.elementIdentifier == "given_name" }
            .elementValue shouldBe "javier"
        issuerSignedItems.first { it.elementIdentifier == "family_name" }
            .elementValue shouldBe "Garcia"
        issuerSignedItems.first { it.elementIdentifier == "issuing_authority" }
            .elementValue shouldBe "Test PID issuer"
        issuerSignedItems.first { it.elementIdentifier == "birth_date" }
            .elementValue shouldBe LocalDate.parse("1965-01-01")
    }

}
private fun String.toHex(): String = encodeToByteArray().encodeToString(Base16())
