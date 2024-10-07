package at.asitplus.wallet.lib.oidc

import at.asitplus.openid.OpenIdConstants
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

@Suppress("unused")
class OidcSiopIsoProtocolTest : FreeSpec({

    lateinit var relyingPartyUrl: String
    lateinit var walletUrl: String

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial

    lateinit var holderAgent: Holder

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        relyingPartyUrl = "https://example.com/rp/${uuid4()}"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)

        val issuerAgent = IssuerAgent(
            EphemeralKeyWithSelfSignedCert(),
            DummyCredentialDataProvider(),
        )
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                holderKeyMaterial.publicKey,
                MobileDrivingLicenceScheme,
                ConstantIndex.CredentialRepresentation.ISO_MDOC,
            ).getOrThrow().toStoreCredentialInput()
        )
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.ISO_MDOC,
            ).getOrThrow().toStoreCredentialInput()
        )


        holderSiop = OidcSiopWallet(
            holder = holderAgent,
            keyMaterial = holderKeyMaterial
        )
    }

    "test with Fragment for mDL" {
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
        )
        val document = runProcess(
            verifierSiop,
            walletUrl,
            OidcSiopVerifier.RequestOptions(
                credentials = setOf(
                    OidcSiopVerifier.RequestOptionsCredential(
                        MobileDrivingLicenceScheme, ConstantIndex.CredentialRepresentation.ISO_MDOC, listOf(
                            MobileDrivingLicenceDataElements.GIVEN_NAME
                        )
                    )
                )
            ),
            holderSiop
        )

        document.validItems.shouldNotBeEmpty()
        document.invalidItems.shouldBeEmpty()
    }

    "test with Fragment for custom attributes" {
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
        )
        val document = runProcess(
            verifierSiop,
            walletUrl,
            OidcSiopVerifier.RequestOptions(
                credentials = setOf(
                    OidcSiopVerifier.RequestOptionsCredential(
                        ConstantIndex.AtomicAttribute2023,
                        ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        listOf(CLAIM_GIVEN_NAME)
                    )
                )
            ),
            holderSiop
        )

        document.validItems.shouldNotBeEmpty()
        document.invalidItems.shouldBeEmpty()
    }

    "Selective Disclosure with mDL" {
        val requestedClaim = MobileDrivingLicenceDataElements.FAMILY_NAME
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
        )
        val document = runProcess(
            verifierSiop,
            walletUrl,
            OidcSiopVerifier.RequestOptions(
                credentials = setOf(
                    OidcSiopVerifier.RequestOptionsCredential(
                        MobileDrivingLicenceScheme,
                        ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        listOf(requestedClaim)
                    )
                )
            ),
            holderSiop,
        )

        document.validItems.shouldNotBeEmpty()
        document.validItems.shouldBeSingleton()
        document.validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
        document.invalidItems.shouldBeEmpty()
    }

    "Selective Disclosure with mDL and encryption" {
        val requestedClaim = MobileDrivingLicenceDataElements.FAMILY_NAME
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
        )
        val requestOptions = OidcSiopVerifier.RequestOptions(
            credentials = setOf(
                OidcSiopVerifier.RequestOptionsCredential(
                    MobileDrivingLicenceScheme, ConstantIndex.CredentialRepresentation.ISO_MDOC, listOf(requestedClaim)
                )
            ),
            responseMode = OpenIdConstants.ResponseMode.DIRECT_POST_JWT,
            responseUrl = "https://example.com/response",
            encryption = true
        )
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = requestOptions
        )

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>()

        val result = verifierSiop.validateAuthnResponseFromPost(authnResponse.params.formUrlEncode())
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessIso>()

        val document = result.document

        document.validItems.shouldNotBeEmpty()
        document.validItems.shouldBeSingleton()
        document.validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
        document.invalidItems.shouldBeEmpty()
    }

    "Selective Disclosure with mDL JSON Path syntax" {
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
        )
        val document = runProcess(
            verifierSiop,
            walletUrl,
            OidcSiopVerifier.RequestOptions(
                credentials = setOf(
                    OidcSiopVerifier.RequestOptionsCredential(
                        MobileDrivingLicenceScheme,
                        ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        listOf(MobileDrivingLicenceDataElements.FAMILY_NAME)
                    )
                )
            ),
            holderSiop,
        )

        document.validItems.shouldNotBeEmpty()
        document.validItems.shouldBeSingleton()
        document.validItems.shouldHaveSingleElement { it.elementIdentifier == MobileDrivingLicenceDataElements.FAMILY_NAME }
        document.invalidItems.shouldBeEmpty()
    }

    "test with null (40) device signed namespaces" {
        val challenge = "65623234623765352D323439352D343861302D613363342D373830656564373666383534"
            .decodeToByteArray(Base16())
            .decodeToString()
        val result = VerifierAgent().verifyPresentation("""
            A367646F6354797065756F72672E69736F2E31383031332E352E312E6D444C6C6973737565725369676E6564A26A6E616D6553706163
            6573A1716F72672E69736F2E31383031332E352E3182D8185866A4686469676573744944006672616E646F6D50B0E121BC0DD5B359AB
            177B724CF9D14B71656C656D656E744964656E7469666965726B66616D696C795F6E616D656C656C656D656E7456616C756577585858
            4D7573746572667261752045727761636873656ED8185856A4686469676573744944016672616E646F6D5026D63D2FA5D69DCF72332D
            73274996B671656C656D656E744964656E7469666965726A676976656E5F6E616D656C656C656D656E7456616C756568585858476572
            64616A697373756572417574688443A10126A11821590154308201503081F8A003020102020466335690300A06082A8648CE3D040302
            303131133011060355040A0C0A412D53495420506C7573311A301806035504030C1157616C6C6574204261636B656E64204D31301E17
            0D3234303530323039303230385A170D3239303530323039303230385A303131133011060355040A0C0A412D53495420506C7573311A
            301806035504030C1157616C6C6574204261636B656E64204D313059301306072A8648CE3D020106082A8648CE3D0301070342000485
            7BD2CAC0BC74DF6F8047B51F9BDA3DBEEB8ED62396C345BF04CE8BCBECF6F74997235B7BC2FF2A61FEA707669AF53F3610AC4B072818
            93B96F7719E5F075ED300A06082A8648CE3D040302034700304402204E88D3F1DE1C054CE32D941AAE32CDD4807308A532800F6450AF
            FB713B53407302204FDBAF2E755159348D6A5400A4228C4CE5DC30C1A6F1D2E97A6EF734BB57BF1659019DD818590198A66776657273
            696F6E63312E306F646967657374416C676F726974686D675348412D3235366C76616C756544696765737473A1716F72672E69736F2E
            31383031332E352E31A200582050B643EB2618F93A77DB057F8FD7E47FA18A54358530B352431572C65E5DDCBB01582056237A435D53
            631E9D9E8CE66B95102619F9A33AC072779986E6E67722ADB9636D6465766963654B6579496E666FA1696465766963654B6579A40102
            200121582015DE28C55FB255B5BFF5929E0F1BF4AEE499F1CDACB9769B67EED978A495079F225820BF60DF8A945C03959AE8F688D0EA
            5BFB27E3CB7DE205AB7B8A56B94CE7F7B3EE67646F6354797065756F72672E69736F2E31383031332E352E312E6D444C6C76616C6964
            697479496E666FA3667369676E6564781E323032342D31302D30375430383A34363A30362E3137383232353834335A6976616C696446
            726F6D781E323032342D31302D30375430383A34363A30362E3137383232353834335A6A76616C6964556E74696C781E323032352D31
            302D30325430383A34363A30362E3137343134363539375A5840AD493976DC65E43E10B980782CAF29CA5E8EFDB440F38607B8CD9BDE
            46DA97C9C5DA64A3FD90B93ADA7A806DCB5808F68250C9B7DA7A51C246CBA51A2059F1776C6465766963655369676E6564A26A6E616D
            65537061636573D818406A64657669636541757468A16F6465766963655369676E61747572658443A10126A058246562323462376535
            2D323439352D343861302D613363342D3738306565643736663835345840F3D8B1235AC6D2D12A4B8BA86438A043E3143D65099DBB22
            FE4C358492E8F6B757A98188526D021866EE71106FF98C1CF6A777F92CE48212F4F60CF917FE1814
        """.trimIndent().replace("\n", ""), challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>()
    }


    "test with empty (41A0) device signed namespaces" {
        val challenge = "65623234623765352D323439352D343861302D613363342D373830656564373666383534"
            .decodeToByteArray(Base16())
            .decodeToString()
        val result = VerifierAgent().verifyPresentation("""
            A367646F6354797065756F72672E69736F2E31383031332E352E312E6D444C6C6973737565725369676E6564A26A6E616D6553706163
            6573A1716F72672E69736F2E31383031332E352E3182D8185866A4686469676573744944006672616E646F6D50B0E121BC0DD5B359AB
            177B724CF9D14B71656C656D656E744964656E7469666965726B66616D696C795F6E616D656C656C656D656E7456616C756577585858
            4D7573746572667261752045727761636873656ED8185856A4686469676573744944016672616E646F6D5026D63D2FA5D69DCF72332D
            73274996B671656C656D656E744964656E7469666965726A676976656E5F6E616D656C656C656D656E7456616C756568585858476572
            64616A697373756572417574688443A10126A11821590154308201503081F8A003020102020466335690300A06082A8648CE3D040302
            303131133011060355040A0C0A412D53495420506C7573311A301806035504030C1157616C6C6574204261636B656E64204D31301E17
            0D3234303530323039303230385A170D3239303530323039303230385A303131133011060355040A0C0A412D53495420506C7573311A
            301806035504030C1157616C6C6574204261636B656E64204D313059301306072A8648CE3D020106082A8648CE3D0301070342000485
            7BD2CAC0BC74DF6F8047B51F9BDA3DBEEB8ED62396C345BF04CE8BCBECF6F74997235B7BC2FF2A61FEA707669AF53F3610AC4B072818
            93B96F7719E5F075ED300A06082A8648CE3D040302034700304402204E88D3F1DE1C054CE32D941AAE32CDD4807308A532800F6450AF
            FB713B53407302204FDBAF2E755159348D6A5400A4228C4CE5DC30C1A6F1D2E97A6EF734BB57BF1659019DD818590198A66776657273
            696F6E63312E306F646967657374416C676F726974686D675348412D3235366C76616C756544696765737473A1716F72672E69736F2E
            31383031332E352E31A200582050B643EB2618F93A77DB057F8FD7E47FA18A54358530B352431572C65E5DDCBB01582056237A435D53
            631E9D9E8CE66B95102619F9A33AC072779986E6E67722ADB9636D6465766963654B6579496E666FA1696465766963654B6579A40102
            200121582015DE28C55FB255B5BFF5929E0F1BF4AEE499F1CDACB9769B67EED978A495079F225820BF60DF8A945C03959AE8F688D0EA
            5BFB27E3CB7DE205AB7B8A56B94CE7F7B3EE67646F6354797065756F72672E69736F2E31383031332E352E312E6D444C6C76616C6964
            697479496E666FA3667369676E6564781E323032342D31302D30375430383A34363A30362E3137383232353834335A6976616C696446
            726F6D781E323032342D31302D30375430383A34363A30362E3137383232353834335A6A76616C6964556E74696C781E323032352D31
            302D30325430383A34363A30362E3137343134363539375A5840AD493976DC65E43E10B980782CAF29CA5E8EFDB440F38607B8CD9BDE
            46DA97C9C5DA64A3FD90B93ADA7A806DCB5808F68250C9B7DA7A51C246CBA51A2059F1776C6465766963655369676E6564A26A6E616D
            65537061636573D81841A06A64657669636541757468A16F6465766963655369676E61747572658443A10126A0582465623234623765
            352D323439352D343861302D613363342D3738306565643736663835345840F3D8B1235AC6D2D12A4B8BA86438A043E3143D65099DBB
            22FE4C358492E8F6B757A98188526D021866EE71106FF98C1CF6A777F92CE48212F4F60CF917FE1814
        """.trimIndent().replace("\n", ""), challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>()
    }
})

private suspend fun runProcess(
    verifierSiop: OidcSiopVerifier,
    walletUrl: String,
    requestOptions: OidcSiopVerifier.RequestOptions,
    holderSiop: OidcSiopWallet,
): IsoDocumentParsed {
    val authnRequest = verifierSiop.createAuthnRequestUrl(
        walletUrl = walletUrl,
        requestOptions = requestOptions
    )

    val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
    authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

    val result = verifierSiop.validateAuthnResponse(authnResponse.url)
    result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessIso>()
    return result.document
}
