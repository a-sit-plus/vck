package at.asitplus.wallet.ios

import at.asitplus.dcapi.ios.IosDcApiMdocPreRequestSummary
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.iso.EncryptionInfo
import at.asitplus.iso.EncryptionParameters
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseEllipticCurve
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.CoseKeyParams
import at.asitplus.signum.indispensable.cosef.CoseKeyType
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.internals.toNSData
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.ktor.openid.ProvisioningContext
import at.asitplus.wallet.lib.oidvci.CredentialIdentifierInfo
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException

private const val ISSUER_METADATA = """{
    "credential_issuer": "https://issuer.example",
    "credential_endpoint": "https://issuer.example/credential",
    "authorization_servers": ["https://auth.example"],
    "nonce_endpoint": "https://issuer.example/nonce",
    "credential_configurations_supported": {
        "pid": {"format": "dc+sd-jwt", "vct": "urn:example:pid"}
    }
}"""

private const val PRE_REQUEST_SUMMARY =
    """{"documentRequests":[{"docType":"org.iso.18013.5.1.mDL","namespaces":{"org.iso.18013.5.1":{"family_name":false}}}]}"""

val CodecsTest by matrixSuite {

    test("JoseCodec round trips through NSData") {
        val codec = JoseCodec(TokenResponseParameters.serializer())
        val token = TokenResponseParameters(accessToken = "token", tokenType = "DPoP", scope = "pid")

        val decoded = codec.decode(codec.encode(token))

        decoded shouldBe token
    }

    test("JoseCodec decodes JSON of the issuer") {
        val codec = JoseCodec(IssuerMetadata.serializer())

        val metadata = codec.decode(ISSUER_METADATA.encodeToByteArray().toNSData())

        metadata.credentialIssuer shouldBe "https://issuer.example"
        metadata.supportedCredentialConfigurations.keys shouldBe setOf("pid")
        codec.decodeFromString(codec.encodeToString(metadata)) shouldBe metadata
    }

    test("JoseCodec rejects malformed input") {
        val codec = JoseCodec(IssuerMetadata.serializer())

        shouldThrow<SerializationException> { codec.decodeFromString("{}") }
    }

    test("JoseCodec round trips JSON web keys") {
        val codec = JoseCodec(JsonWebKey.serializer())
        val key = EphemeralKeyWithoutCert().jsonWebKey

        val decoded = codec.decode(codec.encode(key))

        decoded shouldBe key
    }

    test("JoseCodec round trips store entries as their sealed type") {
        val codec = JoseCodec(SubjectCredentialStore.StoreEntry.serializer())
        val entry: SubjectCredentialStore.StoreEntry = SubjectCredentialStore.StoreEntry.SdJwt(
            vcSerialized = "eyJ~",
            sdJwt = VerifiableCredentialSdJwt(verifiableCredentialType = "urn:example:pid"),
            disclosures = mapOf(
                "digest" to JoseCodec(SelectiveDisclosureItem.serializer())
                    .decodeFromString("[\"salt\",\"given_name\",\"Erika\"]")
            ),
            schemeIdentifier = "urn:example:pid",
        )

        val decoded = codec.decode(codec.encode(entry))

        decoded shouldBe entry
    }

    test("JoseCodec round trips the provisioning context") {
        val codec = JoseCodec(ProvisioningContext.serializer())
        val issuerMetadata = JoseCodec(IssuerMetadata.serializer()).decodeFromString(ISSUER_METADATA)
        val context = ProvisioningContext(
            state = "state",
            credential = CredentialIdentifierInfo(
                issuerMetadata, "pid", issuerMetadata.supportedCredentialConfigurations.getValue("pid")
            ),
            oauthMetadata = JoseCodec(OAuth2AuthorizationServerMetadata.serializer()).decodeFromString(
                """{"issuer":"https://auth.example","token_endpoint":"https://auth.example/token"}"""
            ),
            issuerMetadata = issuerMetadata,
        )

        val decoded = codec.decode(codec.encode(context))

        decoded shouldBe context
    }

    test("JoseCodec round trips DC API types") {
        val summary = JoseCodec(IosDcApiMdocPreRequestSummary.serializer()).decodeFromString(PRE_REQUEST_SUMMARY)
        val codec = JoseCodec(IsoMdocRequest.serializer())
        val request = IsoMdocRequest(
            deviceRequest = summary.toDeviceRequest(),
            encryptionInfo = EncryptionInfo(
                type = "dcapi",
                encryptionParameters = EncryptionParameters(
                    recipientPublicKey = CoseKey(
                        type = CoseKeyType.EC2,
                        keyParams = CoseKeyParams.EcYBoolParams(curve = CoseEllipticCurve.P256)
                    )
                )
            )
        )

        val decoded = codec.decode(codec.encode(request))

        decoded shouldBe request
        shouldThrow<SerializationException> { codec.decodeFromString("{}") }
    }

    test("CoseCodec round trips through NSData") {
        val codec = CoseCodec(CoseHeader.serializer())
        val header = CoseHeader(algorithm = CoseAlgorithm.Signature.ES256)

        val decoded = codec.decode(codec.encode(header))

        decoded shouldBe header
    }
}
