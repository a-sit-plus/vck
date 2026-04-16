package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.request.DCAPIWalletRequest
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.subjectAltName_2_5_29_17
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsGeneral
import at.asitplus.signum.indispensable.josef.JwsProtectedHeaderSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.SubjectAltNameImplicitTags
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.vckJsonSerializer
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

val OpenId4VpDcApiMultiSignedValidationTest by testSuite {

    withFixtureGenerator(suspend {
        val clientIdWithoutPrefix = "example.com"
        val callingOrigin = "https://example.com"
        val requestOptions = OpenId4VpRequestOptions(
            presentationRequest = CredentialPresentationRequestBuilder(
                credentials = setOf(RequestOptionsCredential(AtomicAttribute2023, SD_JWT))
            ).toDCQLRequest(),
            responseMode = OpenIdConstants.ResponseMode.DcApi,
            expectedOrigins = listOf(callingOrigin),
        )
        val extensions = listOf(
            X509CertificateExtension(
                KnownOIDs.subjectAltName_2_5_29_17,
                critical = false,
                Asn1EncapsulatingOctetString(
                    listOf(
                        Asn1.Sequence {
                            +Asn1Primitive(
                                SubjectAltNameImplicitTags.dNSName,
                                Asn1String.UTF8(clientIdWithoutPrefix).encodeToTlv().content
                            )
                        }
                    )
                )
            )
        )
        val verifierKeyMaterial = EphemeralKeyWithSelfSignedCert(extensions = extensions)
        val verifierCertificate = verifierKeyMaterial.getCertificate()!!
        val holderKeyMaterial = EphemeralKeyWithoutCert()

        object {
            val holderOid4vp = OpenId4VpHolder(
                keyMaterial = holderKeyMaterial,
                holder = HolderAgent(holderKeyMaterial),
                randomSource = RandomSource.Default,
            )
            val verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.CertificateSanDns(
                    listOf(verifierCertificate),
                    clientIdWithoutPrefix,
                    clientIdWithoutPrefix,
                ),
            )
            val callingOrigin = callingOrigin
            val fullClientId = "x509_san_dns:$clientIdWithoutPrefix"
            val requestOptions = requestOptions
        }
    }) - {

        "dc-api multisigned requests should accept client_id from protected headers only" {
            val compactSigned = it.verifierOid4vp
                .createAuthnRequestAsSignedRequestObject(it.requestOptions)
                .getOrThrow()
            val generalSigned = compactSigned.jws.toGeneralJsonSerialization(
                payload = compactSigned.payload.copy(clientId = null),
                headerClientId = it.fullClientId,
            )

            shouldNotThrowAny {
                it.holderOid4vp.startAuthorizationResponsePreparation(
                    generalSigned.toDcApiMultiSignedRequest(it.callingOrigin)
                ).getOrThrow().request as RequestParametersFrom.DcApiMultiSigned<AuthenticationRequestParameters>
            }
        }

        "authorization request validation should not assume JwsCompact for dc-api multisigned x509 requests" {
            val compactSigned = it.verifierOid4vp
                .createAuthnRequestAsSignedRequestObject(it.requestOptions)
                .getOrThrow()
            val generalSigned = compactSigned.jws.toGeneralJsonSerialization(
                payload = compactSigned.payload,
                headerClientId = it.fullClientId,
            )

            shouldNotThrowAny {
                AuthorizationRequestValidator().validateAuthorizationRequest(
                    RequestParametersFrom.DcApiMultiSigned(
                        dcApiRequest = generalSigned.toDcApiMultiSignedRequest(it.callingOrigin),
                        parameters = compactSigned.payload,
                        jws = generalSigned,
                        verified = true,
                    )
                )
            }
        }
    }
}

private fun JwsCompact.toGeneralJsonSerialization(
    payload: AuthenticationRequestParameters,
    headerClientId: String,
): JwsGeneral {
    val protectedHeader = buildJsonObject {
        JwsProtectedHeaderSerializer.decodeToJsonObject(plainProtectedHeader).forEach { (key, value) ->
            put(key, value)
        }
        put("client_id", JsonPrimitive(headerClientId))
    }.toString().encodeToByteArray()
    val payloadBytes = joseCompliantSerializer.encodeToString(
        AuthenticationRequestParameters.serializer(),
        payload,
    ).encodeToByteArray()
    val generalJson = """
        {
          "payload": "${payloadBytes.encodeToString(Base64UrlStrict)}",
          "signatures": [
            {
              "protected": "${protectedHeader.encodeToString(Base64UrlStrict)}",
              "signature": "${plainSignature.encodeToString(Base64UrlStrict)}"
            },
            {
              "protected": "${protectedHeader.encodeToString(Base64UrlStrict)}",
              "signature": "${plainSignature.encodeToString(Base64UrlStrict)}"
            }
          ]
        }
    """.trimIndent()

    return vckJsonSerializer.decodeFromString(JwsGeneral.serializer(), generalJson)
}

private fun JwsGeneral.toDcApiMultiSignedRequest(callingOrigin: String) = DCAPIWalletRequest.OpenId4VpMultiSigned(
    request = JarRequestParameters(
        request = vckJsonSerializer.encodeToString(JwsGeneral.serializer(), this)
    ),
    credentialIds = listOf("1"),
    callingPackageName = "com.example.app",
    callingOrigin = callingOrigin,
)
