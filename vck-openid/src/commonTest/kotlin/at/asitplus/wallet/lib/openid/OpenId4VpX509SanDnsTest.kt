package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.subjectAltName_2_5_29_17
import at.asitplus.signum.indispensable.pki.SubjectAltNameImplicitTags
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.openid.formUrlEncode
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreSdJwt
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking

val OpenId4VpX509SanDnsTest by matrixSuite {

    fixture {
        runBlocking {
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val holderAgent = HolderAgent(holderKeyMaterial).also {
                issueAndStoreSdJwt(it, holderKeyMaterial)
            }
            val clientId = "example.com"
            val extensions = listOf(
                X509CertificateExtension(
                    KnownOIDs.subjectAltName_2_5_29_17,
                    critical = false,
                    Asn1EncapsulatingOctetString(
                        listOf(
                            Asn1.Sequence {
                                +Asn1Primitive(
                                    SubjectAltNameImplicitTags.dNSName,
                                    Asn1String.UTF8(clientId).encodeToTlv().content
                                )
                            }
                        ))))
            val verifierKeyMaterial = EphemeralKeyWithSelfSignedCert(extensions = extensions)
            val verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.CertificateSanDns(
                    listOf(verifierKeyMaterial.getCertificate()!!),
                    clientId,
                    clientId
                ),
            )
            object {
                val verifierOid4vp = verifierOid4vp
                val holderKeyMaterial = holderKeyMaterial
                val holderAgent = holderAgent
                var holderOid4vp = OpenId4VpHolder(
                    keyMaterial = holderKeyMaterial,
                    holder = holderAgent,
                    randomSource = RandomSource.Default,
                )

            }
        }
    } - {

        "test with request object" {
            val requestUrl = "https://example.com/request"
            val (walletUrl, jar) = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(
                            credentialScheme = AtomicAttribute2023,
                            representation = SD_JWT,
                            attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME))
                        ),
                    ).toDCQLRequest(),
                    responseMode = OpenIdConstants.ResponseMode.DirectPost,
                    responseUrl = "https://example.com/response",
                ),
                CreationOptions.SignedRequestByReference("haip://", requestUrl)
            ).getOrThrow()
            jar.shouldNotBeNull()

            it.holderOid4vp = OpenId4VpHolder(
                keyMaterial = it.holderKeyMaterial,
                holder = it.holderAgent,
                remoteResourceRetriever = {
                    if (it.url == requestUrl) jar.invoke(it.requestObjectParameters).getOrThrow() else null
                },
                randomSource = RandomSource.Default,
            )

            val authnResponse = it.holderOid4vp.createAuthnResponse(walletUrl).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode()).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>().apply {
                    credentialQueryResponseValidations.values
                        .shouldBeSingleton().first().shouldBeSingleton().first().getOrThrow()
                        .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
                        .reconstructedJsonObject[CLAIM_GIVEN_NAME].shouldNotBeNull()
                }

        }

        "test with encryption" {
            val requestUrl = "https://example.com/request"
            val (walletUrl, jar) = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(
                            credentialScheme = AtomicAttribute2023,
                            representation = SD_JWT,
                            attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME))
                        ),
                    ).toDCQLRequest(),
                    responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                    responseUrl = "https://example.com/response",
                ),
                CreationOptions.SignedRequestByReference("haip://", requestUrl)
            ).getOrThrow()
            jar.shouldNotBeNull()

            it.holderOid4vp = OpenId4VpHolder(
                keyMaterial = it.holderKeyMaterial,
                holder = it.holderAgent,
                remoteResourceRetriever = {
                    if (it.url == requestUrl) jar.invoke(it.requestObjectParameters).getOrThrow() else null
                },
                randomSource = RandomSource.Default,
            )

            val authnResponse = it.holderOid4vp.createAuthnResponse(walletUrl).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode()).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>().apply {
                    credentialQueryResponseValidations.values
                        .shouldBeSingleton().first().shouldBeSingleton().first().getOrThrow()
                        .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
                        .reconstructedJsonObject[CLAIM_GIVEN_NAME].shouldNotBeNull()
                }
        }
    }
}
