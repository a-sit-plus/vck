package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.subjectAltName_2_5_29_17
import at.asitplus.signum.indispensable.pki.SubjectAltNameImplicitTags
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

val OpenId4VpX509SanDnsTest by testSuite {

    withFixtureGenerator(suspend {
        val holderKeyMaterial = EphemeralKeyWithoutCert()
        val holderAgent = HolderAgent(holderKeyMaterial).also {
            it.storeCredential(
                IssuerAgent(
                    identifier = "https://issuer.example.com/".toUri(),
                    randomSource = RandomSource.Default
                ).issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        holderKeyMaterial.publicKey,
                        AtomicAttribute2023,
                        SD_JWT,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            )
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
    }) - {

        "test with request object" {
            val requestUrl = "https://example.com/request"
            val (walletUrl, jar) = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(AtomicAttribute2023, SD_JWT, setOf(CLAIM_GIVEN_NAME))
                    ),
                    responseMode = OpenIdConstants.ResponseMode.DirectPost,
                    responseUrl = "https://example.com/response",
                ),
                OpenId4VpVerifier.CreationOptions.SignedRequestByReference("haip://", requestUrl)
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

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
                .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
                .reconstructed[CLAIM_GIVEN_NAME].shouldNotBeNull()

        }

        "test with encryption" {
            val requestUrl = "https://example.com/request"
            val (walletUrl, jar) = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(AtomicAttribute2023, SD_JWT, setOf(CLAIM_GIVEN_NAME))
                    ),
                    responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                    responseUrl = "https://example.com/response",
                ),
                OpenId4VpVerifier.CreationOptions.SignedRequestByReference("haip://", requestUrl)
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

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
                .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
                .reconstructed[CLAIM_GIVEN_NAME].shouldNotBeNull()
        }
    }
}
