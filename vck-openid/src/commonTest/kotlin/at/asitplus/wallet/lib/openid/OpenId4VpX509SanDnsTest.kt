package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.SubjectAltNameImplicitTags
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

class OpenId4VpX509SanDnsTest : FreeSpec({

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var verifierOid4vp: OpenId4VpVerifier

    beforeEach {
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
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithSelfSignedCert(extensions = extensions)
        holderAgent = HolderAgent(holderKeyMaterial)
        holderAgent.storeCredential(
            IssuerAgent().issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    AtomicAttribute2023,
                    SD_JWT,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )

        holderOid4vp = OpenId4VpHolder(
            keyMaterial = holderKeyMaterial,
            holder = holderAgent,
        )
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.CertificateSanDns(
                listOf(verifierKeyMaterial.getCertificate()!!),
                clientId,
                clientId
            ),
        )
    }

    "test with request object" {
        val requestUrl = "https://example.com/request"
        val (walletUrl, jar) = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(AtomicAttribute2023, SD_JWT, setOf(CLAIM_GIVEN_NAME))
                ),
                responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                responseUrl = "https://example.com/response",
            ),
            OpenId4VpVerifier.CreationOptions.SignedRequestByReference("haip://", requestUrl)
        ).getOrThrow()
        jar.shouldNotBeNull()

        holderOid4vp = OpenId4VpHolder(
            holderKeyMaterial,
            holderAgent,
            remoteResourceRetriever = {
                if (it.url == requestUrl) jar.invoke(it.requestObjectParameters).getOrThrow() else null
            })

        val authnResponse = holderOid4vp.createAuthnResponse(walletUrl).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

        verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
            .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
            .reconstructed[CLAIM_GIVEN_NAME].shouldNotBeNull()

    }

    "test with encryption" {
        val requestUrl = "https://example.com/request"
        val (walletUrl, jar) = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(AtomicAttribute2023, SD_JWT, setOf(CLAIM_GIVEN_NAME))
                ),
                responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                responseUrl = "https://example.com/response",
                encryption = true
            ),
            OpenId4VpVerifier.CreationOptions.SignedRequestByReference("haip://", requestUrl)
        ).getOrThrow()
        jar.shouldNotBeNull()

        holderOid4vp = OpenId4VpHolder(
            holderKeyMaterial,
            holderAgent,
            remoteResourceRetriever = {
                if (it.url == requestUrl) jar.invoke(it.requestObjectParameters).getOrThrow() else null
            })

        val authnResponse = holderOid4vp.createAuthnResponse(walletUrl).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

        verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
            .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
            .reconstructed[CLAIM_GIVEN_NAME].shouldNotBeNull()

    }
})