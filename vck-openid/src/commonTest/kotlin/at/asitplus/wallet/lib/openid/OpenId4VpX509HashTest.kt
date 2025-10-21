package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier.CreationOptions
import at.asitplus.testballoon.*
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.aroundEach
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

val OpenId4VpX509HashTest by testSuite{

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var verifierOid4vp: OpenId4VpVerifier

    testConfig = TestConfig.aroundEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithSelfSignedCert()
        holderAgent = HolderAgent(holderKeyMaterial)
        holderAgent.storeCredential(
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

        holderOid4vp = OpenId4VpHolder(
            keyMaterial = holderKeyMaterial,
            holder = holderAgent,
            randomSource = RandomSource.Default,
        )
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.CertificateHash(
                listOf(verifierKeyMaterial.getCertificate()!!),
                "https://example.com/redirect"
            ),
        )
        it()
    }

    "test with request object" {
        val requestUrl = "https://example.com/request"
        val (walletUrl, jar) = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(AtomicAttribute2023, SD_JWT, setOf(CLAIM_GIVEN_NAME))
                ),
                responseMode = OpenIdConstants.ResponseMode.DirectPost,
                responseUrl = "https://example.com/response",
            ),
            CreationOptions.SignedRequestByReference("haip://", requestUrl)
        ).getOrThrow()
        jar.shouldNotBeNull()

        holderOid4vp = OpenId4VpHolder(
            keyMaterial = holderKeyMaterial,
            holder = holderAgent,
            remoteResourceRetriever = {
                if (it.url == requestUrl) jar.invoke(it.requestObjectParameters).getOrThrow() else null
            },
            randomSource = RandomSource.Default,
        )

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
            CreationOptions.SignedRequestByReference("haip://", requestUrl)
        ).getOrThrow()
        jar.shouldNotBeNull()

        holderOid4vp = OpenId4VpHolder(
            keyMaterial = holderKeyMaterial,
            holder = holderAgent,
            remoteResourceRetriever = {
                if (it.url == requestUrl) jar.invoke(it.requestObjectParameters).getOrThrow() else null
            },
            randomSource = RandomSource.Default,
        )

        val authnResponse = holderOid4vp.createAuthnResponse(walletUrl).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

        verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
            .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
            .reconstructed[CLAIM_GIVEN_NAME].shouldNotBeNull()

    }
}
