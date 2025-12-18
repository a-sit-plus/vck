package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withFixtureGenerator
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
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier.CreationOptions
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

val OpenId4VpX509HashTest by testSuite {

    withData(
        listOf(
            EphemeralKeyWithoutCert().let {
                val agent= HolderAgent(it)
                OpenId4VpHolder(
                keyMaterial = it,
                holder = agent,
                randomSource = RandomSource.Default,
            ) to agent},
            EphemeralKeyWithoutCert().let {
                val agent= HolderAgent(it)
                OpenId4VpHolder(
                    keyMaterial = it,
                    holder = agent,
                    randomSource = RandomSource.Default,
                ) to agent},
            EphemeralKeyWithoutCert().let {
                val agent= HolderAgent(it)
                OpenId4VpHolder(
                    keyMaterial = it,
                    holder = agent,
                    randomSource = RandomSource.Default,
                ) to agent},
            EphemeralKeyWithoutCert().let {
                val agent= HolderAgent(it)
                OpenId4VpHolder(
                    keyMaterial = it,
                    holder = agent,
                    randomSource = RandomSource.Default,
                ) to agent},
        )
    ) - { (holder, holderAgent) ->


        withFixtureGenerator(suspend {
            val verifierKeyMaterial = EphemeralKeyWithSelfSignedCert()
            val holderAgent = holderAgent.also {
                it.storeCredential(
                    IssuerAgent(
                        identifier = "https://issuer.example.com/".toUri(),
                        randomSource = RandomSource.Default
                    ).issueCredential(
                        DummyCredentialDataProvider.getCredential(
                            holderAgent.keyMaterial.publicKey,
                            AtomicAttribute2023,
                            SD_JWT,
                        ).getOrThrow()
                    ).getOrThrow().toStoreCredentialInput()
                )
            }

            val verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.CertificateHash(
                    listOf(verifierKeyMaterial.getCertificate()!!),
                    "https://example.com/redirect"
                )

            )

            object {
                val holderKeyMaterial = holderAgent.keyMaterial
                val holderAgent = holderAgent
                var holderOid4vp = holder
                val verifierOid4vp = verifierOid4vp
            }
        }) - {

            test("test with request object") {
                val requestUrl = "https://example.com/request"
                val (walletUrl, jar) = it.verifierOid4vp.createAuthnRequest(
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

            test("test with encryption") {
                val requestUrl = "https://example.com/request"
                val (walletUrl, jar) = it.verifierOid4vp.createAuthnRequest(
                    RequestOptions(
                        credentials = setOf(
                            RequestOptionsCredential(AtomicAttribute2023, SD_JWT, setOf(CLAIM_GIVEN_NAME))
                        ),
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

                it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
                    .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
                    .reconstructed[CLAIM_GIVEN_NAME].shouldNotBeNull()

            }
        }
    }

}