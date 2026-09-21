package at.asitplus.wallet.lib.openid

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: Credential subject is now a JsonElement
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.openid.VerifierInfo
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStorePlainJwt
import at.asitplus.wallet.lib.utils.MapStore
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.NonceService
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement

val RedirectUriClientTest by matrixSuite {

    fixture {
        runBlocking {
            val holderKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
            val holderAgent: Holder = HolderAgent(holderKeyMaterial).also {
                issueAndStorePlainJwt(it, holderKeyMaterial)
            }
            object {
                val verifierKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
                val clientId: String = "https://example.com/rp/${uuid4()}"
                val walletUrl: String = "https://example.com/wallet/${uuid4()}"

                val holderOid4vp: OpenId4VpHolder = OpenId4VpHolder(
                    holder = holderAgent,
                    randomSource = RandomSource.Default,
                )
                val verifierOid4vp: OpenId4VpVerifier = OpenId4VpVerifier(
                    keyMaterial = verifierKeyMaterial,
                    clientIdScheme = ClientIdScheme.RedirectUri(clientId),
                )
            }
        }
    } - {

        "test with Fragment" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                defaultRequestOptions, CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            authnResponse.url.shouldNotContain("?")
            authnResponse.url.shouldContain("#")
            authnResponse.url.shouldStartWith(it.clientId)

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()

            verifySecondProtocolRun(it.verifierOid4vp, it.walletUrl, it.holderOid4vp)
        }

        "verifier_info is exposed in preparation state" {
            val verifierInfo = listOf(
                VerifierInfo(
                    format = "jwt",
                    data = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9",
                    credentialIds = setOf("id_card"),
                )
            ).toNonEmptyList()

            val requestOptions = OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    credentials = setOf(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                    )
                ).toDCQLRequest(),
                verifierInfo = verifierInfo
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions, CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val preparationState = it.holderOid4vp
                .startAuthorizationResponsePreparation(authnRequest)
                .getOrThrow()

            preparationState.verifierInfo shouldBe verifierInfo
        }

        "registration_cert verifier_info is exposed in preparation state" {
            val verifierInfo = listOf(
                VerifierInfo(
                    format = OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT,
                    data = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ3cnAifQ.signature",
                    credentialIds = setOf("id_card"),
                )
            ).toNonEmptyList()
            val requestOptions = OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    credentials = setOf(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                    )
                ).toDCQLRequest(),
                verifierInfo = verifierInfo,
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions, CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val preparationState = it.holderOid4vp
                .startAuthorizationResponsePreparation(authnRequest)
                .getOrThrow()

            preparationState.verifierInfo shouldBe verifierInfo
        }

        "certificateSanDnsFromPem parses PEM chain and builds client_id" {
            val clientIdScheme = ClientIdScheme.CertificateSanDns(
                chain = parsePemCertificateChain(samplePemChain),
                clientIdDnsName = "*.google.com",
                redirectUri = "https://example.com/callback",
            )

            clientIdScheme.clientIdWithoutPrefix shouldBe "*.google.com"
            clientIdScheme.clientId shouldBe "x509_san_dns:*.google.com"
            clientIdScheme.redirectUri shouldBe "https://example.com/callback"
            clientIdScheme.chain.size shouldBe 2
        }

        "wrong client nonce in vp_token should lead to error" {
            val verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = it.verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.RedirectUri(it.clientId),
                stateToAuthnRequestStore = object : MapStore<String, AuthenticationRequestParameters> {
                    override suspend fun put(key: String, value: AuthenticationRequestParameters) {}
                    override suspend fun get(key: String): AuthenticationRequestParameters? = null
                    override suspend fun remove(key: String): AuthenticationRequestParameters? = null
                },
            )
            val authnRequest = verifierOid4vp.createAuthnRequest(
                defaultRequestOptions, CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            verifierOid4vp.validateAuthnResponse(authnResponse.url).isFailure shouldBe true
        }

        "signed requests not allowed for redirect-uri" {
            shouldThrow<IllegalArgumentException> {
                it.verifierOid4vp.createAuthnRequest(
                    defaultRequestOptions, CreationOptions.SignedRequestByValue(it.walletUrl)
                ).getOrThrow().url
            }
        }

        "signed request by reference not allowed for redirect-uri" {
            shouldThrow<IllegalArgumentException> {
                it.verifierOid4vp.createAuthnRequest(
                    defaultRequestOptions,
                    CreationOptions.SignedRequestByReference(it.walletUrl, "https://example.com")
                ).getOrThrow().url
            }
        }

        "test with direct_post" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                    ).toDCQLRequest(),
                    responseMode = OpenIdConstants.ResponseMode.DirectPost,
                    responseUrl = it.clientId,
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()
            authnResponse.url.shouldBe(it.clientId)

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode()).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
        }

        "test with direct_post and omitted verifier metadata" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                    ).toDCQLRequest(),
                    responseMode = OpenIdConstants.ResponseMode.DirectPost,
                    responseUrl = it.clientId,
                    verifierMetadataMode = VerifierMetadataMode.OMIT_IF_OUT_OF_BAND,
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            authnRequest.shouldNotContain("client_metadata=")

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()
            authnResponse.url.shouldBe(it.clientId)

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode()).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
        }

        "test with direct_post.jwt" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                    ).toDCQLRequest(),
                    responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                    responseUrl = it.clientId,
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>().apply {
                    url.shouldBe(it.clientId)
                    params.shouldHaveSize(1) // only the "response" object
                }

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode()).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
        }

        "test with Query" {
            val expectedState = uuid4().toString()
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                    ).toDCQLRequest(),
                    responseMode = OpenIdConstants.ResponseMode.Query,
                    state = expectedState
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            authnResponse.url.shouldContain("?")
            authnResponse.url.shouldNotContain("#")
            authnResponse.url.shouldStartWith(it.clientId)

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>().apply {
                    vp.freshVerifiableCredentials.shouldNotBeEmpty()
                }
        }

        "test with deserializing" {
            val authnRequest = it.verifierOid4vp
                .createAuthnRequest(defaultRequestOptions, CreationOptions.Query(it.walletUrl))
                .getOrThrow()
            val authnRequestUrlParams = Url(authnRequest.url).encodedQuery

            val parsedAuthnRequest: AuthenticationRequestParameters =
                authnRequestUrlParams.decodeFromUrlQuery()
            val authnResponse = it.holderOid4vp.createAuthnResponse(
                RequestParametersFrom.Uri(
                    Url(authnRequestUrlParams),
                    parsedAuthnRequest
                )
            ).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .params
            val authnResponseParams = authnResponse.encodeToParameters().formUrlEncode()

            it.verifierOid4vp.validateAuthnResponse(authnResponseParams).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
        }

        "test specific credential" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptionsAtomicAttribute(),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
                .map { it.vcJws }.forEach {
                    it.vc.credentialSubject.shouldBeInstanceOf<JsonElement>().also { credentialSubject ->
                        shouldNotThrowAny {
                            AtomicAttribute2023.fromJsonElement(credentialSubject)
                        }
                    }
                }
        }
    }
}

private fun requestOptionsAtomicAttribute() = OpenId4VpRequestOptions(
    presentationRequest = CredentialPresentationRequestBuilder(
        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
    ).toDCQLRequest(),
)

private suspend fun verifySecondProtocolRun(
    verifierOid4vp: OpenId4VpVerifier,
    walletUrl: String,
    holderOid4vp: OpenId4VpHolder,
) {
    val authnRequestUrl = verifierOid4vp.createAuthnRequest(
        defaultRequestOptions, CreationOptions.Query(walletUrl)
    ).getOrThrow().url
    val authnResponse = holderOid4vp.createAuthnResponse(authnRequestUrl)
    verifierOid4vp.validateAuthnResponse((authnResponse.getOrThrow() as AuthenticationResponseResult.Redirect).url)
        .getOrThrow()
        .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
        .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
        .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
        .shouldBeSingleton().first()
        .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
}

private val defaultRequestOptions = OpenId4VpRequestOptions(
    presentationRequest = CredentialPresentationRequestBuilder(
        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
    ).toDCQLRequest(),
)

private val samplePemChain = listOf(
    """
        -----BEGIN CERTIFICATE-----
MIIGvTCCBaWgAwIBAgIIAb1LAwRonlswDQYJKoZIhvcNAQELBQAwcTELMAkGA1UE
BhMCR0IxDzANBgNVBAgTBkxvbmRvbjEPMA0GA1UEBxMGTG9uZG9uMQ8wDQYDVQQK
EwZHb29nbGUxDDAKBgNVBAsTA0VuZzEhMB8GA1UEAxMYRmFrZUNlcnRpZmljYXRl
QXV0aG9yaXR5MB4XDTIzMDgxMTA2NDg0MVoXDTI2MDQxMjA2NDg0MVowggE2MQsw
CQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRh
aW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEVMBMGA1UEAwwMKi5nb29nbGUu
Y29tMYGYMIGVBgNVBAQMgY1SRkM1MjgwIHM0LjIgJ2FwcGxpY2F0aW9ucyBjb25m
b3JtaW5nIHRvIHRoaXMgcHJvZmlsZSBNVVNUIHJlY29nbml6ZSB0aGUgZm9sbG93
aW5nIGV4dGVuc2lvbnM6IC4uLnN1YmplY3QgYWx0ZXJuYXRpdmUgbmFtZSAoU2Vj
dGlvbiA0LjIuMS42KScxMzAxBgNVBCoMKkluY2x1ZGUgU3ViamVjdCBBbHRlcm5h
dGl2ZSBOYW1lIGV4dGVuc2lvbjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLrd
rvPwAwPVXyJV4b8dFs3wwB6EdvlwIjwasxr5SSTEoBQp9rGgLkuGO59x860UnvLR
xKjYFEOKsOt4zjejJBCjggNbMIIDVzAPBgNVHSMECDAGgAQBAgMEMIIDQgYDVR0R
BIIDOTCCAzWCDCouZ29vZ2xlLmNvbYINKi5hbmRyb2lkLmNvbYIWKi5hcHBlbmdp
bmUuZ29vZ2xlLmNvbYISKi5jbG91ZC5nb29nbGUuY29tghYqLmdvb2dsZS1hbmFs
eXRpY3MuY29tggsqLmdvb2dsZS5jYYILKi5nb29nbGUuY2yCDiouZ29vZ2xlLmNv
Lmlugg4qLmdvb2dsZS5jby5qcIIOKi5nb29nbGUuY28udWuCDyouZ29vZ2xlLmNv
bS5hcoIPKi5nb29nbGUuY29tLmF1gg8qLmdvb2dsZS5jb20uYnKCDyouZ29vZ2xl
LmNvbS5jb4IPKi5nb29nbGUuY29tLm14gg8qLmdvb2dsZS5jb20udHKCDyouZ29v
Z2xlLmNvbS52boILKi5nb29nbGUuZGWCCyouZ29vZ2xlLmVzggsqLmdvb2dsZS5m
coILKi5nb29nbGUuaHWCCyouZ29vZ2xlLml0ggsqLmdvb2dsZS5ubIILKi5nb29n
bGUucGyCCyouZ29vZ2xlLnB0ghIqLmdvb2dsZWFkYXBpcy5jb22CDyouZ29vZ2xl
YXBpcy5jboIUKi5nb29nbGVjb21tZXJjZS5jb22CESouZ29vZ2xldmlkZW8uY29t
ggwqLmdzdGF0aWMuY26CDSouZ3N0YXRpYy5jb22CCiouZ3Z0MS5jb22CCiouZ3Z0
Mi5jb22CFCoubWV0cmljLmdzdGF0aWMuY29tggwqLnVyY2hpbi5jb22CECoudXJs
Lmdvb2dsZS5jb22CFioueW91dHViZS1ub2Nvb2tpZS5jb22CDSoueW91dHViZS5j
b22CFioueW91dHViZWVkdWNhdGlvbi5jb22CCyoueXRpbWcuY29tghphbmRyb2lk
LmNsaWVudHMuZ29vZ2xlLmNvbYILYW5kcm9pZC5jb22CBGcuY2+CBmdvby5nbIIU
Z29vZ2xlLWFuYWx5dGljcy5jb22CCmdvb2dsZS5jb22CEmdvb2dsZWNvbW1lcmNl
LmNvbYIKdXJjaGluLmNvbYIIeW91dHUuYmWCC3lvdXR1YmUuY29tghR5b3V0dWJl
ZWR1Y2F0aW9uLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAg0dBdGdXcsfQcXKGB7F6
iOdKJpbVMYwtH43hWNdLbdReMQ5h7eV1y5Vhra5ZJkkWX71v12AEZkD3DpunQ7g7
FP2xPDY2r/Hmw61Zzqm2aEvrAg4PEkypqkfQ6/NiVspqBF3zGinm9qYp/Ifl+vf1
Et9TbTIluVQa2DylQKQ0cKKvQnGsleuCWuxpbJmEZu7q/nMNUwbrs5Ln/FBKMLkJ
+jvuiS71FFeiAFhvXa48j2BoWh9Rpots8iiF4iuGbol8z9NAojwarKyLuTXuGAhv
IBH+LmnJQP5yoUjjgzleBHCD5ENQ4md2eii35cszAkwWOdVGXQpvRnwL2NSfdBe+
cQ==
-----END CERTIFICATE-----
    """,
    """
        -----BEGIN CERTIFICATE-----
MIIDpzCCAo+gAwIBAgIEBAbK/jANBgkqhkiG9w0BAQsFADBxMQswCQYDVQQGEwJH
QjEPMA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdv
b2dsZTEMMAoGA1UECxMDRW5nMSEwHwYDVQQDExhGYWtlQ2VydGlmaWNhdGVBdXRo
b3JpdHkwHhcNMjMxMDEwMDY0ODQwWhcNMjQxMDA5MDY0ODQwWjBxMQswCQYDVQQG
EwJHQjEPMA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoT
Bkdvb2dsZTEMMAoGA1UECxMDRW5nMSEwHwYDVQQDExhGYWtlQ2VydGlmaWNhdGVB
dXRob3JpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDWH5ATQjwc
3aEmsFpltt2PE/hb/Ff9RIaD5W6+Kbi29Q//H4YZFGbk8BVokVuD5yxPsF9aCGfz
T1YqdBtpl1r5Sn9A6BlfSguS6rVDN/zq3L7/OHFIBKF28nibyrxd3sd5wBH2X+AB
c6FU2rP2EeV2T+tCvWNukOH/M6fxkhITKrcJ9ZdFT36MCAsjklBxV/pXzAX3ZXBp
i/2pvYmHqgIlnadCONylUmGn5XY0h9gY/6PUASMBiPyhj1wcwguWgdBm0nwhJ51m
VezRTUs45xs9cbpKMiqkSuHR/kiPqnAfDawyf6KsZhiSCNIZfYZT7Mh4m4a5F2sn
/pZHFn6Kz6SbAgMBAAGjRzBFMA0GA1UdDgQGBAQBAgMEMA8GA1UdIwQIMAaABAEC
AwQwEgYDVR0TAQH/BAgwBgEB/wIBCjAPBgNVHQ8BAf8EBQMDB/+AMA0GCSqGSIb3
DQEBCwUAA4IBAQDKbgFp4SuOghVwFRAWI2f/gOBLIF1UQYzUGqfeVLZGS06xqqYO
lX+RH5RmeY+eG/AtuCi4vgn6f9h0W/0L68sjbs4qIK9t/fBDaaQ6ebzdN5c7s8L9
dX85XnCMHTa5h1zUZURVMwIL97xO/oSsDYF3fX3mU0QyDiA/FWmzvncI8Zu0iWAI
oF9O8CGwWVbU4/iFHCWjbEYjQfqpw88l7qqstW5DkM7P6+T6GGJxQQQ6BmYhh7dn
AS8U1xH6xGhV29ZI2sbbsNaWFlE6Z2Emaov8b1g7iQEEDmQ6xuV8KQ2Ykv9PQ/G1
u6S9IqrmGqWJpkkub533uSa6/rVveTz6aq7G
-----END CERTIFICATE-----
    """
)
private fun parsePemCertificateChain(pemChain: List<String>): List<X509Certificate> {
    require(pemChain.isNotEmpty()) { "No PEM certificates found" }
    return pemChain.map { block ->
        X509Certificate.decodeFromPem(block).getOrThrow()
    }
}
