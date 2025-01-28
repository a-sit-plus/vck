package at.asitplus.wallet.lib.openid

import at.asitplus.dif.ClaimFormat
import at.asitplus.dif.PresentationSubmission
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.SdJwtConstants
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.SdJwtSigned
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.serialization.json.jsonPrimitive

/**
 * Tests our OpenID4VP/SIOP implementation against POTENTIAL Piloting Definition Scope
 */
class OpenId4VpInteropTest : FreeSpec({
    lateinit var issuerKeyId: String
    lateinit var issuerClientId: String
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var verifierClientId: String
    lateinit var verifierRedirectUrl: String
    lateinit var verifierKeyId: String
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var verifierOid4vp: OpenId4VpVerifier

    beforeEach {
        issuerKeyId = uuid4().toString()
        issuerClientId = "https://issuer.example.com"
        val issuerKeyMaterial = EphemeralKeyWithoutCert(customKeyId = issuerKeyId)
        val issuerAgent = IssuerAgent(issuerKeyMaterial, identifier = issuerClientId)

        holderKeyMaterial = EphemeralKeyWithoutCert()
        holderAgent = HolderAgent(
            holderKeyMaterial,
            validator = Validator(
                verifierJwsService = DefaultVerifierJwsService(publicKeyLookup = {
                    setOf(issuerKeyMaterial.publicKey.toJsonWebKey())
                })
            )
        )
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.SD_JWT,
                    listOf(
                        CLAIM_FAMILY_NAME,
                        CLAIM_GIVEN_NAME
                    )
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )
        holderOid4vp = OpenId4VpHolder(holderKeyMaterial, holderAgent)

        verifierKeyId = uuid4().toString()
        verifierClientId = "AT-GV-EGIZ-CUSTOMVERIFIER"
        verifierRedirectUrl = "https://verifier.example.com/cb"
        val clientIdScheme = ClientIdScheme.PreRegistered(verifierClientId, verifierRedirectUrl)
        verifierKeyMaterial = EphemeralKeyWithoutCert(customKeyId = verifierKeyId)
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            verifier = VerifierAgent(
                identifier = clientIdScheme.clientId,
                validator = Validator(
                    verifierJwsService = DefaultVerifierJwsService(publicKeyLookup = {
                        setOf(
                            issuerKeyMaterial.publicKey.toJsonWebKey(),
                            holderKeyMaterial.publicKey.toJsonWebKey(),
                        )
                    })
                )
            ),
            clientIdScheme = clientIdScheme,
        )
    }

    "process with cross-device flow with request_uri and pre-trusted" {
        val verifierJarMetadata = verifierOid4vp.jarMetadata
        val responseNonce = uuid4().toString()
        val requestNonce = uuid4().toString()
        val requestUrl = "https://verifier.example.com/request/$requestNonce"
        val (requestUrlForWallet, requestObject) = verifierOid4vp.createAuthnRequest(
            OpenIdRequestOptions(
                responseMode = OpenIdConstants.ResponseMode.DirectPost,
                responseUrl = "https://verifier.example.com/response/$responseNonce",
                credentials = setOf(
                    RequestOptionsCredential(
                        ConstantIndex.AtomicAttribute2023,
                        ConstantIndex.CredentialRepresentation.SD_JWT,
                        setOf(CLAIM_FAMILY_NAME, CLAIM_GIVEN_NAME)
                    )
                )
            ),
            OpenId4VpVerifier.CreationOptions.SignedRequestByReference("haip://", requestUrl)
        ).getOrThrow()
        requestObject.shouldNotBeNull()

        requestUrlForWallet shouldContain "request_uri="
        requestUrlForWallet shouldContain verifierClientId.encodeURLParameter()
        requestUrlForWallet shouldStartWith "haip://"

        holderOid4vp = OpenId4VpHolder(
            holderKeyMaterial,
            holderAgent,
            remoteResourceRetriever = {
                if (it.url == requestUrl) requestObject.invoke(it.requestObjectParameters).getOrThrow() else null
            })

        val parameters = holderOid4vp.parseAuthenticationRequestParameters(requestUrlForWallet).getOrThrow()
        parameters.shouldBeInstanceOf<RequestParametersFrom.JwsSigned<AuthenticationRequestParameters>>()

        val jar = parameters.jwsSigned
        jar.header.algorithm shouldBe JwsAlgorithm.ES256
        jar.header.type shouldBe "oauth-authz-req+jwt"
        jar.header.keyId shouldBe verifierKeyId

        jar.payload.issuer shouldBe verifierClientId
        jar.payload.clientIdWithoutPrefix shouldBe verifierClientId
        jar.payload.audience shouldBe "https://self-issued.me/v2"
        jar.payload.presentationDefinition.shouldNotBeNull()
        jar.payload.nonce.shouldNotBeNull()
        jar.payload.state.shouldNotBeNull()
        jar.payload.responseType shouldBe "vp_token"
        jar.payload.responseMode shouldBe OpenIdConstants.ResponseMode.DirectPost
        jar.payload.responseUrl.shouldNotBeNull()

        verifierJarMetadata.issuer shouldBe verifierClientId
        val verifierJwks = verifierJarMetadata.jsonWebKeySet.shouldNotBeNull()
        val verifierRequestSigningKey = verifierJwks.keys.first { it.keyId == jar.header.keyId }

        DefaultVerifierJwsService().verifyJws(jar, verifierRequestSigningKey) shouldBe true

        val preparation = holderOid4vp.startAuthorizationResponsePreparation(parameters).getOrThrow()
        val response = holderOid4vp.finalizeAuthorizationResponse(parameters, preparation).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

        response.params.entries.firstOrNull { it.key == "vp_token" }.shouldNotBeNull().value.let { vp_token ->
            val sdJwt = SdJwtSigned.parse(vp_token).shouldNotBeNull()
            sdJwt.keyBindingJws.shouldNotBeNull().also {
                it.header.also {
                    it.algorithm shouldBe JwsAlgorithm.ES256
                    it.type shouldBe "kb+jwt"
                }
                it.payload.also {
                    it.issuedAt.shouldNotBeNull()
                    it.audience shouldBe jar.payload.clientId
                    it.challenge shouldBe jar.payload.nonce
                    it.sdHash.shouldNotBeNull()
                }
            }
            sdJwt.jws.header.also {
                it.keyId shouldBe issuerKeyId
                it.algorithm shouldBe JwsAlgorithm.ES256
                it.type shouldBe "vc+sd-jwt"
            }
            sdJwt.getPayloadAsVerifiableCredentialSdJwt().getOrThrow().also {
                it.issuer shouldBe issuerClientId
                it.issuedAt.shouldNotBeNull()
                it.expiration.shouldNotBeNull()
                it.verifiableCredentialType.shouldNotBeNull()
                it.selectiveDisclosureAlgorithm shouldBe SdJwtConstants.SHA_256
                it.confirmationClaim.shouldNotBeNull().also {
                    it.jsonWebKey.shouldNotBeNull()
                }
            }
        }
        response.params.entries.firstOrNull { it.key == "state" }.shouldNotBeNull()
        response.params.entries.first { it.key == "presentation_submission" }.value.let { presentationSubmission ->
            val presSub = vckJsonSerializer.decodeFromString<PresentationSubmission>(presentationSubmission)
            presSub.definitionId.shouldNotBeNull()
            presSub.descriptorMap.shouldNotBeNull().first().also {
                it.path shouldBe "$"
                it.format shouldBe ClaimFormat.JWT_SD
            }
        }

        verifierOid4vp.validateAuthnResponse(response.params)
            .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
    }

    "parse JAR sample from document" {
        val input = """
            eyJhbGciOiJFUzI1NiIsInR5cCI6IiBvYXV0aC1hdXRoei1yZXErand0ICJ9
            .eyJpc3MiOiJodHRwczovL2Jkci5kZS9qd2siLCJhdWQiOiIgaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZS92MiIsImNsaWVudF9pZCI6Imh0dHB
            zOi8vYmRyLmRlIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiIzMmY1NDE2My03MTY2LTQ4ZjEtOTNkOC1mZjIxN2JkYjA2NTU
            iLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiIzMmY1NDE2My03MTY2LTQ4ZjEtOTNkOC1mZjIxN2JkYjA2NTYiLCJwdXJwb3NlIjoiUmV
            xdWVzdCBwcmVzZW50YXRpb24gaG9sZGluZyBQb3dlciBvZiBSZXByZXNlbnRhdGlvbiBhdHRlc3RhdGlvbiIsImNvbnN0cmFpbnRzIjp7ImZ
            pZWxkcyI6W3sicGF0aCI6WyIkLnZjdCJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsInBhdHRlcm4iOiJ1cm46ZXUuZXVyb3BhLmVjLmV
            1ZGk6cG9yOjEifX1dfX1dfSwibm9uY2UiOiJuLTBTNl9XekEyTWoiLCJzdGF0ZSI6ImFmMGlmanNsZGtqIiwicmVzcG9uc2VfdHlwZSI6InZ
            wX3Rva2VuIiwiIHJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsInJlc3BvbnNlX3VyaSI6Imh0dHBzOi8vbndyLWJlLmRlL3Jlc3BvbnN
            lIn0
            .i7Kli1T5RZzo2-TvWsw9-JpxjYPBUae8Lrc_ORfTdabHlXmuPucGVrE5lkBu7vLss2RKKEmdFFy57-ZvRFn4Tg
        """.trimIndent()

        val jar = JwsSigned.deserialize<AuthenticationRequestParameters>(
            AuthenticationRequestParameters.serializer(),
            input,
            vckJsonSerializer
        ).getOrThrow()

        jar.header.algorithm shouldBe JwsAlgorithm.ES256
        jar.header.type shouldBe " oauth-authz-req+jwt " // that's a typo in the document ...

        jar.payload.issuer shouldBe "https://bdr.de/jwk"
        jar.payload.audience shouldBe " https://self-issued.me/v2" // that's a typo in the document ...
        jar.payload.clientId shouldBe "https://bdr.de"
        jar.payload.nonce shouldBe "n-0S6_WzA2Mj"
        jar.payload.state shouldBe "af0ifjsldkj"
        jar.payload.responseUrl shouldBe "https://nwr-be.de/response"
        val pres = jar.payload.presentationDefinition.shouldNotBeNull()
        pres.id.shouldNotBeNull()
        val inputdesc = pres.inputDescriptors.first()
        inputdesc.purpose shouldBe "Request presentation holding Power of Representation attestation"
        val field = inputdesc.constraints!!.fields!!.first { it -> it.path == listOf("$.vct") }
        field.filter!!.pattern shouldBe "urn:eu.europa.ec.eudi:por:1"
    }

    "parse SD-JWT from document" {
        val input = """
            eyJhbGciOiJFUzI1NiIsInR5cCI6IiB2YytzZC1qd3QgIn0
            .eyJfc2QiOlsiRnZZUTBXcDV6RFgybnlIOEtxWExsQ3lrM3kxQ2tEZ2ozREpyRnNpdFNBOCIsImM4SGN4SHl1OFRTMTZkTkdTc3J0MjFkOEx
            3aDJ2eTE4TDJqUnBKc0RTUlkiLCJDN1lNQ3lnZ0xtdFB2YUFOcmxjX3daQThSdUFhV3FWR0JMS1BESXp3QUVBIiwidi0ybU94eUc0bUthM3R
            ZTTN0SmVhaVgyUURiTmx1eVhwSGd0Mm9nb2s3TSIsIiBEbW1iR2xsVnJheVdZazJJX0VCSzI3bmFNa3hPRU1CaUVuNXRhWl81RDJBIiwiMDA
            xVWY0YUN2dW5pMWpObUxtTzRFWG9HYk12eldtR1FKR2JydHYtZk9vNCIsIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZ
            VYW9tTG8iLCJqc3U5eVZ1bHdRUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sImlzcyI6Imh0dHBzOi8vcnZpZy5ubC9qd2s
            iLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjUzOTAyMiwidmN0IjoidXJuOmV1LmV1cm9wYS5lYy5ldWRpOnBpZDoxIiwiX3NkX2FsZyI
            6InNoYS0yNTYiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVC1acjh2ckYta2RyMXpwakszdWZVdjFmZDd
            EUzBzOFlmOF9OeTNIYjRJNCIsInkiOiJlMHM5dEdXbTZXNnc1cWhRZXdKcTFvWFhvemp4NV9maTUtZFl1Tm13blJrIn19LCJpc3N1aW5nX2F
            1dGhvcml0eSI6IlJ2SUciLCJpc3N1aW5nX2NvdW50cnkiOiJOTCIsImlzc3VuY2VfZGF0ZSI6IjIwMjQtMDMtMThUMTI6MzU6NThaIiwiZXh
            waXJlX2RhdGUiOiIyMDI4LTAxLTAxVDAwOjAwOjAwWiJ9
            .oiADOP-PaiXpEJBRSiNuJtwr-3cMWUuUatuXS7aytaRgAh40lmP-q55I_Tr9zEnmBxML5xOyJqx2FVXcX_KlCA
            ~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd
            ~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~
        """.trimIndent()

        val sdJwt = SdJwtSigned.parse(input).shouldNotBeNull().also {
            it.keyBindingJws.shouldBeNull()
            it.getPayloadAsVerifiableCredentialSdJwt().getOrThrow().also {
                it.issuer shouldBe "https://rvig.nl/jwk"
                it.verifiableCredentialType shouldBe "urn:eu.europa.ec.eudi:pid:1"
                it.selectiveDisclosureAlgorithm shouldBe SdJwtConstants.SHA_256
            }
        }

        val json = SdJwtValidator(sdJwt).reconstructedJsonObject.shouldNotBeNull()
        json["given_name"]!!.jsonPrimitive.content shouldBe "John"
        json["family_name"]!!.jsonPrimitive.content shouldBe "Doe"
    }

})
