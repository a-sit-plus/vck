package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier
import at.asitplus.wallet.lib.oidvci.MapStore
import at.asitplus.wallet.lib.oidvci.NonceService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.datetime.Clock
import kotlin.time.Duration.Companion.seconds

class OpenId4VpProtocolTest : FreeSpec({

    lateinit var clientId: String
    lateinit var walletUrl: String
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var verifierOid4vp: OpenId4VpVerifier

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        clientId = "https://example.com/rp/${uuid4()}"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)

        holderAgent.storeCredential(
            IssuerAgent().issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
        )
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
        )
    }

    "test with Fragment" {
        val authnRequest = verifierOid4vp.createAuthnRequestUrl(walletUrl, defaultRequestOptions)

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        authnResponse.url.shouldNotContain("?")
        authnResponse.url.shouldContain("#")
        authnResponse.url.shouldStartWith(clientId)

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()

        verifySecondProtocolRun(verifierOid4vp, walletUrl, holderOid4vp)
    }

    "wrong client nonce in id_token should lead to error" {
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
            nonceService = object : NonceService {
                override suspend fun provideNonce() = uuid4().toString()
                override suspend fun verifyNonce(it: String) = false
                override suspend fun verifyAndRemoveNonce(it: String) = false
            }
        )
        val requestOptions = RequestOptions(
            credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
            responseType = OpenIdConstants.ID_TOKEN
        )
        val authnRequest = verifierOid4vp.createAuthnRequestUrl(walletUrl, requestOptions)

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
        result.field shouldBe "idToken"
    }

    "wrong client nonce in vp_token should lead to error" {
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
            stateToAuthnRequestStore = object : MapStore<String, AuthenticationRequestParameters> {
                override suspend fun put(key: String, value: AuthenticationRequestParameters) {}
                override suspend fun get(key: String): AuthenticationRequestParameters? = null
                override suspend fun remove(key: String): AuthenticationRequestParameters? = null
            },
        )
        val authnRequest = verifierOid4vp.createAuthnRequestUrl(walletUrl, defaultRequestOptions)

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
        result.field shouldBe "state"
    }

    "test with QR Code" {
        val metadataUrlNonce = uuid4().toString()
        val metadataUrl = "https://example.com/$metadataUrlNonce"
        val requestUrlNonce = uuid4().toString()
        val requestUrl = "https://example.com/$requestUrlNonce"
        val qrcode = verifierOid4vp.createQrCodeUrl(walletUrl, metadataUrl, requestUrl)
        qrcode shouldContain metadataUrlNonce
        qrcode shouldContain requestUrlNonce

        val metadataObject = verifierOid4vp.createSignedMetadata().getOrThrow()
        DefaultVerifierJwsService().verifyJwsObject(metadataObject).shouldBeTrue()

        val authnRequestUrl = verifierOid4vp.createAuthnRequestUrlWithRequestObject(walletUrl, defaultRequestOptions)
            .getOrThrow()
        val authnRequest: AuthenticationRequestParameters =
            Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
        authnRequest.clientId shouldBe clientId
        val jar = authnRequest.request
            .shouldNotBeNull()
        val jwsObject = JwsSigned.Companion.deserialize<AuthenticationRequestParameters>(
            AuthenticationRequestParameters.Companion.serializer(), jar,
            vckJsonSerializer
        ).getOrThrow()
        DefaultVerifierJwsService().verifyJwsObject(jwsObject).shouldBeTrue()

        val authnResponse = holderOid4vp.createAuthnResponse(jar).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
    }

    "test with direct_post" {
        val authnRequest = verifierOid4vp.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(
                credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                responseMode = OpenIdConstants.ResponseMode.DirectPost,
                responseUrl = clientId,
            )
        )

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Post>()
        authnResponse.url.shouldBe(clientId)

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test with direct_post_jwt" {
        val authnRequest = verifierOid4vp.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(
                credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                responseUrl = clientId,
            )
        )

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Post>()
        authnResponse.url.shouldBe(clientId)
        authnResponse.params.shouldHaveSize(2)
        val jarmResponse = authnResponse.params.entries.first { it.key == "response" }.value
        val jwsObject = JwsSigned.Companion.deserialize<AuthenticationResponseParameters>(
            AuthenticationResponseParameters.Companion.serializer(), jarmResponse
        ).getOrThrow()
        DefaultVerifierJwsService().verifyJwsObject(jwsObject).shouldBeTrue()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test with Query" {
        val expectedState = uuid4().toString()
        val authnRequest = verifierOid4vp.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(
                credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                responseMode = OpenIdConstants.ResponseMode.Query,
                state = expectedState
            )
        )

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        authnResponse.url.shouldContain("?")
        authnResponse.url.shouldNotContain("#")
        authnResponse.url.shouldStartWith(clientId)

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.state.shouldBe(expectedState)
    }

    "test with deserializing" {
        val authnRequest = verifierOid4vp.createAuthnRequest(defaultRequestOptions)
        val authnRequestUrlParams = authnRequest.encodeToParameters().formUrlEncode()

        val parsedAuthnRequest: AuthenticationRequestParameters =
            authnRequestUrlParams.decodeFromUrlQuery()
        val authnResponse = holderOid4vp.createAuthnResponseParams(
            RequestParametersFrom.Uri<AuthenticationRequestParameters>(
                Url(authnRequestUrlParams),
                parsedAuthnRequest
            )
        ).getOrThrow().params
        val authnResponseParams = authnResponse.encodeToParameters().formUrlEncode()

        val result = verifierOid4vp.validateAuthnResponse(authnResponseParams)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test specific credential" {
        val authnRequest = verifierOid4vp.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = requestOptionsAtomicAttribute()
        )

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object" {
        val authnRequestWithRequestObject = verifierOid4vp.createAuthnRequestUrlWithRequestObject(
            walletUrl = walletUrl,
            requestOptions = requestOptionsAtomicAttribute()
        ).getOrThrow()

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object and Attestation JWT" {
        val sprsCryptoService = DefaultCryptoService(EphemeralKeyWithoutCert())
        val attestationJwt = buildAttestationJwt(sprsCryptoService, clientId, verifierKeyMaterial)
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.VerifierAttestation(attestationJwt, clientId),
        )
        val authnRequestWithRequestObject = verifierOid4vp.createAuthnRequestUrlWithRequestObject(
            walletUrl = walletUrl,
            requestOptions = requestOptionsAtomicAttribute()
        ).getOrThrow()

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            requestObjectJwsVerifier = attestationJwtVerifier(sprsCryptoService.keyMaterial.jsonWebKey)
        )
        val authnResponse = holderOid4vp.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }
    "test with request object and invalid Attestation JWT" {
        val sprsCryptoService = DefaultCryptoService(EphemeralKeyWithoutCert())
        val attestationJwt = buildAttestationJwt(sprsCryptoService, clientId, verifierKeyMaterial)

        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.VerifierAttestation(attestationJwt, clientId)
        )
        val authnRequestWithRequestObject = verifierOid4vp.createAuthnRequestUrlWithRequestObject(
            walletUrl = walletUrl,
            requestOptions = requestOptionsAtomicAttribute()
        ).getOrThrow()

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            requestObjectJwsVerifier = attestationJwtVerifier(EphemeralKeyWithoutCert().jsonWebKey)
        )
        shouldThrow<OAuth2Exception> {
            holderOid4vp.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
        }
    }

    "test with request object from request_uri as URL query parameters" {
        val authnRequest = verifierOid4vp.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = requestOptionsAtomicAttribute()
        )

        val clientId = Url(authnRequest).parameters["client_id"]!!
        val requestUrl = "https://www.example.com/request/${uuid4()}"

        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", clientId)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            remoteResourceRetriever = {
                if (it == requestUrl) authnRequest else null
            }
        )

        val authnResponse = holderOid4vp.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object from request_uri as JWS" {
        val jar = verifierOid4vp.createAuthnRequestAsSignedRequestObject(
            requestOptions = requestOptionsAtomicAttribute()
        ).getOrThrow()

        val requestUrl = "https://www.example.com/request/${uuid4()}"
        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", clientId)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            remoteResourceRetriever = {
                if (it == requestUrl) jar.serialize() else null
            }
        )

        val authnResponse = holderOid4vp.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object not verified" {
        val jar = verifierOid4vp.createAuthnRequestAsSignedRequestObject(
            requestOptions = requestOptionsAtomicAttribute()
        ).getOrThrow()

        val requestUrl = "https://www.example.com/request/${uuid4()}"
        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", clientId)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            remoteResourceRetriever = {
                if (it == requestUrl) jar.serialize() else null
            },
            requestObjectJwsVerifier = { _ -> false }
        )

        shouldThrow<OAuth2Exception> {
            holderOid4vp.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
        }
    }
})

private fun requestOptionsAtomicAttribute() = RequestOptions(
    credentials = setOf(
        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
    ),
)

private suspend fun buildAttestationJwt(
    sprsCryptoService: DefaultCryptoService,
    clientId: String,
    verifierKeyMaterial: KeyMaterial,
): JwsSigned<JsonWebToken> = DefaultJwsService(sprsCryptoService).createSignedJws(
    header = JwsHeader(
        algorithm = sprsCryptoService.keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
    ),
    payload = JsonWebToken(
        issuer = "sprs", // allows Wallet to determine the issuer's key
        subject = clientId,
        issuedAt = Clock.System.now(),
        expiration = Clock.System.now().plus(10.seconds),
        notBefore = Clock.System.now(),
        confirmationClaim = ConfirmationClaim(jsonWebKey = verifierKeyMaterial.jsonWebKey),
    ),
    serializer = JsonWebToken.Companion.serializer(),
).getOrThrow()

private fun attestationJwtVerifier(trustedKey: JsonWebKey) =
    object : RequestObjectJwsVerifier {
        override fun invoke(jws: JwsSigned<RequestParameters>): Boolean {
            val attestationJwt = jws.header.attestationJwt?.let {
                JwsSigned.Companion.deserialize<JsonWebToken>(
                    JsonWebToken.Companion.serializer(), it
                ).getOrThrow()
            }
                ?: return false
            val verifierJwsService = DefaultVerifierJwsService()
            if (!verifierJwsService.verifyJws(attestationJwt, trustedKey))
                return false
            val verifierPublicKey = attestationJwt.payload.confirmationClaim?.jsonWebKey
                ?: return false
            return verifierJwsService.verifyJws(jws, verifierPublicKey)
        }
    }

private suspend fun verifySecondProtocolRun(
    verifierOid4vp: OpenId4VpVerifier,
    walletUrl: String,
    holderOid4vp: OpenId4VpHolder,
) {
    val authnRequestUrl = verifierOid4vp.createAuthnRequestUrl(walletUrl, defaultRequestOptions)
    val authnResponse = holderOid4vp.createAuthnResponse(authnRequestUrl)
    verifierOid4vp.validateAuthnResponse((authnResponse.getOrThrow() as AuthenticationResponseResult.Redirect).url)
        .shouldBeInstanceOf<AuthnResponseResult.Success>()
}

private val defaultRequestOptions = RequestOptions(
    credentials = setOf(
        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
    )
)