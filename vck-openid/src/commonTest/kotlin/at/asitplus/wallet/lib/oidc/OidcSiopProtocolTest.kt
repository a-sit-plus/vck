package at.asitplus.wallet.lib.oidc

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ID_TOKEN
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.RequestOptions
import at.asitplus.wallet.lib.oidvci.*
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

@Suppress("unused")
class OidcSiopProtocolTest : FreeSpec({

    lateinit var relyingPartyUrl: String
    lateinit var walletUrl: String

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial

    lateinit var holderAgent: Holder

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        val rpUUID = uuid4()
        relyingPartyUrl = "https://example.com/rp/$rpUUID"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)

        holderAgent.storeCredential(
            IssuerAgent(
                EphemeralKeyWithoutCert(),
                DummyCredentialDataProvider(),
            ).issueCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ).getOrThrow().toStoreCredentialInput()
        )

        holderSiop = OidcSiopWallet(
            holder = holderAgent,
        )
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
        )
    }

    "test with Fragment" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(walletUrl, defaultRequestOptions)

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        authnResponse.url.shouldNotContain("?")
        authnResponse.url.shouldContain("#")
        authnResponse.url.shouldStartWith(relyingPartyUrl)

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()

        verifySecondProtocolRun(verifierSiop, walletUrl, holderSiop)
    }

    "wrong client nonce in id_token should lead to error" {
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
            nonceService = object : NonceService {
                override suspend fun provideNonce() = uuid4().toString()
                override suspend fun verifyNonce(it: String) = false
                override suspend fun verifyAndRemoveNonce(it: String) = false
            }
        )
        val requestOptions = RequestOptions(
            credentials = setOf(OidcSiopVerifier.RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
            responseType = "$ID_TOKEN $VP_TOKEN"
        )
        val authnRequest = verifierSiop.createAuthnRequestUrl(walletUrl, requestOptions)

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.ValidationError>()
        result.field shouldBe "idToken"
    }

    "wrong client nonce in vp_token should lead to error" {
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
            stateToNonceStore = object : MapStore<String, String> {
                override suspend fun put(key: String, value: String) {}
                override suspend fun get(key: String): String? = null
                override suspend fun remove(key: String): String? = null
            },
        )
        val authnRequest = verifierSiop.createAuthnRequestUrl(walletUrl, defaultRequestOptions)

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.ValidationError>()
        result.field shouldBe "state"
    }

    "test with QR Code" {
        val metadataUrlNonce = uuid4().toString()
        val metadataUrl = "https://example.com/$metadataUrlNonce"
        val requestUrlNonce = uuid4().toString()
        val requestUrl = "https://example.com/$requestUrlNonce"
        val qrcode = verifierSiop.createQrCodeUrl(walletUrl, metadataUrl, requestUrl)
        qrcode shouldContain metadataUrlNonce
        qrcode shouldContain requestUrlNonce

        val metadataObject = verifierSiop.createSignedMetadata().getOrThrow()
        DefaultVerifierJwsService().verifyJwsObject(metadataObject).shouldBeTrue()

        val authnRequestUrl = verifierSiop.createAuthnRequestUrlWithRequestObject(walletUrl, defaultRequestOptions)
            .getOrThrow()
        val authnRequest: AuthenticationRequestParameters =
            Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
        authnRequest.clientId shouldBe relyingPartyUrl
        val jar = authnRequest.request
        jar.shouldNotBeNull()
        DefaultVerifierJwsService().verifyJwsObject(JwsSigned.deserialize(jar).getOrThrow()).shouldBeTrue()

        val authnResponse = holderSiop.createAuthnResponse(jar).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
    }

    "test with direct_post" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(
                credentials = setOf(OidcSiopVerifier.RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                responseMode = OpenIdConstants.ResponseMode.DIRECT_POST,
                responseUrl = relyingPartyUrl,
            )
        )

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>()
        authnResponse.url.shouldBe(relyingPartyUrl)

        val result =
            verifierSiop.validateAuthnResponseFromPost(authnResponse.params.formUrlEncode())
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test with direct_post_jwt" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(
                credentials = setOf(OidcSiopVerifier.RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                responseMode = OpenIdConstants.ResponseMode.DIRECT_POST_JWT,
                responseUrl = relyingPartyUrl,
            )
        )

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>()
        authnResponse.url.shouldBe(relyingPartyUrl)
        authnResponse.params.shouldHaveSize(2)
        val jarmResponse = authnResponse.params.entries.first { it.key == "response" }.value
        DefaultVerifierJwsService().verifyJwsObject(JwsSigned.deserialize(jarmResponse).getOrThrow()).shouldBeTrue()

        val result =
            verifierSiop.validateAuthnResponseFromPost(authnResponse.params.formUrlEncode())
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test with Query" {
        val expectedState = uuid4().toString()
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(
                credentials = setOf(OidcSiopVerifier.RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                responseMode = OpenIdConstants.ResponseMode.QUERY,
                state = expectedState
            )
        )

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        authnResponse.url.shouldContain("?")
        authnResponse.url.shouldNotContain("#")
        authnResponse.url.shouldStartWith(relyingPartyUrl)

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.state.shouldBe(expectedState)
    }

    "test with deserializing" {
        val authnRequest = verifierSiop.createAuthnRequest(defaultRequestOptions)
        val authnRequestUrlParams = authnRequest.encodeToParameters().formUrlEncode()

        val parsedAuthnRequest: AuthenticationRequestParameters =
            authnRequestUrlParams.decodeFromUrlQuery()
        val authnResponse = holderSiop.createAuthnResponseParams(
            AuthenticationRequestParametersFrom.Uri(
                Url(authnRequestUrlParams),
                parsedAuthnRequest
            )
        ).getOrThrow().params
        val authnResponseParams = authnResponse.encodeToParameters().formUrlEncode()

        val parsedAuthnResponse: AuthenticationResponseParameters =
            authnResponseParams.decodeFromPostBody()
        val result = verifierSiop.validateAuthnResponse(parsedAuthnResponse)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test specific credential" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = requestOptionsAtomicAttribute()
        )

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object" {
        val authnRequestWithRequestObject = verifierSiop.createAuthnRequestUrlWithRequestObject(
            walletUrl = walletUrl,
            requestOptions = requestOptionsAtomicAttribute()
        ).getOrThrow()

        val authnResponse = holderSiop.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object and Attestation JWT" {
        val sprsCryptoService = DefaultCryptoService(EphemeralKeyWithoutCert())
        val attestationJwt = buildAttestationJwt(sprsCryptoService, relyingPartyUrl, verifierKeyMaterial)
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
            clientIdScheme = OidcSiopVerifier.ClientIdScheme.VerifierAttestation(attestationJwt),
        )
        val authnRequestWithRequestObject = verifierSiop.createAuthnRequestUrlWithRequestObject(
            walletUrl = walletUrl,
            requestOptions = requestOptionsAtomicAttribute()
        ).getOrThrow()

        holderSiop = OidcSiopWallet(
            holder = holderAgent,
            requestObjectJwsVerifier = verifierAttestationVerifier(sprsCryptoService.keyMaterial.jsonWebKey)
        )
        val authnResponse = holderSiop.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }
    "test with request object and invalid Attestation JWT" {
        val sprsCryptoService = DefaultCryptoService(EphemeralKeyWithoutCert())
        val attestationJwt = buildAttestationJwt(sprsCryptoService, relyingPartyUrl, verifierKeyMaterial)

        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
            clientIdScheme = OidcSiopVerifier.ClientIdScheme.VerifierAttestation(attestationJwt)
        )
        val authnRequestWithRequestObject = verifierSiop.createAuthnRequestUrlWithRequestObject(
            walletUrl = walletUrl,
            requestOptions = requestOptionsAtomicAttribute()
        ).getOrThrow()

        holderSiop = OidcSiopWallet(
            holder = holderAgent,
            requestObjectJwsVerifier = verifierAttestationVerifier(EphemeralKeyWithoutCert().jsonWebKey)
        )
        shouldThrow<OAuth2Exception> {
            holderSiop.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
        }
    }

    "test with request object from request_uri as URL query parameters" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = requestOptionsAtomicAttribute()
        )

        val clientId = Url(authnRequest).parameters["client_id"]!!
        val requestUrl = "https://www.example.com/request/${uuid4()}"

        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", clientId)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderSiop = OidcSiopWallet(
            holder = holderAgent,
            remoteResourceRetriever = {
                if (it == requestUrl) authnRequest else null
            }
        )

        val authnResponse = holderSiop.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object from request_uri as JWS" {
        val jar = verifierSiop.createAuthnRequestAsSignedRequestObject(
            requestOptions = requestOptionsAtomicAttribute()
        ).getOrThrow()

        val requestUrl = "https://www.example.com/request/${uuid4()}"
        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", relyingPartyUrl)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderSiop = OidcSiopWallet(
            holder = holderAgent,
            remoteResourceRetriever = {
                if (it == requestUrl) jar.serialize() else null
            }
        )

        val authnResponse = holderSiop.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object not verified" {
        val jar = verifierSiop.createAuthnRequestAsSignedRequestObject(
            requestOptions = requestOptionsAtomicAttribute()
        ).getOrThrow()

        val requestUrl = "https://www.example.com/request/${uuid4()}"
        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", relyingPartyUrl)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderSiop = OidcSiopWallet(
            holder = holderAgent,
            remoteResourceRetriever = {
                if (it == requestUrl) jar.serialize() else null
            },
            requestObjectJwsVerifier = { _, _ -> false }
        )

        shouldThrow<OAuth2Exception> {
            holderSiop.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
        }
    }
})

private fun requestOptionsAtomicAttribute() = RequestOptions(
    credentials = setOf(
        OidcSiopVerifier.RequestOptionsCredential(
            ConstantIndex.AtomicAttribute2023,
        )
    ),
)

private suspend fun buildAttestationJwt(
    sprsCryptoService: DefaultCryptoService,
    relyingPartyUrl: String,
    verifierKeyMaterial: KeyMaterial
): JwsSigned = DefaultJwsService(sprsCryptoService).createSignedJws(
    header = JwsHeader(
        algorithm = sprsCryptoService.keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
    ),
    payload = JsonWebToken(
        issuer = "sprs", // allows Wallet to determine the issuer's key
        subject = relyingPartyUrl,
        issuedAt = Clock.System.now(),
        expiration = Clock.System.now().plus(10.seconds),
        notBefore = Clock.System.now(),
        confirmationClaim = ConfirmationClaim(jsonWebKey = verifierKeyMaterial.jsonWebKey),
    ).serialize().encodeToByteArray()
).getOrThrow()

private fun verifierAttestationVerifier(trustedKey: JsonWebKey) =
    object : RequestObjectJwsVerifier {
        override fun invoke(jws: JwsSigned, authnRequest: AuthenticationRequestParameters): Boolean {
            val attestationJwt = jws.header.attestationJwt?.let { JwsSigned.deserialize(it).getOrThrow() }
                ?: return false
            val verifierJwsService = DefaultVerifierJwsService()
            if (!verifierJwsService.verifyJws(attestationJwt, trustedKey))
                return false
            val verifierPublicKey = JsonWebToken.deserialize(attestationJwt.payload.decodeToString())
                .getOrNull()?.confirmationClaim?.jsonWebKey
                ?: return false
            return verifierJwsService.verifyJws(jws, verifierPublicKey)
        }
    }

private suspend fun verifySecondProtocolRun(
    verifierSiop: OidcSiopVerifier,
    walletUrl: String,
    holderSiop: OidcSiopWallet
) {
    val authnRequestUrl = verifierSiop.createAuthnRequestUrl(walletUrl, defaultRequestOptions)
    val authnResponse = holderSiop.createAuthnResponse(authnRequestUrl)
    val validation = verifierSiop.validateAuthnResponse(
        (authnResponse.getOrThrow() as AuthenticationResponseResult.Redirect).url
    )
    validation.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
}

private val defaultRequestOptions = RequestOptions(
    credentials = setOf(
        OidcSiopVerifier.RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
    )
)