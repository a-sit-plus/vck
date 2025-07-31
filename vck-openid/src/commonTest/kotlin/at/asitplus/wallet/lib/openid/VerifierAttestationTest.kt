package at.asitplus.wallet.lib.openid

import at.asitplus.openid.RequestParameters
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithKey
import at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

class VerifierAttestationTest : FreeSpec({

    lateinit var clientId: String
    lateinit var redirectUrl: String
    lateinit var walletUrl: String
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var verifierOid4vp: OpenId4VpVerifier

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        clientId = "${uuid4()}"
        redirectUrl = "https://example.com/rp/${uuid4()}"
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
    }

    "test with request object and Attestation JWT" {
        val sprsKeyMaterial = EphemeralKeyWithoutCert()
        val attestationJwt = buildAttestationJwt(sprsKeyMaterial, clientId, verifierKeyMaterial)
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.VerifierAttestation(attestationJwt, redirectUrl),
        )
        val authnRequestWithRequestObject = verifierOid4vp.createAuthnRequest(
            requestOptionsAtomicAttribute(), OpenId4VpVerifier.CreationOptions.SignedRequestByValue(walletUrl)
        ).getOrThrow().url

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            requestObjectJwsVerifier = attestationJwtVerifier(sprsKeyMaterial.jsonWebKey)
        )
        val authnResponse = holderOid4vp.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.freshVerifiableCredentials.shouldNotBeEmpty()
        result.vp.freshVerifiableCredentials.map { it.vcJws }.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }
    "test with request object and invalid Attestation JWT" {
        val sprsKeyMaterial = EphemeralKeyWithoutCert()
        val attestationJwt = buildAttestationJwt(sprsKeyMaterial, clientId, verifierKeyMaterial)

        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.VerifierAttestation(attestationJwt, redirectUrl)
        )
        val authnRequestWithRequestObject = verifierOid4vp.createAuthnRequest(
            requestOptionsAtomicAttribute(), OpenId4VpVerifier.CreationOptions.SignedRequestByValue(walletUrl)
        ).getOrThrow().url

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            requestObjectJwsVerifier = attestationJwtVerifier(EphemeralKeyWithoutCert().jsonWebKey)
        )
        shouldThrow<OAuth2Exception> {
            holderOid4vp.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
        }
    }
})


private fun requestOptionsAtomicAttribute() = OpenIdRequestOptions(
    credentials = setOf(
        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
    ),
)

private suspend fun buildAttestationJwt(
    sprsKeyMaterial: KeyMaterial,
    clientId: String,
    verifierKeyMaterial: KeyMaterial,
): JwsSigned<JsonWebToken> = SignJwt<JsonWebToken>(sprsKeyMaterial, JwsHeaderNone())(
    null,
    JsonWebToken(
        issuer = "sprs", // allows Wallet to determine the issuer's key
        subject = clientId,
        issuedAt = Clock.System.now(),
        expiration = Clock.System.now().plus(10.seconds),
        notBefore = Clock.System.now(),
        confirmationClaim = ConfirmationClaim(jsonWebKey = verifierKeyMaterial.jsonWebKey),
    ),
    JsonWebToken.Companion.serializer(),
).getOrThrow()

private fun attestationJwtVerifier(trustedKey: JsonWebKey) =
    RequestObjectJwsVerifier { jws: JwsSigned<RequestParameters> ->
        val attestationJwt = jws.header.attestationJwt?.let {
            JwsSigned.Companion.deserialize<JsonWebToken>(
                JsonWebToken.Companion.serializer(), it
            ).getOrThrow()
        } ?: return@RequestObjectJwsVerifier false
        val verifyJwsSignatureWithKey = VerifyJwsSignatureWithKey()
        if (!verifyJwsSignatureWithKey(attestationJwt, trustedKey))
            return@RequestObjectJwsVerifier false
        val verifierPublicKey = attestationJwt.payload.confirmationClaim?.jsonWebKey
            ?: return@RequestObjectJwsVerifier false
        verifyJwsSignatureWithKey(jws, verifierPublicKey)
    }


