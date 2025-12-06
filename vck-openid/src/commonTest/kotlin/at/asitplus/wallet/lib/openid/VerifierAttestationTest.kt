package at.asitplus.wallet.lib.openid

import at.asitplus.openid.RequestParameters
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithKey
import at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

val VerifierAttestationTest by testSuite {

    withFixtureGenerator(suspend {
        val holderKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
        val holderAgent: Holder = HolderAgent(holderKeyMaterial).also { agent ->
            agent.storeCredential(
                IssuerAgent(
                    identifier = "https://issuer.example.com/".toUri(),
                    randomSource = RandomSource.Default
                ).issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        holderKeyMaterial.publicKey,
                        ConstantIndex.AtomicAttribute2023,
                        ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            )
        }
        object {
            val holderAgent = holderAgent
            val verifierKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
            val clientId: String = "${uuid4()}"
            val redirectUrl: String = "https://example.com/rp/${uuid4()}"
            val walletUrl: String = "https://example.com/wallet/${uuid4()}"

            val holderOid4vp: OpenId4VpHolder = OpenId4VpHolder(
                holder = holderAgent,
                randomSource = RandomSource.Default,
            )
        }
    }) - {

        "test with request object and Attestation JWT" {
            val sprsKeyMaterial = EphemeralKeyWithoutCert()
            val attestationJwt = buildAttestationJwt(sprsKeyMaterial, it.clientId, it.verifierKeyMaterial)
            val verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = it.verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.VerifierAttestation(attestationJwt, it.redirectUrl),
            )
            val authnRequestWithRequestObject = verifierOid4vp.createAuthnRequest(
                requestOptionsAtomicAttribute(), OpenId4VpVerifier.CreationOptions.SignedRequestByValue(it.walletUrl)
            ).getOrThrow().url

            val holderOid4vp = OpenId4VpHolder(
                holder = it.holderAgent,
                requestObjectJwsVerifier = attestationJwtVerifier(sprsKeyMaterial.jsonWebKey),
                randomSource = RandomSource.Default,
            )
            val authnResponse = holderOid4vp.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.Success>().apply {
                    vp.freshVerifiableCredentials.shouldNotBeEmpty().map { it.vcJws }.forEach {
                        it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
                    }
                }
        }
        "test with request object and invalid Attestation JWT" {
            val sprsKeyMaterial = EphemeralKeyWithoutCert()
            val attestationJwt = buildAttestationJwt(sprsKeyMaterial, it.clientId, it.verifierKeyMaterial)

            val verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = it.verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.VerifierAttestation(attestationJwt, it.redirectUrl)
            )
            val authnRequestWithRequestObject = verifierOid4vp.createAuthnRequest(
                requestOptionsAtomicAttribute(), OpenId4VpVerifier.CreationOptions.SignedRequestByValue(it.walletUrl)
            ).getOrThrow().url

            val holderOid4vp = OpenId4VpHolder(
                holder = it.holderAgent,
                requestObjectJwsVerifier = attestationJwtVerifier(EphemeralKeyWithoutCert().jsonWebKey),
                randomSource = RandomSource.Default,
            )
            shouldThrow<OAuth2Exception> {
                holderOid4vp.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
            }
        }
    }
}


private fun requestOptionsAtomicAttribute() = OpenId4VpRequestOptions(
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
    JsonWebToken.serializer(),
).getOrThrow()

private fun attestationJwtVerifier(trustedKey: JsonWebKey) =
    RequestObjectJwsVerifier { jws: JwsSigned<RequestParameters> ->
        val attestationJwt = jws.header.attestationJwt?.let {
            JwsSigned.deserialize(JsonWebToken.serializer(), it).getOrThrow()
        } ?: return@RequestObjectJwsVerifier false
        val verifyJwsSignatureWithKey = VerifyJwsSignatureWithKey()
        if (!verifyJwsSignatureWithKey(attestationJwt, trustedKey).isSuccess)
            return@RequestObjectJwsVerifier false
        val verifierPublicKey = attestationJwt.payload.confirmationClaim?.jsonWebKey
            ?: return@RequestObjectJwsVerifier false
        verifyJwsSignatureWithKey(jws, verifierPublicKey).isSuccess
    }


