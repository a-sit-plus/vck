package at.asitplus.wallet.lib.openid

import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.subjectAltName_2_5_29_17
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.pki.SubjectAltNameImplicitTags
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStorePlainJwt
import com.benasher44.uuid.uuid4
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

/**
 * A wallet establishing trust in the relying party sending an authorization request, per client identifier
 * scheme, see [RelyingPartyTrust].
 */
val OpenId4VpRelyingPartyTrustTest by matrixSuite {

    "x509_san_dns request from a relying party certified by a trusted CA is accepted" {
        val ca = TestCertificateAuthority()
        val relyingParty = ca.issue(extensions = subjectAltNameDns(CLIENT_ID_DNS))

        presentTo(
            relyingParty = relyingParty,
            clientIdScheme = sanDnsScheme(relyingParty),
            trust = RelyingPartyTrust(certificates = { setOf(ca.certificate()) }),
        ).getOrThrow()
    }

    "x509_san_dns request from a relying party certified by an untrusted CA is rejected" {
        val ca = TestCertificateAuthority()
        val relyingParty = ca.issue(extensions = subjectAltNameDns(CLIENT_ID_DNS))

        presentTo(
            relyingParty = relyingParty,
            clientIdScheme = sanDnsScheme(relyingParty),
            trust = RelyingPartyTrust(certificates = { setOf(TestCertificateAuthority().certificate()) }),
        ).exceptionOrNull().shouldNotBeNull()
            .message.shouldNotBeNull() shouldContain "trust anchor"
    }

    // Without a trust list, a self-signed certificate naming any DNS name satisfies both the SAN check and the
    // signature check, so the trust list is the only thing standing between a wallet and an impersonated verifier
    "x509_san_dns request from a self-signed certificate naming the relying party is rejected" {
        val impostor = EphemeralKeyWithSelfSignedCert(extensions = subjectAltNameDns(CLIENT_ID_DNS))

        presentTo(
            relyingParty = impostor,
            clientIdScheme = sanDnsScheme(impostor),
            trust = RelyingPartyTrust(certificates = { setOf(TestCertificateAuthority().certificate()) }),
        ).exceptionOrNull().shouldNotBeNull()
            .message.shouldNotBeNull() shouldContain "self-signed"
    }

    "x509_hash request from a relying party certified by a trusted CA is accepted, untrusted is rejected" {
        val ca = TestCertificateAuthority()
        val relyingParty = ca.issue()
        val chain = listOf(relyingParty.getCertificate()!!)
        val scheme = ClientIdScheme.CertificateHash(chain, REDIRECT_URI)

        presentTo(relyingParty, scheme, RelyingPartyTrust(certificates = { setOf(ca.certificate()) }))
            .getOrThrow()

        presentTo(
            relyingParty, scheme,
            RelyingPartyTrust(certificates = { setOf(TestCertificateAuthority().certificate()) }),
        ).exceptionOrNull().shouldNotBeNull()
            .message.shouldNotBeNull() shouldContain "trust anchor"
    }

    "verifier_attestation from an attester trusted by key is accepted, from an untrusted one rejected" {
        val attester = EphemeralKeyWithoutCert()
        val relyingParty = EphemeralKeyWithoutCert()
        val clientId = uuid4().toString()
        val scheme = ClientIdScheme.VerifierAttestation(
            attestationJwt(attester, subject = clientId, confirmedKey = relyingParty),
            REDIRECT_URI,
        )

        presentTo(
            relyingParty, scheme,
            RelyingPartyTrust(verifierAttesterKeys = { setOf(attester.jsonWebKey) }),
        ).getOrThrow()

        presentTo(
            relyingParty, scheme,
            RelyingPartyTrust(verifierAttesterKeys = { setOf(EphemeralKeyWithoutCert().jsonWebKey) }),
        ).exceptionOrNull().shouldNotBeNull()
            .message.shouldNotBeNull() shouldContain "not issued by a trusted party"
    }

    // ponytail: `sub` != client_id is enforced but not covered, ClientIdScheme.VerifierAttestation derives the
    // client_id from the attestation's `sub`, so the request builder cannot produce a mismatching pair

    "verifier_attestation signed by a key other than the attested cnf key is rejected" {
        val attester = EphemeralKeyWithoutCert()
        val impostor = EphemeralKeyWithoutCert()
        val scheme = ClientIdScheme.VerifierAttestation(
            attestationJwt(attester, subject = uuid4().toString(), confirmedKey = EphemeralKeyWithoutCert()),
            REDIRECT_URI,
        )

        presentTo(
            impostor, scheme,
            RelyingPartyTrust(verifierAttesterKeys = { setOf(attester.jsonWebKey) }),
        ).exceptionOrNull().shouldNotBeNull()
            .message.shouldNotBeNull() shouldContain "signature not verified"
    }

    "pre-registered request from a known client identifier is accepted, from an unknown one rejected" {
        val relyingParty = EphemeralKeyWithoutCert()
        val clientId = "known-${uuid4()}"
        val scheme = ClientIdScheme.PreRegistered(clientId, REDIRECT_URI)

        presentTo(
            relyingParty, scheme,
            RelyingPartyTrust(preRegisteredClients = { if (it == clientId) setOf(relyingParty.jsonWebKey) else null }),
        ).getOrThrow()

        presentTo(
            relyingParty, scheme,
            RelyingPartyTrust(preRegisteredClients = { null }),
        ).exceptionOrNull().shouldNotBeNull()
            .message.shouldNotBeNull() shouldContain "not a pre-registered relying party"
    }

    "a scheme without configured trust material is rejected" {
        val relyingParty = EphemeralKeyWithoutCert()
        val scheme = ClientIdScheme.PreRegistered("some-${uuid4()}", REDIRECT_URI)

        presentTo(relyingParty, scheme, RelyingPartyTrust(certificates = { setOf() }))
            .exceptionOrNull().shouldNotBeNull()
            .message.shouldNotBeNull() shouldContain "no pre-registered relying parties configured"
    }
}

private const val CLIENT_ID_DNS = "example.com"
private const val REDIRECT_URI = "https://example.com/rp"

private fun subjectAltNameDns(dnsName: String) = listOf(
    X509CertificateExtension(
        KnownOIDs.subjectAltName_2_5_29_17,
        critical = false,
        Asn1EncapsulatingOctetString(
            listOf(
                Asn1.Sequence {
                    +Asn1Primitive(
                        SubjectAltNameImplicitTags.dNSName,
                        Asn1String.UTF8(dnsName).encodeToTlv().content
                    )
                }
            )
        )
    )
)

private suspend fun sanDnsScheme(relyingParty: KeyMaterial) = ClientIdScheme.CertificateSanDns(
    listOf(relyingParty.getCertificate()!!), CLIENT_ID_DNS, "https://$CLIENT_ID_DNS/rp"
)

private suspend fun attestationJwt(
    attester: KeyMaterial,
    subject: String,
    confirmedKey: KeyMaterial,
): JwsCompactTyped<JsonWebToken> = SignJwt<JsonWebToken>(attester, JwsHeaderNone())(
    null,
    JsonWebToken(
        issuer = "https://attester.example.com",
        subject = subject,
        issuedAt = Clock.System.now(),
        notBefore = Clock.System.now(),
        expiration = Clock.System.now().plus(5.minutes),
        confirmationClaim = ConfirmationClaim(jsonWebKey = confirmedKey.jsonWebKey),
    ),
    JsonWebToken.serializer(),
).getOrThrow()

/** Runs a signed OpenID4VP request from [relyingParty] against a wallet configured with [trust]. */
private suspend fun presentTo(
    relyingParty: KeyMaterial,
    clientIdScheme: ClientIdScheme,
    trust: RelyingPartyTrust,
) = runCatchingToResult {
    val verifierOid4vp = OpenId4VpVerifier(
        keyMaterial = relyingParty,
        clientIdScheme = clientIdScheme,
    )
    val walletUrl = "https://example.com/wallet/${uuid4()}"
    val request = verifierOid4vp.createAuthnRequest(
        OpenId4VpRequestOptions(
            presentationRequest = CredentialPresentationRequestBuilder(
                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
            ).toDCQLRequest(),
        ),
        CreationOptions.SignedRequestByValue(walletUrl),
    ).getOrThrow().url

    val holderKeyMaterial = EphemeralKeyWithoutCert()
    val holder: Holder = HolderAgent(holderKeyMaterial).also {
        issueAndStorePlainJwt(it, holderKeyMaterial)
    }
    OpenId4VpHolder(
        holder = holder,
        relyingPartyTrust = trust,
        randomSource = RandomSource.Default,
    ).createAuthnResponse(request).getOrThrow()
        .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
}

private suspend fun <T> runCatchingToResult(block: suspend () -> T): Result<T> =
    try {
        Result.success(block())
    } catch (throwable: Throwable) {
        Result.failure(throwable)
    }
