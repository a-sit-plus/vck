package at.asitplus.wallet.lib.validation

import at.asitplus.etsi.ListOfTrustedEntities
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.selfSignedKey
import at.asitplus.wallet.lib.etsi.LoTEFilterService
import at.asitplus.wallet.lib.etsi.LoTETestData
import at.asitplus.wallet.lib.etsi.LoteProfile
import at.asitplus.wallet.lib.etsi.TrustAnchorProvider
import at.asitplus.wallet.lib.validation.CheckOutcome.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days

private const val PID_VCT = "urn:eudi:pid:1"
private const val PID_DOCTYPE = "eu.europa.ec.eudi.pid.1"
private const val MDL_DOCTYPE = "org.iso.18013.5.1.mDL"

private val json = Json { ignoreUnknownKeys = true }

/** Read when a check runs, i.e. after the certificates of the test have been issued. */
private fun now() = Clock.System.now()

private fun lote(payload: String) = json.decodeFromString<ListOfTrustedEntities>(payload)

private fun TestCertificateAuthority.scope(
    vararg identifiers: String,
    source: String,
    status: Set<X509Certificate> = setOf(certificate),
) = CredentialTrustScope(
    credentialIdentifiers = identifiers.toSet(),
    source = source,
    issuance = TrustedCertificates { setOf(certificate) },
    status = TrustedCertificates { status },
)

private suspend fun TestCertificateAuthority.signerChain() = listOf(issue().getCertificate().shouldNotBeNull())

val CredentialTrustTest by matrixSuite {

    "trust scopes" - {
        "resolve the issuance and status anchors of a type, by every identifier of the type" {
            val pidProviders = TestCertificateAuthority()
            val pidRevocation = TestCertificateAuthority()
            val scopes = CredentialTrustScopes(
                pidProviders.scope(PID_VCT, PID_DOCTYPE, source = "PID", status = setOf(pidRevocation.certificate))
            )

            listOf(PID_VCT, PID_DOCTYPE).forEach { identifier ->
                scopes.resolve(identifier, TrustPurpose.ISSUANCE) shouldBe
                        CredentialTrustAnchorSet("PID", setOf(pidProviders.certificate))
                scopes.resolve(identifier, TrustPurpose.STATUS) shouldBe
                        CredentialTrustAnchorSet("PID", setOf(pidRevocation.certificate))
            }
        }

        "match identifiers exactly and case-sensitively" {
            val scopes = CredentialTrustScopes(TestCertificateAuthority().scope(MDL_DOCTYPE, source = "mDL"))

            listOf("org.iso.18013.5.1.mdl", "org.iso.18013.5.1.mDLx", "org.iso.18013.5.1", "urn:example:1")
                .forEach { scopes.resolve(it, TrustPurpose.ISSUANCE).shouldBeNull() }
        }

        "an identifier in two scopes is a configuration error" {
            shouldThrow<IllegalArgumentException> {
                CredentialTrustScopes(
                    TestCertificateAuthority().scope(PID_VCT, source = "PID"),
                    TestCertificateAuthority().scope(PID_VCT, source = "pinned"),
                )
            }.message.shouldNotBeNull() shouldContain PID_VCT
        }

        "a scope covers at least one identifier" {
            shouldThrow<IllegalArgumentException> { TestCertificateAuthority().scope(source = "empty") }
        }

        "an unavailable trust source propagates" {
            val unavailable = IllegalStateException("trust list unavailable")
            val scopes = CredentialTrustScopes(
                CredentialTrustScope(setOf(PID_VCT), "PID", { throw unavailable }, { emptySet() })
            )

            shouldThrow<IllegalStateException> { scopes.resolve(PID_VCT, TrustPurpose.ISSUANCE) } shouldBe unavailable
        }
    }

    "credential trust" - {
        "an issuer of the type's list is authorized" {
            val pidProviders = TestCertificateAuthority()
            val scopes = CredentialTrustScopes(pidProviders.scope(PID_VCT, source = "PID"))

            scopes.checkCredentialTrust(PID_VCT, TrustPurpose.ISSUANCE, pidProviders.signerChain(), now()) shouldBe
                    TrustValidation(Passed, PID_VCT, "PID")
        }

        "an issuer listed for one type is not authorized for another" {
            val pidProviders = TestCertificateAuthority()
            val mdlProviders = TestCertificateAuthority()
            val scopes = CredentialTrustScopes(
                pidProviders.scope(PID_VCT, source = "PID"),
                mdlProviders.scope(MDL_DOCTYPE, source = "mDL")
            )

            val trust = scopes.checkCredentialTrust(
                credentialIdentifier = MDL_DOCTYPE,
                purpose = TrustPurpose.ISSUANCE,
                chain = pidProviders.signerChain(),
                at = now()
            )
            trust.outcome.shouldBeInstanceOf<Failed>()
            trust.credentialIdentifier shouldBe MDL_DOCTYPE
            trust.source shouldBe "mDL"
        }

        "a type no scope covers is blocked, without a source" {
            val pidProviders = TestCertificateAuthority()
            val scopes = CredentialTrustScopes(pidProviders.scope(PID_VCT, source = "PID"))

            val trust = scopes.checkCredentialTrust(
                "urn:example:loyalty:1", TrustPurpose.ISSUANCE, pidProviders.signerChain(), now()
            )
            trust.outcome.shouldBeInstanceOf<Blocked>()
            trust.credentialIdentifier shouldBe "urn:example:loyalty:1"
            trust.source.shouldBeNull()
        }

        "without any configured anchors trust is blocked" {
            val chain = TestCertificateAuthority().signerChain()

            (null as CredentialTrustAnchors?).checkCredentialTrust(PID_VCT, TrustPurpose.ISSUANCE, chain, now())
                .outcome.shouldBeInstanceOf<Blocked>()
        }

        "an unavailable trust source blocks with its cause" {
            val unavailable = IllegalStateException("trust list unavailable")
            val anchors = CredentialTrustAnchors { _, _ -> throw unavailable }

            val chain = TestCertificateAuthority().signerChain()
            anchors.checkCredentialTrust(PID_VCT, TrustPurpose.ISSUANCE, chain, now())
                .outcome shouldBe Blocked(unavailable)
        }

        "an issuer may be listed itself" {
            val listed = selfSignedKey().getCertificate().shouldNotBeNull()
            val scopes = CredentialTrustScopes(
                CredentialTrustScope(setOf(PID_VCT), "PID", { setOf(listed) }, { setOf(listed) })
            )

            scopes.checkCredentialTrust(PID_VCT, TrustPurpose.ISSUANCE, listOf(listed), now()).outcome shouldBe Passed
        }

        "a status list signer has to be issued by an anchor, it can not be listed itself" {
            val listed = selfSignedKey().getCertificate().shouldNotBeNull()
            val scopes = CredentialTrustScopes(
                CredentialTrustScope(setOf(PID_VCT), "PID", { setOf(listed) }, { setOf(listed) })
            )

            scopes.checkCredentialTrust(PID_VCT, TrustPurpose.STATUS, listOf(listed), now())
                .outcome.shouldBeInstanceOf<Failed>()
        }

        "a status list signer issued by a status anchor is authorized" {
            val pidRevocation = TestCertificateAuthority()
            val scopes = CredentialTrustScopes(
                TestCertificateAuthority().scope(PID_VCT, source = "PID", status = setOf(pidRevocation.certificate))
            )

            scopes.checkCredentialTrust(PID_VCT, TrustPurpose.STATUS, pidRevocation.signerChain(), now()) shouldBe
                    TrustValidation(Passed, PID_VCT, "PID")
        }

        "status anchors never fall back to the issuance anchors" {
            val pidProviders = TestCertificateAuthority()
            val scopes = CredentialTrustScopes(pidProviders.scope(PID_VCT, source = "PID", status = emptySet()))

            val trust = scopes.checkCredentialTrust(PID_VCT, TrustPurpose.STATUS, pidProviders.signerChain(), now())
            trust.outcome.shouldBeInstanceOf<Failed>()
                .throwable.message.shouldNotBeNull() shouldContain "No trust anchor"
        }
    }

    "trust check" - {
        "without anchors it is blocked, with no anchors it fails" {
            val chain = TestCertificateAuthority().signerChain()

            checkTrust(chain, anchors = null, now(), TrustRule.ISSUED_BY_ANCHOR)
                .shouldBeInstanceOf<Blocked>()
            checkTrust(chain, anchors = emptySet(), now(), TrustRule.ISSUED_BY_ANCHOR)
                .shouldBeInstanceOf<Failed>()
        }

        "a signed object without certificate fails" {
            val ca = TestCertificateAuthority()

            checkTrust(null, setOf(ca.certificate), now(), TrustRule.ISSUED_BY_ANCHOR)
                .shouldBeInstanceOf<Failed>()
            checkTrust(emptyList(), setOf(ca.certificate), now(), TrustRule.ISSUED_BY_ANCHOR)
                .shouldBeInstanceOf<Failed>()
        }

        listOf(TrustRule.ISSUED_BY_ANCHOR_OR_LISTED, TrustRule.ISSUED_BY_ANCHOR, TrustRule.CHAIN_TO_ANCHOR)
            .asData(nameFn = { "$it passes for a signer issued by an anchor, fails after its validity" }) test { rule ->
            val ca = TestCertificateAuthority()
            val chain = ca.signerChain()

            checkTrust(chain, setOf(ca.certificate), now(), rule) shouldBe Passed
            checkTrust(chain, setOf(ca.certificate), now() + 1.days, rule)
                .shouldBeInstanceOf<Failed>()
        }

        "an anchor transported with the signer fails, unless the chain is checked to the anchor" {
            val ca = TestCertificateAuthority()
            val chain = ca.signerChain() + ca.certificate

            checkTrust(chain, setOf(ca.certificate), now(), TrustRule.ISSUED_BY_ANCHOR)
                .shouldBeInstanceOf<Failed>()
            checkTrust(chain, setOf(ca.certificate), now(), TrustRule.CHAIN_TO_ANCHOR) shouldBe Passed
        }
    }

    "adapters" - {
        "a scope from LoTEs takes issuance and revocation services of its profile only" {
            val pidLote = lote(LoTETestData.pidProvidersPayload)
            val wrpacLote = lote(LoTETestData.wrpacProvidersOriginal)
            val filter = LoTEFilterService()
            val scope = filter.credentialTrustScope(
                credentialIdentifiers = setOf(PID_VCT),
                profile = LoteProfile.PID,
                source = "PID providers",
                lists = { listOf(pidLote, wrpacLote) },
            )

            scope.issuance() shouldBe filter.extractIssuanceCertificates(pidLote, LoteProfile.PID)
                .mapNotNull { it.certificate }.toSet()
            scope.status() shouldBe filter.extractRevocationCertificates(pidLote, LoteProfile.PID)
                .mapNotNull { it.certificate }.toSet()
        }

        "a trust anchor provider without anchors for a type does not cover it" {
            val ca = TestCertificateAuthority()
            val provider = object : TrustAnchorProvider {
                override suspend fun issuanceAnchors(credentialIdentifier: String) =
                    if (credentialIdentifier == PID_VCT) listOf(ca.certificate) else emptyList()

                override suspend fun issuanceAnchors(profile: LoteProfile) = emptyList<X509Certificate>()
                override suspend fun revocationAnchors(credentialIdentifier: String) = emptyList<X509Certificate>()
                override suspend fun revocationAnchors(profile: LoteProfile) = emptyList<X509Certificate>()
            }
            val anchors = provider.asCredentialTrustAnchors("provider")

            anchors.resolve(PID_VCT, TrustPurpose.ISSUANCE) shouldBe
                    CredentialTrustAnchorSet("provider", setOf(ca.certificate))
            anchors.resolve(PID_VCT, TrustPurpose.STATUS).shouldBeNull()
            anchors.resolve(MDL_DOCTYPE, TrustPurpose.ISSUANCE).shouldBeNull()
        }

        "the legacy adapter uses the same anchors for every type" {
            val ca = TestCertificateAuthority()
            val anchors = CredentialTrustAnchors.sameForAllTypes(
                issuance = { setOf(ca.certificate) },
                status = null,
                source = "trustedIssuers",
            )

            listOf(PID_VCT, MDL_DOCTYPE).forEach {
                anchors.resolve(it, TrustPurpose.ISSUANCE) shouldBe
                        CredentialTrustAnchorSet("trustedIssuers", setOf(ca.certificate))
                anchors.resolve(it, TrustPurpose.STATUS).shouldBeNull()
            }
        }
    }
}
