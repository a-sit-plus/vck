package at.asitplus.wallet.lib.validation

import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.FixedTimePeriodProvider
import at.asitplus.wallet.lib.agent.InMemoryIssuerCredentialStore
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.StatusListAgent
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.StatusListJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.patchHeader
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.NotApplicable
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.JsonPrimitive
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

private val scheme = ConstantIndex.AtomicAttribute2023

private val integrityOnly = strictPolicy.copy(trust = TrustPolicy.IntegrityOnly, status = StatusPolicy.Skip)

/** An issuer and a status list issuer, each with a certificate of their own authority, and a holder. */
private class Issuance(
    val issuerCa: TestCertificateAuthority,
    val statusCa: TestCertificateAuthority,
) {
    val holderKey = EphemeralKeyWithoutCert()
    private val store = InMemoryIssuerCredentialStore()
    lateinit var statusListAgent: StatusListAgent
    lateinit var issuer: IssuerAgent

    suspend fun setUp() = apply {
        statusListAgent = StatusListAgent(keyMaterial = statusCa.issue(), issuerCredentialStore = store)
        issuer = IssuerAgent(
            keyMaterial = issuerCa.issue(),
            issuerCredentialStore = store,
            identifier = "https://issuer.example.com/".toUri(),
            statusListAgent = statusListAgent,
        )
    }

    val trustAnchors
        get() = CredentialTrustScopes(
            CredentialTrustScope(
                credentialIdentifiers = setOf(scheme.sdJwtType, scheme.isoDocType),
                source = "test issuers",
                issuance = { setOf(issuerCa.certificate) },
                status = { setOf(statusCa.certificate) },
            )
        )

    val statusTokens
        get() = StatusListTokenResolver { StatusListJwt(statusListAgent.issueStatusListJwt(), Clock.System.now()) }

    fun validator(clock: Clock = Clock.System) = CredentialValidator(
        trustAnchors = trustAnchors,
        statusValidator = StatusValidator(statusTokens),
        clock = clock,
    )

    suspend fun issue(representation: CredentialRepresentation): Issuer.IssuedCredential = issuer.issueCredential(
        DummyCredentialDataProvider.getCredential(holderKey.publicKey, scheme, representation).getOrThrow()
    ).getOrThrow()

    fun context(identifier: String? = null) =
        CredentialValidationContext(expectedHolderKey = holderKey.publicKey, expectedCredentialIdentifier = identifier)
}

private suspend fun issuance() = Issuance(TestCertificateAuthority(), TestCertificateAuthority()).setUp()

private fun Issuer.IssuedCredential.input(): CredentialValidationInput = when (this) {
    is Issuer.IssuedCredential.VcJwt -> CredentialValidationInput.VcJwt(signedVcJws.jws.toString())
    is Issuer.IssuedCredential.VcSdJwt -> CredentialValidationInput.SdJwtVc(signedSdJwtVc.serialize())
    is Issuer.IssuedCredential.Iso ->
        CredentialValidationInput.IsoMdoc(coseCompliantSerializer.encodeToByteArray(issuerSigned))
}

private fun Issuer.IssuedCredential.status(): RevocationListInfo = when (this) {
    is Issuer.IssuedCredential.VcJwt -> vc.credentialStatus
    is Issuer.IssuedCredential.VcSdJwt -> sdJwtVc.statusElement
    is Issuer.IssuedCredential.Iso -> issuerSigned.issuerAuth.payload?.status
}.shouldNotBeNull()

private suspend fun Issuance.validate(
    issued: Issuer.IssuedCredential,
    policy: ValidationPolicy = strictPolicy,
    validator: CredentialValidator = validator(),
    holderBinding: HolderBindingPolicy = HolderBindingPolicy.RequireExpectedKey,
    context: CredentialValidationContext = context(),
) = validator.validate(issued.input(), policy, holderBinding, context)

private val CredentialValidationResult.checks get() = report.checks.shouldBeInstanceOf<CredentialChecks>()

/** Replaces the payload of a JWS, keeping its header and signature. */
private fun String.withPayloadOf(other: String) =
    split(".").let { parts -> "${parts[0]}.${other.split(".")[1]}.${parts[2]}" }

val CredentialValidatorTest by matrixSuite {

    "every format" - {
        listOf(CredentialRepresentation.PLAIN_JWT, CredentialRepresentation.SD_JWT, CredentialRepresentation.ISO_MDOC)
            .asData(nameFn = { "$it" }) - { representation ->

                "an issued credential is accepted under a strict policy" {
                    val issuance = issuance()
                    val result = issuance.validate(issuance.issue(representation))

                    result.report.decision shouldBe ACCEPTED
                    result.credential.shouldNotBeNull()
                    result.checks.issuerTrust.outcome shouldBe Passed
                    result.checks.issuerTrust.source shouldBe "test issuers"
                    result.checks.holderBinding shouldBe Passed
                    result.checks.timeliness.outcome shouldBe Passed
                    result.checks.status.mechanisms.single().observed shouldBe TokenStatus.Valid
                    result.checks.disclosedItems.forEach { it.digest shouldBe Passed }
                }

                "an issuer of another authority is not trusted, and the status is not resolved then" {
                    val issuance = issuance()
                    val other = issuance()
                    val result = issuance.validate(other.issue(representation))

                    result.report.decision shouldBe REJECTED
                    result.credential.shouldBeNull()
                    result.checks.issuerTrust.outcome.shouldBeInstanceOf<Failed>()
                    result.checks.status.claim.shouldBeInstanceOf<Blocked>()
                    result.checks.status.mechanisms.shouldBeEmpty()
                }

                "without trust anchors trust is blocked, unless the policy only requires integrity" {
                    val issuance = issuance()
                    val issued = issuance.issue(representation)
                    val untrusting = CredentialValidator()

                    issuance.validate(issued, validator = untrusting).checks.issuerTrust.outcome
                        .shouldBeInstanceOf<Blocked>()
                    issuance.validate(issued, integrityOnly, untrusting).let {
                        it.report.decision shouldBe ACCEPTED
                        it.checks.issuerTrust.outcome shouldBe NotApplicable
                        it.checks.status.claim shouldBe NotApplicable
                    }
                }

                "a credential bound to another key fails holder binding, unless binding is not required" {
                    val issuance = issuance()
                    val issued = issuance.issue(representation)
                    val otherKey = CredentialValidationContext(expectedHolderKey = EphemeralKeyWithoutCert().publicKey)

                    issuance.validate(issued, context = otherKey).checks.holderBinding.shouldBeInstanceOf<Failed>()
                    issuance.validate(issued, holderBinding = HolderBindingPolicy.None, context = otherKey).let {
                        it.report.decision shouldBe ACCEPTED
                        it.checks.holderBinding shouldBe NotApplicable
                    }
                    issuance.validate(issued, context = CredentialValidationContext()).checks.holderBinding
                        .shouldBeInstanceOf<Blocked>()
                }

                "a credential of another type than expected fails semantics" {
                    val issuance = issuance()
                    val issued = issuance.issue(representation)
                    val result = issuance.validate(issued, context = issuance.context("urn:other"))

                    result.report.decision shouldBe REJECTED
                    result.checks.semantics.shouldBeInstanceOf<Failed>()
                }

                "a revoked credential fails its status" {
                    val issuance = issuance()
                    val issued = issuance.issue(representation)
                    val index = issued.status().shouldBeInstanceOf<StatusListInfo>().index
                    issuance.statusListAgent.revokeCredentialByIndex(FixedTimePeriodProvider.timePeriod, index)

                    val result = issuance.validate(issued)
                    result.report.decision shouldBe REJECTED
                    result.checks.status.mechanisms.single().observed shouldBe TokenStatus.Invalid
                }

                "an expired credential is accepted only if timeliness is not required, and its status is resolved" {
                    val issuance = issuance()
                    val issued = issuance.issue(representation)
                    val later = object : Clock {
                        override fun now(): Instant = Clock.System.now() + 1.days
                    }
                    val policy = strictPolicy.copy(
                        trust = TrustPolicy.IntegrityOnly,
                        status = StatusPolicy.RequireClaim(TrustPolicy.IntegrityOnly),
                    )

                    issuance.validate(issued, policy, issuance.validator(later)).let {
                        it.report.decision shouldBe REJECTED
                        it.checks.timeliness.outcome.shouldBeInstanceOf<Failed>()
                            .throwable.shouldBeInstanceOf<TimelinessException>()
                        it.checks.status.claim.shouldBeInstanceOf<Blocked>()
                    }
                    issuance.validate(issued, policy.copy(requireTimeliness = false), issuance.validator(later)).let {
                        it.checks.timeliness.outcome.shouldBeInstanceOf<Failed>()
                        it.checks.status.claim shouldBe Passed
                        it.checks.status.mechanisms.shouldNotBeEmpty()
                    }
                }

                "malformed input fails parsing and blocks everything else" {
                    val input = when (representation) {
                        CredentialRepresentation.PLAIN_JWT -> CredentialValidationInput.VcJwt("not a jws")
                        CredentialRepresentation.SD_JWT -> CredentialValidationInput.SdJwtVc("not an sd-jwt~")
                        CredentialRepresentation.ISO_MDOC -> CredentialValidationInput.IsoMdoc(byteArrayOf(1, 2, 3))
                    }
                    val result = issuance().validator().validate(input, strictPolicy, HolderBindingPolicy.None)

                    result.report.decision shouldBe REJECTED
                    result.checks.parsing.shouldBeInstanceOf<Failed>()
                    result.checks.issuerSignature.shouldBeInstanceOf<Blocked>()
                    result.checks.issuerTrust.outcome.shouldBeInstanceOf<Blocked>()
                }
            }
    }

    "VC-JWT and SD-JWT with a signature over another payload fail the signature" {
        val issuance = issuance()
        val vc = issuance.issue(CredentialRepresentation.PLAIN_JWT) as Issuer.IssuedCredential.VcJwt
        val otherVc = issuance.issue(CredentialRepresentation.PLAIN_JWT) as Issuer.IssuedCredential.VcJwt
        val forgedVc = vc.signedVcJws.jws.toString().withPayloadOf(otherVc.signedVcJws.jws.toString())
        issuance.validator().validate(CredentialValidationInput.VcJwt(forgedVc), strictPolicy, HolderBindingPolicy.None)
            .checks.let {
                it.issuerSignature.shouldBeInstanceOf<Failed>()
                it.semantics.shouldBeInstanceOf<Blocked>()
            }

        val sdJwt = issuance.issue(CredentialRepresentation.SD_JWT) as Issuer.IssuedCredential.VcSdJwt
        val otherSdJwt = issuance.issue(CredentialRepresentation.SD_JWT) as Issuer.IssuedCredential.VcSdJwt
        val forgedJws = sdJwt.signedSdJwtVc.jws.toString().withPayloadOf(otherSdJwt.signedSdJwtVc.jws.toString())
        val forgedSdJwt = sdJwt.signedSdJwtVc.serialize().replaceBefore("~", forgedJws)
        issuance.validator()
            .validate(CredentialValidationInput.SdJwtVc(forgedSdJwt), strictPolicy, HolderBindingPolicy.None)
            .checks.issuerSignature.shouldBeInstanceOf<Failed>()
    }

    "SD-JWT" - {
        suspend fun Issuance.sdJwt() = issue(CredentialRepresentation.SD_JWT) as Issuer.IssuedCredential.VcSdJwt

        suspend fun Issuance.validateSdJwt(compact: String) =
            validator().validate(
                CredentialValidationInput.SdJwtVc(compact),
                strictPolicy,
                HolderBindingPolicy.RequireExpectedKey,
                context(),
            )

        "every supplied disclosure is reported, and applied" {
            val issuance = issuance()
            val issued = issuance.sdJwt()
            val result = issuance.validateSdJwt(issued.signedSdJwtVc.serialize())

            result.checks.disclosedItems.size shouldBe issued.signedSdJwtVc.rawDisclosures.size
            result.credential.shouldBeInstanceOf<ValidatedCredential.SdJwtVc>().let {
                it.disclosures.keys shouldBe issued.signedSdJwtVc.rawDisclosures.toSet()
                it.reconstructedJsonObject.keys.contains("_sd") shouldBe false
            }
        }

        "a withheld disclosure is fine" {
            val issuance = issuance()
            val issued = issuance.sdJwt().signedSdJwtVc
            val withheld = (listOf(issued.jws.toString()) + issued.rawDisclosures.drop(1))
                .joinToString("~", postfix = "~")

            issuance.validateSdJwt(withheld).report.decision shouldBe ACCEPTED
        }

        "a disclosure the payload does not reference fails its digest, and can not disappear" {
            val issuance = issuance()
            val issued = issuance.sdJwt().signedSdJwtVc
            val unreferenced =
                SelectiveDisclosureItem(Random.nextBytes(16), "extra", JsonPrimitive("value")).toDisclosure()
            val result = issuance.validateSdJwt(issued.serialize() + "$unreferenced~")

            result.report.decision shouldBe REJECTED
            result.checks.disclosedItems.last().let {
                it.parsing shouldBe Passed
                it.digest.shouldBeInstanceOf<Failed>()
            }
        }

        "a malformed disclosure fails parsing, the others are still checked" {
            val issuance = issuance()
            val issued = issuance.sdJwt().signedSdJwtVc
            val result = issuance.validateSdJwt(issued.serialize() + "bm90IGFuIGFycmF5~")

            result.report.decision shouldBe REJECTED
            result.checks.disclosedItems.last().parsing.shouldBeInstanceOf<Failed>()
            result.checks.disclosedItems.dropLast(1).forEach { it.digest shouldBe Passed }
        }

        "a disclosure supplied twice fails its structure" {
            val issuance = issuance()
            val issued = issuance.sdJwt().signedSdJwtVc
            val result = issuance.validateSdJwt(issued.serialize() + "${issued.rawDisclosures.first()}~")

            result.report.decision shouldBe REJECTED
            result.checks.disclosedItems.last().structure.shouldBeInstanceOf<Failed>()
        }

        "a key binding JWT on an issued credential fails parsing" {
            val issuance = issuance()
            val issued = issuance.sdJwt().signedSdJwtVc
            val kb = issued.jws.toString()

            issuance.validateSdJwt(issued.serialize() + kb).checks.parsing.shouldBeInstanceOf<Failed>()
        }

        "the legacy type vc+sd-jwt fails parsing" {
            val issuance = issuance()
            val issued = issuance.sdJwt().signedSdJwtVc
            val legacy = issued.jws.patchHeader { put("typ", JsonPrimitive("vc+sd-jwt")) }
            val compact = (listOf(legacy.toString()) + issued.rawDisclosures).joinToString("~", postfix = "~")

            issuance.validateSdJwt(compact).checks.parsing.shouldBeInstanceOf<Failed>()
        }
    }

    "ISO mdoc" - {
        suspend fun Issuance.mdoc() =
            (issue(CredentialRepresentation.ISO_MDOC) as Issuer.IssuedCredential.Iso).issuerSigned

        suspend fun Issuance.validateMdoc(issuerSigned: IssuerSigned) = validator().validate(
            CredentialValidationInput.IsoMdoc(coseCompliantSerializer.encodeToByteArray(issuerSigned)),
            strictPolicy,
            HolderBindingPolicy.RequireExpectedKey,
            context(),
        )

        fun IssuerSigned.items() = namespaces.shouldNotBeNull().mapValues { (_, list) -> list.entries.map { it.value } }

        fun IssuerSigned.mapItems(transform: (List<IssuerSignedItem>) -> List<IssuerSignedItem>) =
            IssuerSigned.fromIssuerSignedItems(items().mapValues { (_, items) -> transform(items) }, issuerAuth)

        "every supplied item is reported" {
            val issuance = issuance()
            val issuerSigned = issuance.mdoc()
            val result = issuance.validateMdoc(issuerSigned)

            result.report.decision shouldBe ACCEPTED
            result.checks.disclosedItems.size shouldBe issuerSigned.items().values.sumOf { it.size }
        }

        "a withheld item is fine" {
            val issuance = issuance()
            issuance.validateMdoc(issuance.mdoc().mapItems { it.drop(1) }).report.decision shouldBe ACCEPTED
        }

        "an item that does not match its digest fails" {
            val issuance = issuance()
            val changed = issuance.mdoc().mapItems { items ->
                items.mapIndexed { i, item -> if (i == 0) item.copy(random = Random.nextBytes(16)) else item }
            }
            val result = issuance.validateMdoc(changed)

            result.report.decision shouldBe REJECTED
            result.checks.disclosedItems.first().digest.shouldBeInstanceOf<Failed>()
        }

        "an item supplied twice fails its structure" {
            val issuance = issuance()
            val result = issuance.validateMdoc(issuance.mdoc().mapItems { it + it.first() })

            result.report.decision shouldBe REJECTED
            result.checks.disclosedItems.last().structure.shouldBeInstanceOf<Failed>()
        }

        "a signature of another MSO fails the signature" {
            val issuance = issuance()
            val issuerSigned = issuance.mdoc()
            val other = issuance.mdoc()
            val forged = IssuerSigned.fromIssuerSignedItems(
                namespacedItems = issuerSigned.items(),
                issuerAuth = CoseSigned.create(
                    protectedHeader = issuerSigned.issuerAuth.protectedHeader,
                    unprotectedHeader = issuerSigned.issuerAuth.unprotectedHeader,
                    payload = issuerSigned.issuerAuth.payload,
                    signature = other.issuerAuth.signature,
                    payloadSerializer = MobileSecurityObject.serializer(),
                ),
            )

            issuance.validateMdoc(forged).checks.issuerSignature.shouldBeInstanceOf<Failed>()
        }
    }
}
