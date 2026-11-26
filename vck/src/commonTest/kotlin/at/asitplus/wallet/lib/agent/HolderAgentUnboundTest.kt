package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.CredentialChecks
import at.asitplus.wallet.lib.validation.CredentialValidationInput
import at.asitplus.wallet.lib.validation.HolderBindingPolicy
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationPolicy
import at.asitplus.wallet.lib.validation.input
import at.asitplus.wallet.lib.validation.issuance
import at.asitplus.wallet.lib.validation.scheme
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds

/** Credentials of a configuration that requires no holder binding are stored only if they are bound to no key. */
val HolderAgentUnboundTest by matrixSuite {

    val noKey = ValidationPolicy(
        trust = TrustPolicy.RequireAuthorizedSigner,
        status = StatusPolicy.Skip,
        timeLeeway = 300.seconds,
        requireTimeliness = false,
        holderBinding = HolderBindingPolicy.RequireNoKey,
    )

    "an SD-JWT VC without cnf is stored, also by a holder with a resolver" {
        val issuance = issuance()
        val salt = Random.nextBytes(16).encodeToString(Base64UrlStrict)
        val disclosure = """["$salt", "family_name", "Musterfrau"]""".encodeToByteArray().encodeToString(Base64UrlStrict)
        val jws = SignJwt<JsonObject>(issuance.issuerCa.issue(), JwsHeaderCertOrJwk())(
            JwsContentTypeConstants.SD_JWT,
            buildJsonObject {
                put("vct", scheme.sdJwtType)
                put("_sd", buildJsonArray { add(disclosure.hashDisclosure()) })
                put("_sd_alg", "sha-256")
            },
            JsonObject.serializer(),
        ).getOrThrow()
        val holder = HolderAgent(
            holderKeyResolver = { error("No key is resolved for a credential without holder binding") },
            credentialValidator = issuance.validator(),
        )

        val prepared = holder.prepareCredentialStorage(
            CredentialValidationInput.SdJwtVc("${jws.jws}~$disclosure~"), scheme, noKey
        ).getOrThrow()

        prepared.validation.report.checks.shouldBeInstanceOf<CredentialChecks>().holderBinding shouldBe
                CheckOutcome.Passed
        prepared.validation.report.decision shouldBe ACCEPTED
        prepared.holderKey.shouldBeNull()
        holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldNotBeNull().holderKey().shouldBeNull()
        holder.getCredentials().shouldNotBeNull().shouldHaveSize(1)
    }

    listOf(CredentialRepresentation.PLAIN_JWT, CredentialRepresentation.SD_JWT, CredentialRepresentation.ISO_MDOC)
        .asData(nameFn = { "$it" }) - { representation ->

            "a credential bound to a key anyway is rejected and can't be stored" {
                val issuance = issuance()
                val holder = HolderAgent(issuance.holderKey, credentialValidator = issuance.validator())

                val prepared = holder.prepareCredentialStorage(issuance.issue(representation).input(), scheme, noKey)
                    .getOrThrow()

                prepared.validation.report.checks.shouldBeInstanceOf<CredentialChecks>().holderBinding
                    .shouldBeInstanceOf<CheckOutcome.Failed>()
                holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldBeNull()
                holder.storeAfterUserConsent(prepared).isFailure shouldBe true
            }
        }

    // A cnf that names its key instead of containing it still binds the SD-JWT VC to a key (SD-JWT VC, 2.2.2.3)
    listOf(
        "kid" to buildJsonObject { put("kid", "holder-key-1") },
        "jku" to buildJsonObject { put("jku", "https://issuer.example.com/jwks") },
        "jkt" to buildJsonObject { put("jkt", "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I") },
    ).asData(nameFn = { "an SD-JWT VC with a cnf by ${it.first} is rejected and can't be stored" }) test { (_, cnf) ->
        val issuance = issuance()
        val salt = Random.nextBytes(16).encodeToString(Base64UrlStrict)
        val disclosure = """["$salt", "family_name", "Musterfrau"]""".encodeToByteArray().encodeToString(Base64UrlStrict)
        val jws = SignJwt<JsonObject>(issuance.issuerCa.issue(), JwsHeaderCertOrJwk())(
            JwsContentTypeConstants.SD_JWT,
            buildJsonObject {
                put("vct", scheme.sdJwtType)
                put("_sd", buildJsonArray { add(disclosure.hashDisclosure()) })
                put("_sd_alg", "sha-256")
                put("cnf", cnf)
            },
            JsonObject.serializer(),
        ).getOrThrow()
        val holder = HolderAgent(
            holderKeyResolver = { error("No key is resolved for a credential that can't be stored") },
            credentialValidator = issuance.validator(),
        )

        val prepared = holder.prepareCredentialStorage(
            CredentialValidationInput.SdJwtVc("${jws.jws}~$disclosure~"), scheme, noKey
        ).getOrThrow()

        prepared.validation.report.checks.shouldBeInstanceOf<CredentialChecks>().holderBinding
            .shouldBeInstanceOf<CheckOutcome.Failed>()
        holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldBeNull()
        holder.storeAfterUserConsent(prepared).isFailure shouldBe true
        holder.getCredentials().shouldNotBeNull().shouldHaveSize(0)
    }
}
