package at.asitplus.wallet.lib.oidvci

import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.HolderKeyResolver
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.CredentialChecks
import at.asitplus.wallet.lib.validation.CredentialValidationInput
import at.asitplus.wallet.lib.validation.HolderBindingPolicy
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidationDecision
import at.asitplus.wallet.lib.validation.ValidationPolicy
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.time.Duration

val ReceivedCredentialHolderBindingTest by matrixSuite {
    listOf(true, false).asData(nameFn = { "holder binding required: $it" }) - { bindingRequired ->
        listOf(HolderBindingPolicy.None, HolderBindingPolicy.RequireExpectedKey, HolderBindingPolicy.RequireNoKey)
            .asData(nameFn = { "caller policy: $it" }) - { callerBinding ->
                listOf("unbound", "proof key", "foreign key").asData(nameFn = { "response: $it" }) test { binding ->
                    val proofKey = EphemeralKeyWithoutCert()
                    val responseKey = when (binding) {
                        "proof key" -> proofKey
                        "foreign key" -> EphemeralKeyWithoutCert()
                        else -> null
                    }
                    val signed = SignJwt<JsonObject>(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk())(
                        type = JwsContentTypeConstants.SD_JWT,
                        payload = buildJsonObject {
                            put("iss", "https://issuer.example.com")
                            put("vct", AtomicAttribute2023.sdJwtType)
                            responseKey?.let { key ->
                                put("cnf", buildJsonObject {
                                    put("jwk", joseCompliantSerializer.encodeToJsonElement(
                                        JsonWebKey.serializer(), key.jsonWebKey
                                    ))
                                })
                            }
                        },
                        serializer = JsonObject.serializer(),
                    ).getOrThrow()
                    val holder = HolderAgent(holderKeyResolver = HolderKeyResolver.single(proofKey))
                    val received = ReceivedCredential.Decoded(
                        input = CredentialValidationInput.SdJwtVc("${signed.jws}~"),
                        proofKeys = if (bindingRequired) setOf(proofKey.publicKey) else emptySet(),
                        holderBindingRequired = bindingRequired,
                    )

                    val prepared = received.prepareCredentialStorage(
                        holder = holder,
                        scheme = AtomicAttribute2023,
                        policy = ValidationPolicy(
                            trust = TrustPolicy.IntegrityOnly,
                            status = StatusPolicy.Skip,
                            timeLeeway = Duration.ZERO,
                            requireTimeliness = false,
                            holderBinding = callerBinding,
                        ),
                    ).getOrThrow()

                    val accepted = if (bindingRequired) binding == "proof key" else binding == "unbound"
                    val outcome = prepared.validation.report.checks.shouldBeInstanceOf<CredentialChecks>().holderBinding
                    if (accepted) {
                        outcome shouldBe CheckOutcome.Passed
                        prepared.validation.report.decision shouldBe ValidationDecision.ACCEPTED
                        holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldNotBeNull()
                    } else {
                        outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
                        holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldBeNull()
                        holder.storeAfterUserConsent(prepared).isFailure shouldBe true
                    }
                }
            }
    }
}
