package at.asitplus.wallet.lib.agent

import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.QesApprovalTestData.approvalJson
import at.asitplus.wallet.lib.agent.QesApprovalTestData.encodeTransactionData
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldEndWith
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.random.Random

val VerifiablePresentationFactoryUnboundSdJwtTest by matrixSuite {

    fixture {
        object {
            @Suppress("DEPRECATION")
            val factory = VerifiablePresentationFactory(EphemeralKeyWithoutCert())

            /** An SD-JWT VC without `cnf`, i.e. not holder-bound. */
            suspend fun unboundCredential(): SubjectCredentialStore.StoreEntry.SdJwt {
                val salt = Random.nextBytes(16).encodeToString(Base64UrlStrict)
                val disclosure = """["$salt", "family_name", "Musterfrau"]"""
                    .encodeToByteArray().encodeToString(Base64UrlStrict)
                val jws = SignJwt<JsonObject>(EphemeralKeyWithoutCert(), JwsHeaderNone())(
                    JwsContentTypeConstants.SD_JWT,
                    buildJsonObject {
                        put("vct", "https://example.com/credentials/unbound")
                        put("_sd", buildJsonArray { add(disclosure.hashDisclosure()) })
                        put("_sd_alg", "sha-256")
                    },
                    JsonObject.serializer(),
                ).getOrThrow()
                return SubjectCredentialStore.StoreEntry.SdJwt(
                    vcSerialized = "${jws.jws}~$disclosure~",
                    sdJwt = VerifiableCredentialSdJwt(verifiableCredentialType = "https://example.com/credentials/unbound"),
                    disclosures = mapOf(
                        disclosure to SelectiveDisclosureItem(
                            salt = salt.decodeToByteArray(Base64UrlStrict),
                            claimName = "family_name",
                            claimValue = JsonPrimitive("Musterfrau"),
                        )
                    ),
                    schemeIdentifier = "unbound",
                )
            }
        }
    } - {

        test("an SD-JWT VC without cnf is presented without KB-JWT") {
            val credential = it.unboundCredential()
            credential.holderKey().shouldBeNull()

            val presentation = it.factory.createVerifiablePresentation(
                request = PresentationRequestParameters(nonce = "nonce", audience = "https://verifier.example.com/"),
                credential = credential,
                disclosedAttributes = AllClaimsMatchingResult,
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            presentation.sdJwt.keyBindingJws.shouldBeNull()
            presentation.serialized shouldEndWith "~"
            presentation.sdJwt.rawDisclosures shouldBe credential.disclosures.keys.toList()
        }

        test("an SD-JWT VC without cnf can't be presented with transaction data") {
            it.factory.createVerifiablePresentation(
                request = PresentationRequestParameters(
                    nonce = "nonce",
                    audience = "https://verifier.example.com/",
                    transactionData = listOf(JsonPrimitive(encodeTransactionData(approvalJson(Digest.SHA256.oid.toString())))),
                ),
                credential = it.unboundCredential(),
                disclosedAttributes = AllClaimsMatchingResult,
            ).exceptionOrNull().shouldBeInstanceOf<PresentationException>()
        }

        test("an SD-JWT VC with a cnf without a key by value is never presented without KB-JWT") {
            val unbound = it.unboundCredential()
            val credential = unbound.copy(sdJwt = unbound.sdJwt.copy(confirmationClaim = ConfirmationClaim(keyId = "k1")))
            credential.isHolderBound() shouldBe true

            // Holder-bound, so either with a KB-JWT or not at all, as its key can't be read
            it.factory.createVerifiablePresentation(
                request = PresentationRequestParameters(nonce = "nonce", audience = "https://verifier.example.com/"),
                credential = credential,
                disclosedAttributes = AllClaimsMatchingResult,
            ).getOrNull()?.let { presentation ->
                presentation.shouldBeInstanceOf<CreatePresentationResult.SdJwt>().sdJwt.keyBindingJws.shouldNotBeNull()
            }
        }
    }
}
