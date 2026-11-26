package at.asitplus.wallet.lib.agent

import at.asitplus.iso.CborCredentialSerializer
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueIsoMdoc
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issuePlainJwt
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.rfc3986.toUri
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.LocalDate
import kotlinx.serialization.builtins.ByteArraySerializer

val StoreEntryHolderKeyTest by matrixSuite {

    fixture {
        object {
            val issuer = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                issuerCredentialStore = InMemoryIssuerCredentialStore(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val holder = HolderAgent(holderKeyMaterial)

            suspend fun vcEntry() = holder.storeCredential(
                issuePlainJwt(issuer, holderKeyMaterial).shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()
                    .toStoreCredentialInput()
            ).getOrThrow().shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.Vc>()

            suspend fun vcWith(transform: (VerifiableCredentialJws) -> VerifiableCredentialJws) =
                vcEntry().let { it.copy(vc = transform(it.vc)) }
        }
    }- {

        test("SD-JWT VC: the key in cnf") {
            val entry = it.holder.storeCredential(
                issueSdJwt(it.issuer, it.holderKeyMaterial).shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>()
                    .toStoreCredentialInput()
            ).getOrThrow().shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.SdJwt>()

            entry.holderKey() shouldBe it.holderKeyMaterial.publicKey
            entry.isHolderBound() shouldBe true
            entry.copy(sdJwt = entry.sdJwt.copy(confirmationClaim = null)).let { unbound ->
                unbound.holderKey().shouldBeNull()
                unbound.isHolderBound() shouldBe false
            }
        }

        "SD-JWT VC: a cnf without a key by value is holder-bound, without a holder key" - { fixture ->
            listOf(
                "kid" to ConfirmationClaim(keyId = "holder-key-1"),
                "jku" to ConfirmationClaim(jsonWebKeySetUrl = "https://issuer.example.com/jwks"),
                "jkt" to ConfirmationClaim(
                    jsonWebKeyThumbprint = EphemeralKeyWithoutCert().publicKey.toJsonWebKey().jwkThumbprint
                ),
            ).asData(nameFn = { "cnf with ${it.first}" }) test { (_, cnf) ->
                val entry = fixture.holder.storeCredential(
                    issueSdJwt(fixture.issuer, fixture.holderKeyMaterial)
                        .shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>().toStoreCredentialInput()
                ).getOrThrow().shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.SdJwt>()

                val bound = entry.copy(sdJwt = entry.sdJwt.copy(confirmationClaim = cnf))
                bound.isHolderBound() shouldBe true
                bound.holderKey().shouldBeNull()
            }
        }

        test("ISO mdoc: the deviceKey") {
            CborCredentialSerializer.register(
                mapOf(
                    ConstantIndex.AtomicAttribute2023.CLAIM_PORTRAIT to ByteArraySerializer(),
                    ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH to LocalDate.serializer(),
                ),
                ConstantIndex.AtomicAttribute2023.isoNamespace
            )
            val entry = it.holder.storeCredential(
                issueIsoMdoc(it.issuer, it.holderKeyMaterial).shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()
                    .toStoreCredentialInput()
            ).getOrThrow().shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.Iso>()

            entry.holderKey() shouldBe it.holderKeyMaterial.publicKey
            entry.isHolderBound() shouldBe true
        }

        test("VC-JWT: the did:key in sub") {
            it.vcEntry().let { entry ->
                entry.holderKey() shouldBe it.holderKeyMaterial.publicKey
                entry.isHolderBound() shouldBe true
            }
        }

        "VC-JWT: a sub that is no did:key is no key binding" - { fixture ->
            listOf<Pair<String, (KeyMaterial) -> String?>>(
                "the JWK thumbprint of the holder key" to { key -> key.jsonWebKey.jwkThumbprint },
                "an https URI" to { "https://holder.example.com/" },
                "absent" to { null },
            ).asData(nameFn = { "sub is ${it.first}" }) test { (_, subOf) ->
                fixture.vcWith { vc -> vc.copy(subject = subOf(fixture.holderKeyMaterial)) }.let { entry ->
                    entry.holderKey().shouldBeNull()
                    entry.isHolderBound() shouldBe false
                }
            }
        }

        test("VC-JWT: a did:key in sub that can't be decoded is holder-bound, without a holder key") {
            it.vcWith { vc -> vc.copy(subject = "did:key:invalid") }.let { entry ->
                entry.isHolderBound() shouldBe true
                entry.holderKey().shouldBeNull()
            }
        }
    }
}
