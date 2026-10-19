package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.validation.issuance
import at.asitplus.wallet.lib.validation.scheme
import at.asitplus.wallet.lib.validation.strictPolicy
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToByteArray

val SubjectCredentialStoreTest by matrixSuite {

    val renewalInfo = CredentialRenewalInfo(
        refreshToken = "refresh-token",
        issuerMetadata = IssuerMetadata(
            credentialIssuer = "https://issuer.example.com/",
            credentialEndpointUrl = "https://issuer.example.com/credential",
            supportedCredentialConfigurations = mapOf(),
        ),
        oauthMetadata = OAuth2AuthorizationServerMetadata(issuer = "https://issuer.example.com/"),
        credentialFormat = SupportedCredentialFormat.forSdJwt(
            scope = scheme.sdJwtType,
            sdJwtVcType = scheme.sdJwtType,
            sdJwtClaims = setOf(),
        ),
        credentialIdentifier = scheme.sdJwtType,
    )

    "storing" - {
        listOf(CredentialRepresentation.PLAIN_JWT, CredentialRepresentation.SD_JWT, CredentialRepresentation.ISO_MDOC)
            .asData(nameFn = { "$it" }) - { representation ->

                "the holder stores the entry built from the prepared credential" {
                    val issuance = issuance()
                    val store = InMemorySubjectCredentialStore()
                    val holder = HolderAgent(issuance.holderKey, store, credentialValidator = issuance.validator())
                    val prepared = holder.prepareCredentialStorage(
                        issuance.issue(representation).toStoreCredentialInput(),
                        strictPolicy,
                        renewalInfo,
                    ).getOrThrow()

                    val stored = holder.storeAccepted(prepared).getOrThrow().storedEntry.shouldNotBeNull()

                    stored shouldBe StoreEntry.fromPreparedCredential(prepared).getOrThrow()
                    stored.renewalInfo shouldBe renewalInfo
                    stored.issuer.shouldNotBeNull()
                    stored.resolveScheme() shouldBe scheme
                    store.getCredentials().getOrThrow().shouldContainExactly(stored)
                }

                "the entry of a credential that is not intact can not be built" {
                    val issuance = issuance()
                    val holder = HolderAgent(EphemeralKeyWithoutCert(), credentialValidator = issuance.validator())
                    val prepared = holder.prepareCredentialStorage(
                        issuance.issue(representation).toStoreCredentialInput(),
                        strictPolicy,
                    ).getOrThrow()

                    prepared.validation.unacceptedCredential.shouldBeNull()
                    StoreEntry.fromPreparedCredential(prepared).isFailure.shouldBeTrue()
                }

                "parsing the serialized credential gives the stored entry" {
                    val issuance = issuance()
                    val holder = HolderAgent(issuance.holderKey, credentialValidator = issuance.validator())
                    val stored = holder.storeCredentialWithReport(
                        issuance.issue(representation).toStoreCredentialInput(),
                        strictPolicy,
                    ).getOrThrow().storedEntry.shouldNotBeNull()

                    val parsed = when (stored) {
                        is StoreEntry.Vc -> StoreEntry.Vc.fromString(stored.vcSerialized)
                        is StoreEntry.SdJwt -> StoreEntry.SdJwt.fromString(stored.vcSerialized)
                        // As an mdoc is issued in OpenID4VCI 1.0, A.2.4
                        is StoreEntry.Iso -> StoreEntry.Iso.fromString(
                            coseCompliantSerializer.encodeToByteArray(stored.issuerSigned).encodeToString(Base64UrlStrict)
                        )
                    }

                    parsed.getOrThrow() shouldBe stored
                }
            }

        "the deprecated methods store through storeCredential(StoreEntry)" {
            val issuance = issuance()
            val store = EntryOnlyStore()
            val sdJwt = issuance.issue(CredentialRepresentation.SD_JWT)
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>()
            val iso = issuance.issue(CredentialRepresentation.ISO_MDOC)
                .shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()
            val vc = issuance.issue(CredentialRepresentation.PLAIN_JWT)
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            @Suppress("DEPRECATION")
            val stored = listOf(
                store.storeCredential(vc.signedVcJws.payload, vc.signedVcJws.toString(), scheme, renewalInfo),
                store.storeCredential(
                    sdJwt.signedSdJwtVc.jws.getPayload<VerifiableCredentialSdJwt>().getOrThrow(),
                    sdJwt.signedSdJwtVc.serialize(),
                    mapOf(),
                    scheme,
                ),
                store.storeCredential(iso.issuerSigned, scheme),
            )

            store.entries shouldBe stored
            stored[0].shouldBeInstanceOf<StoreEntry.Vc>().renewalInfo shouldBe renewalInfo
            stored[1].shouldBeInstanceOf<StoreEntry.SdJwt>().schemeIdentifier shouldBe scheme.sdJwtType
            stored[2].shouldBeInstanceOf<StoreEntry.Iso>().schemeIdentifier shouldBe scheme.isoDocType
        }
    }
}

/** Implements only what a store has to implement. */
private class EntryOnlyStore : SubjectCredentialStore {
    val entries = mutableListOf<StoreEntry>()

    override suspend fun storeCredential(entry: StoreEntry): KmmResult<StoreEntry> =
        catching { entry.also { entries += it } }

    override suspend fun getCredentials(credentialSchemes: Collection<CredentialScheme>?) =
        catching { entries.toList() }
}
