package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.CborCredentialSerializer
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.LocalDate
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToString

class StoreEntrySerializationTest : FreeSpec({

    lateinit var issuer: Issuer
    lateinit var holder: Holder
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var holderCredentialStore: SubjectCredentialStore

    beforeEach {
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        holderCredentialStore = InMemorySubjectCredentialStore()
        issuer = IssuerAgent(EphemeralKeyWithSelfSignedCert(), issuerCredentialStore)
        holderKeyMaterial = EphemeralKeyWithoutCert()
        holder = HolderAgent(holderKeyMaterial, holderCredentialStore)
    }

    "serialize stored VC" {
        val credentials = issuer.issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ).getOrThrow()
        ).getOrThrow()
            .shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

        val entry = holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
            .shouldBeInstanceOf<Holder.StoredCredential.Vc>()
            .storeEntry

        val serialized = vckJsonSerializer.encodeToString(entry)

        vckJsonSerializer.decodeFromString<SubjectCredentialStore.StoreEntry.Vc>(serialized) shouldBe entry

    }

    "serialize stored SD-JWT" {
        val credentials = issuer.issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.SD_JWT,
            ).getOrThrow()
        ).getOrThrow()
            .shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>()

        val entry = holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
            .shouldBeInstanceOf<Holder.StoredCredential.SdJwt>()
            .storeEntry

        val serialized = vckJsonSerializer.encodeToString(entry)

        vckJsonSerializer.decodeFromString<SubjectCredentialStore.StoreEntry.SdJwt>(serialized) shouldBe entry
    }

    "serialize stored ISO mDoc" {
        CborCredentialSerializer.register(
            mapOf(
                ConstantIndex.AtomicAttribute2023.CLAIM_PORTRAIT to ByteArraySerializer(),
                ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH to LocalDate.serializer(),
            ),
            ConstantIndex.AtomicAttribute2023.isoNamespace
        )
        val credentials = issuer.issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.ISO_MDOC,
            ).getOrThrow()
        ).getOrThrow()
            .shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()

        val entry = holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
            .shouldBeInstanceOf<Holder.StoredCredential.Iso>()
            .storeEntry

        val serialized = vckJsonSerializer.encodeToString(entry)

        vckJsonSerializer.decodeFromString<SubjectCredentialStore.StoreEntry.Iso>(serialized) shouldBe entry
    }

})
