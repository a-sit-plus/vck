package at.asitplus.wallet.lib.agent

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.StatusListCwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.rfc3986.toUri
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf


val AgentIsoIdentifierMdocTest by testSuite {

    withFixtureGenerator(suspend {
        val issuerCredentialStore = InMemoryIssuerCredentialStore()
        val issuer = IssuerAgent(
            keyMaterial = EphemeralKeyWithSelfSignedCert(),
            issuerCredentialStore = issuerCredentialStore,
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )
        val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
        val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
        object {
            val holderKeyMaterial = holderKeyMaterial
            val issuer = issuer
            val statusListIssuer = statusListIssuer
        }
    }) - {
        "identifier list: status info is encoded on issued ISO_MDOC credential" {
            val issuedCredential = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    revocationKind = RevocationList.Kind.IDENTIFIER_LIST,
                ).getOrThrow()
            ).getOrThrow().shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()

            val statusInfo = issuedCredential.issuedIdentifierListInfo()
            statusInfo.identifier.isNotEmpty() shouldBe true
            statusInfo.uri.string shouldContain "/identifier/"
        }

        "identifier list: identifiers are unique across issued ISO_MDOC credentials" {
            val first = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    revocationKind = RevocationList.Kind.IDENTIFIER_LIST,
                ).getOrThrow()
            ).getOrThrow().shouldBeInstanceOf<Issuer.IssuedCredential.Iso>().issuedIdentifierListInfo().identifier
            val second = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    revocationKind = RevocationList.Kind.IDENTIFIER_LIST,
                ).getOrThrow()
            ).getOrThrow().shouldBeInstanceOf<Issuer.IssuedCredential.Iso>().issuedIdentifierListInfo().identifier

            first.contentEquals(second) shouldBe false
        }

        "identifier list: issuing CWT token yields IdentifierList payload" {
            val payload = StatusListCwt(
                value = it.statusListIssuer.issueStatusListCwt(kind = RevocationList.Kind.IDENTIFIER_LIST),
                resolvedAt = null,
            ).parsedPayload.getOrThrow()

            payload.revocationList.shouldBeInstanceOf<IdentifierList>()
            payload.subject.string shouldContain "/identifier/"
        }
    }
}

private fun Issuer.IssuedCredential.Iso.issuedIdentifierListInfo(): IdentifierListInfo =
    issuerSigned.issuerAuth.payload.shouldNotBeNull().status.shouldNotBeNull().shouldBeInstanceOf<IdentifierListInfo>()
