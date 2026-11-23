package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.StatusListCwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.validation.CredentialValidator
import at.asitplus.wallet.lib.validation.StatusValidator
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking

val AgentIsoMdocIdentifierListTest by matrixSuite {

    fixture { runBlocking { createIsoMdocFixture(IsoRevocationMode.IDENTIFIER_LIST, StatusListTokenFormat.CWT) } } - {
        "identifier list: status info is encoded on issued ISO_MDOC credential" {
            val issuedCredential = it.issuer.issueIdentifierListIsoMdoc(it.holderKeyMaterial.publicKey)

            issuedCredential.issuedIdentifierListInfo().apply {
                identifier.isNotEmpty() shouldBe true
                uri.string shouldContain "/identifier/"
            }
        }

        "identifier list: identifiers are unique across issued ISO_MDOC credentials" {
            val first = it.issuer.issueIdentifierListIsoMdoc(it.holderKeyMaterial.publicKey)
                .issuedIdentifierListInfo().identifier
            val second = it.issuer.issueIdentifierListIsoMdoc(it.holderKeyMaterial.publicKey)
                .issuedIdentifierListInfo().identifier

            first.contentEquals(second) shouldBe false
        }

        "identifier list: issuing CWT token yields IdentifierList payload" {
            val statusInfo = it.issuer.issueIdentifierListIsoMdoc(it.holderKeyMaterial.publicKey)
                .issuedIdentifierListInfo()

            StatusListCwt(
                value = it.statusListIssuer.issueStatusListCwt(kind = RevocationList.Kind.IDENTIFIER_LIST),
                resolvedAt = null,
            ).parsedPayload.getOrThrow().apply {
                revocationList.shouldBeInstanceOf<IdentifierList>()
                subject shouldBe statusInfo.uri
            }
        }

        "identifier list: revoking one credential keeps non-revoked credential valid" {
            val secondHolderKeyMaterial = EphemeralKeyWithSelfSignedCert()
            val secondHolder = HolderAgent(
                secondHolderKeyMaterial,
                InMemorySubjectCredentialStore(),
            ).also { holder ->
                holder.storeCredential(
                    it.issuer.issueIdentifierListIsoMdoc(secondHolderKeyMaterial.publicKey)
                        .toStoreCredentialInput()
                ).getOrThrow()
            }

            val firstVp = it.createDcqlDeviceResponse(CLAIM_GIVEN_NAME)
            val secondRequest = it.verifier.createPresentationRequest(
                calcIsoSessionTranscript = qrSessionTranscript,
            )
            val secondVp = PresentedIsoResponse(
                request = secondRequest,
                response = createDcqlDeviceResponse(
                    holder = secondHolder,
                    request = secondRequest,
                    attributeNames = arrayOf(CLAIM_GIVEN_NAME),
                ),
            )

            it.revokeSingleStoredCredential() shouldBe true

            val verifyPresentation = it.verifyPresentation(firstVp)
            verifyPresentation.presentation.shouldBeNull()
            verifyPresentation.observedStatus shouldBe TokenStatus.Invalid
            it.verifyPresentation(secondVp).assertPresentedClaims(expectDateOfBirth = false)
        }

        "identifier list: verifier rejects presentation when resolver returns status list token" {
            val vp = it.createDcqlDeviceResponse(CLAIM_GIVEN_NAME)

            val mismatchedValidator = CredentialValidator(
                statusValidator = StatusValidator({ url ->
                    StatusListCwt(
                        value = it.statusListIssuer.issueStatusListCwt(kind = RevocationList.Kind.STATUS_LIST),
                        resolvedAt = null,
                    )
                }),
            )

            it.verifyPresentation(vp, mismatchedValidator).apply {
                presentation.shouldBeNull()
                observedStatus.shouldBeNull()
            }
        }
    }
}

private fun Issuer.IssuedCredential.Iso.issuedIdentifierListInfo(): IdentifierListInfo =
    issuerSigned.issuerAuth.payload.shouldNotBeNull().status.shouldNotBeNull().shouldBeInstanceOf<IdentifierListInfo>()

private suspend fun IssuerAgent.issueIdentifierListIsoMdoc(subjectPublicKey: CryptoPublicKey) = issueCredential(
    DummyCredentialDataProvider.getCredential(
        subjectPublicKey = subjectPublicKey,
        credentialScheme = ConstantIndex.AtomicAttribute2023,
        representation = ISO_MDOC,
        revocationKind = RevocationList.Kind.IDENTIFIER_LIST,
    ).getOrThrow()
).getOrThrow().shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()
