package at.asitplus.wallet.lib.oidc

import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

@Suppress("unused")
class OidcSiopWalletScopeSupportTest : FreeSpec({
    "specified well known scopes" - {
        // no scopes with a mapping to a presentation definition are known yet
        val wellKnownScopePresentationDefinitionRetriever =
            mapOf<String, PresentationDefinition>()::get
    }

    "test scopes" - {
        val testScopes = object {
            val EmptyPresentationRequest: String = "emptyPresentationRequest"
            val MdocMdlWithGivenName: String = "mdocMdlWithGivenName"
        }
        val testScopePresentationDefinitionRetriever = mapOf(
            testScopes.EmptyPresentationRequest to PresentationDefinition(
                id = uuid4().toString(),
                inputDescriptors = listOf()
            ),
            testScopes.MdocMdlWithGivenName to PresentationDefinition(
                id = uuid4().toString(),
                inputDescriptors = listOf(
                    DifInputDescriptor(
                        id = MobileDrivingLicenceScheme.isoDocType,
                        constraints = Constraint(
                            fields = listOf(
                                ConstraintField(
                                    path = listOf(
                                        NormalizedJsonPath(
                                            NormalizedJsonPathSegment.NameSegment(MobileDrivingLicenceScheme.isoNamespace),
                                            NormalizedJsonPathSegment.NameSegment(MobileDrivingLicenceDataElements.GIVEN_NAME),
                                        ).toString()
                                    ),
                                )
                            )
                        ),
                    )
                )
            ),
        )::get

        lateinit var relyingPartyUrl: String

        lateinit var holderKeyMaterial: KeyMaterial
        lateinit var verifierKeyMaterial: KeyMaterial

        lateinit var holderAgent: Holder
        lateinit var verifierAgent: Verifier

        lateinit var holderSiop: OidcSiopWallet
        lateinit var verifierSiop: OidcSiopVerifier

        beforeEach {
            holderKeyMaterial = EphemeralKeyWithoutCert()
            verifierKeyMaterial = EphemeralKeyWithoutCert()
            relyingPartyUrl = "https://example.com/rp/${uuid4()}"
            holderAgent = HolderAgent(holderKeyMaterial)
            verifierAgent = VerifierAgent(verifierKeyMaterial)

            holderSiop = OidcSiopWallet(
                keyMaterial = holderKeyMaterial,
                holder = holderAgent,
                scopePresentationDefinitionRetriever = testScopePresentationDefinitionRetriever
            )
            verifierSiop = OidcSiopVerifier(
                keyMaterial = verifierKeyMaterial,
                relyingPartyUrl = relyingPartyUrl,
            )
        }

        "get empty scope works even without available credentials" {
            val issuerAgent = IssuerAgent(
                EphemeralKeyWithSelfSignedCert(),
                DummyCredentialDataProvider(),
            )
            holderAgent.storeCredential(
                issuerAgent.issueCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
                ).getOrThrow().toStoreCredentialInput()
            )

            val authnRequest = verifierSiop.createAuthnRequest().let { request ->
                request.copy(
                    presentationDefinition = null,
                    scope = request.scope + " " + testScopes.EmptyPresentationRequest
                )
            }

            val authnResponse = holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
            authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>().also { println(it) }

            val result = verifierSiop.validateAuthnResponse(authnResponse.url)
            result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.VerifiablePresentationValidationResults>()
            result.validationResults.shouldBeEmpty()
        }

        "get MdocMdlWithGivenName scope without available credentials fails" {
            val authnRequest = verifierSiop.createAuthnRequest().let { request ->
                request.copy(
                    presentationDefinition = null,
                    scope = request.scope + " " + testScopes.MdocMdlWithGivenName
                )
            }

            val authnResponse = holderSiop.createAuthnResponse(authnRequest.serialize())
            authnResponse.isFailure shouldBe true
            shouldThrow<OAuth2Exception> {
                authnResponse.getOrThrow()
            }
        }

        "get MdocMdlWithGivenName scope with available credentials succeeds" {
            val issuerAgent = IssuerAgent(
                EphemeralKeyWithSelfSignedCert(),
                DummyCredentialDataProvider(),
            )
            holderAgent.storeCredential(
                issuerAgent.issueCredential(
                    holderKeyMaterial.publicKey,
                    MobileDrivingLicenceScheme,
                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
                ).getOrThrow().toStoreCredentialInput()
            )


            val authnRequest = verifierSiop.createAuthnRequest().let { request ->
                request.copy(
                    presentationDefinition = null,
                    scope = request.scope + " " + testScopes.MdocMdlWithGivenName
                )
            }

            val authnResponse = holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
            authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>().also { println(it) }

            val result = verifierSiop.validateAuthnResponse(authnResponse.url)
            result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessIso>()
            result.document.validItems.shouldNotBeEmpty()
        }
    }
})