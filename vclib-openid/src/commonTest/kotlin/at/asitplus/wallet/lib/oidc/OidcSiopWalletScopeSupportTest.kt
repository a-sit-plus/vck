package at.asitplus.wallet.lib.oidc

import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyPairAdapter
import at.asitplus.wallet.lib.agent.RandomKeyPairAdapter
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.dif.Constraint
import at.asitplus.wallet.lib.data.dif.ConstraintField
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.dif.SchemaReference
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
                    InputDescriptor(
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
                        schema = listOf(
                            SchemaReference(MobileDrivingLicenceScheme.schemaUri)
                        )
                    )
                )
            ),
        )::get

        lateinit var relyingPartyUrl: String

        lateinit var holderKeyPair: KeyPairAdapter
        lateinit var verifierKeyPair: KeyPairAdapter

        lateinit var holderAgent: Holder
        lateinit var verifierAgent: Verifier

        lateinit var holderSiop: OidcSiopWallet
        lateinit var verifierSiop: OidcSiopVerifier

        beforeEach {
            holderKeyPair = RandomKeyPairAdapter()
            verifierKeyPair = RandomKeyPairAdapter()
            relyingPartyUrl = "https://example.com/rp/${uuid4()}"
            holderAgent = HolderAgent(holderKeyPair)
            verifierAgent = VerifierAgent(verifierKeyPair)

            holderSiop = OidcSiopWallet.newDefaultInstance(
                keyPairAdapter = holderKeyPair,
                holder = holderAgent,
                scopePresentationDefinitionRetriever = testScopePresentationDefinitionRetriever
            )
            verifierSiop = OidcSiopVerifier.newInstance(
                verifier = verifierAgent,
                relyingPartyUrl = relyingPartyUrl,
            )
        }

        "get empty scope works even without available credentials" {
            val issuerAgent = IssuerAgent(
                RandomKeyPairAdapter(),
                DummyCredentialDataProvider(),
            )
            holderAgent.storeCredentials(
                issuerAgent.issueCredential(
                    holderKeyPair.publicKey,
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
                RandomKeyPairAdapter(),
                DummyCredentialDataProvider(),
            )
            holderAgent.storeCredentials(
                issuerAgent.issueCredential(
                    holderKeyPair.publicKey,
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