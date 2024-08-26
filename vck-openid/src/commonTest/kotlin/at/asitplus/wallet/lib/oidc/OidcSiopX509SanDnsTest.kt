package at.asitplus.wallet.lib.oidc

import at.asitplus.signum.indispensable.asn1.Asn1
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.pki.SubjectAltNameImplicitTags
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyPairAdapter
import at.asitplus.wallet.lib.agent.RandomKeyPairAdapter
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.RequestOptions
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf

class OidcSiopX509SanDnsTest : FreeSpec({

    lateinit var responseUrl: String
    lateinit var walletUrl: String

    lateinit var holderKeyPair: KeyPairAdapter
    lateinit var verifierKeyPair: KeyPairAdapter

    lateinit var holderAgent: Holder
    lateinit var verifierAgent: Verifier

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        val extensions = listOf(X509CertificateExtension(
            KnownOIDs.subjectAltName_2_5_29_17,
            critical = false,
            Asn1EncapsulatingOctetString(listOf(
                Asn1.Sequence {
                    +Asn1Primitive(
                        SubjectAltNameImplicitTags.dNSName,
                        Asn1String.UTF8("example.com").encodeToTlv().content
                    )
                }
            ))))
        holderKeyPair = RandomKeyPairAdapter()
        verifierKeyPair = RandomKeyPairAdapter(extensions)
        responseUrl = "https://example.com"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyPair)
        verifierAgent = VerifierAgent(verifierKeyPair)
        holderAgent.storeCredential(
            IssuerAgent(
                RandomKeyPairAdapter(),
                DummyCredentialDataProvider(),
            ).issueCredential(
                holderKeyPair.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.SD_JWT,
            ).getOrThrow().toStoreCredentialInput()
        )

        holderSiop = OidcSiopWallet(
            keyPairAdapter = holderKeyPair,
            holder = holderAgent,
        )
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            relyingPartyUrl = null,
            responseUrl = responseUrl,
            x5c = listOf(verifierKeyPair.certificate!!)
        )
    }

    "test with Fragment" {
        val authnRequest = verifierSiop.createAuthnRequestAsSignedRequestObject(
            requestOptions = RequestOptions(
                representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                responseMode = OpenIdConstants.ResponseMode.DIRECT_POST_JWT,
                requestedAttributes = listOf("given_name")
            )
        ).also { println(it) }.getOrThrow()

        val authnResponse = holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>().also { println(it) }

        val result = verifierSiop.validateAuthnResponseFromPost(authnResponse.params.formUrlEncode())
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt>()
        result.disclosures.shouldNotBeEmpty()

    }
})

