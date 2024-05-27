package at.asitplus.wallet.lib.oidc

import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.pki.SubjectAltNameImplicitTags
import at.asitplus.crypto.datatypes.pki.X509CertificateExtension
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.RequestOptions
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking

class OidcSiopX509SanDnsTest : FreeSpec({

    lateinit var responseUrl: String
    lateinit var walletUrl: String

    lateinit var holderCryptoService: CryptoService
    lateinit var verifierCryptoService: CryptoService

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
        holderCryptoService = DefaultCryptoService()
        verifierCryptoService = DefaultCryptoService.withSelfSignedCert(extensions)
        responseUrl = "https://example.com"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent.newDefaultInstance(holderCryptoService)
        verifierAgent = VerifierAgent.newDefaultInstance(verifierCryptoService.publicKey)
        runBlocking {
            holderAgent.storeCredentials(
                IssuerAgent.newDefaultInstance(
                    DefaultCryptoService(),
                    dataProvider = DummyCredentialDataProvider(),
                ).issueCredential(
                    subjectPublicKey = holderCryptoService.publicKey,
                    attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                ).toStoreCredentialInput()
            )
        }

        holderSiop = OidcSiopWallet.newDefaultInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService
        )
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = null,
            responseUrl = responseUrl,
            x5c = listOf(verifierCryptoService.certificate!!)
        )
    }

    "test with Fragment" {
        val authnRequest = verifierSiop.createAuthnRequestAsSignedRequestObject(
            requestOptions = RequestOptions(
                representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                responseMode = OpenIdConstants.ResponseMode.DIRECT_POST_JWT,
                requestedAttributes = listOf("given-name")
            )
        ).also { println(it) }.getOrThrow()

        val authnResponse = holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>().also { println(it) }

        val result = verifierSiop.validateAuthnResponseFromPost(authnResponse.params.formUrlEncode())
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt>()
        result.disclosures.shouldNotBeEmpty()

    }
})

