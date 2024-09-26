package at.asitplus.wallet.lib.oidc

import at.asitplus.openid.OpenIdConstants
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.SubjectAltNameImplicitTags
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.wallet.lib.agent.*
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

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial

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
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithSelfSignedCert(extensions = extensions)
        responseUrl = "https://example.com"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)
        verifierAgent = VerifierAgent(verifierKeyMaterial)
        holderAgent.storeCredential(
            IssuerAgent(
                EphemeralKeyWithoutCert(),
                DummyCredentialDataProvider(),
            ).issueCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.SD_JWT,
            ).getOrThrow().toStoreCredentialInput()
        )

        holderSiop = OidcSiopWallet(
            keyMaterial = holderKeyMaterial,
            holder = holderAgent,
        )
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            responseUrl = responseUrl,
            clientIdScheme = OidcSiopVerifier.ClientIdScheme.CertificateSanDns(listOf(verifierKeyMaterial.getCertificate()!!)),
        )
    }

    "test with Fragment" {
        val authnRequest = verifierSiop.createAuthnRequestAsSignedRequestObject(
            requestOptions = RequestOptions(
                credentials = setOf(
                    OidcSiopVerifier.RequestOptionsCredential(
                        ConstantIndex.AtomicAttribute2023,
                        ConstantIndex.CredentialRepresentation.SD_JWT,
                        listOf("given_name")
                    )
                ),
                responseMode = OpenIdConstants.ResponseMode.DIRECT_POST_JWT,
            )
        ).also { println(it) }.getOrThrow()

        val authnResponse = holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>().also { println(it) }

        val result = verifierSiop.validateAuthnResponseFromPost(authnResponse.params.formUrlEncode())
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt>()
        result.disclosures.shouldNotBeEmpty()

    }
})

