package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.SubjectAltNameImplicitTags
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

class OpenId4VpX509SanDnsTest : FreeSpec({

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var verifierOid4vp: OpenId4VpVerifier

    beforeEach {
        val clientId = "example.com"
        val extensions = listOf(
            X509CertificateExtension(
                KnownOIDs.subjectAltName_2_5_29_17,
                critical = false,
                Asn1EncapsulatingOctetString(
                    listOf(
                        Asn1.Sequence {
                            +Asn1Primitive(
                                SubjectAltNameImplicitTags.dNSName,
                                Asn1String.UTF8(clientId).encodeToTlv().content
                            )
                        }
                    ))))
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithSelfSignedCert(extensions = extensions)
        holderAgent = HolderAgent(holderKeyMaterial)
        holderAgent.storeCredential(
            IssuerAgent().issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.SD_JWT,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )

        holderOid4vp = OpenId4VpHolder(
            keyMaterial = holderKeyMaterial,
            holder = holderAgent,
        )
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.CertificateSanDns(listOf(verifierKeyMaterial.getCertificate()!!), clientId),
        )
    }

    "test with Fragment" {
        val authnRequest = verifierOid4vp.createAuthnRequestAsSignedRequestObject(
            requestOptions = RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(
                        ConstantIndex.AtomicAttribute2023,
                        ConstantIndex.CredentialRepresentation.SD_JWT,
                        setOf(CLAIM_GIVEN_NAME)
                    )
                ),
                responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                responseUrl = "https://example.com/response",
            )
        ).getOrThrow()

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
        result.shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
        result.reconstructed[CLAIM_GIVEN_NAME].shouldNotBeNull()

    }
})