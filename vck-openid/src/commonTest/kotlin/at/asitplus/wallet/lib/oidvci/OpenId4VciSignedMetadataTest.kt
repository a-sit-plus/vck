package at.asitplus.wallet.lib.oidvci

import at.asitplus.etsi.relyingParty.WrpCredential
import at.asitplus.etsi.relyingParty.WrpCredentialMeta
import at.asitplus.etsi.relyingParty.WrpIdentifier
import at.asitplus.etsi.relyingParty.WrpMultiLangString
import at.asitplus.etsi.relyingParty.WrpRegistrarDataset
import at.asitplus.openid.IssuerInfo
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OpenIdConstants.IssuerInfo.REGISTRAR_DATASET_FORMAT
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.ReceivedHttpResponse
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oauth2.FakeHttpStack
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oauth2.received
import at.asitplus.wallet.lib.oauth2.scripted
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.IssuerMetadataChecks
import at.asitplus.wallet.lib.validation.IssuerMetadataValidator
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import at.asitplus.wallet.lib.validation.ValidationPolicy
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

val OpenId4VciSignedMetadataTest by matrixSuite {

    "signed metadata are requested over unsigned ones, and validated" {
        val signing = SigningIssuer()
        val http = signing.metadataEndpoint()

        val loaded = http.execute(signing.client().loadIssuerMetadata(ISSUER, strictPolicy))

        http.sent.single().http.headers[HttpHeaders.Accept].shouldNotBeNull() shouldContain MediaTypes.Application.JWT
        loaded.shouldBeInstanceOf<LoadedIssuerMetadata.Signed>().validation.apply {
            report.decision shouldBe ACCEPTED
            issuer.shouldNotBeNull().registrarDataset.registryURI shouldBe REGISTRY
        }
        loaded.metadata.shouldNotBeNull().credentialIssuer shouldBe ISSUER
    }

    "credential configurations of signed metadata carry the validated issuer, also when serialized" {
        val signing = SigningIssuer()
        val client = signing.client()
        val loaded = signing.metadataEndpoint().execute(client.loadIssuerMetadata(ISSUER, strictPolicy))

        val info = client.parseCredentialMetadata(loaded).getOrThrow().first()

        info.issuer.shouldNotBeNull().registrarDataset.registryURI shouldBe REGISTRY
        val serialized = joseCompliantSerializer.encodeToString(CredentialIdentifierInfo.serializer(), info)
        joseCompliantSerializer.decodeFromString(CredentialIdentifierInfo.serializer(), serialized) shouldBe info
    }

    "credential configurations of unsigned metadata carry no issuer, rejected signed metadata none at all" {
        val signing = SigningIssuer()
        val unsigned = FakeHttpStack(scripted(jsonResponse(signing.server.metadata)))
            .execute(signing.client().loadIssuerMetadata(ISSUER, strictPolicy))
        val untrusting = OpenId4VciProtocolClient(
            issuerMetadataValidator = IssuerMetadataValidator(accessCertificates = { emptySet() }),
        )
        val rejected = signing.metadataEndpoint().execute(untrusting.loadIssuerMetadata(ISSUER, strictPolicy))

        signing.client().parseCredentialMetadata(unsigned).getOrThrow().first().issuer.shouldBeNull()
        untrusting.parseCredentialMetadata(rejected).isFailure shouldBe true
    }

    "signed metadata of an untrusted issuer are rejected, or reported for a warning" {
        val signing = SigningIssuer()
        val http = signing.metadataEndpoint()
        val client = OpenId4VciProtocolClient(
            issuerMetadataValidator = IssuerMetadataValidator(accessCertificates = { emptySet() }),
        )

        http.execute(client.loadIssuerMetadata(ISSUER, strictPolicy)).apply {
            shouldBeInstanceOf<LoadedIssuerMetadata.Signed>().validation.report.decision shouldBe REJECTED
            metadata.shouldBeNull()
        }
        http.execute(client.loadIssuerMetadata(ISSUER, strictPolicy.copy(trust = TrustPolicy.IntegrityOnly))).apply {
            shouldBeInstanceOf<LoadedIssuerMetadata.Signed>().validation.report.checks
                .shouldBeInstanceOf<IssuerMetadataChecks>().trust.outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
            metadata.shouldNotBeNull()
        }
    }

    "unsigned metadata are returned as such, if they are of the requested credential issuer" {
        val signing = SigningIssuer()
        val unsigned = jsonResponse(signing.server.metadata)

        FakeHttpStack(scripted(unsigned)).execute(signing.client().loadIssuerMetadata(ISSUER, strictPolicy))
            .shouldBeInstanceOf<LoadedIssuerMetadata.Unsigned>().metadata.credentialIssuer shouldBe ISSUER
        shouldThrow<IllegalArgumentException> {
            FakeHttpStack(scripted(unsigned))
                .execute(signing.client().loadIssuerMetadata("https://other.example.com", strictPolicy))
        }
    }

    "metadata without a supported media type are rejected" {
        val signing = SigningIssuer()
        val body = joseCompliantSerializer.encodeToString(IssuerMetadata.serializer(), signing.server.metadata)

        shouldThrow<IllegalArgumentException> {
            FakeHttpStack(scripted(ReceivedHttpResponse(HttpStatusCode.OK, Headers.Empty, body)))
                .execute(signing.client().loadIssuerMetadata(ISSUER, strictPolicy))
        }
        shouldThrow<IllegalArgumentException> {
            FakeHttpStack(scripted(ReceivedHttpResponse(HttpStatusCode.OK, contentType("text/html"), body)))
                .execute(signing.client().loadIssuerMetadata(ISSUER, strictPolicy))
        }
    }

    "the legacy method asks for unsigned metadata, and rejects those of another credential issuer" {
        val signing = SigningIssuer()
        val http = signing.metadataEndpoint()

        http.execute(signing.client().loadIssuerMetadata(ISSUER)).credentialIssuer shouldBe ISSUER
        http.sent.single().http.headers[HttpHeaders.Accept] shouldBe MediaTypes.Application.JSON
        shouldThrow<IllegalArgumentException> {
            FakeHttpStack(scripted(jsonResponse(signing.server.metadata)))
                .execute(signing.client().loadIssuerMetadata("https://other.example.com"))
        }
    }
}

private const val ISSUER = "https://issuer.example.com"
private const val REGISTRY = "https://registrar.example.com"

private val strictPolicy = ValidationPolicy(
    trust = TrustPolicy.RequireAuthorizedSigner,
    status = StatusPolicy.Skip,
    timeLeeway = 5.minutes,
    requireTimeliness = true,
)

private fun contentType(value: String) = headersOf(HttpHeaders.ContentType, value)

private fun jsonResponse(metadata: IssuerMetadata) = ReceivedHttpResponse(
    HttpStatusCode.OK,
    contentType(MediaTypes.Application.JSON),
    joseCompliantSerializer.encodeToString(IssuerMetadata.serializer(), metadata),
)

/**
 * A credential issuer signing its metadata with an access certificate (WRPAC) of [provider], with its registration
 * information in `issuer_info` (ETSI TS 119 472-3 V1.1.1, 4.2).
 */
private class SigningIssuer private constructor(
    private val provider: TestCertificateAuthority,
    accessKey: KeyMaterial,
    accessCertificate: X509Certificate,
) {
    val server = OpenId4VciServer(
        authorizationService = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(AttributeIndex.schemeSet),
            publicContext = ISSUER,
        ),
        issuer = IssuerAgent(identifier = ISSUER.toUri()),
        credentialSchemes = AttributeIndex.schemeSet,
        publicContext = ISSUER,
        signMetadata = SignJwt(accessKey, { header, _ -> header.copy(certificateChain = listOf(accessCertificate)) }),
        issuerInfo = listOf(
            IssuerInfo(
                format = REGISTRAR_DATASET_FORMAT,
                data = joseCompliantSerializer.encodeToJsonElement(
                    WrpRegistrarDataset.serializer(),
                    WrpRegistrarDataset(
                        identifier = listOf(WrpIdentifier("http://data.europa.eu/eudi/id/LEI", "LEI-ISSUER")),
                        srvDescription = listOf(WrpMultiLangString("en", "Issues PIDs")),
                        registryURI = REGISTRY,
                        providesAttestations = listOf(
                            WrpCredential("dc+sd-jwt", WrpCredentialMeta(vctValues = listOf("urn:eudi:pid:1")))
                        ),
                    ),
                ),
            )
        ),
    )

    /** Serves the metadata as the well-known endpoint does, signed if asked for (OpenID4VCI 1.0, 12.2.2). */
    fun metadataEndpoint() = FakeHttpStack {
        server.metadataHttpResponse(it.headers[HttpHeaders.Accept]).getOrThrow().received()
    }

    /** Trusts the WRPAC provider of this issuer. */
    fun client() = OpenId4VciProtocolClient(
        issuerMetadataValidator = IssuerMetadataValidator(accessCertificates = TrustedCertificates {
            setOf(provider.certificate)
        }),
    )

    companion object {
        suspend operator fun invoke(): SigningIssuer {
            val providerKey = EphemeralKeyWithoutCert()
            val provider = TestCertificateAuthority(name = PROVIDER_NAME, key = providerKey)
            val accessKey = EphemeralKeyWithoutCert()
            return SigningIssuer(provider, accessKey, accessCertificate(providerKey, accessKey))
        }

        private const val PROVIDER_NAME = "WRPAC Provider"

        /** A WRPAC issued by [providerKey], with the identifier of a legal person (ETSI TS 119 475 V1.2.1, 5.1.2). */
        private suspend fun accessCertificate(providerKey: KeyMaterial, accessKey: KeyMaterial): X509Certificate {
            val algorithm = providerKey.signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow()
            val notBefore = Clock.System.now().truncateToSeconds()
            val tbsCertificate = TbsCertificate(
                version = 2,
                serialNumber = Random.nextBytes(8),
                issuerName = listOf(
                    RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(PROVIDER_NAME)))
                ),
                subjectName = listOf(
                    RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8("PID Provider"))),
                    RelativeDistinguishedName(
                        AttributeTypeAndValue.Other(ObjectIdentifier("2.5.4.97"), Asn1String.UTF8("LEIXG-ISSUER")),
                    ),
                ),
                validFrom = Asn1Time(notBefore),
                validUntil = Asn1Time(notBefore + 30.days),
                signatureAlgorithm = algorithm,
                publicKey = accessKey.publicKey,
            )
            val signature = providerKey.sign(tbsCertificate.encodeToDer()).asKmmResult().getOrThrow()
            return X509Certificate(tbsCertificate, algorithm, signature)
        }
    }
}
