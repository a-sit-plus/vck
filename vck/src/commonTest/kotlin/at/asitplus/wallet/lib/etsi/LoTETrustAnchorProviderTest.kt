package at.asitplus.wallet.lib.etsi

import at.asitplus.etsi.ListOfTrustedEntities
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.testballoon.matrix.matrixSuite
import com.goncalossilva.resources.Resource
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

/**
 * Lists of trusted entities from `etsi-data-classes/src/commonTest/resources/lote`, which `vck/build.gradle.kts` adds to
 * the test resources of this module.
 */
object LoTETestData {
    val pidProviders = Resource("lote/pid-providers-seq9.json").readText()
    val wrpacProviders = Resource("lote/wrpac-providers-seq2.json").readText()
}

private val json = Json { ignoreUnknownKeys = true }
private fun lote(jsonTxt: String) = json.decodeFromString<ListOfTrustedEntities>(jsonTxt)

private val pidLote = lote(LoTETestData.pidProviders)
private val wrpacLote = lote(LoTETestData.wrpacProviders)
private val filter = LoTEFilterService()

private fun issuanceCertsOf(lote: ListOfTrustedEntities, profile: LoteProfile) =
    filter.extractIssuanceCertificates(lote, profile).mapNotNull { it.certificate }

private fun certificateOf(
    lote: ListOfTrustedEntities,
    profile: LoteProfile,
    provider: String,
    kind: ServiceKind = ServiceKind.ISSUANCE,
): X509Certificate {
    val certs = when (kind) {
        ServiceKind.ISSUANCE -> filter.extractIssuanceCertificates(lote, profile)
        ServiceKind.REVOCATION -> filter.extractRevocationCertificates(lote, profile)
    }
    return certs.first { tc -> tc.providerName.any { it.value == provider } }.certificate!!
}

private val asitCert = certificateOf(pidLote, LoteProfile.PID, "A-SIT")
private val pidOnlyCert = certificateOf(pidLote, LoteProfile.PID, "PID Provider1")
private val wrpacOnlyCert = certificateOf(wrpacLote, LoteProfile.WRPAC, "Idakto")
private val referenceRevocationCert =
    certificateOf(pidLote, LoteProfile.PID, "Reference implementation TEST EU PID Provider", ServiceKind.REVOCATION)

private fun List<X509Certificate>.containsCert(cert: X509Certificate): Boolean {
    val der = cert.encodeToDer()
    return any { it.encodeToDer().contentEquals(der) }
}

private fun provider(
    lists: Collection<ListOfTrustedEntities> = listOf(pidLote, wrpacLote),
    trustListsFor: (suspend (String) -> Collection<ListOfTrustedEntities>)? = null,
) = trustListsFor?.let { LoTETrustAnchorProvider({ lists }, it) }
    ?: LoTETrustAnchorProvider(trustLists = { lists })

val LoTETrustAnchorProviderTest by matrixSuite {


    "profileOf detects the list from its metadata" {
        filter.profileOf(pidLote) shouldBe LoteProfile.PID
        filter.profileOf(wrpacLote) shouldBe LoteProfile.WRPAC
    }

    "the detecting overload equals the explicit one" {
        filter.extractIssuanceCertificates(pidLote) shouldBe
                filter.extractIssuanceCertificates(pidLote, LoteProfile.PID)
        filter.extractRevocationCertificates(pidLote) shouldBe
                filter.extractRevocationCertificates(pidLote, LoteProfile.PID)
    }

    "the explicit overload rejects a list of another profile" {
        filter.extractIssuanceCertificates(pidLote, LoteProfile.WRPAC) shouldBe emptyList()
    }

    "a PID resolves to the PID list" {
        provider().issuanceAnchors("urn:eudi:pid:1") shouldBe issuanceCertsOf(pidLote, LoteProfile.PID)
    }

    "PID anchors contain the PID providers and nothing from the WRPAC list" {
        val anchors = provider().issuanceAnchors("urn:eudi:pid:1")
        anchors.containsCert(asitCert) shouldBe true
        anchors.containsCert(pidOnlyCert) shouldBe true
        anchors.containsCert(wrpacOnlyCert) shouldBe false
    }

    "the other PID prefix resolves to the same list" {
        provider().issuanceAnchors("eu.europa.ec.eudi.pid.1") shouldBe
                provider().issuanceAnchors("urn:eudi:pid:1")
    }

    "an unknown credential identifier has no list, not even the Pub-EAA one" {
        LoteProfile.fromSchemeIdentifier("urn:example:loyalty-card:1") shouldBe null
        provider().issuanceAnchors("urn:example:loyalty-card:1") shouldBe emptyList()
        provider().revocationAnchors("urn:example:loyalty-card:1") shouldBe emptyList()
    }

    "credential identifiers select their list case-sensitively, the mDL docType exactly" {
        LoteProfile.fromSchemeIdentifier("urn:eudi:pid:1") shouldBe LoteProfile.PID
        LoteProfile.fromSchemeIdentifier("urn:eudi:pid:de:1") shouldBe LoteProfile.PID
        LoteProfile.fromSchemeIdentifier("eu.europa.ec.eudi.pid.1") shouldBe LoteProfile.PID
        LoteProfile.fromSchemeIdentifier("org.iso.18013.5.1.mDL") shouldBe LoteProfile.mDL
        LoteProfile.fromSchemeIdentifier("URN:EUDI:PID:1") shouldBe null
        LoteProfile.fromSchemeIdentifier("org.iso.18013.5.1.mdl") shouldBe null
        LoteProfile.fromSchemeIdentifier("org.iso.18013.5.1.mDLanything") shouldBe null
        LoteProfile.fromSchemeIdentifier("") shouldBe null
        LoteProfile.fromSchemeIdentifier(null) shouldBe null
    }

    "a custom trustListsFor overrides the default mapping" {
        val custom = provider(trustListsFor = { listOf(wrpacLote) })
        val anchors = custom.issuanceAnchors("urn:eudi:pid:1")
        anchors.containsCert(wrpacOnlyCert) shouldBe true
        anchors.containsCert(asitCert) shouldBe false
    }

    "a trustListsFor returning nothing yields no anchors" {
        provider(trustListsFor = { emptyList() }).issuanceAnchors("urn:eudi:pid:1") shouldBe emptyList()
    }

    "the PID revocation anchor is returned, although its certificate O is the TETradeName" {
        val anchors = provider().revocationAnchors("urn:eudi:pid:1")
        anchors.containsCert(referenceRevocationCert) shouldBe true
        anchors.size shouldBe 1 
    }

    "revocation anchors hold no issuance-only certificates and nothing from another list" {
        val anchors = provider().revocationAnchors("urn:eudi:pid:1")
        anchors.containsCert(asitCert) shouldBe false
        anchors.containsCert(pidOnlyCert) shouldBe false
        anchors.containsCert(wrpacOnlyCert) shouldBe false
    }

    "the WRPAC list has no revocation services" {
        provider().revocationAnchors(LoteProfile.WRPAC) shouldBe emptyList()
    }

    "the profile overload selects that list" {
        provider().issuanceAnchors(LoteProfile.WRPAC) shouldBe issuanceCertsOf(wrpacLote, LoteProfile.WRPAC)
    }

    "the profile overload yields nothing when no such list is configured" {
        provider(lists = listOf(pidLote)).issuanceAnchors(LoteProfile.WRPAC) shouldBe emptyList()
        provider(lists = listOf(pidLote)).revocationAnchors(LoteProfile.WALLET) shouldBe emptyList()
    }

    "without lists the result is empty" {
        provider(lists = emptyList()).issuanceAnchors("urn:eudi:pid:1") shouldBe emptyList()
    }
}