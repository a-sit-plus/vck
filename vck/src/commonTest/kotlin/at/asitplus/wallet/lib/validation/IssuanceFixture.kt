package at.asitplus.wallet.lib.validation

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.InMemoryIssuerCredentialStore
import at.asitplus.wallet.lib.agent.Issuer.IssuedCredential
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.StatusListAgent
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.StatusListJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import at.asitplus.wallet.lib.data.rfc3986.toUri
import io.kotest.matchers.nulls.shouldNotBeNull
import kotlinx.serialization.encodeToByteArray
import kotlin.time.Clock

internal val scheme = ConstantIndex.AtomicAttribute2023

/** An issuer and a status list issuer, each with a certificate of their own authority, and a holder. */
internal class Issuance(
    val issuerCa: TestCertificateAuthority,
    val statusCa: TestCertificateAuthority,
) {
    val holderKey = EphemeralKeyWithoutCert()
    private val store = InMemoryIssuerCredentialStore()
    lateinit var statusListAgent: StatusListAgent
    lateinit var issuer: IssuerAgent

    suspend fun setUp() = apply {
        statusListAgent = StatusListAgent(keyMaterial = statusCa.issue(), issuerCredentialStore = store)
        issuer = IssuerAgent(
            keyMaterial = issuerCa.issue(),
            issuerCredentialStore = store,
            identifier = "https://issuer.example.com/".toUri(),
            statusListAgent = statusListAgent,
        )
    }

    val trustAnchors
        get() = CredentialTrustScopes(
            CredentialTrustScope(
                credentialIdentifiers = setOf(scheme.sdJwtType, scheme.isoDocType),
                source = "test issuers",
                issuance = { setOf(issuerCa.certificate) },
                status = { setOf(statusCa.certificate) },
            )
        )

    val statusTokens
        get() = StatusListTokenResolver { StatusListJwt(statusListAgent.issueStatusListJwt(), Clock.System.now()) }

    fun validator(clock: Clock = Clock.System) = CredentialValidator(
        trustAnchors = trustAnchors,
        statusValidator = StatusValidator(statusTokens),
        clock = clock,
    )

    suspend fun issue(representation: CredentialRepresentation): IssuedCredential = issuer.issueCredential(
        DummyCredentialDataProvider.getCredential(holderKey.publicKey, scheme, representation).getOrThrow()
    ).getOrThrow()

    fun context(identifier: String? = null) =
        CredentialValidationContext(expectedHolderKey = holderKey.publicKey, expectedCredentialIdentifier = identifier)
}

internal suspend fun issuance() = Issuance(TestCertificateAuthority(), TestCertificateAuthority()).setUp()

internal fun IssuedCredential.input(): CredentialValidationInput = when (this) {
    is IssuedCredential.VcJwt -> CredentialValidationInput.VcJwt(signedVcJws.jws.toString())
    is IssuedCredential.VcSdJwt -> CredentialValidationInput.SdJwtVc(signedSdJwtVc.serialize())
    is IssuedCredential.Iso -> CredentialValidationInput.IsoMdoc(coseCompliantSerializer.encodeToByteArray(issuerSigned))
}

internal fun IssuedCredential.status(): RevocationListInfo = when (this) {
    is IssuedCredential.VcJwt -> vc.credentialStatus
    is IssuedCredential.VcSdJwt -> sdJwtVc.statusElement
    is IssuedCredential.Iso -> issuerSigned.issuerAuth.payload?.status
}.shouldNotBeNull()
