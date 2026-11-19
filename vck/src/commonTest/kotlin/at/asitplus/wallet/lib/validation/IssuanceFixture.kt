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
import at.asitplus.wallet.lib.data.VerifiableCredential
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import io.kotest.matchers.nulls.shouldNotBeNull
import kotlin.time.Clock
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.JsonObject

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

    /**
     * A validator trusting only the authorities of another issuance, so that it rejects the credentials of this one for
     * their untrusted issuer and status list signer, although they are intact.
     */
    suspend fun untrustingValidator() = issuance().validator()

    suspend fun issue(representation: CredentialRepresentation): IssuedCredential = issuer.issueCredential(
        DummyCredentialDataProvider.getCredential(holderKey.publicKey, scheme, representation).getOrThrow()
    ).getOrThrow()

    fun context(identifier: String? = null) = CredentialValidationContext(
        expectedHolderKeys = setOf(holderKey.publicKey),
        expectedCredentialIdentifier = identifier,
    )
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

/** The issued SD-JWT with every disclosure, its issuer-signed payload changed by [change] and signed again. */
internal suspend fun Issuance.sdJwtWithPayload(change: (JsonObject) -> JsonObject): String {
    val issued = (issue(CredentialRepresentation.SD_JWT) as IssuedCredential.VcSdJwt).signedSdJwtVc
    val jws = SignJwt<JsonObject>(issuer.keyMaterial, JwsHeaderCertOrJwk())(
        JwsContentTypeConstants.SD_JWT,
        change(issued.jws.getPayload<JsonObject>().getOrThrow()),
        JsonObject.serializer(),
    ).getOrThrow().jws
    return (listOf(jws.toString()) + issued.rawDisclosures).joinToString("~", postfix = "~")
}

/** The issued VC-JWT, its credential changed by [vc] and then its JWT claims by [jwt], signed again. */
internal suspend fun Issuance.vcJwtWithPayload(
    vc: (VerifiableCredential) -> VerifiableCredential = { it },
    jwt: (VerifiableCredentialJws) -> VerifiableCredentialJws = { it },
): String {
    val issued = (issue(CredentialRepresentation.PLAIN_JWT) as IssuedCredential.VcJwt).signedVcJws.payload
    return SignJwt<VerifiableCredentialJws>(issuer.keyMaterial, JwsHeaderCertOrJwk())(
        JwsContentTypeConstants.JWT,
        jwt(issued.copy(vc = vc(issued.vc))),
        VerifiableCredentialJws.serializer(),
    ).getOrThrow().jws.toString()
}
