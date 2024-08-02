package at.asitplus.wallet.lib.aries

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.IssuerCredentialDataProvider
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import kotlinx.datetime.Clock
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes

class DummyCredentialDataProvider(
    private val clock: Clock = Clock.System,
) : IssuerCredentialDataProvider {

    private val defaultLifetime = 1.minutes

    override fun getCredential(
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        claimNames: Collection<String>?
    ): KmmResult<CredentialToBeIssued> = catching {
        if (credentialScheme != ConstantIndex.AtomicAttribute2023) {
            throw NotImplementedError()
        }
        val subjectId = subjectPublicKey.didEncoded
        val expiration = clock.now() + defaultLifetime
        val claims = listOf(
            ClaimToBeIssued("given_name", "Susanne"),
            ClaimToBeIssued("family_name", "Meier"),
            ClaimToBeIssued("date_of_birth", "1990-01-01"),
        )
        when (representation) {
            ConstantIndex.CredentialRepresentation.SD_JWT -> CredentialToBeIssued.VcSd(
                claims = claims,
                expiration = expiration,
            )

            ConstantIndex.CredentialRepresentation.PLAIN_JWT -> CredentialToBeIssued.VcJwt(
                subject = AtomicAttribute2023(subjectId, "given_name", "Susanne"),
                expiration = expiration,
            )

            ConstantIndex.CredentialRepresentation.ISO_MDOC -> CredentialToBeIssued.Iso(
                issuerSignedItems = claims.mapIndexed { index, claim ->
                    issuerSignedItem(claim.name, claim.value, index.toUInt())
                },
                expiration = expiration,
            )
        }
    }

    private fun issuerSignedItem(name: String, value: Any, digestId: UInt) =
        IssuerSignedItem(
            digestId = digestId,
            random = Random.nextBytes(16),
            elementIdentifier = name,
            elementValue = value
        )
}
