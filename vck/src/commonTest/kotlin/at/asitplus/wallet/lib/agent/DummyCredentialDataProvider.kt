package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_PORTRAIT
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import kotlinx.datetime.Clock
import kotlinx.datetime.LocalDate
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
        val expiration = clock.now() + defaultLifetime
        val claims = claimNames?.map {
            ClaimToBeIssued(it, "${it}_DUMMY_VALUE")
        } ?: listOf(
            ClaimToBeIssued(CLAIM_GIVEN_NAME, "Susanne"),
            ClaimToBeIssued(CLAIM_FAMILY_NAME, "Meier"),
            ClaimToBeIssued(CLAIM_DATE_OF_BIRTH, LocalDate.parse("1990-01-01")),
            ClaimToBeIssued(CLAIM_PORTRAIT, Random.nextBytes(32)),
        )
        val subjectId = subjectPublicKey.didEncoded
        when (representation) {
            ConstantIndex.CredentialRepresentation.SD_JWT -> CredentialToBeIssued.VcSd(
                claims = claims,
                expiration = expiration,
            )

            ConstantIndex.CredentialRepresentation.PLAIN_JWT -> CredentialToBeIssued.VcJwt(
                subject = AtomicAttribute2023(subjectId, CLAIM_GIVEN_NAME, "Susanne"),
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
