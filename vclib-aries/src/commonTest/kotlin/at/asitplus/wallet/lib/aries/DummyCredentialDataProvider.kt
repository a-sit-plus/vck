package at.asitplus.wallet.lib.aries

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.Issuer
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
    ): KmmResult<List<CredentialToBeIssued>> {
        if (credentialScheme != ConstantIndex.AtomicAttribute2023) {
            return KmmResult.failure(UnsupportedOperationException("no data"))
        }
        val subjectId = subjectPublicKey.didEncoded
        val expiration = clock.now() + defaultLifetime
        val claims = listOf(
            ClaimToBeIssued("given-name", "Susanne"),
            ClaimToBeIssued("family-name", "Meier"),
            ClaimToBeIssued("date-of-birth", "1990-01-01"),
        )
        val credentials = when (representation) {
            ConstantIndex.CredentialRepresentation.SD_JWT -> listOf(
                CredentialToBeIssued.VcSd(
                    claims = claims,
                    expiration = expiration,
                )
            )

            ConstantIndex.CredentialRepresentation.PLAIN_JWT -> claims.map { claim ->
                CredentialToBeIssued.VcJwt(
                    subject = AtomicAttribute2023(subjectId, claim.name, claim.value.toString()),
                    expiration = expiration,
                )
            } + CredentialToBeIssued.VcJwt(
                subject = AtomicAttribute2023(subjectId, "picture", "foo"),
                expiration = expiration,
                attachments = listOf(Issuer.Attachment("picture", "image/webp", byteArrayOf(32)))
            )

            ConstantIndex.CredentialRepresentation.ISO_MDOC -> listOf(
                CredentialToBeIssued.Iso(
                    issuerSignedItems = claims.mapIndexed { index, claim ->
                        issuerSignedItem(claim.name, claim.value, index.toUInt())
                    },
                    expiration = expiration,
                )
            )
        }
        return KmmResult.success(credentials)
    }

    private fun issuerSignedItem(name: String, value: Any, digestId: UInt) =
        IssuerSignedItem(
            digestId = digestId,
            random = Random.nextBytes(16),
            elementIdentifier = name,
            elementValue = value
        )
}
