package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.CryptoPublicKey
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.ElementValue
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import kotlinx.datetime.Clock
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes

class DummyCredentialDataProvider(
    private val clock: Clock = Clock.System,
) : IssuerCredentialDataProvider {

    private val defaultLifetime = 1.minutes

    override fun getCredentialWithType(
        subjectId: String,
        subjectPublicKey: CryptoPublicKey?,
        attributeTypes: Collection<String>,
        representation: ConstantIndex.CredentialRepresentation
    ): KmmResult<List<CredentialToBeIssued>> {
        val attributeType = ConstantIndex.AtomicAttribute2023.vcType
        if (!attributeTypes.contains(attributeType)) {
            return KmmResult.failure(UnsupportedOperationException("no data"))
        }
        val expiration = clock.now() + defaultLifetime
        val claims = listOf(
            ClaimToBeIssued("given-name", "Susanne"),
            ClaimToBeIssued("family-name", "Meier"),
            ClaimToBeIssued("date-of-birth", "1990-01-01"),
        )
        val credentials = when (representation) {
            ConstantIndex.CredentialRepresentation.SD_JWT -> listOf(
                CredentialToBeIssued.VcSd(
                    subjectId = subjectId,
                    claims = claims,
                    expiration = expiration,
                    scheme = ConstantIndex.AtomicAttribute2023,
                )
            )

            ConstantIndex.CredentialRepresentation.PLAIN_JWT -> claims.map { claim ->
                CredentialToBeIssued.Vc(
                    subject = AtomicAttribute2023(subjectId, claim.name, claim.value),
                    expiration = expiration,
                    scheme = ConstantIndex.AtomicAttribute2023
                )
            } + CredentialToBeIssued.Vc(
                subject = AtomicAttribute2023(subjectId, "picture", "foo"),
                expiration = expiration,
                scheme = ConstantIndex.AtomicAttribute2023,
                attachments = listOf(Issuer.Attachment("picture", "image/webp", byteArrayOf(32)))
            )

            ConstantIndex.CredentialRepresentation.ISO_MDOC -> listOf(
                CredentialToBeIssued.Iso(
                    issuerSignedItems = claims.mapIndexed { index, claim ->
                        buildIssuerSignedItem(claim.name, claim.value, index.toUInt())
                    },
                    subjectPublicKey = subjectPublicKey!!.toCoseKey(),
                    expiration = expiration,
                    scheme = ConstantIndex.AtomicAttribute2023
                )
            )
        }
        return KmmResult.success(credentials)
    }

    private fun buildIssuerSignedItem(elementIdentifier: String, elementValue: String, digestId: UInt) =
        IssuerSignedItem(
            digestId = digestId,
            random = Random.nextBytes(16),
            elementIdentifier = elementIdentifier,
            elementValue = ElementValue(string = elementValue)
        )
}
