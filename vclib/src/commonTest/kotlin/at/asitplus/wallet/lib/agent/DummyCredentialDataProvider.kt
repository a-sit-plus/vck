package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.ElementValue
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
    ): KmmResult<List<CredentialToBeIssued>> {
        val expiration = clock.now() + defaultLifetime
        val claims = listOf(
            ClaimToBeIssued("given-name", "Susanne"),
            ClaimToBeIssued("family-name", "Meier"),
            ClaimToBeIssued("date-of-birth", "1990-01-01"),
        )
        val subjectId = subjectPublicKey.toJsonWebKey().getOrNull()!!.identifier
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
            elementValue = when (value) {
                is String -> ElementValue(string = value)
                is ByteArray -> ElementValue(bytes = value)
                is LocalDate -> ElementValue(date = value)
                is Boolean -> ElementValue(boolean = value)
                else -> ElementValue(string = value.toString())
            }
        )
}
