package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerCredentialDataProvider
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import io.matthewnelson.component.encoding.base16.encodeBase16
import kotlinx.datetime.Clock
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes

class DummyCredentialDataProvider(
    private val clock: Clock = Clock.System,
) : IssuerCredentialDataProvider {

    private val defaultLifetime = 1.minutes

    override fun getCredentialWithType(
        subjectId: String,
        attributeTypes: Collection<String>
    ): KmmResult<List<IssuerCredentialDataProvider.CredentialToBeIssued>> {
        val attributeType = ConstantIndex.AtomicAttribute2023.vcType
        if (!attributeTypes.contains(attributeType)) {
            return KmmResult.failure(UnsupportedOperationException("no data"))
        }
        val expiration = clock.now() + defaultLifetime
        return KmmResult.success(
            listOf(
                IssuerCredentialDataProvider.CredentialToBeIssued(
                    AtomicAttribute2023(subjectId, "given-name", "Susanne"),
                    expiration,
                    attributeType,
                ),
                IssuerCredentialDataProvider.CredentialToBeIssued(
                    AtomicAttribute2023(subjectId, "family-name", "Meier"),
                    expiration,
                    attributeType,
                ),
                IssuerCredentialDataProvider.CredentialToBeIssued(
                    AtomicAttribute2023(subjectId, "date-of-birth", "1990-01-01"),
                    expiration,
                    attributeType,
                ),
                IssuerCredentialDataProvider.CredentialToBeIssued(
                    AtomicAttribute2023(subjectId, "identifier", randomValue()),
                    expiration,
                    attributeType,
                ),
                IssuerCredentialDataProvider.CredentialToBeIssued(
                    AtomicAttribute2023(subjectId, "picture", randomValue()),
                    expiration,
                    attributeType,
                    listOf(Issuer.Attachment("picture", "image/webp", byteArrayOf(32)))
                )
            )
        )
    }

    private fun randomValue() = Random.nextBytes(32).encodeBase16()

}
