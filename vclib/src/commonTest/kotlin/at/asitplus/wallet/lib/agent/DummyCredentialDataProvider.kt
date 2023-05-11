package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.AtomicAttributeCredential
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
        val attributeType = ConstantIndex.Generic.vcType
        if (!attributeTypes.contains(attributeType)) {
            return KmmResult.failure(UnsupportedOperationException("no data"))
        }
        val expiration = clock.now() + defaultLifetime
        return KmmResult.success(
            listOf(
                IssuerCredentialDataProvider.CredentialToBeIssued(
                    AtomicAttributeCredential(subjectId, "given-name", "Susanne"),
                    expiration,
                    attributeType,
                ),
                IssuerCredentialDataProvider.CredentialToBeIssued(
                    AtomicAttributeCredential(subjectId, "family-name", "Meier"),
                    expiration,
                    attributeType,
                ),
                IssuerCredentialDataProvider.CredentialToBeIssued(
                    AtomicAttributeCredential(subjectId, "date-of-birth", "1990-01-01"),
                    expiration,
                    attributeType,
                ),
                IssuerCredentialDataProvider.CredentialToBeIssued(
                    AtomicAttributeCredential(subjectId, "identifier", randomValue()),
                    expiration,
                    attributeType,
                ),
                IssuerCredentialDataProvider.CredentialToBeIssued(
                    AtomicAttributeCredential(subjectId, "picture", randomValue()),
                    expiration,
                    attributeType,
                    listOf(Issuer.Attachment("picture", "image/webp", byteArrayOf(32)))
                )
            )
        )
    }

    private fun randomValue() = Random.nextBytes(32).encodeBase16()

}
