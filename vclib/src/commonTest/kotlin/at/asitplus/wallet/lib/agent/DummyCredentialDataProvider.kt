package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.AtomicAttributeCredential
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.SchemaIndex
import io.matthewnelson.component.encoding.base16.encodeBase16
import kotlinx.datetime.Clock
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes

class DummyCredentialDataProvider(
    private val clock: Clock = Clock.System,
) : IssuerCredentialDataProvider {

    private val defaultLifetime = 1.minutes

    override fun getClaim(subjectId: String, attributeName: String) =
        getClaimInt(subjectId, attributeName)?.let {
            KmmResult.success(
                IssuerCredentialDataProvider.CredentialToBeIssued(
                    it,
                    clock.now() + defaultLifetime,
                    ConstantIndex.Generic.vcType,
                    attachmentList(attributeName)
                )
            )
        } ?: KmmResult.failure(UnsupportedOperationException("no data"))

    private fun attachmentList(attributeName: String) = if (attributeName.endsWith(ATTRIBUTE_WITH_ATTACHMENT))
        listOf(Issuer.Attachment(ATTRIBUTE_WITH_ATTACHMENT, "image/webp", byteArrayOf(32)))
    else null

    override fun getCredential(subjectId: String, attributeType: String) = KmmResult.failure(UnsupportedOperationException("empty"))

    private fun getClaimInt(subjectId: String, attributeName: String) = when {
        attributeName.startsWith(SchemaIndex.ATTR_GENERIC_PREFIX + "/") ->
            when (attributeName.removePrefix(SchemaIndex.ATTR_GENERIC_PREFIX + "/")) {
                "given-name" -> AtomicAttributeCredential(subjectId, attributeName, "Susanne")
                "family-name" -> AtomicAttributeCredential(subjectId, attributeName, "Meier")
                "date-of-birth" -> AtomicAttributeCredential(subjectId, attributeName, "1990-01-01")
                "identifier" -> AtomicAttributeCredential(subjectId, attributeName, randomId())
                "picture" -> AtomicAttributeCredential(subjectId, attributeName, randomId())
                else -> null
            }
        else -> null
    }

    private fun randomId() = Random.nextBytes(32).encodeBase16()

    companion object {
        const val ATTRIBUTE_WITH_ATTACHMENT = "picture"
    }

}
