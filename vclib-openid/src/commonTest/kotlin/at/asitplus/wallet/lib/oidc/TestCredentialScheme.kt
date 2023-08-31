package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.IssuerCredentialDataProvider
import at.asitplus.wallet.lib.cbor.CoseKey
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialSubject
import io.matthewnelson.component.encoding.base16.encodeBase16
import kotlinx.datetime.Clock
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes

object TestCredentialScheme : ConstantIndex.CredentialScheme {
    override val credentialDefinitionName: String = "test-credential"
    override val schemaUri: String = "https://example.com/schema/testcredential/1.0.0"
    override val vcType: String = "TestCredential"
    override val credentialFormat: ConstantIndex.CredentialFormat = ConstantIndex.CredentialFormat.W3C_VC
}

@Serializable
@SerialName("TestCredential")
data class TestCredential (
    override val id: String,

    @SerialName("name")
    val name: String,

    @SerialName("value")
    val value: String
) : CredentialSubject()

class TestCredentialDataProvider(
    private val clock: Clock = Clock.System,
) : IssuerCredentialDataProvider {

    private val defaultLifetime = 1.minutes

    override fun getCredentialWithType(
        subjectId: String,
        subjectPublicKey: CoseKey?,
        attributeTypes: Collection<String>
    ): KmmResult<List<CredentialToBeIssued>> {
        val attributeType = TestCredentialScheme.vcType
        if (!attributeTypes.contains(attributeType)) {
            return KmmResult.failure(UnsupportedOperationException("no data"))
        }
        val expiration = clock.now() + defaultLifetime
        return KmmResult.success(
            listOf(
                CredentialToBeIssued.Vc(
                    TestCredential(subjectId, randomValue(), randomValue()),
                    expiration,
                    attributeType,
                ),
            )
        )
    }

    private fun randomValue() = Random.nextBytes(32).encodeBase16()

}
