package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.IssuerCredentialDataProvider
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
class TestCredential : CredentialSubject {
    @SerialName("name")
    val name: String

    @SerialName("value")
    val value: String

    constructor(id: String, name: String, value: String) : super(id = id) {
        this.name = name
        this.value = value
    }

    override fun toString(): String {
        return "TestCredential(id='$id', name='$name', value='$value')"
    }

}

class TestCredentialDataProvider(
    private val clock: Clock = Clock.System,
) : IssuerCredentialDataProvider {

    private val defaultLifetime = 1.minutes

    override fun getCredentialWithType(
        subjectId: String,
        attributeTypes: Collection<String>
    ): KmmResult<List<IssuerCredentialDataProvider.CredentialToBeIssued>> {
        val attributeType = TestCredentialScheme.vcType
        if (!attributeTypes.contains(attributeType)) {
            return KmmResult.failure(UnsupportedOperationException("no data"))
        }
        val expiration = clock.now() + defaultLifetime
        return KmmResult.success(
            listOf(
                IssuerCredentialDataProvider.CredentialToBeIssued(
                    TestCredential(subjectId, randomValue(), randomValue()),
                    expiration,
                    attributeType,
                ),
            )
        )
    }

    private fun randomValue() = Random.nextBytes(32).encodeBase16()

}
