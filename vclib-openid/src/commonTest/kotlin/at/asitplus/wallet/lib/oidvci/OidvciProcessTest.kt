package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.IssuerCredentialDataProvider
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.ktor.http.Url
import kotlinx.datetime.Clock

class OidvciProcessTest : FunSpec({

    val client = WalletService(tokenType = arrayOf("SomeCredential"))

    val dataProvider = object : IssuerCredentialDataProvider {
        override fun getCredentialWithType(
            subjectId: String,
            attributeTypes: Collection<String>
        ): KmmResult<List<IssuerCredentialDataProvider.CredentialToBeIssued>> {
            return KmmResult.success(
                listOf(
                    IssuerCredentialDataProvider.CredentialToBeIssued(
                        subject = AtomicAttribute2023(subjectId, "name", "value"),
                        expiration = Clock.System.now(),
                        attributeType = ConstantIndex.AtomicAttribute2023.vcType,
                    )
                )
            )
        }
    }
    val issuer = IssuerService(
        issuer = IssuerAgent.newDefaultInstance(
            cryptoService = DefaultCryptoService(),
            dataProvider = dataProvider
        )
    )

    test("process") {
        val metadata = issuer.metadata()
        val authnRequest = client.createAuthRequest()
        val codeUrl = issuer.authorize(authnRequest)
        val code = Url(codeUrl).parameters["code"]
        code.shouldNotBeNull()
        val tokenRequest = client.createTokenRequestParameters(code)
        val token = issuer.token(tokenRequest)
        val credentialRequest = client.createCredentialRequest(token, metadata)
        val credential = issuer.credential("Bearer ${token.accessToken}", credentialRequest)
        credential.credential.shouldNotBeNull()
    }

})
