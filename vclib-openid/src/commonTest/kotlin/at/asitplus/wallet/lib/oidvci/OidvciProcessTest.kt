package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.IssuerCredentialDataProvider
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidc.OpenIdConstants.GRANT_TYPE_CODE
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.ktor.http.Url
import kotlinx.datetime.Clock

class OidvciProcessTest : FunSpec({

    val dataProvider = object : IssuerCredentialDataProvider {
        override fun getCredentialWithType(
            subjectId: String,
            attributeTypes: Collection<String>
        ): KmmResult<List<IssuerCredentialDataProvider.CredentialToBeIssued>> {
            return KmmResult.success(
                attributeTypes.mapNotNull {
                    when (it) {
                        ConstantIndex.AtomicAttribute2023.vcType -> {
                            IssuerCredentialDataProvider.CredentialToBeIssued(
                                subject = AtomicAttribute2023(subjectId, "name", "value"),
                                expiration = Clock.System.now(),
                                attributeType = ConstantIndex.AtomicAttribute2023.vcType,
                            )
                        }

                        ConstantIndex.MobileDrivingLicence2023.vcType -> {
                            IssuerCredentialDataProvider.CredentialToBeIssued(
                                subject = AtomicAttribute2023(subjectId, "name", "value"),
                                expiration = Clock.System.now(),
                                attributeType = ConstantIndex.AtomicAttribute2023.vcType,
                            )
                        }

                        else -> {
                            null
                        }
                    }
                }
            )
        }
    }
    val issuer = IssuerService(
        issuer = IssuerAgent.newDefaultInstance(
            cryptoService = DefaultCryptoService(),
            dataProvider = dataProvider
        ),
        credentialSchemes = listOf(ConstantIndex.AtomicAttribute2023, ConstantIndex.MobileDrivingLicence2023)
    )

    test("process with W3C VC") {
        val client = WalletService(credentialScheme = ConstantIndex.AtomicAttribute2023)
        val metadata = issuer.metadata
        val authnRequest = client.createAuthRequest()
        val codeUrl = issuer.authorize(authnRequest)
        codeUrl.shouldNotBeNull()
        val code = Url(codeUrl).parameters[GRANT_TYPE_CODE]
        code.shouldNotBeNull()
        val tokenRequest = client.createTokenRequestParameters(code)
        val token = issuer.token(tokenRequest)
        val credentialRequest = client.createCredentialRequest(token, metadata)
        val credential = issuer.credential(OpenIdConstants.TOKEN_PREFIX_BEARER + token.accessToken, credentialRequest)
        credential.format shouldBe CredentialFormatEnum.JWT_VC
        credential.credential.shouldNotBeNull()
    }

    test("process with ISO MDOC") {
        val client = WalletService(credentialScheme = ConstantIndex.MobileDrivingLicence2023)
        val metadata = issuer.metadata
        val authnRequest = client.createAuthRequest()
        val codeUrl = issuer.authorize(authnRequest)
        codeUrl.shouldNotBeNull()
        val code = Url(codeUrl).parameters[GRANT_TYPE_CODE]
        code.shouldNotBeNull()
        val tokenRequest = client.createTokenRequestParameters(code)
        val token = issuer.token(tokenRequest)
        val credentialRequest = client.createCredentialRequest(token, metadata)
        val credential = issuer.credential(OpenIdConstants.TOKEN_PREFIX_BEARER + token.accessToken, credentialRequest)
        credential.format shouldBe CredentialFormatEnum.MSO_MDOC
        credential.credential.shouldNotBeNull()
    }

})
