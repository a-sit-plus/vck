package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.IssuerCredentialDataProvider
import at.asitplus.wallet.lib.cbor.CoseKey
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.DeviceKeyInfo
import at.asitplus.wallet.lib.iso.DrivingPrivilege
import at.asitplus.wallet.lib.iso.DrivingPrivilegeCode
import at.asitplus.wallet.lib.iso.ElementValue
import at.asitplus.wallet.lib.iso.IsoDataModelConstants
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.lib.iso.MobileSecurityObject
import at.asitplus.wallet.lib.iso.ValidityInfo
import at.asitplus.wallet.lib.iso.ValueDigest
import at.asitplus.wallet.lib.iso.ValueDigestList
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidc.OpenIdConstants.GRANT_TYPE_CODE
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.ktor.http.Url
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.LocalDate
import kotlinx.datetime.plus
import kotlin.random.Random

class OidvciProcessTest : FunSpec({

    class OidvciDataProvider : IssuerCredentialDataProvider {
        override fun getCredentialWithType(
            subjectId: String,
            subjectPublicKey: CoseKey?,
            attributeTypes: Collection<String>
        ): KmmResult<List<CredentialToBeIssued>> {
            return KmmResult.success(
                attributeTypes.mapNotNull {
                    when (it) {
                        ConstantIndex.MobileDrivingLicence2023.vcType -> {
                            val drivingPrivilege = DrivingPrivilege(
                                vehicleCategoryCode = "B",
                                issueDate = LocalDate.parse("2023-01-01"),
                                expiryDate = LocalDate.parse("2033-01-31"),
                                codes = arrayOf(DrivingPrivilegeCode(code = "B", sign = "sign", value = "value"))
                            )
                            val issuerSignedItems = listOf(
                                buildIssuerSignedItem(DataElements.FAMILY_NAME, "Mustermann", 0U),
                                buildIssuerSignedItem(DataElements.GIVEN_NAME, "Max", 1U),
                                buildIssuerSignedItem(DataElements.DOCUMENT_NUMBER, "123456789", 2U),
                                buildIssuerSignedItem(DataElements.ISSUE_DATE, "2023-01-01", 3U),
                                buildIssuerSignedItem(DataElements.EXPIRY_DATE, "2033-01-31", 4U),
                                buildIssuerSignedItem(DataElements.DRIVING_PRIVILEGES, drivingPrivilege, 4U),
                            )
                            CredentialToBeIssued.Iso(
                                issuerSignedItems = issuerSignedItems,
                                subjectPublicKey = subjectPublicKey!!,
                                expiration = Clock.System.now().plus(60, DateTimeUnit.SECOND),
                                attributeType = ConstantIndex.MobileDrivingLicence2023.vcType,
                            )
                        }

                        ConstantIndex.AtomicAttribute2023.vcType -> {
                            CredentialToBeIssued.Vc(
                                subject = AtomicAttribute2023(subjectId, "name", "value"),
                                expiration = Clock.System.now().plus(60, DateTimeUnit.SECOND),
                                attributeType = ConstantIndex.AtomicAttribute2023.vcType,
                            )
                        }

                        else -> null
                    }
                }
            )
        }
    }

    val dataProvider = OidvciDataProvider()
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

fun buildIssuerSignedItem(elementIdentifier: String, elementValue: String, digestId: UInt) = IssuerSignedItem(
    digestId = digestId,
    random = Random.nextBytes(16),
    elementIdentifier = elementIdentifier,
    elementValue = ElementValue(string = elementValue)
)

fun buildIssuerSignedItem(elementIdentifier: String, elementValue: DrivingPrivilege, digestId: UInt) = IssuerSignedItem(
    digestId = digestId,
    random = Random.nextBytes(16),
    elementIdentifier = elementIdentifier,
    elementValue = ElementValue(drivingPrivilege = listOf(elementValue))
)
