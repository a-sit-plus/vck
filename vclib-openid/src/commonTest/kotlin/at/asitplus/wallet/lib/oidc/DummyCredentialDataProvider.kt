package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.CryptoPublicKey
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerCredentialDataProvider
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.DrivingPrivilege
import at.asitplus.wallet.lib.iso.DrivingPrivilegeCode
import at.asitplus.wallet.lib.iso.ElementValue
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import kotlinx.datetime.Clock
import kotlinx.datetime.LocalDate
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
        val expiration = clock.now() + defaultLifetime
        val credentials = mutableListOf<CredentialToBeIssued>()
        if (attributeTypes.contains(ConstantIndex.AtomicAttribute2023.vcType)) {
            val claims = listOf(
                ClaimToBeIssued("given-name", "Susanne"),
                ClaimToBeIssued("family-name", "Meier"),
                ClaimToBeIssued("date-of-birth", "1990-01-01"),
            )
            credentials += when (representation) {
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
        }

        if (attributeTypes.contains(ConstantIndex.MobileDrivingLicence2023.vcType) && subjectPublicKey != null) {
            val drivingPrivilege = DrivingPrivilege(
                vehicleCategoryCode = "B",
                issueDate = LocalDate.parse("2023-01-01"),
                expiryDate = LocalDate.parse("2033-01-31"),
                codes = arrayOf(DrivingPrivilegeCode(code = "B"))
            )
            val issuerSignedItems = listOf(
                buildIssuerSignedItem(DataElements.FAMILY_NAME, "Mustermann", 0U),
                buildIssuerSignedItem(DataElements.GIVEN_NAME, "Max", 1U),
                buildIssuerSignedItem(DataElements.DOCUMENT_NUMBER, "123456789", 2U),
                buildIssuerSignedItem(DataElements.ISSUE_DATE, "2023-01-01", 3U),
                buildIssuerSignedItem(DataElements.EXPIRY_DATE, "2033-01-31", 4U),
                buildIssuerSignedItem(DataElements.DRIVING_PRIVILEGES, drivingPrivilege, 5U),
            )

            credentials.add(
                CredentialToBeIssued.Iso(
                    issuerSignedItems = issuerSignedItems,
                    subjectPublicKey = subjectPublicKey.toCoseKey(),
                    expiration = expiration,
                    scheme = ConstantIndex.MobileDrivingLicence2023,
                )
            )
        }
        return KmmResult.success(credentials)
    }

    private fun buildIssuerSignedItem(elementIdentifier: String, elementValue: String, digestId: UInt) = IssuerSignedItem(
        digestId = digestId,
        random = Random.nextBytes(16),
        elementIdentifier = elementIdentifier,
        elementValue = ElementValue(string = elementValue)
    )

    fun buildIssuerSignedItem(elementIdentifier: String, elementValue: DrivingPrivilege, digestId: UInt) =
        IssuerSignedItem(
            digestId = digestId,
            random = Random.nextBytes(16),
            elementIdentifier = elementIdentifier,
            elementValue = ElementValue(drivingPrivilege = arrayOf(elementValue))
        )

}
