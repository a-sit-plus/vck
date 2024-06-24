package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.wallet.eupid.EuPidCredential
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.IssuerCredentialDataProvider
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.mdl.DrivingPrivilege
import at.asitplus.wallet.mdl.DrivingPrivilegeCode
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.AGE_OVER_18
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.BIRTH_DATE
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.DOCUMENT_NUMBER
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.DRIVING_PRIVILEGES
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.EXPIRY_DATE
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.FAMILY_NAME
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.GIVEN_NAME
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.ISSUE_DATE
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.ISSUING_AUTHORITY
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.ISSUING_COUNTRY
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.PORTRAIT
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.UN_DISTINGUISHING_SIGN
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
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
    ): KmmResult<CredentialToBeIssued> = catching {
        val issuance = clock.now()
        val expiration = issuance + defaultLifetime
        if (credentialScheme == ConstantIndex.AtomicAttribute2023) {
            val subjectId = subjectPublicKey.didEncoded
            val claims = listOfNotNull(
                optionalClaim(claimNames, "given-name", "Susanne"),
                optionalClaim(claimNames, "family-name", "Meier"),
                optionalClaim(claimNames, "date-of-birth", "1990-01-01"),
                optionalClaim(claimNames, "is-active", true)
            )
            when (representation) {
                ConstantIndex.CredentialRepresentation.SD_JWT -> CredentialToBeIssued.VcSd(
                    claims = claims,
                    expiration = expiration,
                )

                ConstantIndex.CredentialRepresentation.PLAIN_JWT -> CredentialToBeIssued.VcJwt(
                    subject = AtomicAttribute2023(subjectId, "given_name", "Susanne"),
                    expiration = expiration,
                )

                ConstantIndex.CredentialRepresentation.ISO_MDOC -> CredentialToBeIssued.Iso(
                    issuerSignedItems = claims.mapIndexed { index, claim ->
                        issuerSignedItem(claim.name, claim.value, index.toUInt())
                    },
                    expiration = expiration,
                )
            }
        } else if (credentialScheme == MobileDrivingLicenceScheme) {
            val drivingPrivilege = DrivingPrivilege(
                vehicleCategoryCode = "B",
                issueDate = LocalDate.parse("2023-01-01"),
                expiryDate = LocalDate.parse("2033-01-31"),
                codes = arrayOf(DrivingPrivilegeCode(code = "B"))
            )
            var digestId = 0U
            val issuerSignedItems = listOfNotNull(
                if (claimNames.isNullOrContains(FAMILY_NAME))
                    issuerSignedItem(FAMILY_NAME, "Mustermann", digestId++) else null,
                if (claimNames.isNullOrContains(GIVEN_NAME))
                    issuerSignedItem(GIVEN_NAME, "Max", digestId++) else null,
                if (claimNames.isNullOrContains(BIRTH_DATE))
                    issuerSignedItem(BIRTH_DATE, LocalDate.parse("1970-01-01"), digestId++) else null,
                if (claimNames.isNullOrContains(DOCUMENT_NUMBER))
                    issuerSignedItem(DOCUMENT_NUMBER, "123456789", digestId++) else null,
                if (claimNames.isNullOrContains(ISSUE_DATE))
                    issuerSignedItem(ISSUE_DATE, LocalDate.parse("2023-01-01"), digestId++) else null,
                if (claimNames.isNullOrContains(EXPIRY_DATE))
                    issuerSignedItem(EXPIRY_DATE, LocalDate.parse("2033-01-01"), digestId++) else null,
                if (claimNames.isNullOrContains(ISSUING_COUNTRY))
                    issuerSignedItem(ISSUING_COUNTRY, "AT", digestId++) else null,
                if (claimNames.isNullOrContains(ISSUING_AUTHORITY))
                    issuerSignedItem(ISSUING_AUTHORITY, "AT", digestId++) else null,
                if (claimNames.isNullOrContains(PORTRAIT))
                    issuerSignedItem(PORTRAIT, Random.nextBytes(32), digestId++) else null,
                if (claimNames.isNullOrContains(UN_DISTINGUISHING_SIGN))
                    issuerSignedItem(UN_DISTINGUISHING_SIGN, "AT", digestId++) else null,
                if (claimNames.isNullOrContains(DRIVING_PRIVILEGES))
                    issuerSignedItem(DRIVING_PRIVILEGES, arrayOf(drivingPrivilege), digestId++) else null,
                if (claimNames.isNullOrContains(AGE_OVER_18))
                    issuerSignedItem(AGE_OVER_18, true, digestId++) else null,
            )

            CredentialToBeIssued.Iso(
                issuerSignedItems = issuerSignedItems,
                expiration = expiration,
            )
        } else if (credentialScheme == EuPidScheme) {
            val subjectId = subjectPublicKey.didEncoded
            val familyName = "Musterfrau"
            val givenName = "Maria"
            val birthDate = LocalDate.parse("1970-01-01")
            val issuingCountry = "AT"
            val nationality = "FR"
            val claims = listOfNotNull(
                optionalClaim(claimNames, EuPidScheme.Attributes.FAMILY_NAME, familyName),
                optionalClaim(claimNames, EuPidScheme.Attributes.GIVEN_NAME, givenName),
                optionalClaim(claimNames, EuPidScheme.Attributes.BIRTH_DATE, birthDate),
                optionalClaim(claimNames, EuPidScheme.Attributes.NATIONALITY, nationality),
                optionalClaim(claimNames, EuPidScheme.Attributes.ISSUANCE_DATE, issuance),
                optionalClaim(claimNames, EuPidScheme.Attributes.EXPIRY_DATE, expiration),
                optionalClaim(claimNames, EuPidScheme.Attributes.ISSUING_COUNTRY, issuingCountry),
                optionalClaim(claimNames, EuPidScheme.Attributes.ISSUING_AUTHORITY, issuingCountry),
            )
            when (representation) {
                ConstantIndex.CredentialRepresentation.SD_JWT ->
                    CredentialToBeIssued.VcSd(
                        claims = claims,
                        expiration = expiration
                    )

                ConstantIndex.CredentialRepresentation.PLAIN_JWT -> CredentialToBeIssued.VcJwt(
                    EuPidCredential(
                        id = subjectId,
                        familyName = familyName,
                        givenName = givenName,
                        birthDate = birthDate,
                        issuanceDate = issuance,
                        expiryDate = expiration,
                        issuingCountry = issuingCountry,
                        issuingAuthority = issuingCountry,
                    ),
                    expiration,
                )

                ConstantIndex.CredentialRepresentation.ISO_MDOC -> CredentialToBeIssued.Iso(
                    issuerSignedItems = claims.mapIndexed { index, claim ->
                        issuerSignedItem(claim.name, claim.value, index.toUInt())
                    },
                    expiration = expiration,
                )
            }
        } else {
            throw NotImplementedError()
        }
    }

    private fun Collection<String>?.isNullOrContains(s: String) =
        this == null || contains(s)

    private fun optionalClaim(claimNames: Collection<String>?, name: String, value: Any) =
        if (claimNames.isNullOrContains(name)) ClaimToBeIssued(name, value) else null


    private fun issuerSignedItem(name: String, value: Any, digestId: UInt) =
        IssuerSignedItem(
            digestId = digestId,
            random = Random.nextBytes(16),
            elementIdentifier = name,
            elementValue = value
        )
}
