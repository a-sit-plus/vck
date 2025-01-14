package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.eupid.EuPidCredential
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.mdl.DrivingPrivilege
import at.asitplus.wallet.mdl.DrivingPrivilegeCode
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import kotlinx.datetime.Clock
import kotlinx.datetime.LocalDate
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes

object DummyCredentialDataProvider {

    private val defaultLifetime = 1.minutes

    fun getCredential(
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        claimNames: Collection<String>? = null,
    ): KmmResult<CredentialToBeIssued> = catching {
        val issuance = Clock.System.now()
        val expiration = issuance + defaultLifetime
        if (credentialScheme == ConstantIndex.AtomicAttribute2023) {
            val subjectId = subjectPublicKey.didEncoded
            val claims = listOfNotNull(
                optionalClaim(claimNames, ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME, "Susanne"),
                optionalClaim(claimNames, ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME, "Meier"),
                optionalClaim(claimNames, ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH, LocalDate.Companion.parse("1990-01-01")),
                optionalClaim(claimNames, ConstantIndex.AtomicAttribute2023.CLAIM_PORTRAIT, Random.Default.nextBytes(32)),
            )
            when (representation) {
                ConstantIndex.CredentialRepresentation.SD_JWT -> CredentialToBeIssued.VcSd(
                    claims = claims,
                    expiration = expiration,
                    scheme = credentialScheme,
                    subjectPublicKey = subjectPublicKey,
                )

                ConstantIndex.CredentialRepresentation.PLAIN_JWT -> CredentialToBeIssued.VcJwt(
                    subject = AtomicAttribute2023(
                        subjectId,
                        ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME,
                        "Susanne"
                    ),
                    expiration = expiration,
                    scheme = credentialScheme,
                    subjectPublicKey = subjectPublicKey,
                )

                ConstantIndex.CredentialRepresentation.ISO_MDOC -> CredentialToBeIssued.Iso(
                    issuerSignedItems = claims.mapIndexed { index, claim ->
                        issuerSignedItem(claim.name, claim.value, index.toUInt())
                    },
                    expiration = expiration,
                    scheme = credentialScheme,
                    subjectPublicKey = subjectPublicKey,
                )
            }
        } else if (credentialScheme == MobileDrivingLicenceScheme) {
            val drivingPrivilege = DrivingPrivilege(
                vehicleCategoryCode = "B",
                issueDate = LocalDate.Companion.parse("2023-01-01"),
                expiryDate = LocalDate.Companion.parse("2033-01-31"),
                codes = arrayOf(DrivingPrivilegeCode(code = "B"))
            )
            var digestId = 0U
            val issuerSignedItems = listOfNotNull(
                if (claimNames.isNullOrContains(MobileDrivingLicenceDataElements.FAMILY_NAME))
                    issuerSignedItem(MobileDrivingLicenceDataElements.FAMILY_NAME, "Mustermann", digestId++) else null,
                if (claimNames.isNullOrContains(MobileDrivingLicenceDataElements.GIVEN_NAME))
                    issuerSignedItem(MobileDrivingLicenceDataElements.GIVEN_NAME, "Max", digestId++) else null,
                if (claimNames.isNullOrContains(MobileDrivingLicenceDataElements.BIRTH_DATE))
                    issuerSignedItem(MobileDrivingLicenceDataElements.BIRTH_DATE, LocalDate.Companion.parse("1970-01-01"), digestId++) else null,
                if (claimNames.isNullOrContains(MobileDrivingLicenceDataElements.DOCUMENT_NUMBER))
                    issuerSignedItem(MobileDrivingLicenceDataElements.DOCUMENT_NUMBER, "123456789", digestId++) else null,
                if (claimNames.isNullOrContains(MobileDrivingLicenceDataElements.ISSUE_DATE))
                    issuerSignedItem(MobileDrivingLicenceDataElements.ISSUE_DATE, LocalDate.Companion.parse("2023-01-01"), digestId++) else null,
                if (claimNames.isNullOrContains(MobileDrivingLicenceDataElements.EXPIRY_DATE))
                    issuerSignedItem(MobileDrivingLicenceDataElements.EXPIRY_DATE, LocalDate.Companion.parse("2033-01-01"), digestId++) else null,
                if (claimNames.isNullOrContains(MobileDrivingLicenceDataElements.ISSUING_COUNTRY))
                    issuerSignedItem(MobileDrivingLicenceDataElements.ISSUING_COUNTRY, "AT", digestId++) else null,
                if (claimNames.isNullOrContains(MobileDrivingLicenceDataElements.ISSUING_AUTHORITY))
                    issuerSignedItem(MobileDrivingLicenceDataElements.ISSUING_AUTHORITY, "AT", digestId++) else null,
                if (claimNames.isNullOrContains(MobileDrivingLicenceDataElements.PORTRAIT))
                    issuerSignedItem(MobileDrivingLicenceDataElements.PORTRAIT, Random.Default.nextBytes(32), digestId++) else null,
                if (claimNames.isNullOrContains(MobileDrivingLicenceDataElements.UN_DISTINGUISHING_SIGN))
                    issuerSignedItem(MobileDrivingLicenceDataElements.UN_DISTINGUISHING_SIGN, "AT", digestId++) else null,
                if (claimNames.isNullOrContains(MobileDrivingLicenceDataElements.DRIVING_PRIVILEGES))
                    issuerSignedItem(MobileDrivingLicenceDataElements.DRIVING_PRIVILEGES, arrayOf(drivingPrivilege), digestId++) else null,
                if (claimNames.isNullOrContains(MobileDrivingLicenceDataElements.AGE_OVER_18))
                    issuerSignedItem(MobileDrivingLicenceDataElements.AGE_OVER_18, true, digestId++) else null,
            )

            CredentialToBeIssued.Iso(
                issuerSignedItems = issuerSignedItems,
                expiration = expiration,
                scheme = credentialScheme,
                subjectPublicKey = subjectPublicKey,
            )
        } else if (credentialScheme == EuPidScheme) {
            val subjectId = subjectPublicKey.didEncoded
            val familyName = "Musterfrau"
            val givenName = "Maria"
            val birthDate = LocalDate.Companion.parse("1970-01-01")
            val issuingCountry = "AT"
            val nationality = "FR"
            val claims = listOfNotNull(
                optionalClaim(claimNames, EuPidScheme.Attributes.FAMILY_NAME, familyName),
                optionalClaim(claimNames, EuPidScheme.Attributes.GIVEN_NAME, givenName),
                optionalClaim(claimNames, EuPidScheme.Attributes.BIRTH_DATE, birthDate),
                optionalClaim(claimNames, EuPidScheme.Attributes.AGE_OVER_18, true),
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
                        expiration = expiration,
                        scheme = credentialScheme,
                        subjectPublicKey = subjectPublicKey,
                    )

                ConstantIndex.CredentialRepresentation.PLAIN_JWT -> CredentialToBeIssued.VcJwt(
                    subject = EuPidCredential(
                        id = subjectId,
                        familyName = familyName,
                        givenName = givenName,
                        birthDate = birthDate,
                        ageOver18 = true,
                        issuanceDate = issuance,
                        expiryDate = expiration,
                        issuingCountry = issuingCountry,
                        issuingAuthority = issuingCountry,
                    ),
                    expiration = expiration,
                    scheme = credentialScheme,
                    subjectPublicKey = subjectPublicKey,
                )

                ConstantIndex.CredentialRepresentation.ISO_MDOC -> CredentialToBeIssued.Iso(
                    issuerSignedItems = claims.mapIndexed { index, claim ->
                        issuerSignedItem(claim.name, claim.value, index.toUInt())
                    },
                    expiration = expiration,
                    scheme = credentialScheme,
                    subjectPublicKey = subjectPublicKey,
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
            random = Random.Default.nextBytes(16),
            elementIdentifier = name,
            elementValue = value
        )
}