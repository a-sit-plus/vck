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
                optionalClaim(
                    claimNames,
                    ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH,
                    LocalDate.parse("1990-01-01")
                ),
                optionalClaim(
                    claimNames,
                    ConstantIndex.AtomicAttribute2023.CLAIM_PORTRAIT,
                    Random.Default.nextBytes(32)
                ),
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
                issueDate = LocalDate.parse("2023-01-01"),
                expiryDate = LocalDate.parse("2033-01-31"),
                codes = arrayOf(DrivingPrivilegeCode(code = "B"))
            )
            var digestId = 0U
            val issuerSignedItems = with(MobileDrivingLicenceDataElements) {
                listOfNotNull(
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
                        issuerSignedItem(PORTRAIT, Random.Default.nextBytes(32), digestId++) else null,
                    if (claimNames.isNullOrContains(UN_DISTINGUISHING_SIGN))
                        issuerSignedItem(UN_DISTINGUISHING_SIGN, "AT", digestId++) else null,
                    if (claimNames.isNullOrContains(DRIVING_PRIVILEGES))
                        issuerSignedItem(DRIVING_PRIVILEGES, arrayOf(drivingPrivilege), digestId++) else null,
                    if (claimNames.isNullOrContains(AGE_OVER_18))
                        issuerSignedItem(AGE_OVER_18, true, digestId++) else null,
                )
            }

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
            val birthDate = LocalDate.parse("1970-01-01")
            val issuingCountry = "AT"
            val nationality = "FR"
            val claims = when (representation) {

                ConstantIndex.CredentialRepresentation.SD_JWT -> with(EuPidScheme.SdJwtAttributes) {
                    listOfNotNull(
                        optionalClaim(claimNames, FAMILY_NAME, familyName),
                        optionalClaim(claimNames, FAMILY_NAME_BIRTH, familyName),
                        optionalClaim(claimNames, GIVEN_NAME, givenName),
                        optionalClaim(claimNames, GIVEN_NAME_BIRTH, givenName),
                        optionalClaim(claimNames, BIRTH_DATE, birthDate),
                        optionalClaim(claimNames, AGE_EQUAL_OR_OVER_18, true),
                        optionalClaim(claimNames, NATIONALITIES, listOf(nationality)),
                        optionalClaim(claimNames, ISSUANCE_DATE, issuance),
                        optionalClaim(claimNames, EXPIRY_DATE, expiration),
                        optionalClaim(claimNames, ISSUING_COUNTRY, issuingCountry),
                        optionalClaim(claimNames, ISSUING_AUTHORITY, issuingCountry),
                    )
                }

                ConstantIndex.CredentialRepresentation.ISO_MDOC -> with(EuPidScheme.Attributes) {
                    listOfNotNull(
                        optionalClaim(claimNames, FAMILY_NAME, familyName),
                        optionalClaim(claimNames, FAMILY_NAME_BIRTH, familyName),
                        optionalClaim(claimNames, GIVEN_NAME, givenName),
                        optionalClaim(claimNames, GIVEN_NAME_BIRTH, givenName),
                        optionalClaim(claimNames, BIRTH_DATE, birthDate),
                        optionalClaim(claimNames, AGE_OVER_18, true),
                        optionalClaim(claimNames, NATIONALITY, nationality),
                        optionalClaim(claimNames, ISSUANCE_DATE, issuance),
                        optionalClaim(claimNames, EXPIRY_DATE, expiration),
                        optionalClaim(claimNames, ISSUING_COUNTRY, issuingCountry),
                        optionalClaim(claimNames, ISSUING_AUTHORITY, issuingCountry),
                    )
                }

                else -> null
            }
            when (representation) {
                ConstantIndex.CredentialRepresentation.SD_JWT ->
                    CredentialToBeIssued.VcSd(
                        claims = claims!!,
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
                    issuerSignedItems = claims!!.mapIndexed { index, claim ->
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