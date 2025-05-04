package at.asitplus.wallet.lib.rqes

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.data.ConstantIndex
import io.ktor.util.*
import kotlinx.datetime.Clock
import kotlinx.datetime.LocalDate
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
        if (credentialScheme == EuPidScheme) {
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
                        optionalClaim(claimNames, EuPidScheme.Attributes.BIRTH_DATE, birthDate), //incorrect encoding in german test vector?
                        optionalClaim(claimNames, AGE_EQUAL_OR_OVER_18, true),
                        optionalClaim(claimNames, NATIONALITIES, listOf(nationality)),
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
                else -> throw NotImplementedError()
            }
        } else {
            throw NotImplementedError()
        }
    }

    private fun Collection<String>?.isNullOrContains(s: String) =
        this == null || contains(s)

    private fun optionalClaim(claimNames: Collection<String>?, name: String, value: Any) =
        if (claimNames.isNullOrContains(name)) ClaimToBeIssued(name, value) else null

}