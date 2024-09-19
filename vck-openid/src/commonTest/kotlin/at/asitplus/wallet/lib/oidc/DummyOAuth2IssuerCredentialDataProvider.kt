package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.eupid.EuPidCredential
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.IssuerCredentialDataProvider
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.lib.oidvci.OAuth2DataProvider
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.DOCUMENT_NUMBER
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.EXPIRY_DATE
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.FAMILY_NAME
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.GIVEN_NAME
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.ISSUE_DATE
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.datetime.LocalDate
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes


class DummyOAuth2IssuerCredentialDataProvider(
    private val userInfo: OidcUserInfoExtended,
    private val clock: Clock = Clock.System,
) : IssuerCredentialDataProvider {

    private val defaultLifetime = 1.minutes

    override fun getCredential(
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        claimNames: Collection<String>?
    ): KmmResult<CredentialToBeIssued> = catching {
        when (credentialScheme) {
            ConstantIndex.AtomicAttribute2023 -> getAtomicAttribute(subjectPublicKey, claimNames, representation)
            MobileDrivingLicenceScheme -> getMdl(claimNames)
            EuPidScheme -> getEupId(subjectPublicKey, claimNames, representation)
            else -> throw NotImplementedError()
        }
    }

    private fun getAtomicAttribute(
        subjectPublicKey: CryptoPublicKey,
        claimNames: Collection<String>?,
        representation: ConstantIndex.CredentialRepresentation
    ): CredentialToBeIssued {
        val issuance = clock.now()
        val expiration = issuance + defaultLifetime
        val familyName = userInfo.userInfo.familyName
        val givenName = userInfo.userInfo.givenName
        val subjectId = subjectPublicKey.didEncoded
        val claims = listOfNotNull(
            givenName?.let { optionalClaim(claimNames, CLAIM_GIVEN_NAME, it) },
            familyName?.let { optionalClaim(claimNames, "family_name", it) },
            userInfo.userInfo.birthDate?.let { optionalClaim(claimNames, "date_of_birth", it) },
            userInfo.userInfo.picture?.let { optionalClaim(claimNames, CLAIM_PORTRAIT, it.decodeToByteArray(Base64())) },
        )
        return when (representation) {
            ConstantIndex.CredentialRepresentation.SD_JWT ->
                CredentialToBeIssued.VcSd(claims, expiration)

            ConstantIndex.CredentialRepresentation.PLAIN_JWT -> CredentialToBeIssued.VcJwt(
                AtomicAttribute2023(subjectId, GIVEN_NAME, givenName ?: "no value"), expiration,
            )

            ConstantIndex.CredentialRepresentation.ISO_MDOC -> CredentialToBeIssued.Iso(
                claims.mapIndexed { index, claim ->
                    issuerSignedItem(claim.name, claim.value, index.toUInt())
                },
                expiration,
            )
        }
    }

    private fun getMdl(
        claimNames: Collection<String>?
    ): CredentialToBeIssued.Iso {
        val issuance = clock.now()
        val expiration = issuance + defaultLifetime
        val familyName = userInfo.userInfo.familyName
        val givenName = userInfo.userInfo.givenName
        var digestId = 0U
        val issuerSignedItems = listOfNotNull(
            if (claimNames.isNullOrContains(FAMILY_NAME) && familyName != null)
                issuerSignedItem(FAMILY_NAME, familyName, digestId++) else null,
            if (claimNames.isNullOrContains(GIVEN_NAME) && givenName != null)
                issuerSignedItem(GIVEN_NAME, givenName, digestId++) else null,
            if (claimNames.isNullOrContains(DOCUMENT_NUMBER))
                issuerSignedItem(DOCUMENT_NUMBER, "123456789", digestId++) else null,
            if (claimNames.isNullOrContains(ISSUE_DATE))
                issuerSignedItem(ISSUE_DATE, "2023-01-01", digestId++) else null,
            if (claimNames.isNullOrContains(EXPIRY_DATE))
                issuerSignedItem(EXPIRY_DATE, "2033-01-01", digestId++) else null,
        )
        return CredentialToBeIssued.Iso(issuerSignedItems, expiration)
    }

    private fun getEupId(
        subjectPublicKey: CryptoPublicKey,
        claimNames: Collection<String>?,
        representation: ConstantIndex.CredentialRepresentation
    ): CredentialToBeIssued {
        val issuance = clock.now()
        val expiration = issuance + defaultLifetime
        val familyName = userInfo.userInfo.familyName ?: "Unknown"
        val givenName = userInfo.userInfo.givenName ?: "Unknown"
        val subjectId = subjectPublicKey.didEncoded
        val birthDate = LocalDate.parse(userInfo.userInfo.birthDate ?: "1970-01-01")
        val issuingCountry = "AT"
        val claims = listOfNotNull(
            optionalClaim(claimNames, EuPidScheme.Attributes.FAMILY_NAME, familyName),
            optionalClaim(claimNames, EuPidScheme.Attributes.GIVEN_NAME, givenName),
            optionalClaim(claimNames, EuPidScheme.Attributes.BIRTH_DATE, birthDate),
            optionalClaim(claimNames, EuPidScheme.Attributes.ISSUANCE_DATE, issuance),
            optionalClaim(claimNames, EuPidScheme.Attributes.EXPIRY_DATE, expiration),
            optionalClaim(claimNames, EuPidScheme.Attributes.ISSUING_COUNTRY, issuingCountry),
            optionalClaim(claimNames, EuPidScheme.Attributes.ISSUING_AUTHORITY, issuingCountry),
        )
        return when (representation) {
            ConstantIndex.CredentialRepresentation.SD_JWT -> CredentialToBeIssued.VcSd(claims, expiration)

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
                claims.mapIndexed { index, claim ->
                    issuerSignedItem(claim.name, claim.value, index.toUInt())
                },
                expiration,
            )
        }
    }

    private fun Collection<String>?.isNullOrContains(s: String) =
        this == null || contains(s)

    private fun optionalClaim(claimNames: Collection<String>?, name: String, value: Any) =
        if (claimNames.isNullOrContains(name)) ClaimToBeIssued(name, value) else null

    private fun issuerSignedItem(name: String, value: Any, digestId: UInt) = IssuerSignedItem(
        digestId = digestId,
        random = Random.nextBytes(16),
        elementIdentifier = name,
        elementValue = value
    )

    companion object {
        const val CLAIM_GIVEN_NAME = "given_name"
        const val CLAIM_PORTRAIT = "portrait"
    }
}

object DummyOAuth2DataProvider : OAuth2DataProvider {
    val user = OidcUserInfoExtended.fromOidcUserInfo(
        OidcUserInfo(
            subject = "subject",
            givenName = "Erika",
            familyName = "Musterfrau",
            picture = Random.nextBytes(64).encodeToString(Base64())
        )
    ).getOrThrow()

    override suspend fun loadUserInfo(request: AuthenticationRequestParameters, code: String) = user
}
