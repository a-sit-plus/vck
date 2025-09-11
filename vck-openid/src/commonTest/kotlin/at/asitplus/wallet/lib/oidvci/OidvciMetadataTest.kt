package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.nulls.shouldNotBeNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

class OidvciMetadataTest : FreeSpec({

    lateinit var authorizationService: SimpleAuthorizationService
    lateinit var issuer: CredentialIssuer

    beforeEach {
        authorizationService = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(setOf(AtomicAttribute2023, MobileDrivingLicenceScheme)),
        )
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(
                identifier = "https://issuer.example.com".toUri(),
                randomSource = RandomSource.Default
            ),
            credentialSchemes = setOf(AtomicAttribute2023, MobileDrivingLicenceScheme),
        )
    }

    "metadata for ISO_MDOC" {
        vckJsonSerializer.encodeToJsonElement(issuer.metadata).jsonObject.apply {
            get("credential_configurations_supported").shouldNotBeNull().jsonObject.apply {
                get("org.iso.18013.5.1").shouldNotBeNull().jsonObject.apply {
                    get("credential_signing_alg_values_supported").shouldNotBeNull().jsonArray.apply {
                        shouldHaveSingleElement(JsonPrimitive(-7))
                    }
                }
            }
        }
    }
})