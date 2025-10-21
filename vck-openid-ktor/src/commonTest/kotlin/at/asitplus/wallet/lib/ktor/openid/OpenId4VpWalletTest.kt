package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.dcapi.request.DCAPIWalletRequest
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants.ResponseMode
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NameSegment
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLClaimsQueryResult.IsoMdocResult
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.ClaimsQueryResults
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialPresentation.DCQLPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.DCQLRequest
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.AuthnResponseResult
import at.asitplus.wallet.lib.openid.AuthnResponseResult.SuccessIso
import at.asitplus.wallet.lib.openid.AuthnResponseResult.SuccessSdJwt
import at.asitplus.wallet.lib.openid.ClientIdScheme
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier.CreationOptions
import at.asitplus.wallet.lib.openid.OpenId4VpRequestOptions
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.github.aakira.napier.Napier
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.engine.*
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.util.toMap
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes


val OpenId4VpWalletTest by testSuite {

    withFixtureGenerator {
        object {
            val countdownLatch = Mutex(true)
            val keyMaterial = EphemeralKeyWithoutCert()
            val holderAgent = HolderAgent(keyMaterial)
            lateinit var wallet: OpenId4VpWallet
            lateinit var url: String
            lateinit var mockEngine: HttpClientEngine

            suspend fun setup(
                scheme: ConstantIndex.CredentialScheme,
                representation: ConstantIndex.CredentialRepresentation,
                attributes: Map<String, String>,
                responseMode: ResponseMode,
                clientId: String,
                storeCredentials: Boolean = true,
            ) {
                val requestOptions = OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(
                            credentialScheme = scheme,
                            representation = representation,
                            requestedAttributes = attributes.keys
                        )
                    ),
                    responseMode = responseMode,
                )
                if (storeCredentials)
                    storeMockCredentials(scheme, representation, attributes)
                setupRelyingPartyService(clientId, requestOptions) {
                    verifyReceivedAttributes(it, attributes)
                }
                setupWallet(this.mockEngine)
            }

            fun setupWallet(engine: HttpClientEngine) = OpenId4VpWallet(
                engine = engine,
                keyMaterial = keyMaterial,
                holderAgent = holderAgent,
            ).also { this.wallet = it }

            fun verifyReceivedAttributes(
                authnResponseResult: AuthnResponseResult,
                expectedAttributes: Map<String, String>
            ) {
                if (authnResponseResult.containsAllAttributes(expectedAttributes)) {
                    countdownLatch.unlock()
                }
            }

            suspend fun storeMockCredentials(
                scheme: ConstantIndex.CredentialScheme,
                representation: ConstantIndex.CredentialRepresentation,
                attributes: Map<String, Any>,
            ) = holderAgent.storeCredential(
                IssuerAgent(
                    keyMaterial = EphemeralKeyWithSelfSignedCert(),
                    identifier = "https://issuer.example.com/".toUri(),
                    randomSource = RandomSource.Default
                ).issueCredential(
                    representation.toCredentialToBeIssued(scheme, attributes)
                ).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()

            fun ConstantIndex.CredentialRepresentation.toCredentialToBeIssued(
                scheme: ConstantIndex.CredentialScheme,
                attributes: Map<String, Any>,
            ): CredentialToBeIssued = when (this) {
                SD_JWT -> CredentialToBeIssued.VcSd(
                    claims = attributes.map { it.toClaimToBeIssued() },
                    expiration = Clock.System.now().plus(1.minutes),
                    scheme = scheme,
                    subjectPublicKey = keyMaterial.publicKey,
                    userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                    sdAlgorithm = supportedSdAlgorithms.random()
                )

                ISO_MDOC -> CredentialToBeIssued.Iso(
                    issuerSignedItems = attributes.map { it.toIssuerSignedItem() },
                    expiration = Clock.System.now().plus(1.minutes),
                    scheme = scheme,
                    subjectPublicKey = keyMaterial.publicKey,
                    userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                )

                else -> TODO()
            }

            /**
             * Setup the mock relying party service, for getting requests (referenced by `request_uri`) and to decode posted
             * authentication responses
             */
            suspend fun setupRelyingPartyService(
                clientId: String,
                requestOptions: OpenId4VpRequestOptions,
                validate: (AuthnResponseResult) -> Unit,
            ) {
                val requestEndpointPath = "/request/${uuid4()}"
                val redirectUri = "http://rp.example.com/cb"
                val verifier = OpenId4VpVerifier(
                    clientIdScheme = ClientIdScheme.PreRegistered(clientId, redirectUri),
                )
                val responseEndpointPath = "/response"
                val (url, jar) = verifier.createAuthnRequest(
                    requestOptions.copy(responseUrl = responseEndpointPath),
                    CreationOptions.SignedRequestByReference(
                        "http://wallet.example.com/",
                        "http://rp.example.com$requestEndpointPath"
                    )
                ).getOrThrow()
                jar.shouldNotBeNull()

                this.mockEngine = MockEngine { request ->
                    when {
                        request.url.fullPath.startsWith(requestEndpointPath) -> {
                            val requestBody = request.body.toByteArray().decodeToString()
                            val queryParameters: Map<String, String> =
                                request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                            val requestObjectParameters = if (requestBody.isNotEmpty())
                                requestBody.decodeFromPostBody<RequestObjectParameters>()
                            else RequestObjectParameters(
                                walletMetadataString = queryParameters["wallet_metadata"],
                                walletNonce = queryParameters["wallet_nonce"]
                            )
                            respond(jar.invoke(requestObjectParameters).getOrThrow())
                        }

                        request.url.fullPath.startsWith(responseEndpointPath) or request.url.toString()
                            .startsWith(redirectUri) -> {
                            val requestBody = request.body.toByteArray().decodeToString()
                            val result =
                                if (requestBody.isNotEmpty()) verifier.validateAuthnResponse(requestBody)
                                else verifier.validateAuthnResponse(request.url.toString())
                            validate(result)
                            respondOk()
                        }

                        else -> respondError(HttpStatusCode.NotFound)
                            .also { Napier.w("NOT MATCHED ${request.url.fullPath}") }
                    }
                }
                this.url = url
            }

        }
    } - {

        test("presentEuPidCredentialSdJwtDirectPost") {
            it.setup(
                scheme = EuPidScheme,
                representation = SD_JWT,
                attributes = mapOf(
                    EuPidScheme.Attributes.FAMILY_NAME to randomString()
                ),
                responseMode = ResponseMode.DirectPost,
                clientId = uuid4().toString()
            )

            val state = it.wallet.startAuthorizationResponsePreparation(it.url).getOrThrow()
            // sends the response to the mock RP, which calls verifyReceivedAttributes, which unlocks the latch
            it.wallet.finalizeAuthorizationResponse(state).getOrThrow()
                .shouldBeInstanceOf<OpenId4VpWallet.AuthenticationSuccess>()
                .redirectUri?.let { uri -> HttpClient(it.mockEngine).get(uri) }

            assertPresentation(it.countdownLatch)
        }


        test("presentEuPidCredentialIsoQuery") {
            it.setup(
                scheme = EuPidScheme,
                representation = ISO_MDOC,
                attributes = mapOf(
                    EuPidScheme.Attributes.GIVEN_NAME to randomString()
                ),
                responseMode = ResponseMode.Query,
                clientId = uuid4().toString()
            )

            val state = it.wallet.startAuthorizationResponsePreparation(it.url).getOrThrow()
            // sends the response to the mock RP, which calls verifyReceivedAttributes, which unlocks the latch
            it.wallet.finalizeAuthorizationResponse(state).getOrThrow()
                .shouldBeInstanceOf<OpenId4VpWallet.AuthenticationSuccess>()
                .redirectUri?.let { uri -> HttpClient(it.mockEngine).get(uri) }

            assertPresentation(it.countdownLatch)
        }

        test("DC API") {
            it.setupWallet(HttpClient().engine)

            val attributes = mapOf(
                "family_name" to "XXXMûstérfřău",
                "given_name" to "XXXĤáčęk Elfriede Hàčêk",
                "age_over_21" to true
            )

            val credential = it.storeMockCredentials(MobileDrivingLicenceScheme, ISO_MDOC, attributes)

            val dcqlQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    list = nonEmptyListOf(
                        DCQLIsoMdocCredentialQuery(
                            id = DCQLCredentialQueryIdentifier("cred1"),
                            format = CredentialFormatEnum.MSO_MDOC,
                            meta = DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                                doctypeValue = MobileDrivingLicenceScheme.isoDocType
                            ),
                            claims = DCQLClaimsQueryList(
                                list = nonEmptyListOf(
                                    DCQLIsoMdocClaimsQuery(
                                        path = DCQLClaimsPathPointer(
                                            nonEmptyListOf(
                                                NameSegment("org.iso.18013.5.1"),
                                                NameSegment("family_name")
                                            )
                                        ),
                                    ),
                                    DCQLIsoMdocClaimsQuery(
                                        path = DCQLClaimsPathPointer(
                                            nonEmptyListOf(
                                                NameSegment("org.iso.18013.5.1"),
                                                NameSegment("given_name")
                                            )
                                        ),
                                    ),
                                    DCQLIsoMdocClaimsQuery(
                                        id = null,
                                        values = null,
                                        path = DCQLClaimsPathPointer(
                                            nonEmptyListOf(
                                                NameSegment("org.iso.18013.5.1"),
                                                NameSegment("age_over_21")
                                            )
                                        ),
                                    )
                                )
                            ),
                        )
                    )
                ),
            )

            val matchingResult = ClaimsQueryResults(
                claimsQueryResults = listOf(
                    IsoMdocResult(
                        namespace = "org.iso.18013.5.1",
                        claimName = "family_name",
                        claimValue = "XXXMûstérfřău"
                    ),
                    IsoMdocResult(
                        namespace = "org.iso.18013.5.1",
                        claimName = "given_name",
                        claimValue = "XXXĤáčęk Elfriede Hàčêk"
                    ),
                    IsoMdocResult(
                        namespace = "org.iso.18013.5.1",
                        claimName = "age_over_21",
                        claimValue = true
                    )
                )
            )

                val credentialQuerySubmissions = mapOf(
                    DCQLCredentialQueryIdentifier("cred1") to listOf(
                        DCQLCredentialSubmissionOption(
                            credential = credential,
                            matchingResult = matchingResult
                        )
                    )
                )

            // TODO test with signed request
            val request = """
                    {
                       "client_metadata" : {
                          "vp_formats_supported" : {
                             "mso_mdoc" : {
                                "deviceauth_alg_values" : [
                                   -7
                                ],
                                "issuerauth_alg_values" : [
                                   -7
                                ]
                             }
                          }
                       },
                       "dcql_query" : {
                          "credentials" : [
                             {
                                "claims" : [
                                   {
                                      "path" : [
                                         "org.iso.18013.5.1",
                                         "family_name"
                                      ]
                                   },
                                   {
                                      "path" : [
                                         "org.iso.18013.5.1",
                                         "given_name"
                                      ]
                                   },
                                   {
                                      "path" : [
                                         "org.iso.18013.5.1",
                                         "age_over_21"
                                      ]
                                   }
                                ],
                                "format" : "mso_mdoc",
                                "id" : "cred1",
                                "meta" : {
                                   "doctype_value" : "org.iso.18013.5.1.mDL"
                                }
                             }
                          ]
                       },
                       "nonce" : "4mqexiA_rQQyzHOYkuW6-BrHKaza02b8JHFVoyB5Iw8",
                       "response_mode" : "dc_api",
                       "response_type" : "vp_token"
                    }
                    """.trimIndent()
            val dcApiRequest = DCAPIWalletRequest.OpenId4VpUnsigned(
                request = vckJsonSerializer.decodeFromString(request),
                credentialId = "c72a2a8a6e94564cd8dea6ef0c7eb47b31a31947620ebcc0f07177bb71078def",
                callingPackageName = "com.android.chrome",
                callingOrigin = "https://apps.egiz.gv.at/customverifier"
            )

            val preparationState = it.wallet.startAuthorizationResponsePreparation(dcApiRequest).getOrThrow()
            val presentation = DCQLPresentation(DCQLRequest(dcqlQuery), credentialQuerySubmissions)
            it.wallet.finalizeAuthorizationResponse(preparationState, presentation)
                .getOrThrow()
                .shouldBeInstanceOf<OpenId4VpWallet.AuthenticationForward>()
                .authenticationResponseResult.shouldBeInstanceOf<AuthenticationResponseResult.DcApi>().apply {
                    val responseJson = vckJsonSerializer.encodeToString(
                        AuthenticationResponseParameters.serializer(),
                        params.data
                    )
                    responseJson shouldContain "\"vp_token\""
                    responseJson shouldContain "\"cred1\""
                }
        }

        test("No matching credential test") {
            it.setup(
                scheme = EuPidScheme,
                representation = ISO_MDOC,
                attributes = mapOf(
                    EuPidScheme.Attributes.GIVEN_NAME to randomString()
                ),
                responseMode = ResponseMode.Query,
                clientId = uuid4().toString(),
                storeCredentials = false
            )

            val preparationState = it.wallet.startAuthorizationResponsePreparation(it.url).getOrThrow()
            shouldThrow<OAuth2Exception.AccessDenied> {
                it.wallet.getMatchingCredentials(preparationState).getOrThrow()
            }
        }
    }
}

private fun Map.Entry<String, Any>.toClaimToBeIssued(): ClaimToBeIssued = ClaimToBeIssued(key, value)

private fun Map.Entry<String, Any>.toIssuerSignedItem(): IssuerSignedItem =
    IssuerSignedItem(0U, Random.nextBytes(16), key, value)


private fun AuthnResponseResult.containsAllAttributes(expectedAttributes: Map<String, String>): Boolean =
    when (this) {
        is SuccessSdJwt -> this.containsAllAttributes(expectedAttributes)
        is SuccessIso -> this.containsAllAttributes(expectedAttributes)
        else -> false
    }

private fun SuccessSdJwt.containsAllAttributes(attributes: Map<String, String>): Boolean =
    attributes.all { containsAttribute(it) }

private fun SuccessSdJwt.containsAttribute(attribute: Map.Entry<String, String>): Boolean =
    disclosures.toList().any { it.matchesAttribute(attribute) }

private fun SuccessIso.containsAllAttributes(attributes: Map<String, String>): Boolean =
    attributes.all { containsAttribute(it) }

private fun SuccessIso.containsAttribute(attribute: Map.Entry<String, String>): Boolean =
    documents.any { doc -> doc.validItems.any { it.matchesAttribute(attribute) } }

private fun SelectiveDisclosureItem.matchesAttribute(attribute: Map.Entry<String, String>): Boolean =
    claimName == attribute.key && claimValue.jsonPrimitive.content == attribute.value

private fun IssuerSignedItem.matchesAttribute(attribute: Map.Entry<String, String>): Boolean =
    elementIdentifier == attribute.key && elementValue.toString() == attribute.value

// If the countdownLatch has been unlocked, the correct credential has been posted to the RP, and we're done!
private suspend fun assertPresentation(countdownLatch: Mutex) {
    withContext(Dispatchers.Default.limitedParallelism(1)) {
        withTimeout(5000) {
            countdownLatch.lock()
        }
    }
}


private fun randomString(): String = Random.nextBytes(32).encodeToString(Base16)
