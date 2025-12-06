package at.asitplus.wallet.lib.rqes

import at.asitplus.csc.contentEquals
import at.asitplus.iso.sha256
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QCertCreationAcceptance
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.signum.indispensable.Digest
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.ValidatorSdJwt
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.SdJwtConstants
import at.asitplus.wallet.lib.data.digest
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.toBase64UrlJsonString
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.AuthnResponseResult
import at.asitplus.wallet.lib.openid.ClientIdScheme
import at.asitplus.wallet.lib.openid.OpenId4VpHolder
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier
import at.asitplus.wallet.lib.rqes.helper.DummyCredentialDataProvider
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import io.ktor.utils.io.charsets.*
import io.ktor.utils.io.core.*

private fun malignTransactionData(): List<TransactionDataBase64Url> = listOf(
    QCertCreationAcceptance(
        credentialIds = setOf(),
        qcTermsConditionsUri = uuid4().toString(),
        qcHash = uuid4().bytes,
        qcHashAlgorithmOid = Digest.SHA256.oid,
    ).toBase64UrlJsonString()
)

val KeyBindingTests by testSuite {

    withFixtureGenerator(suspend {
        val holderKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
        val holderAgent: Holder = HolderAgent(holderKeyMaterial).also { agent ->
            agent.storeCredential(
                IssuerAgent(
                    identifier = "https://issuer.example.com/".toUri(),
                    randomSource = RandomSource.Default
                ).issueCredential(
                    DummyCredentialDataProvider.getCredential(holderKeyMaterial.publicKey, EuPidScheme, SD_JWT)
                        .getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            )
        }

        object {
            val holderOid4vp = OpenId4VpHolder(
                holder = holderAgent,
                randomSource = RandomSource.Default
            )
            val externalMapStore = DefaultMapStore<String, AuthenticationRequestParameters>()

            val walletUrl = "https://example.com/wallet/${uuid4()}"
            val clientId = "https://example.com/rp/${uuid4()}"
            val cibaWalletTransactionData = """
            eyJ0eXBlIjoicWNlcnRfY3JlYXRpb25fYWNjZXB0YW5jZSIsImNyZWRlbnRpYWxfaWRzIjpbIjYwNzUxMGE5LWM5NTctNDA5NS05MDZkLWY5
            OWZkMDA2YzRhZSJdLCJRQ190ZXJtc19jb25kaXRpb25zX3VyaSI6Imh0dHBzOi8vd3d3LmQtdHJ1c3QubmV0L2RlL2FnYiIsIlFDX2hhc2gi
            OiI3UXptNUVqdXpYS1NIRmxjME9IOVBQOXFVYUgtVkJsMmFHTmJ3WWoxb09BIiwiUUNfaGFzaEFsZ29yaXRobU9JRCI6IjIuMTYuODQwLjEu
            MTAxLjMuNC4yLjEiLCJ0cmFuc2FjdGlvbl9kYXRhX2hhc2hlc19hbGciOlsic2hhLTI1NiJdfQ
        """.trimIndent().replace("\n", "")

            val cibaWalletTestVector = """
                {
                    "response_type": "vp_token",
                    "client_id": "redirect_uri:$clientId",
                    "scope": "",
                    "state": "iTGlKl-AJxmncWPbXHp2xy58bNy18wqZ4TR9EzhBl2R4ulxeTEO0VyWYR2qMDpCDV5JWeOxecTqcEJ61bFKrUg",
                    "nonce": "f90d0982-52f4-4a1c-8525-bdf1d33c232b",
                    "client_metadata": {
                        "jwks_uri": "https://cibawallet.local-ip.medicmobile.org/wallet/jarm/iTGlKl-AJxmncWPbXHp2xy58bNy18wqZ4TR9EzhBl2R4ulxeTEO0VyWYR2qMDpCDV5JWeOxecTqcEJ61bFKrUg/jwks.json",
                        "id_token_signed_response_alg": "RS256",
                        "authorization_encrypted_response_alg": "ECDH-ES",
                        "authorization_encrypted_response_enc": "A128CBC-HS256",
                        "id_token_encrypted_response_alg": "RSA-OAEP-256",
                        "id_token_encrypted_response_enc": "A128CBC-HS256",
                        "subject_syntax_types_supported": [
                            "urn:ietf:params:oauth:jwk-thumbprint"
                        ],
                        "vp_formats": {
                            "dc+sd-jwt": {
                                "sd-jwt_alg_values": [
                                    "ES256"
                                ],
                                "kb-jwt_alg_values": [
                                    "ES256"
                                ]
                            },
                            "dc+sd-jwt": {
                                "sd-jwt_alg_values": [
                                    "ES256"
                                ],
                                "kb-jwt_alg_values": [
                                    "ES256"
                                ]
                            },
                            "mso_mdoc": {
                                "alg": [
                                    "ES256"
                                ]
                            }
                        }
                    },
                    "presentation_definition": {
                        "id": "4c7038cf-bd1e-47c0-8f70-eaf9d62c6fae",
                        "name": "Cibazmaj",
                        "purpose": "where su pare",
                        "input_descriptors": [
                            {
                                "id": "607510a9-c957-4095-906d-f99fd006c4ae",
                                "name": "niko kao",
                                "purpose": "hajduk iz splita",
                                "format": {
                                    "dc+sd-jwt": {
                                        "sd-jwt_alg_values": [
                                            "ES256"
                                        ],
                                        "kb-jwt_alg_values": [
                                            "ES256"
                                        ]
                                    }
                                },
                                "constraints": {
                                    "fields": [
                                        {
                                            "path": [
                                                "${'$'}.family_name"
                                            ]
                                        },
                                        {
                                            "path": [
                                                "${'$'}.given_name"
                                            ]
                                        },
                                        {
                                            "path": [
                                                "${'$'}.vct"
                                            ],
                                            "filter": {
                                                "type": "string",
                                                "enum": [
                                                    "urn:eu.europa.ec.eudi:pid:1"
                                                ]
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    "response_mode": "direct_post",
                    "response_uri": "https://cibawallet.local-ip.medicmobile.org/wallet/direct_post/iTGlKl-AJxmncWPbXHp2xy58bNy18wqZ4TR9EzhBl2R4ulxeTEO0VyWYR2qMDpCDV5JWeOxecTqcEJ61bFKrUg",
                    "aud": "https://self-issued.me/v2",
                    "iat": 1744198186,
                    "transaction_data": [
                        "eyJ0eXBlIjoicWNlcnRfY3JlYXRpb25fYWNjZXB0YW5jZSIsImNyZWRlbnRpYWxfaWRzIjpbIjYwNzUxMGE5LWM5NTctNDA5NS05MDZkLWY5OWZkMDA2YzRhZSJdLCJRQ190ZXJtc19jb25kaXRpb25zX3VyaSI6Imh0dHBzOi8vd3d3LmQtdHJ1c3QubmV0L2RlL2FnYiIsIlFDX2hhc2giOiI3UXptNUVqdXpYS1NIRmxjME9IOVBQOXFVYUgtVkJsMmFHTmJ3WWoxb09BIiwiUUNfaGFzaEFsZ29yaXRobU9JRCI6IjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiLCJ0cmFuc2FjdGlvbl9kYXRhX2hhc2hlc19hbGciOlsic2hhLTI1NiJdfQ"
                    ]
                }
            """.trimIndent()
        }
    }) - {

        "KB-JWT contains transaction data" {
            val verifierOid4Vp = OpenId4VpVerifier(
                keyMaterial = EphemeralKeyWithoutCert(),
                clientIdScheme = ClientIdScheme.RedirectUri(it.clientId),
                stateToAuthnRequestStore = it.externalMapStore
            )
            val requestOptions = buildRequestOptions(transactionDataHashAlgorithms = null)
            val authnRequest = verifierOid4Vp.createAuthnRequest(requestOptions)

            val authnRequestUrl = URLBuilder(it.walletUrl).apply {
                authnRequest.encodeToParameters()
                    .forEach { parameters.append(it.key, it.value) }
            }.buildString().apply {
                this shouldContain "transaction_data"
            }

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequestUrl).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            verifierOid4Vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
                .sdJwtSigned.keyBindingJws.shouldNotBeNull().payload.apply {
                    transactionDataHashes.shouldNotBeNull()
                    transactionDataHashes.contentEquals(requestOptions.transactionData!!.map { it.digest(Digest.SHA256) })
                    transactionDataHashesAlgorithmString.shouldBeNull()
                    transactionDataHashesAlgorithm.shouldBe(Digest.SHA256)
                }
        }

        "KB-JWT transaction data hashed with SHA384" {
            //[AuthenticationRequestParameters] do not contain [transactionData] in [presentationDefinition]
            val verifierOid4Vp = OpenId4VpVerifier(
                keyMaterial = EphemeralKeyWithoutCert(),
                clientIdScheme = ClientIdScheme.RedirectUri(it.clientId),
                stateToAuthnRequestStore = it.externalMapStore
            )
            val requestOptions = buildRequestOptions(transactionDataHashAlgorithms = setOf(SdJwtConstants.SHA_384))
            val authnRequest = verifierOid4Vp.createAuthnRequest(requestOptions)

            val authnRequestUrl = URLBuilder(it.walletUrl).apply {
                authnRequest.encodeToParameters()
                    .forEach { parameters.append(it.key, it.value) }
            }.buildString()

            authnRequestUrl shouldContain "transaction_data"

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequestUrl).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            val result = verifierOid4Vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()

            with(result.sdJwtSigned.keyBindingJws.shouldNotBeNull().payload) {
                transactionDataHashes.shouldNotBeNull()
                transactionDataHashes.contentEquals(requestOptions.transactionData!!.map { it.digest(Digest.SHA384) })
                transactionDataHashesAlgorithmString.shouldBe(SdJwtConstants.SHA_384)
            }
        }

        "Incorrect TransactionData is rejected" {
            val verifierOid4Vp = OpenId4VpVerifier(
                keyMaterial = EphemeralKeyWithoutCert(),
                clientIdScheme = ClientIdScheme.RedirectUri(it.clientId),
                stateToAuthnRequestStore = it.externalMapStore
            )
            val requestOptions =
                buildRequestOptions(OpenIdConstants.ResponseMode.DirectPost, setOf(SdJwtConstants.SHA_256))
            val authnRequest = verifierOid4Vp.createAuthnRequest(requestOptions)

            val malignResponse = it.holderOid4vp.createAuthnResponse(
                vckJsonSerializer.encodeToString(
                    authnRequest.copy(
                        transactionData = malignTransactionData()
                    )
                )
            ).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            verifierOid4Vp.validateAuthnResponse(malignResponse.params.formUrlEncode())
                .shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
        }

        "Transaction Data validation can be turned off" {
            val clientIdScheme = ClientIdScheme.RedirectUri(it.clientId)
            val lenientVerifier = OpenId4VpVerifier(
                keyMaterial = EphemeralKeyWithoutCert(),
                clientIdScheme = clientIdScheme,
                stateToAuthnRequestStore = it.externalMapStore,
                verifier = VerifierAgent(
                    identifier = clientIdScheme.clientId,
                    validatorSdJwt = ValidatorSdJwt(verifyTransactionData = false)
                )
            )

            val requestOptions = buildRequestOptions(OpenIdConstants.ResponseMode.DirectPost, null)
            val authnRequest = lenientVerifier.createAuthnRequest(requestOptions)

            val malignResponse = it.holderOid4vp.createAuthnResponse(
                vckJsonSerializer.encodeToString(
                    authnRequest.copy(
                        transactionData = malignTransactionData()
                    )
                )
            ).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            lenientVerifier.validateAuthnResponse(malignResponse.params.formUrlEncode())
                .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
        }

        "Hash of transaction data is not changed during processing" {
            val referenceHash = it.cibaWalletTransactionData.toByteArray(Charsets.UTF_8).sha256()

            val verifierOid4Vp = OpenId4VpVerifier(
                keyMaterial = EphemeralKeyWithoutCert(),
                clientIdScheme = ClientIdScheme.RedirectUri(it.clientId),
                stateToAuthnRequestStore = it.externalMapStore
            )

            val state = it.holderOid4vp.startAuthorizationResponsePreparation(it.cibaWalletTestVector)
                .getOrThrow().apply {
                    request.parameters.transactionData.shouldNotBeEmpty().shouldNotBeNull()
                }

            it.externalMapStore.put(
                "iTGlKl-AJxmncWPbXHp2xy58bNy18wqZ4TR9EzhBl2R4ulxeTEO0VyWYR2qMDpCDV5JWeOxecTqcEJ61bFKrUg",
                state.request.parameters
            )

            val authnResponse = it.holderOid4vp.createAuthnResponse(state.request).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            verifierOid4Vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
                .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
                .sdJwtSigned.keyBindingJws.shouldNotBeNull().payload.transactionDataHashes!!.first()
                .shouldBe(referenceHash)
        }
    }
}
