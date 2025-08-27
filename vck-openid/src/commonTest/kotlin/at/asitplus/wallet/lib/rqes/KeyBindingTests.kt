package io.kotest.provided.at.asitplus.wallet.lib.rqes

import at.asitplus.iso.sha256
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QCertCreationAcceptance
import at.asitplus.csc.contentEquals
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.toBase64UrlJsonString
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidvci.DefaultMapStore
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.openid.*
import io.kotest.provided.at.asitplus.wallet.lib.rqes.helper.DummyCredentialDataProvider
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

class KeyBindingTests : FreeSpec({

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder

    val externalMapStore = DefaultMapStore<String, AuthenticationRequestParameters>()

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        holderAgent = HolderAgent(holderKeyMaterial)
        holderAgent.storeCredential(
            IssuerAgent(
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            ).issueCredential(
                DummyCredentialDataProvider.getCredential(holderKeyMaterial.publicKey, EuPidScheme, SD_JWT)
                    .getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )
        holderOid4vp = OpenId4VpHolder(holder = holderAgent, randomSource = RandomSource.Default)
    }

    "Rqes Request with EU PID credential" - {
        val walletUrl = "https://example.com/wallet/${uuid4()}"
        val clientId = "https://example.com/rp/${uuid4()}"
        val rqesVerifier = OpenId4VpVerifier(
            keyMaterial = EphemeralKeyWithoutCert(),
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
            stateToAuthnRequestStore = externalMapStore
        )

        val cibaWalletTransactionData = """
                    eyJ0eXBlIjoicWNlcnRfY3JlYXRpb25fYWNjZXB0YW5jZSIsImNyZWRlbnRpYWxfaWRzIjpbIjYwNzUxMGE5LWM5NTctNDA5NS05MDZkLWY5OWZkMDA2YzRhZSJdLCJRQ190ZXJtc19jb25kaXRpb25zX3VyaSI6Imh0dHBzOi8vd3d3LmQtdHJ1c3QubmV0L2RlL2FnYiIsIlFDX2hhc2giOiI3UXptNUVqdXpYS1NIRmxjME9IOVBQOXFVYUgtVkJsMmFHTmJ3WWoxb09BIiwiUUNfaGFzaEFsZ29yaXRobU9JRCI6IjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiLCJ0cmFuc2FjdGlvbl9kYXRhX2hhc2hlc19hbGciOlsic2hhLTI1NiJdfQ
                """.trimIndent()

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
                            "vc+sd-jwt": {
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
                                    "vc+sd-jwt": {
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

        "KB-JWT contains transaction data" {
            //[AuthenticationRequestParameters] do not contain [transactionData] in [presentationDefinition]
            val requestOptions = buildRequestOptions()
            val authnRequest = rqesVerifier.createAuthnRequest(requestOptions)

            val authnRequestUrl = URLBuilder(walletUrl).apply {
                authnRequest.encodeToParameters()
                    .forEach { parameters.append(it.key, it.value) }
            }.buildString()

            authnRequestUrl shouldContain "transaction_data"

            val authnResponse = holderOid4vp.createAuthnResponse(authnRequestUrl).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            val result = rqesVerifier.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()

            with(result.sdJwtSigned.keyBindingJws.shouldNotBeNull().payload) {
                transactionDataHashes.shouldNotBeNull()
                transactionDataHashes.contentEquals(requestOptions.transactionData!!.getReferenceHashes())
                transactionDataHashesAlgorithm.shouldNotBeNull()
            }
        }

        "Incorrect TransactionData is rejected" {
            val requestOptions = buildRequestOptions(OpenIdConstants.ResponseMode.DirectPost)
            val authnRequest = rqesVerifier.createAuthnRequest(requestOptions)

            val malignResponse = holderOid4vp.createAuthnResponse(
                vckJsonSerializer.encodeToString(
                    authnRequest.copy(
                        transactionData = listOf(
                            QCertCreationAcceptance(
                                qcTermsConditionsUri = uuid4().toString(),
                                qcHash = uuid4().bytes,
                                qcHashAlgorithmOid = Digest.SHA256.oid,
                            ).toBase64UrlJsonString()
                        )
                    )
                )
            ).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            val result = rqesVerifier.validateAuthnResponse(malignResponse.params)
            result.shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
        }

        "Transaction Data validation can be turned off" {
            val clientIdScheme = ClientIdScheme.RedirectUri(clientId)
            val lenientVerifier = OpenId4VpVerifier(
                keyMaterial = EphemeralKeyWithoutCert(),
                clientIdScheme = clientIdScheme,
                stateToAuthnRequestStore = externalMapStore,
                verifier = VerifierAgent(
                    identifier = clientIdScheme.clientId,
                    validatorSdJwt = ValidatorSdJwt(verifyTransactionData = false)
                )
            )

            val requestOptions = buildRequestOptions(OpenIdConstants.ResponseMode.DirectPost)
            val authnRequest = lenientVerifier.createAuthnRequest(requestOptions)

            val malignResponse = holderOid4vp.createAuthnResponse(
                vckJsonSerializer.encodeToString(
                    authnRequest.copy(
                        transactionData = listOf(
                            QCertCreationAcceptance(
                                qcTermsConditionsUri = uuid4().toString(),
                                qcHash = uuid4().bytes,
                                qcHashAlgorithmOid = Digest.SHA256.oid,
                            ).toBase64UrlJsonString()
                        )
                    )
                )
            ).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            lenientVerifier.validateAuthnResponse(malignResponse.params)
                .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
        }

        "Hash of transaction data is not changed during processing" {
            val referenceHash = cibaWalletTransactionData.decodeToByteArray(Base64UrlStrict).sha256()

            val authenticationRequest =
                holderOid4vp.parseAuthenticationRequestParameters(cibaWalletTestVector).getOrThrow()
            authenticationRequest.parameters.transactionData.shouldNotBeEmpty().shouldNotBeNull()

            externalMapStore.put(
                "iTGlKl-AJxmncWPbXHp2xy58bNy18wqZ4TR9EzhBl2R4ulxeTEO0VyWYR2qMDpCDV5JWeOxecTqcEJ61bFKrUg",
                authenticationRequest.parameters
            )

            val authnResponse = holderOid4vp.createAuthnResponse(authenticationRequest).getOrThrow()
            authnResponse shouldNotBe null
            authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            val result = rqesVerifier.validateAuthnResponse(authnResponse.params)
            result.shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
            result.sdJwtSigned.keyBindingJws.shouldNotBeNull().payload.transactionDataHashes!!.first()
                .contentEquals(referenceHash)
        }
    }
})