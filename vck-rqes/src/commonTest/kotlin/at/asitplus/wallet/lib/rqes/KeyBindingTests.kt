package at.asitplus.wallet.lib.rqes

import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.rqes.collection_entries.QesAuthorization
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.toDataclass
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.openid.*
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier.CreationOptions.Query
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

class KeyBindingTests : FreeSpec({

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var requestOptions: RqesRequestOptions
    lateinit var transactionDataReferenceHashes: List<ByteArray>

    beforeContainer {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        holderAgent = HolderAgent(holderKeyMaterial)

        holderAgent.storeCredential(
            IssuerAgent().issueCredential(
                DummyCredentialDataProvider.getCredential(holderKeyMaterial.publicKey, EuPidScheme, SD_JWT)
                    .getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
        )

        requestOptions = buildRqesRequestOptions()
        transactionDataReferenceHashes = requestOptions.transactionData!!.getReferenceHashes()
    }

    "Rqes Request with EU PID credential" - {
        val walletUrl = "https://example.com/wallet/${uuid4()}"
        val clientId = "https://example.com/rp/${uuid4()}"
        val rqesVerifier = OpenId4VpVerifier(
            keyMaterial = EphemeralKeyWithoutCert(),
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
        )

        "KB-JWT contains transaction data" - {
            "OID4VP" {
                //[AuthenticationRequestParameter] do not contain [transactionData] in [presentationDefinition]
                val rawRequest = rqesVerifier.createAuthnRequest(requestOptions)
                val newInputDescriptors = rawRequest.presentationDefinition!!.inputDescriptors.map {
                    (it as QesInputDescriptor).copy(transactionData = null)
                }
                val authnRequest =
                    rawRequest.copy(presentationDefinition = rawRequest.presentationDefinition!!.copy(inputDescriptors = newInputDescriptors))

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
                    transactionData.shouldBeNull()
                    transactionDataHashes.shouldNotBeNull()
                    transactionDataHashes!!.first().contentEquals(transactionDataReferenceHashes.first())
                    transactionDataHashesAlgorithm.shouldNotBeNull()
                }
            }

            "UC5" {
                //[AuthenticationRequestParameter] do not contain [transactionData] directly
                val authnRequest = rqesVerifier.createAuthnRequest(requestOptions).copy(transactionData = null)

                val authnRequestUrl = URLBuilder(walletUrl).apply {
                    authnRequest.encodeToParameters()
                        .forEach { parameters.append(it.key, it.value) }
                }.buildString()

                val authnResponse = holderOid4vp.createAuthnResponse(authnRequestUrl).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

                val result = rqesVerifier.validateAuthnResponse(authnResponse.url)
                    .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()

                val originalTransactionData = (requestOptions.transactionData!!.first() as QesAuthorization).copy(
                    transactionDataHashAlgorithms = null,
                    credentialIds = null
                )
                with(result.sdJwtSigned.keyBindingJws.shouldNotBeNull().payload) {
                    transactionData.shouldNotBeNull()
                    transactionData!!.first().toDataclass() shouldBe originalTransactionData
                    transactionDataHashes.shouldBeNull()
                    transactionDataHashesAlgorithm.shouldBeNull()
                }
            }

            "Generic" {
                //[AuthenticationRequestParameter] contain both versions - in this case prefer OID4VP
                val authnRequestUrl = rqesVerifier.createAuthnRequest(requestOptions, Query(walletUrl)).getOrThrow().url

                val authnResponse = holderOid4vp.createAuthnResponse(authnRequestUrl).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

                val result = rqesVerifier.validateAuthnResponse(authnResponse.url)
                    .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()

                with(result.sdJwtSigned.keyBindingJws.shouldNotBeNull().payload) {
                    transactionData.shouldBeNull()
                    transactionDataHashes.shouldNotBeNull()
                    transactionDataHashes!!.shouldHaveSize(2)
                    transactionDataHashes!!.first().contentEquals(transactionDataReferenceHashes.first())
                    transactionDataHashesAlgorithm.shouldNotBeNull()
                }
            }
        }

        "Hash of transaction data is not changed during processing" {
            val germanTestVectorJwt = """
            eyJ4NWMiOlsiTUlJRFp6Q0NBdTZnQXdJQkFnSVVDMEV5a0ZlclpPSDlieGZVTVpnRkNWOFgrSlF3Q2dZSUtvWkl6ajBFQXdJd1hERWVNQndHQTFVRUF3d1ZVRWxFSUVsemMzVmxjaUJEUVNBdElGVlVJREF4TVMwd0t3WURWUVFLRENSRlZVUkpJRmRoYkd4bGRDQlNaV1psY21WdVkyVWdTVzF3YkdWdFpXNTBZWFJwYjI0eEN6QUpCZ05WQkFZVEFsVlVNQjRYRFRJMU1ESXlOakE0TkRRek9Gb1hEVEkzTURJeU5qQTRORFF6TjFvd2VURXNNQ29HQTFVRUF3d2pZMmxpWVhkaGJHeGxkQzVzYjJOaGJDMXBjQzV0WldScFkyMXZZbWxzWlM1dmNtY3hEakFNQmdOVkJBVVRCVEl3TURBd01Td3dLZ1lEVlFRS0RDTmphV0poZDJGc2JHVjBMbXh2WTJGc0xXbHdMbTFsWkdsamJXOWlhV3hsTG05eVp6RUxNQWtHQTFVRUJoTUNWVlF3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVNXdkFwbVVUYjlEejBGMWdmYjVXeVhzdXNYY0dtb045ZEltb0FWU0pYWEN3MysyOE5hbGVDU2M0UDBJdmRpcm9nSHExajh5RjQ2K0V4blFSY2REdVRLbzRJQmJ6Q0NBV3N3REFZRFZSMFRBUUgvQkFJd0FEQWZCZ05WSFNNRUdEQVdnQlN6YkxpUkZ4elhwQnBtTVlkQzRZdkFRTXlWR3pCVEJnTlZIUkVFVERCS2dTTnRZWEpwYnk1amFXSmhjbWxqUUcxaGRYSmxjaTFsYkdWamRISnZibWxqY3k1b2NvSWpZMmxpWVhkaGJHeGxkQzVzYjJOaGJDMXBjQzV0WldScFkyMXZZbWxzWlM1dmNtY3dFZ1lEVlIwbEJBc3dDUVlIS0lHTVhRVUJCakJEQmdOVkhSOEVQREE2TURpZ05xQTBoakpvZEhSd2N6b3ZMM0J5WlhCeWIyUXVjR3RwTG1WMVpHbDNMbVJsZGk5amNtd3ZjR2xrWDBOQlgxVlVYekF4TG1OeWJEQWRCZ05WSFE0RUZnUVV1SnVSbGdYdmpsQWg5elovUzdMcFVzdUc4bkF3RGdZRFZSMFBBUUgvQkFRREFnZUFNRjBHQTFVZEVnUldNRlNHVW1oMGRIQnpPaTh2WjJsMGFIVmlMbU52YlM5bGRTMWthV2RwZEdGc0xXbGtaVzUwYVhSNUxYZGhiR3hsZEM5aGNtTm9hWFJsWTNSMWNtVXRZVzVrTFhKbFptVnlaVzVqWlMxbWNtRnRaWGR2Y21zd0NnWUlLb1pJemowRUF3SURad0F3WkFJd0taaXVOSUdvRGxuZERoVEdna2NNMEFCcFhES1o5bVQ0b0dzVDVlbUZhbXNzT3daOEMzcXI2TlpValhSUUN6LzhBakJxSDlSYWROUW85M3FNbHA1UGhwYVB2NWhaRWgrbmtrZ214cDV5Sks4dytZTlhndERqckN2R3pESmlDbkU1aUlrPSJdLCJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRVMyNTYifQ.eyJyZXNwb25zZV91cmkiOiJodHRwczovL2NpYmF3YWxsZXQubG9jYWwtaXAubWVkaWNtb2JpbGUub3JnL3dhbGxldC9kaXJlY3RfcG9zdC9pVEdsS2wtQUp4bW5jV1BiWEhwMnh5NThiTnkxOHdxWjRUUjlFemhCbDJSNHVseGVURU8wVnlXWVIycU1EcENEVjVKV2VPeGVjVHFjRUo2MWJGS3JVZyIsInRyYW5zYWN0aW9uX2RhdGEiOlsiZXlKMGVYQmxJam9pY1dObGNuUmZZM0psWVhScGIyNWZZV05qWlhCMFlXNWpaU0lzSW1OeVpXUmxiblJwWVd4ZmFXUnpJanBiSWpZd056VXhNR0U1TFdNNU5UY3ROREE1TlMwNU1EWmtMV1k1T1daa01EQTJZelJoWlNKZExDSlJRMTkwWlhKdGMxOWpiMjVrYVhScGIyNXpYM1Z5YVNJNkltaDBkSEJ6T2k4dmQzZDNMbVF0ZEhKMWMzUXVibVYwTDJSbEwyRm5ZaUlzSWxGRFgyaGhjMmdpT2lJM1VYcHROVVZxZFhwWVMxTklSbXhqTUU5SU9WQlFPWEZWWVVndFZrSnNNbUZIVG1KM1dXb3hiMDlCSWl3aVVVTmZhR0Z6YUVGc1oyOXlhWFJvYlU5SlJDSTZJakl1TVRZdU9EUXdMakV1TVRBeExqTXVOQzR5TGpFaUxDSjBjbUZ1YzJGamRHbHZibDlrWVhSaFgyaGhjMmhsYzE5aGJHY2lPbHNpYzJoaExUSTFOaUpkZlEiXSwicmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIiwibm9uY2UiOiJmOTBkMDk4Mi01MmY0LTRhMWMtODUyNS1iZGYxZDMzYzIzMmIiLCJjbGllbnRfaWQiOiJ4NTA5X3Nhbl9kbnM6Y2liYXdhbGxldC5sb2NhbC1pcC5tZWRpY21vYmlsZS5vcmciLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3Quand0IiwiYXVkIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZS92MiIsInNjb3BlIjoiIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiI0YzcwMzhjZi1iZDFlLTQ3YzAtOGY3MC1lYWY5ZDYyYzZmYWUiLCJuYW1lIjoiQ2liYXptYWoiLCJwdXJwb3NlIjoid2hlcmUgc3UgcGFyZSIsImlucHV0X2Rlc2NyaXB0b3JzIjpbeyJpZCI6IjYwNzUxMGE5LWM5NTctNDA5NS05MDZkLWY5OWZkMDA2YzRhZSIsIm5hbWUiOiJuaWtvIGthbyIsInB1cnBvc2UiOiJoYWpkdWsgaXogc3BsaXRhIiwiZm9ybWF0Ijp7InZjK3NkLWp3dCI6eyJzZC1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiJdLCJrYi1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiJdfX0sImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLmZhbWlseV9uYW1lIl19LHsicGF0aCI6WyIkLmdpdmVuX25hbWUiXX0seyJwYXRoIjpbIiQuYmlydGhfZGF0ZSJdfSx7InBhdGgiOlsiJC52Y3QiXSwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJlbnVtIjpbInVybjpldS5ldXJvcGEuZWMuZXVkaTpwaWQ6MSJdfX1dfX1dfSwic3RhdGUiOiJpVEdsS2wtQUp4bW5jV1BiWEhwMnh5NThiTnkxOHdxWjRUUjlFemhCbDJSNHVseGVURU8wVnlXWVIycU1EcENEVjVKV2VPeGVjVHFjRUo2MWJGS3JVZyIsImlhdCI6MTc0NDE5ODE4NiwiY2xpZW50X21ldGFkYXRhIjp7ImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IkVDREgtRVMiLCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMTI4Q0JDLUhTMjU2IiwiaWRfdG9rZW5fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IlJTQS1PQUVQLTI1NiIsImlkX3Rva2VuX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiandrc191cmkiOiJodHRwczovL2NpYmF3YWxsZXQubG9jYWwtaXAubWVkaWNtb2JpbGUub3JnL3dhbGxldC9qYXJtL2lUR2xLbC1BSnhtbmNXUGJYSHAyeHk1OGJOeTE4d3FaNFRSOUV6aEJsMlI0dWx4ZVRFTzBWeVdZUjJxTURwQ0RWNUpXZU94ZWNUcWNFSjYxYkZLclVnL2p3a3MuanNvbiIsInZwX2Zvcm1hdHMiOnsidmMrc2Qtand0Ijp7InNkLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2Il0sImtiLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2Il19LCJkYytzZC1qd3QiOnsic2Qtand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiXSwia2Itand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiXX0sIm1zb19tZG9jIjp7ImFsZyI6WyJFUzI1NiJdfX0sInN1YmplY3Rfc3ludGF4X3R5cGVzX3N1cHBvcnRlZCI6WyJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQiXSwiaWRfdG9rZW5fc2lnbmVkX3Jlc3BvbnNlX2FsZyI6IlJTMjU2In19.f-LeHpQF2aZ3qFNG6DdWy-QBmnNGtV0MvoQWhUFRzbgQhHSMTee5pxcG8_UTRINVAVXkhoR85fYpjyjWm3bizw
        """.trimIndent()

            val germanTransactionDataOriginal = """
            eyJ0eXBlIjoicWNlcnRfY3JlYXRpb25fYWNjZXB0YW5jZSIsImNyZWRlbnRpYWxfaWRzIjpbIjYwNzUxMGE5LWM5NTctNDA5NS05MDZkLWY5OWZkMDA2YzRhZSJdLCJRQ190ZXJtc19jb25kaXRpb25zX3VyaSI6Imh0dHBzOi8vd3d3LmQtdHJ1c3QubmV0L2RlL2FnYiIsIlFDX2hhc2giOiI3UXptNUVqdXpYS1NIRmxjME9IOVBQOXFVYUgtVkJsMmFHTmJ3WWoxb09BIiwiUUNfaGFzaEFsZ29yaXRobU9JRCI6IjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiLCJ0cmFuc2FjdGlvbl9kYXRhX2hhc2hlc19hbGciOlsic2hhLTI1NiJdfQ
        """.trimIndent().replace("\n", "").replace("\r", "").replace(" ", "")

            val referenceHash = germanTransactionDataOriginal.decodeToByteArray(Base64UrlStrict).sha256()

            val authnResponse = holderOid4vp.createAuthnResponse(germanTestVectorJwt).getOrThrow()

            authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>()
            val test = authnResponse.params["response"]!!
            val test1 = vckJsonSerializer.decodeFromString<AuthenticationResponse>(test)
            authnResponse shouldNotBe null
            test1 shouldNotBe null
            val result = rqesVerifier.validateAuthnResponse(authnResponse.params)
            result.shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
            result.sdJwtSigned.keyBindingJws.shouldNotBeNull().payload.transactionDataHashes!!.first()
                .contentEquals(referenceHash)
        }
    }
})