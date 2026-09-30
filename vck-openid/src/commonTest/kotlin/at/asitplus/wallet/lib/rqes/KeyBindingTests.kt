package at.asitplus.wallet.lib.rqes

import at.asitplus.csc.contentEquals
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QCertCreationAcceptance
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_VCT
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.ValidatorSdJwt
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.SdJwtConstants
import at.asitplus.wallet.lib.data.digest
import at.asitplus.wallet.lib.data.toBase64UrlJsonString
import at.asitplus.openid.decodeFromQuery
import at.asitplus.openid.formUrlEncode
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.ClientIdScheme
import at.asitplus.wallet.lib.openid.CreationOptions
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreSdJwt
import at.asitplus.wallet.lib.openid.OpenId4VpHolder
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier
import at.asitplus.wallet.lib.openid.VpTokenValidationResultDCQL
import at.asitplus.wallet.lib.utils.DefaultMapStore
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.coroutines.runBlocking

private fun malignTransactionData(): List<TransactionDataBase64Url> = listOf(
    QCertCreationAcceptance(
        credentialIds = setOf(),
        qcTermsConditionsUri = uuid4().toString(),
        qcHash = uuid4().bytes,
        qcHashAlgorithmOid = Digest.SHA256.oid,
    ).toBase64UrlJsonString()
)

val KeyBindingTests by matrixSuite {

    fixture {
        runBlocking {
            val euPidSdJwtScheme = AttributeIndex.resolveIdentifier(EU_PID_SD_JWT_VCT, SD_JWT)
            val holderKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
            val holderAgent: Holder = HolderAgent(holderKeyMaterial).also {
                issueAndStoreSdJwt(it, holderKeyMaterial, euPidSdJwtScheme)
            }

            object {
                val holderOid4vp = OpenId4VpHolder(
                    holder = holderAgent,
                    randomSource = RandomSource.Default
                )
                val externalMapStore = DefaultMapStore<String, AuthenticationRequestParameters>()

                val walletUrl = "https://example.com/wallet/${uuid4()}"
                val clientId = "https://example.com/rp/${uuid4()}"
            }
        }
    } - {

        "KB-JWT contains transaction data" {
            val verifierOid4Vp = OpenId4VpVerifier(
                keyMaterial = EphemeralKeyWithoutCert(),
                clientIdScheme = ClientIdScheme.RedirectUri(it.clientId),
                stateToAuthnRequestStore = it.externalMapStore
            )
            val requestOptions = buildRequestOptions(transactionDataHashAlgorithms = null)

            val authnRequestUrl = verifierOid4Vp.createAuthnRequest(
                requestOptions = requestOptions,
                creationOptions = CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url.apply {
                this shouldContain "transaction_data"
            }

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequestUrl).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            verifierOid4Vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
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

            val authnRequestUrl = verifierOid4Vp.createAuthnRequest(
                requestOptions = requestOptions,
                creationOptions = CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url.apply {
                this.shouldContain("transaction_data")
            }

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequestUrl).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            val result = verifierOid4Vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()

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

            val authnRequest = verifierOid4Vp.createAuthnRequest(
                requestOptions = requestOptions,
                creationOptions = CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url.run {
                Url(this).decodeFromQuery<AuthenticationRequestParameters>()
            }

            val malignResponse = it.holderOid4vp.createAuthnResponse(
                joseCompliantSerializer.encodeToString(
                    authnRequest.copy(transactionData = malignTransactionData())
                )
            ).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            verifierOid4Vp.validateAuthnResponse(malignResponse.params.formUrlEncode()).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.shouldBeSingleton().first().first().isFailure shouldBe true
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
            val authnRequest = lenientVerifier.createAuthnRequest(
                requestOptions = requestOptions,
                creationOptions = CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url.run {
                Url(this).decodeFromQuery<AuthenticationRequestParameters>()
            }
            val malignResponse = it.holderOid4vp.createAuthnResponse(
                joseCompliantSerializer.encodeToString(
                    authnRequest.copy(transactionData = malignTransactionData())
                )
            ).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            lenientVerifier.validateAuthnResponse(malignResponse.params.formUrlEncode()).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
        }
    }
}
