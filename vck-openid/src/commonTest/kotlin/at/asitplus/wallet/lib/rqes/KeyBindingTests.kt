package at.asitplus.wallet.lib.rqes

import at.asitplus.csc.api.contentEquals
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QCertCreationAcceptance
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.openid.decodeFromQuery
import at.asitplus.openid.digest
import at.asitplus.openid.formUrlEncode
import at.asitplus.openid.toBase64UrlJsonString
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
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.SdJwtConstants
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.AuthnResponseResult
import at.asitplus.wallet.lib.openid.ClientIdScheme
import at.asitplus.wallet.lib.openid.CreationOptions
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreSdJwt
import at.asitplus.wallet.lib.openid.OpenId4VpHolder
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier
import at.asitplus.wallet.lib.openid.createAuthorizationResponse
import at.asitplus.wallet.lib.openid.singleAcceptedPresentation
import at.asitplus.wallet.lib.openid.testPresentationPolicy
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.validation.ValidatedPresentation
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

private fun malignTransactionData(queryId: String): List<TransactionDataBase64Url> = listOf(
    QCertCreationAcceptance(
        credentialIds = setOf(queryId),
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
                stateToAuthnRequestStore = it.externalMapStore,
                presentationPolicy = testPresentationPolicy,
            )
            val requestOptions = buildRequestOptions(transactionDataHashAlgorithms = null)

            val authnRequestUrl = verifierOid4Vp.createAuthnRequest(
                requestOptions = requestOptions,
                creationOptions = CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url.apply {
                this shouldContain "transaction_data"
            }

            val authnResponse = it.holderOid4vp.createAuthorizationResponse(authnRequestUrl).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            verifierOid4Vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .singleAcceptedPresentation()
                .shouldBeInstanceOf<ValidatedPresentation.SdJwt>()
                .keyBinding.shouldNotBeNull().payload.apply {
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
                stateToAuthnRequestStore = it.externalMapStore,
                presentationPolicy = testPresentationPolicy,
            )
            val requestOptions = buildRequestOptions(transactionDataHashAlgorithms = setOf(SdJwtConstants.SHA_384))

            val authnRequestUrl = verifierOid4Vp.createAuthnRequest(
                requestOptions = requestOptions,
                creationOptions = CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url.apply {
                this.shouldContain("transaction_data")
            }

            val authnResponse = it.holderOid4vp.createAuthorizationResponse(authnRequestUrl).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            val result = verifierOid4Vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .singleAcceptedPresentation()
                .shouldBeInstanceOf<ValidatedPresentation.SdJwt>()

            with(result.keyBinding.shouldNotBeNull().payload) {
                transactionDataHashes.shouldNotBeNull()
                transactionDataHashes.contentEquals(requestOptions.transactionData!!.map { it.digest(Digest.SHA384) })
                transactionDataHashesAlgorithmString.shouldBe(SdJwtConstants.SHA_384)
            }
        }

        "Incorrect TransactionData is rejected" {
            val verifierOid4Vp = OpenId4VpVerifier(
                keyMaterial = EphemeralKeyWithoutCert(),
                clientIdScheme = ClientIdScheme.RedirectUri(it.clientId),
                stateToAuthnRequestStore = it.externalMapStore,
                presentationPolicy = testPresentationPolicy,
            )

            val requestOptions =
                buildRequestOptions(OpenIdConstants.ResponseMode.DirectPost, setOf(SdJwtConstants.SHA_256))

            val authnRequest = verifierOid4Vp.createAuthnRequest(
                requestOptions = requestOptions,
                creationOptions = CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url.run {
                Url(this).decodeFromQuery<AuthenticationRequestParameters>()
            }

            val malignResponse = it.holderOid4vp.createAuthorizationResponse(
                joseCompliantSerializer.encodeToString(
                    authnRequest.copy(
                        transactionData = malignTransactionData(authnRequest.dcqlQuery!!.credentials.first().id.string)
                    )
                )
            ).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            verifierOid4Vp.validateAuthnResponse(malignResponse.params.formUrlEncode()).getOrThrow()
                .shouldBeInstanceOf<AuthnResponseResult.Success>()
                .presentationValidations.values.shouldBeSingleton().first().first().presentation.shouldBeNull()
        }
    }
}
