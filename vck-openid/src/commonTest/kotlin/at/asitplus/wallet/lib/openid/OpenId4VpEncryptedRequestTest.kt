package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toEncryptionJsonWebKey
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.jws.EncryptJwe
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStorePlainJwt
import at.asitplus.wallet.lib.utils.DefaultMapStore
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.coroutines.runBlocking

/**
 * Encrypted authorization requests as per
 * [OpenID4VP 1.0, 5.10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-request-uri-method-post).
 */
val OpenId4VpEncryptedRequestTest by matrixSuite {

    fixture {
        runBlocking {
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val holderAgent = HolderAgent(holderKeyMaterial).also {
                issueAndStorePlainJwt(it, holderKeyMaterial)
            }
            object {
                val holderAgent = holderAgent
                val clientId = "PRE-REGISTERED-CLIENT-${uuid4()}"
                val redirectUrl = "https://example.com/rp/${uuid4()}"
                val walletUrl = "https://example.com/wallet/${uuid4()}"
                val requestUrl = "https://example.com/request/${uuid4()}"
                val verifierKeyMaterial = EphemeralKeyWithoutCert()
                val clientIdScheme = ClientIdScheme.PreRegistered(clientId, redirectUrl)
                val verifierOid4vp = OpenId4VpVerifier(
                    keyMaterial = verifierKeyMaterial,
                    clientIdScheme = clientIdScheme,
                )
                val requestOptions = OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                    ).toDCQLRequest(),
                )
                val requestFactory = OpenId4VpRequestFactory(
                    clientIdScheme = clientIdScheme,
                    ephemeralEncryptionKeyService = EphemeralEncryptionKeyService(),
                    decryptionKeyMaterial = null,
                    signAuthnRequest = SignJwt(verifierKeyMaterial, JwsHeaderClientIdScheme(clientIdScheme)),
                    nonceService = DefaultNonceService(),
                    supportedAlgorithms = setOf(SignatureAlgorithm.ECDSAwithSHA256),
                    stateToAuthnRequestStore = DefaultMapStore(),
                    supportedJweEncryptionAlgorithms = JweEncryption.entries.toSet(),
                )

                /** Holder fetching the request object from [requestUrl] with POST, [served] records what it got. */
                var served: String? = null
                fun holder(
                    ephemeralEncryptionKeyService: EphemeralEncryptionKeyService? = null,
                    requireEncryptedRequests: Boolean = false,
                    serve: suspend (at.asitplus.openid.RequestObjectParameters?) -> String = { "" },
                ) = OpenId4VpHolder(
                    holder = holderAgent,
                    randomSource = RandomSource.Default,
                    ephemeralEncryptionKeyService = ephemeralEncryptionKeyService,
                    requireEncryptedRequests = requireEncryptedRequests,
                    remoteResourceRetriever = { input ->
                        if (input.url == requestUrl)
                            serve(input.requestObjectParameters).also { served = it }
                        else null
                    },
                )
            }
        }
    } - {

        "verifier encrypts request object when the wallet advertises a key" { f ->
            val (url, jar) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.POST
                )
            ).getOrThrow()
            jar.shouldNotBeNull()

            val holder = f.holder(EphemeralEncryptionKeyService()) { jar.invoke(it).getOrThrow() }

            holder.createAuthnResponse(url).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .let { f.verifierOid4vp.validateAuthnResponse(it.url).getOrThrow() }
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()

            // five parts, i.e. a JWE, not the three parts of the signed request object
            f.served.shouldNotBeNull().count { it == '.' } shouldBe 4
        }

        "verifier keeps sending plain request objects when the wallet advertises no key" { f ->
            val (url, jar) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.POST
                )
            ).getOrThrow()
            jar.shouldNotBeNull()

            val holder = f.holder { jar.invoke(it).getOrThrow() }

            holder.createAuthnResponse(url).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .let { f.verifierOid4vp.validateAuthnResponse(it.url).getOrThrow() }
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()

            f.served.shouldNotBeNull().count { it == '.' } shouldBe 2
        }

        "wallet advertising a key still accepts a plain request object" { f ->
            val (url, jar) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.POST
                )
            ).getOrThrow()
            jar.shouldNotBeNull()

            // drop the wallet's metadata, so that the verifier does not encrypt
            val holder = f.holder(EphemeralEncryptionKeyService()) {
                jar.invoke(it?.copy(walletMetadataString = null)).getOrThrow()
            }

            holder.createAuthnResponse(url).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .let { f.verifierOid4vp.validateAuthnResponse(it.url).getOrThrow() }
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
        }

        "request object encrypted to a key we never advertised is rejected" { f ->
            val (url, jar) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.POST
                )
            ).getOrThrow()
            jar.shouldNotBeNull()

            val foreignKey = EphemeralEncryptionKeyService().createKey().toEncryptionJsonWebKey()
            val holder = f.holder(EphemeralEncryptionKeyService()) { params ->
                EncryptJwe()(
                    JweHeader(JweAlgorithm.ECDH_ES, JweEncryption.A128GCM, keyId = foreignKey.keyId),
                    jar.invoke(params).getOrThrow(),
                    foreignKey,
                ).getOrThrow().serialize()
            }

            holder.createAuthnResponse(url).isFailure shouldBe true
        }

        "encryption key is consumed, so the same request object can't be replayed" { f ->
            val (url, jar) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.POST
                )
            ).getOrThrow()
            jar.shouldNotBeNull()

            var first: String? = null
            val holder = f.holder(EphemeralEncryptionKeyService()) { params ->
                // serve the very first (encrypted) request object again on every subsequent fetch
                first ?: jar.invoke(params).getOrThrow().also { first = it }
            }

            holder.createAuthnResponse(url).getOrThrow()
            first.shouldNotBeNull()
            holder.createAuthnResponse(url).isFailure shouldBe true
        }

        "encrypted request object is rejected if we did not ask for encryption" { f ->
            val (url, jar) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.POST
                )
            ).getOrThrow()
            jar.shouldNotBeNull()

            val foreignKey = EphemeralEncryptionKeyService().createKey().toEncryptionJsonWebKey()
            val holder = f.holder { params ->
                EncryptJwe()(
                    JweHeader(JweAlgorithm.ECDH_ES, JweEncryption.A128GCM, keyId = foreignKey.keyId),
                    jar.invoke(params).getOrThrow(),
                    foreignKey,
                ).getOrThrow().serialize()
            }

            holder.createAuthnResponse(url).isFailure shouldBe true
        }

        "no encryption when verifier and wallet share no content encryption algorithm" { f ->
            val verifier = OpenId4VpVerifier(
                keyMaterial = EphemeralKeyWithoutCert(),
                clientIdScheme = ClientIdScheme.PreRegistered(f.clientId, f.redirectUrl),
                supportedJweEncryptionAlgorithms = setOf(JweEncryption.A128GCM),
            )
            val (url, jar) = verifier.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.POST
                )
            ).getOrThrow()
            jar.shouldNotBeNull()

            val holder = OpenId4VpHolder(
                holder = f.holderAgent,
                randomSource = RandomSource.Default,
                ephemeralEncryptionKeyService = EphemeralEncryptionKeyService(),
                supportedJweEncryptionAlgorithms = setOf(JweEncryption.A256GCM),
                remoteResourceRetriever = { input ->
                    if (input.url == f.requestUrl)
                        jar.invoke(input.requestObjectParameters).getOrThrow().also { f.served = it }
                    else null
                },
            )

            holder.createAuthnResponse(url).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .let { verifier.validateAuthnResponse(it.url).getOrThrow() }
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()

            // no common algorithm, so the verifier serves the plain signed request object
            f.served.shouldNotBeNull().count { it == '.' } shouldBe 2
        }

        "request object dropping the wallet_nonce we sent is rejected" { f ->
            val (url, jar) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.POST
                )
            ).getOrThrow()
            jar.shouldNotBeNull()

            // drop the nonce, so that the verifier can't echo it back in the request object
            val holder = f.holder(EphemeralEncryptionKeyService()) {
                jar.invoke(it?.copy(walletNonce = null)).getOrThrow()
            }

            holder.createAuthnResponse(url).isFailure shouldBe true
        }

        "no wallet metadata is sent when fetching the request object with GET" { f ->
            val (url, jar) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.GET
                )
            ).getOrThrow()
            jar.shouldNotBeNull()

            var params: at.asitplus.openid.RequestObjectParameters? = null
            val holder = f.holder(EphemeralEncryptionKeyService()) {
                params = it
                jar.invoke(it).getOrThrow()
            }

            holder.createAuthnResponse(url).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .let { f.verifierOid4vp.validateAuthnResponse(it.url).getOrThrow() }
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()

            params shouldBe null
        }

        "plain request object from the POST fetch is rejected when we require encryption" { f ->
            val (url, jar) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.POST
                )
            ).getOrThrow()
            jar.shouldNotBeNull()

            // drop the wallet's metadata, so that the verifier has no key to encrypt to
            val holder = f.holder(EphemeralEncryptionKeyService(), requireEncryptedRequests = true) {
                jar.invoke(it?.copy(walletMetadataString = null)).getOrThrow()
            }

            holder.createAuthnResponse(url).isFailure shouldBe true
        }

        "GET flow is still accepted when we require encryption" { f ->
            val (url, jar) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.GET
                )
            ).getOrThrow()
            jar.shouldNotBeNull()

            // deliberate limit: a GET fetch never advertises a key, so there is nothing to require, see OpenID4VP 5.10
            val holder = f.holder(EphemeralEncryptionKeyService(), requireEncryptedRequests = true) {
                jar.invoke(it).getOrThrow()
            }

            holder.createAuthnResponse(url).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .let { f.verifierOid4vp.validateAuthnResponse(it.url).getOrThrow() }
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
        }

        "requiring encryption needs a key service to advertise a key with" { f ->
            shouldThrow<IllegalArgumentException> {
                OpenId4VpHolder(
                    holder = f.holderAgent,
                    randomSource = RandomSource.Default,
                    ephemeralEncryptionKeyService = null,
                    requireEncryptedRequests = true,
                )
            }
        }

        "the decrypted request records the JWE header it came from" { f ->
            val (url, jar) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.POST
                )
            ).getOrThrow()
            jar.shouldNotBeNull()

            val holder = f.holder(EphemeralEncryptionKeyService()) { jar.invoke(it).getOrThrow() }

            holder.startAuthorizationResponsePreparation(url).getOrThrow().apply {
                requestWasEncrypted shouldBe true
                request.decryptedFrom.shouldNotBeNull().apply {
                    algorithm shouldBe JweAlgorithm.ECDH_ES
                    encryption shouldBe JweEncryption.A128GCM
                }
            }
        }

        "a plain request records no JWE header" { f ->
            val (url, jar) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.POST
                )
            ).getOrThrow()
            jar.shouldNotBeNull()

            val holder = f.holder { jar.invoke(it).getOrThrow() }

            holder.startAuthorizationResponsePreparation(url).getOrThrow().apply {
                requestWasEncrypted shouldBe false
                request.decryptedFrom shouldBe null
            }
        }

        "plain request object served at the request_uri is rejected" { f ->
            // OpenID4VP 1.0, 5.10.1: the request URI response body is "a signed, optionally encrypted, request object"
            val (url, _) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.POST
                )
            ).getOrThrow()

            val holder = f.holder(EphemeralEncryptionKeyService()) { params ->
                joseCompliantSerializer.encodeToString(
                    f.requestFactory.createPlainAuthnRequest(f.requestOptions, params)
                )
            }

            holder.createAuthnResponse(url).isFailure shouldBe true
        }

        "encrypted request object whose payload is plain JSON is rejected" { f ->
            // encryption is permitted in addition to signing, never instead of it, see OpenID4VP 1.0, 5.10.1
            val (url, _) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.POST
                )
            ).getOrThrow()

            val holder = f.holder(EphemeralEncryptionKeyService()) { params ->
                val recipientKey = params.shouldNotBeNull().walletMetadata.shouldNotBeNull()
                    .jsonWebKeySet.shouldNotBeNull().keys.first()
                EncryptJwe()(
                    JweHeader(JweAlgorithm.ECDH_ES, JweEncryption.A128GCM, keyId = recipientKey.keyId),
                    joseCompliantSerializer.encodeToString(
                        f.requestFactory.createPlainAuthnRequest(f.requestOptions, params)
                    ),
                    recipientKey,
                ).getOrThrow().serialize()
            }

            holder.createAuthnResponse(url).isFailure shouldBe true
        }

        "request object with the wrong typ is rejected" { f ->
            // OpenID4VP 1.0, 5: "Wallets MUST NOT process Request Objects where the typ Header Parameter is not
            // present or does not have the value oauth-authz-req+jwt"
            val (url, _) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.POST
                )
            ).getOrThrow()

            val holder = f.holder(EphemeralEncryptionKeyService()) { params ->
                SignJwt<AuthenticationRequestParameters>(EphemeralKeyWithoutCert(), JwsHeaderNone())(
                    JwsContentTypeConstants.JWT,
                    f.requestFactory.createPlainAuthnRequest(f.requestOptions, params),
                    AuthenticationRequestParameters.serializer(),
                ).getOrThrow().toString()
            }

            holder.createAuthnResponse(url).isFailure shouldBe true
        }

        "plain request object in the request parameter is rejected" { f ->
            // RFC 9101, 4: a request object is "JWS signed" or "JWS signed and JWE encrypted", there is no third form
            val url = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions, CreationOptions.Query(f.walletUrl)
            ).getOrThrow().url + "&request=" + joseCompliantSerializer.encodeToString(
                f.requestFactory.createPlainAuthnRequest(f.requestOptions)
            ).encodeURLParameter()

            f.holder().createAuthnResponse(url).isFailure shouldBe true
        }

        "unparseable request parameter is rejected" { f ->
            // `RequestParametersSerializer` picks `JarRequestParameters` as soon as `request` is present, so the other
            // query parameters are dropped and there is nothing to fall back to either way, but the error should name
            // the request object rather than the `response_type` that went missing with it
            val url = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions, CreationOptions.Query(f.walletUrl)
            ).getOrThrow().url + "&request=not-a-request-object"

            f.holder().createAuthnResponse(url).isFailure shouldBe true
        }

        "wallet metadata carries exactly one encryption key, fresh for every request" { f ->
            val keyIds = mutableListOf<String?>()
            val (url, jar) = f.verifierOid4vp.createAuthnRequest(
                f.requestOptions,
                CreationOptions.SignedRequestByReference(
                    f.walletUrl, f.requestUrl, JarRequestParameters.RequestUriMethod.POST
                )
            ).getOrThrow()
            jar.shouldNotBeNull()

            val holder = f.holder(EphemeralEncryptionKeyService()) { params ->
                params.shouldNotBeNull().walletMetadata.shouldNotBeNull().jsonWebKeySet.shouldNotBeNull()
                    .keys.also { it.size shouldBe 1 }
                    .first().also { keyIds += it.keyId }
                jar.invoke(params).getOrThrow()
            }

            holder.createAuthnResponse(url).getOrThrow()
            holder.createAuthnResponse(url).getOrThrow()
            keyIds.size shouldBe 2
            keyIds[0].shouldNotBeNull() shouldNotBe keyIds[1].shouldNotBeNull()
        }
    }
}
