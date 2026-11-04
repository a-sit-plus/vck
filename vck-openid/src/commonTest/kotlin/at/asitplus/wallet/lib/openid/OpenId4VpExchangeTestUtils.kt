package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.decodeFromFormUrlEncoded
import at.asitplus.wallet.lib.ReceivedHttpResponse
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.oauth2.FakeHttpStack
import at.asitplus.wallet.lib.oauth2.scripted
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.PresentationValidationResult
import at.asitplus.wallet.lib.validation.ProtocolResponseChecks
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidatedCredential
import at.asitplus.wallet.lib.validation.ValidatedPresentation
import at.asitplus.wallet.lib.validation.ValidationPolicy
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlin.time.Duration.Companion.minutes

/**
 * Prepares the authorization request [input] as a wallet does, i.e. with
 * [OpenId4VpProtocolClient.prepareAuthorizationResponse], sending its requests with [http]. By default, no request
 * is expected, as for requests passed by value.
 */
suspend fun OpenId4VpHolder.prepareAuthorizationResponse(
    input: String,
    http: FakeHttpStack = FakeHttpStack(scripted()),
): KmmResult<AuthorizationResponsePreparationState> = catching {
    http.execute(OpenId4VpProtocolClient(this).prepareAuthorizationResponse(input))
}

/**
 * Prepares [input] as [prepareAuthorizationResponse] does, and creates the response with the presentation the request
 * asks for, without user interaction.
 */
suspend fun OpenId4VpHolder.createAuthorizationResponse(
    input: String,
    http: FakeHttpStack = FakeHttpStack(scripted()),
): KmmResult<AuthenticationResponseResult> = catching {
    finalizeAuthorizationResponse(prepareAuthorizationResponse(input, http).getOrThrow()).getOrThrow()
}

/**
 * Plays the verifier's `request_uri` endpoint at [requestUrl]: answers with the request object [serve] returns for the
 * `wallet_metadata` and `wallet_nonce` the wallet has posted (`null` for GET), and every other request with 404.
 */
fun requestUriEndpoint(
    requestUrl: String,
    serve: suspend (RequestObjectParameters?) -> String,
) = FakeHttpStack { request ->
    if (request.url == requestUrl) ReceivedHttpResponse(
        status = HttpStatusCode.OK,
        headers = headersOf(HttpHeaders.ContentType, MediaTypes.Application.AUTHZ_REQ_JWT),
        body = serve(request.body?.text?.decodeFromFormUrlEncoded<RequestObjectParameters>()),
    ) else ReceivedHttpResponse(HttpStatusCode.NotFound, Headers.Empty, "")
}

/**
 * The accepted presentations of a processed response by the credential query they answer, failing for an
 * authorization error response, or with the cause of the first rejecting check of a rejected presentation.
 */
fun AuthnResponseResult.acceptedPresentations(): Map<DCQLCredentialQueryIdentifier, List<ValidatedPresentation>> =
    shouldBeInstanceOf<AuthnResponseResult.Success>().presentationValidations.mapValues { entry ->
        entry.value.map { it.acceptedOrThrow() }
    }

/** The single accepted presentation of a processed response, see [acceptedPresentations]. */
fun AuthnResponseResult.singleAcceptedPresentation(): ValidatedPresentation =
    acceptedPresentations().values.shouldBeSingleton().first().shouldBeSingleton().first()

/** The accepted documents of an ISO/IEC 18013-7 Annex C response. */
fun Iso180137AnnexCWrapper.acceptedDocuments(): List<ValidatedPresentation> =
    presentationValidations.mapNotNull { it.presentation }

/** Whether the presentations of a processed response satisfy its request, see [ProtocolResponseChecks]. */
fun AuthnResponseResult.submissionRequirements(): CheckOutcome =
    shouldBeInstanceOf<AuthnResponseResult.Success>().validationReport.checks
        .shouldBeInstanceOf<ProtocolResponseChecks>().submissionRequirements

/** The accepted presentation, failing with the cause of the first rejecting check otherwise. */
fun PresentationValidationResult.acceptedOrThrow(): ValidatedPresentation =
    presentation ?: throw rejection() ?: IllegalStateException("Presentation rejected without a cause")

/** The SD-JWT VC of this accepted SD-JWT presentation. */
val ValidatedPresentation.sdJwtVc: ValidatedCredential.SdJwtVc
    get() = shouldBeInstanceOf<ValidatedPresentation.SdJwt>().credential

/** The issuer-signed items this accepted mdoc document discloses. */
val ValidatedPresentation.issuerSignedItems: List<IssuerSignedItem>
    get() = shouldBeInstanceOf<ValidatedPresentation.MdocDocument>().credential.issuerSigned.namespaces.orEmpty()
        .values.flatMap { list -> list.entries.map { it.value } }

/**
 * The policy for verifiers in tests whose issuers are on no trust list: signatures, holder binding, and time are
 * validated as always, but issuers need not be authorized, and the status is not resolved, as no status list token
 * resolver is configured.
 */
val testPresentationPolicy = ValidationPolicy(
    trust = TrustPolicy.IntegrityOnly,
    status = StatusPolicy.Skip,
    timeLeeway = 5.minutes,
    requireTimeliness = true,
)
