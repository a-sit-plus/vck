package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.dif.FormatHolder
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionBuilder
import at.asitplus.wallet.lib.data.dif.SubmissionRequirement
import kotlinx.serialization.Serializable

@Serializable
class AuthenticationResponseBuilder(
    val parameters: AuthenticationRequestParameters,
    val responseType: String,
    val targetUrl: String,
    val clientMetadata: RelyingPartyMetadata,
    val audience: String,
    val nonce: String,
    val submissionBuilder: PresentationSubmissionBuilder?,
)
