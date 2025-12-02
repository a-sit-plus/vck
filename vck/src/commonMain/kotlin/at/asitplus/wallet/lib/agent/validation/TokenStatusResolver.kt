package at.asitplus.wallet.lib.agent.validation

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.IssuerSigned
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureFun
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.extensions.toView
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import kotlin.time.Clock

/**
 * Checks the status mechanisms in a given status claim to extract the token status.
 */
fun interface TokenStatusResolver {
    suspend operator fun invoke(revocationListInfo: RevocationListInfo): KmmResult<TokenStatus>
}

class TokenStatusResolverImpl(
    private val resolveStatusListToken: StatusListTokenResolver,
    private val clock: Clock = Clock.System,
    private val zlibService: ZlibService = DefaultZlibService(),
    private val verifyJwsObjectIntegrity: VerifyJwsObjectFun = VerifyJwsObject(),
    private val verifyCoseSignature: VerifyCoseSignatureFun<ByteArray> = VerifyCoseSignature(),
) : TokenStatusResolver {
    override suspend fun invoke(revocationListInfo: RevocationListInfo): KmmResult<TokenStatus> = catching {
        val token = resolveStatusListToken(revocationListInfo.uri)

        val payload = token.validate(
            verifyJwsObject = verifyJwsObjectIntegrity,
            verifyCoseSignature = verifyCoseSignature,
            revocationListInfo = revocationListInfo,
            isInstantInThePast = { it < clock.now() },
        ).getOrThrow()

        extractTokenStatus(
            revocationList = payload.revocationList as StatusList,
            revocationListInfo = revocationListInfo,
            zlibService = zlibService,
        ).getOrThrow()
    }
}

/** Fallback implementation: Token status is always valid. */
object TokenStatusResolverNoop : TokenStatusResolver {
    override suspend fun invoke(revocationListInfo: RevocationListInfo): KmmResult<TokenStatus> =
        catching { TokenStatus.Valid }
}

fun StatusListTokenResolver.toTokenStatusResolver(
    clock: Clock = Clock.System,
    zlibService: ZlibService = DefaultZlibService(),
    verifyJwsObjectIntegrity: VerifyJwsObjectFun = VerifyJwsObject(),
    verifyCoseSignature: VerifyCoseSignatureFun<ByteArray> = VerifyCoseSignature(),
) = TokenStatusResolver { revocationListInfo ->
    catching {
        val token = this(revocationListInfo.uri)

        val payload = token.validate(
            verifyJwsObject = verifyJwsObjectIntegrity,
            verifyCoseSignature = verifyCoseSignature,
            revocationListInfo = revocationListInfo,
            isInstantInThePast = { it < clock.now() },
        ).getOrThrow()

        extractTokenStatus(
            revocationList = payload.revocationList as StatusList,
            revocationListInfo = revocationListInfo,
            zlibService = zlibService,
        ).getOrThrow()
    }
}

/**
 * Decompress the Status List with a decompressor that is compatible with DEFLATE [RFC1951] and
 * ZLIB [RFC1950]
 *
 * Retrieve the status value of the index specified in the Referenced Token as described in
 * Section 4. Fail if the provided index is out of bound of the Status List
 */
private fun extractTokenStatus(
    revocationList: RevocationList,
    revocationListInfo: RevocationListInfo,
    zlibService: ZlibService = DefaultZlibService(),
): KmmResult<TokenStatus> = catching {
    if (revocationList is StatusList && revocationListInfo is StatusListInfo) {
        revocationList.toView(zlibService).getOrNull(revocationListInfo.index)
            ?: throw IndexOutOfBoundsException("The index specified in the status list info is out of bounds of the status list.")
    } else if (revocationList is IdentifierList && revocationListInfo is IdentifierListInfo) {
        TODO("Identifier logic to be implemented")
    } else throw IllegalArgumentException("RevocationList / RevocationListInfo mismatch")
}

suspend operator fun TokenStatusResolver.invoke(issuerSigned: IssuerSigned) =
    invoke(CredentialWrapper.Mdoc(issuerSigned))

suspend operator fun TokenStatusResolver.invoke(sdJwt: VerifiableCredentialSdJwt) =
    invoke(CredentialWrapper.SdJwt(sdJwt))

suspend operator fun TokenStatusResolver.invoke(vcJws: VerifiableCredentialJws) = invoke(CredentialWrapper.VcJws(vcJws))

suspend operator fun TokenStatusResolver.invoke(storeEntry: SubjectCredentialStore.StoreEntry) = when (storeEntry) {
    is SubjectCredentialStore.StoreEntry.Iso -> invoke(CredentialWrapper.Mdoc(storeEntry.issuerSigned))
    is SubjectCredentialStore.StoreEntry.SdJwt -> invoke(CredentialWrapper.SdJwt(storeEntry.sdJwt))
    is SubjectCredentialStore.StoreEntry.Vc -> invoke(CredentialWrapper.VcJws(storeEntry.vc))
}

suspend operator fun TokenStatusResolver.invoke(credentialWrapper: CredentialWrapper) = when (credentialWrapper) {
    is CredentialWrapper.Mdoc -> credentialWrapper.issuerSigned.issuerAuth.payload?.status
    is CredentialWrapper.SdJwt -> credentialWrapper.sdJwt.credentialStatus
    is CredentialWrapper.VcJws -> credentialWrapper.verifiableCredentialJws.vc.credentialStatus
}?.let {
    invoke(it)
}

