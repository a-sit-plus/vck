package at.asitplus.wallet.lib.aries

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

class IssueCredentialMessengerTest : FreeSpec() {

    private lateinit var issuerCryptoService: CryptoService
    private lateinit var holderCryptoService: CryptoService
    private lateinit var issuer: Issuer
    private lateinit var holder: Holder
    private lateinit var issuerServiceEndpoint: String
    private lateinit var issuerMessenger: IssueCredentialMessenger
    private lateinit var holderMessenger: IssueCredentialMessenger

    init {
        beforeEach {
            issuerCryptoService = DefaultCryptoService()
            holderCryptoService = DefaultCryptoService()
            issuer = IssuerAgent.newDefaultInstance(issuerCryptoService, dataProvider = DummyCredentialDataProvider())
            holder = HolderAgent(holderCryptoService)
            issuerServiceEndpoint = "https://example.com/issue?${uuid4()}"
            holderMessenger = initHolderMessenger(ConstantIndex.AtomicAttribute2023)
        }

        "issueCredentialGeneric" {
            issuerMessenger = initIssuerMessenger(ConstantIndex.AtomicAttribute2023)

            val issuedCredential = runProtocolFlow()

            assertAtomicVc(issuedCredential)
            assertAttachment(issuedCredential, "picture")
        }

        // can't be created with a wrong keyId anymore, so that test was removed
    }

    private fun initHolderMessenger(scheme: ConstantIndex.CredentialScheme) =
        IssueCredentialMessenger.newHolderInstance(
            holder = holder,
            messageWrapper = MessageWrapper(holderCryptoService),
            credentialScheme = scheme,
        )

    private fun initIssuerMessenger(scheme: ConstantIndex.CredentialScheme) =
        IssueCredentialMessenger.newIssuerInstance(
            issuer = issuer,
            messageWrapper = MessageWrapper(issuerCryptoService),
            serviceEndpoint = issuerServiceEndpoint,
            credentialScheme = scheme,
        )

    private suspend fun runProtocolFlow(): IssueCredentialProtocolResult {
        val oobInvitation = issuerMessenger.startCreatingInvitation()
        oobInvitation.shouldBeInstanceOf<NextMessage.Send>()
        val invitationMessage = oobInvitation.message

        val parsedInvitation = holderMessenger.parseMessage(invitationMessage)
        parsedInvitation.shouldBeInstanceOf<NextMessage.Send>()
        parsedInvitation.endpoint shouldBe issuerServiceEndpoint
        val requestCredential = parsedInvitation.message

        val parsedRequestCredential = issuerMessenger.parseMessage(requestCredential)
        parsedRequestCredential.shouldBeInstanceOf<NextMessage.Send>()
        val issueCredential = parsedRequestCredential.message

        val parsedIssueCredential = holderMessenger.parseMessage(issueCredential)
        parsedIssueCredential.shouldBeInstanceOf<NextMessage.Result<IssueCredentialProtocolResult>>()

        val issuedCredential = parsedIssueCredential.result
        issuedCredential.shouldBeInstanceOf<IssueCredentialProtocolResult>()
        return issuedCredential
    }

    private fun assertAtomicVc(issuedCredentials: IssueCredentialProtocolResult) {
        issuedCredentials.acceptedVcJwt.shouldNotBeEmpty()
        issuedCredentials.acceptedVcJwt.map { it.vc.credentialSubject }.forEach {
            it.shouldBeInstanceOf<AtomicAttribute2023>()
        }
        issuedCredentials.rejected.shouldBeEmpty()
    }

    private fun assertAttachment(issuedCredentials: IssueCredentialProtocolResult, attributeName: String) {
        issuedCredentials.acceptedVcJwt.shouldNotBeEmpty()
        issuedCredentials.acceptedVcJwt.map { it.vc.credentialSubject }
            .filterIsInstance<AtomicAttribute2023>()
            .filter { it.name == attributeName }
            .shouldNotBeEmpty()
        issuedCredentials.attachments.shouldNotBeEmpty()
    }

    private fun assertEmptyVc(issuedCredentials: IssueCredentialProtocolResult) {
        issuedCredentials.acceptedVcJwt.shouldBeEmpty()
        issuedCredentials.rejected.shouldNotBeEmpty()
    }

}