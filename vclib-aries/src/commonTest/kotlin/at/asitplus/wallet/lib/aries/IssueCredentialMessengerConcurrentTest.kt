package at.asitplus.wallet.lib.aries

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.AtomicAttributeCredential
import at.asitplus.wallet.lib.data.ConstantIndex
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch

class IssueCredentialMessengerConcurrentTest : FreeSpec() {

    private lateinit var issuerCryptoService: CryptoService
    private lateinit var issuer: Issuer
    private lateinit var issuerServiceEndpoint: String
    private lateinit var issuerMessenger: IssueCredentialMessenger

    init {
        beforeEach {
            issuerCryptoService = DefaultCryptoService()
            issuer = IssuerAgent.newDefaultInstance(issuerCryptoService, dataProvider = DummyCredentialDataProvider())
            issuerServiceEndpoint = "https://example.com/issue?${uuid4()}"
            issuerMessenger = initIssuerMessenger(ConstantIndex.Generic)
        }

        "issueCredentialGeneric" {
            coroutineScope {
                repeat(100) {
                    launch {
                        val holderMessenger = initHolderMessenger()
                        val issuedCredential = runProtocolFlow(holderMessenger)
                        assertAtomicVc(issuedCredential)
                        assertAttachment(issuedCredential, "picture")
                    }
                }
            }
        }
    }

    private fun initHolderMessenger(): IssueCredentialMessenger {
        val cryptoService = DefaultCryptoService()
        return IssueCredentialMessenger.newHolderInstance(
            holder = HolderAgent.newDefaultInstance(cryptoService),
            messageWrapper = MessageWrapper(cryptoService),
        )
    }

    private fun initIssuerMessenger(scheme: ConstantIndex.CredentialScheme) =
        IssueCredentialMessenger.newIssuerInstance(
            issuer = issuer,
            messageWrapper = MessageWrapper(issuerCryptoService),
            serviceEndpoint = issuerServiceEndpoint,
            credentialScheme = scheme,
        )

    private suspend fun runProtocolFlow(holderMessenger: IssueCredentialMessenger): IssueCredentialProtocolResult {
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
        issuedCredentials.accepted.shouldNotBeEmpty()
        issuedCredentials.accepted.map { it.vc.credentialSubject }.forEach {
            it.shouldBeInstanceOf<AtomicAttributeCredential>()
        }
        issuedCredentials.rejected.shouldBeEmpty()
    }

    private fun assertAttachment(issuedCredentials: IssueCredentialProtocolResult, attributeName: String) {
        issuedCredentials.accepted.shouldNotBeEmpty()
        issuedCredentials.accepted.map { it.vc.credentialSubject }
            .filterIsInstance<AtomicAttributeCredential>()
            .filter { it.name == attributeName }
            .shouldNotBeEmpty()
        issuedCredentials.attachments.shouldNotBeEmpty()
    }

}