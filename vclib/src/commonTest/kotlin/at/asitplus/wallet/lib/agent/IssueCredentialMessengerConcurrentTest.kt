package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.Companion.ATTRIBUTE_WITH_ATTACHMENT
import at.asitplus.wallet.lib.data.AtomicAttributeCredential
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.SchemaIndex
import at.asitplus.wallet.lib.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch

class IssueCredentialMessengerConcurrentTest : FreeSpec() {

    lateinit var issuerCryptoService: CryptoService
    lateinit var issuer: Issuer
    lateinit var issuerServiceEndpoint: String
    lateinit var issuerMessenger: IssueCredentialMessenger

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
                        assertAtomicVc(issuedCredential, SchemaIndex.ATTR_GENERIC_PREFIX)
                        assertAttachment(
                            issuedCredential,
                            "${SchemaIndex.ATTR_GENERIC_PREFIX}/$ATTRIBUTE_WITH_ATTACHMENT"
                        )
                    }
                }
            }
        }
    }

    private fun initHolderMessenger(): IssueCredentialMessenger {
        val cryptoService = DefaultCryptoService()
        return IssueCredentialMessenger.newHolderInstance(
            holder = HolderAgent.newDefaultInstance(cryptoService),
            keyId = cryptoService.keyId,
            messageWrapper = MessageWrapper(cryptoService),
        )
    }

    private fun initIssuerMessenger(scheme: ConstantIndex.CredentialScheme) =
        IssueCredentialMessenger.newIssuerInstance(
            issuer = issuer,
            keyId = issuerCryptoService.keyId,
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

    private fun assertAtomicVc(issuedCredentials: IssueCredentialProtocolResult, schema: String) {
        issuedCredentials.accepted.shouldNotBeEmpty()
        issuedCredentials.accepted.map { it.vc.credentialSubject }.forEach {
            it.shouldBeInstanceOf<AtomicAttributeCredential>()
            it.name shouldStartWith schema
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
