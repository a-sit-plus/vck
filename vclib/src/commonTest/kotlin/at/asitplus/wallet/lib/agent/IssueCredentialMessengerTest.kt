package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.Companion.ATTRIBUTE_WITH_ATTACHMENT
import at.asitplus.wallet.lib.data.AtomicAttributeCredential
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.SchemaIndex
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
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
            holder = HolderAgent.newDefaultInstance(holderCryptoService)
            issuerServiceEndpoint = "https://example.com/issue?${uuid4()}"
            holderMessenger = initHolderMessenger()
        }


        "issueCredentialGeneric" {
            issuerMessenger = initIssuerMessenger(ConstantIndex.Generic)

            val issuedCredential = runProtocolFlow()

            assertAtomicVc(issuedCredential, SchemaIndex.ATTR_GENERIC_PREFIX)
            assertAttachment(issuedCredential, "${SchemaIndex.ATTR_GENERIC_PREFIX}/$ATTRIBUTE_WITH_ATTACHMENT")
        }

        "wrongKeyId" {
            holderMessenger = IssueCredentialMessenger.newHolderInstance(
                holder = holder,
                keyId = issuerCryptoService.keyId,
                messageWrapper = MessageWrapper(holderCryptoService),
            )
            issuerMessenger = initIssuerMessenger(ConstantIndex.Generic)

            val issuedCredential = runProtocolFlow()

            assertEmptyVc(issuedCredential)
        }
    }

    private fun initHolderMessenger() = IssueCredentialMessenger.newHolderInstance(
        holder = holder,
        keyId = holderCryptoService.keyId,
        messageWrapper = MessageWrapper(holderCryptoService),
    )

    private fun initIssuerMessenger(scheme: ConstantIndex.CredentialScheme) =
        IssueCredentialMessenger.newIssuerInstance(
            issuer = issuer,
            keyId = issuerCryptoService.keyId,
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

    private fun assertEmptyVc(issuedCredentials: IssueCredentialProtocolResult) {
        issuedCredentials.accepted.shouldBeEmpty()
        issuedCredentials.rejected.shouldNotBeEmpty()
    }

}
