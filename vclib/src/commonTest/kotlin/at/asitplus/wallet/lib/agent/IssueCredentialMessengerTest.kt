package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.Companion.ATTRIBUTE_WITH_ATTACHMENT
import at.asitplus.wallet.lib.data.AtomicAttributeCredential
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.SchemaIndex
import at.asitplus.wallet.lib.uuid4
import at.asitplus.testballoon.matrix.matrixSuite
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.aroundEachTest
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf

val IssueCredentialMessengerTest by matrixSuite {

    lateinit var issuerCryptoService: CryptoService
    lateinit var holderCryptoService: CryptoService
    lateinit var issuer: Issuer
    lateinit var holder: Holder
    lateinit var issuerServiceEndpoint: String
    lateinit var issuerMessenger: IssueCredentialMessenger
    lateinit var holderMessenger: IssueCredentialMessenger


    fun initHolderMessenger() = IssueCredentialMessenger.newHolderInstance(
        holder = holder,
        keyId = holderCryptoService.keyId,
        messageWrapper = MessageWrapper(holderCryptoService),
    )

    fun initIssuerMessenger(scheme: ConstantIndex.CredentialScheme) =
        IssueCredentialMessenger.newIssuerInstance(
            issuer = issuer,
            keyId = issuerCryptoService.keyId,
            messageWrapper = MessageWrapper(issuerCryptoService),
            serviceEndpoint = issuerServiceEndpoint,
            credentialScheme = scheme,
        )

    suspend fun runProtocolFlow(): IssueCredentialProtocolResult {
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

    fun assertAtomicVc(issuedCredentials: IssueCredentialProtocolResult, schema: String) {
        issuedCredentials.accepted.shouldNotBeEmpty()
        issuedCredentials.accepted.map { it.vc.credentialSubject }.forEach {
            it.shouldBeInstanceOf<AtomicAttributeCredential>()
            it.name shouldStartWith schema
        }
        issuedCredentials.rejected.shouldBeEmpty()
    }

    fun assertAttachment(issuedCredentials: IssueCredentialProtocolResult, attributeName: String) {
        issuedCredentials.accepted.shouldNotBeEmpty()
        issuedCredentials.accepted.map { it.vc.credentialSubject }
            .filterIsInstance<AtomicAttributeCredential>()
            .filter { it.name == attributeName }
            .shouldNotBeEmpty()
        issuedCredentials.attachments.shouldNotBeEmpty()
    }

    fun assertEmptyVc(issuedCredentials: IssueCredentialProtocolResult) {
        issuedCredentials.accepted.shouldBeEmpty()
        issuedCredentials.rejected.shouldNotBeEmpty()
    }

    testSuite("tests", testConfig = TestConfig.aroundEachTest { action ->
        issuerCryptoService = DefaultCryptoService()
        holderCryptoService = DefaultCryptoService()
        issuer = IssuerAgent.newDefaultInstance(issuerCryptoService, dataProvider = DummyCredentialDataProvider())
        holder = HolderAgent.newDefaultInstance(holderCryptoService)
        issuerServiceEndpoint = "https://example.com/issue?${uuid4()}"
        holderMessenger = initHolderMessenger()
        action()
    }) {
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
}
