package at.asitplus.iso.zk

import at.asitplus.KmmResult
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSystemParamRegistry
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.wallet.lib.agent.IsoPresentationMeta
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.SubjectCredentialStore


object IsoMdocZkProofRegistry {
    private val factories = LinkedHashSet<IsoMdocZkProofFactory>()

    init {
        // TODO: rethink autoregistering
    }

    fun register(factory: IsoMdocZkProofFactory): KmmResult<IsoMdocZkProofFactory> {
        if (!factories.contains(factory)) {
            val initResult = factory.initialize()
            return initResult.fold(
                onSuccess = {
                    ZkSystemParamRegistry.register(factory.systemName, factory.paramSerializers)
                    factories.add(factory)
                    KmmResult.success(factory)
                },
                onFailure = { KmmResult.failure(it) }
            )
        } else {
            // TODO: adjust exception type
            return KmmResult.failure(IllegalStateException("Factory already registered!"))
        }
    }


    // TODO: consider giving even more options to findFactory, a document or zkDocument could be relevant,
    //  for example if the number of attributes is relevant, or the existence of a DeviceSigned namespaces
    private fun findFactory(zkSystemSpecs: List<ZkSystemSpec>): Pair<IsoMdocZkProofFactory, ZkSystemSpec> {
        zkSystemSpecs.forEach { zkSystemSpec ->
            factories.firstOrNull { it.supports(zkSystemSpec) }
                ?.let { return it to zkSystemSpec}
        }
        error("Unsupported zkSystemSpecs: $zkSystemSpecs")
    }

    suspend fun generate(
        request: PresentationRequestParameters,
        credentialAndMeta: Map.Entry<SubjectCredentialStore.StoreEntry.Iso, IsoPresentationMeta>): IsoMdocZkProof {
        val credential = credentialAndMeta.key
        val meta = credentialAndMeta.value
        val (isoMdocZkProofFactory, zkSystemSpec) = findFactory(meta.spec.systemSpecs)
        return isoMdocZkProofFactory.generate(request, credential, meta.claims, zkSystemSpec)
    }

    fun load(
        zkSystemSpecs: List<ZkSystemSpec>,
        zkDocument: ZkDocument,
        sessionTranscript: SessionTranscript
    ): IsoMdocZkProof {
        val (isoMdocZkProofFactory, zkSystemSpec) = findFactory(zkSystemSpecs)
        return isoMdocZkProofFactory.load(zkDocument, sessionTranscript, zkSystemSpec)
    }

}