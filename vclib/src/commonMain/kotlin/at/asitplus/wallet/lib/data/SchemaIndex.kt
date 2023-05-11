package at.asitplus.wallet.lib.data

object SchemaIndex {

    const val BASE = "https://wallet.a-sit.at"
    const val CRED_GENERIC = "$BASE/schemas/1.0.0/generic.json"
    const val PROT_ISSUE_CRED = "$BASE/issue-credential/1.0"
    const val MSG_ISSUE_CRED_REQUEST = "$PROT_ISSUE_CRED/request-credential"
    const val MSG_ISSUE_CRED_ISSUE = "$PROT_ISSUE_CRED/issue-credential"
    const val MSG_PROBLEM_REPORT = "$BASE/problems/1.0/problem-report"
    const val PROT_PRESENT_PROOF = "$BASE/present-proof/1.0"
    const val MSG_PRESENT_PROOF_REQUEST = "$PROT_PRESENT_PROOF/request-presentation"
    const val MSG_PRESENT_PROOF_PRESENTATION = "$PROT_PRESENT_PROOF/presentation"
    const val PROT_OOB = "$BASE/out-of-band/1.0"
    const val MSG_OOB_INVITATION = "$PROT_OOB/invitation"

}