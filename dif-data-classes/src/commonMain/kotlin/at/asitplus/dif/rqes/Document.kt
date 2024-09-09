package at.asitplus.dif.rqes

data class Document(
    //TODO CSC P.79
    val document: String,
    val signatureFormat: String,
    val conformanceLevel: String,
    val signAlgo: String,
    val signAlgoParams: String,
    val signedProps: List<String>,
)