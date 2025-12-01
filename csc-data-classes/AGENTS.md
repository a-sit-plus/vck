# CSC Data Classes Agent

`csc-data-classes` hosts the Kotlin multiplatform models that mirror the Cloud Signature Consortium (CSC) REST API v2.\* specification (implemented against v2.0.0.2 today). The goal is to offer type-safe serialization targets for any VC-K agent that needs to consume or emit CSC-compliant payloads, without pulling in business logic or transport code.

## What Lives Here
- **Top-level CSC payloads** under `at.asitplus.csc`:  
  `CredentialListRequest` / `CredentialListResponse`, `CredentialInfoRequest` / `CredentialInfo`, `SignHashRequestParameters` / `SignHashResponseParameters`, `SignDocRequestParameters` / `SignDocResponseParameters`, `Hashes`, `Comparison`, `Method`, `QtspSignatureRequest`, and `QtspSignatureResponse`.
- **Collection entry structures** under `at.asitplus.csc.collection_entries`:  
  `Document`, `DocumentDigest`, `DocumentLocation`, `CertificateParameters`, `KeyParameters`, `AuthParameters`, `DocumentDigest` derivatives (RQES/OAuth), and related digest helpers referenced by CSC chapters 11.4–11.11.
- **Enumerations & flags** under `at.asitplus.csc.enums`:  
  `OperationMode`, `ConformanceLevel`, `SignatureFormats`, `SignatureQualifier`, `SignedEnvelopeProperty`, `CertificateOptions`, etc., matching the vocabularies defined by the CSC data tables.
- **Serialization helpers** under `at.asitplus.csc.serializers`:  
  Custom serializers for Base64-encoded X.509 certificates, ASN.1 blobs, hash lists, and QTSP-specific request/response sections so the wire format aligns with CSC JSON examples.

## Scope Guardrails
- This module **must only contain CSC API v2.\*** data classes plus the minimal supporting enums/serializers they depend on.  
  If you need data models for a different protocol, add them to a sibling `*-data-classes` module instead.
- Keep class names, field casing, and `@SerialName` annotations synchronized with the official CSC tables; cite the chapter (e.g., 11.11) in KDoc when adding new structures so downstream users can trace the source.
- When CSC publishes a new 2.x revision, update the relevant models in place and note the chapter/version in the KDoc + CHANGELOG entry.

## Tests & Verification
- Lightweight serialization sanity checks live in `src/commonTest`; expand them with deterministic fixtures whenever you touch a CSC payload to ensure we keep parity across JVM, Android, iOS, and server targets.
