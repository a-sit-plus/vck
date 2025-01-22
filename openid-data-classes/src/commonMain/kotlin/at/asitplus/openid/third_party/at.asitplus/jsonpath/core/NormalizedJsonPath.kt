package at.asitplus.openid.third_party.at.asitplus.jsonpath.core

import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment

operator fun NormalizedJsonPath.plus(name: String) = NormalizedJsonPath(segments + NormalizedJsonPathSegment.NameSegment(name))
operator fun NormalizedJsonPath.plus(index: UInt) = NormalizedJsonPath(segments + NormalizedJsonPathSegment.IndexSegment(index))