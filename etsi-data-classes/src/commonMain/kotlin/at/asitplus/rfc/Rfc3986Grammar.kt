package at.asitplus.rfc

interface Rfc3986Grammar : Rfc2234Grammar {
    companion object : Rfc3986Grammar
    /**
     * unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
     */
    fun isUnreserved(char: Char) = isAlpha(char) || isDigit(char) || char in "-._~"

    /**
     *       reserved    = gen-delims / sub-delims
     *
     *       gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
     *
     *       sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
     *                   / "*" / "+" / "," / ";" / "="
     */
    fun isReserved(char: Char) = isGenericUriDelimiter(char) || isSubcomponentDelimiter(char)
    fun isGenericUriDelimiter(char: Char) = char in ":/?#[]@"
    fun isSubcomponentDelimiter(char: Char) = char in "!$&'()*+,;="

    /**
     * All these characters are allowed in a pchar from a tokenizer perspective.
     * Semantic validation may need to ensure that % is always followed by 2 hex digits.
     */
    fun isPCharLikeCharacter(char: Char) =
        isUnreserved(char) || isSubcomponentDelimiter(char) || char in ":@" || isPercentEncodedLikeCharacter(char)

    /**
     * All these characters are allowed in a pct-encoded char from a tokenizer perspective.
     * Semantic validation may need to ensure that % is always followed by 2 hex digits.
     */
    fun isPercentEncodedLikeCharacter(char: Char) = char == '%' || isHexDigit(char)
}