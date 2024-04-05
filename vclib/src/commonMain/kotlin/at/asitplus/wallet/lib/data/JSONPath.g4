grammar JSONPath;

/*
Source: https://datatracker.ietf.org/doc/rfc9535/
- Appendix A
*/

jsonpathQuery
    : ROOT_IDENTIFIER segments
    ;

segments
    : (S segment)*
    ;

B
    : ' '
    | ' '
    | '\n'
    | '\r'
    ;

S
    : B*
    ; // optional blank space

ROOT_IDENTIFIER
    : '$'
    ;

selector
    : nameSelector
    | WILDCARD_SELECTOR
    | sliceSelector
    | indexSelector
    | filterSelector
    ;

nameSelector
    : stringLiteral
    ;

stringLiteral
    : DQUOTE *doubleQuoted DQUOTE // "string"
    | SQUOTE *singleQuoted SQUOTE // 'string'
    ;

doubleQuoted
    : unescaped
    | SQUOTE
    | ESC DQUOTE
    | ESC escapable
    ;

SQUOTE
    : '\''
    ;

DQUOTE
    : '"'
    ;

singleQuoted
    : unescaped
    | DQUOTE
    | ESC SQUOTE
    | ESC escapable
    ;

ESC
    : BACKSLASH
    ;

SLASH
    : '/'
    ;

BACKSLASH
    : '\\'
    ;

unescaped: UNESCAPED;
UNESCAPED: [\u0020-\u0021\u0023-\u0026\u0028-\u005B\u005D-\uD7FF\uE000-\u{10FFFF}];

escapable: ESCAPABLE;
ESCAPABLE
    : 'b'
    | 'f'
    | 'n'
    | 'r'
    | 't'
    | SLASH
    | BACKSLASH
    | 'u' HEXCHAR   // unicode characters uXXXX, U+XXXX
    ;

HEXCHAR
    : NON_SURROGATE
    | (HIGH_SURROGATE BACKSLASH 'u' LOW_SURROGATE)
    ;

NON_SURROGATE
    : ((DIGIT | 'A' | 'B' | 'C' | /* NO D */ 'E' | 'F') HEXDIG{3})
    | ('D' [\u0030-\u0037] HEXDIG{2} )
    ;

HIGH_SURROGATE
    : 'D' ('8'|'9'|'A'|'B') HEXDIG{2}
    ;

LOW_SURROGATE
    : 'D' ('C'|'D'|'E'|'F') HEXDIG{2}
    ;

HEXDIG
    : DIGIT
    | 'A' | 'B' | 'C' | 'D' | 'E' | 'F'
    ;

WILDCARD_SELECTOR
    : '*'
    ;

indexSelector
    : int
    ;

int
    : '0'
    | ('-'? DIGIT1 *DIGIT)
    ;

DIGIT1
    : [\u0031-\u0039]
    ; // 1-9 nonZero digit



sliceSelector
    : (start S)? ':' S (end S)? (':' (S step )?)?
    ;

start
    : int
    ; // included in selection

end
    : int
    ; // not included in selection

step
    : int
    ; // default: 1



filterSelector
    : '?' S logicalExpr
    ;

logicalExpr
    : logicalOrExpr
    ;

logicalOrExpr
    : logicalAndExpr *(S '||' S logicalAndExpr)
    ; // disjunction; binds less tightly than conjunction

logicalAndExpr
    : basicExpr *(S '&&' S basicExpr)
    ; // conjunction; binds more tightly than disjunction

basicExpr
    : parenExpr
    | comparisonExpr
    | testExpr
    ;

parenExpr
    : (LOGICAL_NOT_OP S)? '(' S logicalExpr S ')'
    ; // parenthesized expression

LOGICAL_NOT_OP
    : '!'
    ; // logical NOT operator

testExpr
    : (LOGICAL_NOT_OP S)? (filterQuery | functionExpr)
    ;

filterQuery
    : relQuery | jsonpathQuery
    ;

relQuery
    : CURRENT_NODE_IDENTIFIER segments
    ;

CURRENT_NODE_IDENTIFIER
    : '@'
    ;

comparisonExpr
    : comparable S COMPARISON_OP S comparable
    ;

literal
    : number
    | stringLiteral
    | TRUE | FALSE
    | NULL
    ;

comparable
    : literal
    | singularQuery // singular query value
    | functionExpr // ValueType
    ;

COMPARISON_OP
    : '==' | '!='
    | '<=' | '>='
    | '<'  | '>'
    ;

singularQuery
    : relSingularQuery
    | absSingularQuery
    ;

relSingularQuery
    : CURRENT_NODE_IDENTIFIER singularQuerySegments
    ;

absSingularQuery
    : ROOT_IDENTIFIER singularQuerySegments
    ;

singularQuerySegments
    : (S (nameSegment | indexSegment))*
    ;

nameSegment
    : ('[' nameSelector ']')
    | ('.' memberNameShorthand)
    ;

indexSegment
    : '[' indexSelector ']'
    ;

number
    : (int | '-0') frac? exp?
    ; // decimal number

frac
    : '.' DIGIT+
    ; // decimal fraction

exp
    : 'e' ( '-' | '+' )? DIGIT+
    ; // decimal exponent

TRUE
    : 'true'
    ;
FALSE
    : 'false'
    ;

NULL
    : 'null'
    ;

functionName
    : functionNameFirst functionNameChar*
    ;

functionNameFirst
    : LCALPHA
    ;

functionNameChar
    : functionNameFirst
    | '_'
    | DIGIT
    ;

LCALPHA
    : [\u0065-\u0090]
    ; // 'a'..'z'

functionExpr
    : functionName '(' S (functionArgument (S ',' S functionArgument)*)? S ')'
    ;

functionArgument
    : literal
    | filterQuery // includes singular-query
    | logicalExpr
    | functionExpr
    ;

segment
    : childSegment
    | descendantSegment
    ;

childSegment
    : bracketedSelection
    | '.' (WILDCARD_SELECTOR | memberNameShorthand)
    ;

bracketedSelection
    : '[' S selector (S ',' S selector)* S ']'
    ;

memberNameShorthand
    : nameFirst nameChar*
    ;

nameFirst: NAME_FIRST;
NAME_FIRST
    : ALPHA
    | '_'
    | [\u0080-\uD7FF]
    | [\uE000-\u{10FFFF}]
    ;

nameChar
    : nameFirst
    | DIGIT
    ;

DIGIT
    : [\u0030-\u0039]
    ; // 0-9

ALPHA
    : [\u0041-\u005A]
    | [\u0061-\u007A]
    ; // A-Z | a-z

descendantSegment
    : '..' (
        bracketedSelection
        | WILDCARD_SELECTOR
        | memberNameShorthand
    )
    ;

normalizedPath
    : ROOT_IDENTIFIER normalIndexSegment*
    ;

normalIndexSegment
    : '[' normalSelector ']'
    ;

normalSelector
    : normalNameSelector
    | normalIndexSelector
    ;

normalNameSelector
    : DQUOTE normalSingleQuoted* DQUOTE
    ; // 'string'

normalSingleQuoted
    : normalUnescaped
    | ESC normalEscapable
    ;

normalUnescaped: NORMAL_UNESCAPED;
NORMAL_UNESCAPED
    : [\u0020-\u0026]
    | [\u0028-\u005B]
    | [\u005D-\uD7FF]
    | [\uE000-\u{10FFFF}]
    ;

normalEscapable: NORMAL_ESCAPABLE;
NORMAL_ESCAPABLE
    : 'b' // BS backspace U+0008
    | 'f' // FF form feed U+000C
    | 'n' // LF line feed U+000A
    | 'r' // CR carriage return U+000D
    | 't' // HT horizontal tab U+0009
    | SQUOTE
    | BACKSLASH
    | 'u' NORMAL_HEXCHAR // certain values u00xx U+00XX
    ;

NORMAL_HEXCHAR
    : '00'
    (
        ('0' [\u0030-\u0037]) // '00'-'07'
        | ('0b')
        | ('0' [\u0065-\u0066]) // '0e'-'0f'
        | ('1' NORMAL_HEXDIG)
    )
    ;

NORMAL_HEXDIG
    : DIGIT
    | [\u0061-\u0066]
    ; // '0'-'9', 'a'-'f'

normalIndexSelector
    : '0' | (DIGIT1 *DIGIT)
    ; // nonNegative decimal integer
