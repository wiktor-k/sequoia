use std::fmt;

use Error;

pub type Spanned<Token, Loc, Error> = Result<(Loc, Token, Loc), Error>;

// The type of the parser's input.
//
// The parser iterators over tuples consisting of the token's starting
// position, the token itself, and the token's ending position.
pub(crate) type LexerItem<Token, Loc, Error> = Spanned<Token, Loc, Error>;

#[derive(Debug, Clone, PartialEq)]
pub enum Token<'a> {
    WSP(char),
    #[allow(non_camel_case_types)]
    NO_WS_CTL(char),
    CR,
    LF,
    LPAREN,
    RPAREN,
    LANGLE,
    RANGLE,
    LBRACKET,
    RBRACKET,
    COLON,
    SEMICOLON,
    AT,
    BACKSLASH,
    COMMA,
    DOT,
    DQUOTE,
    // Everything else.
    OTHER(&'a str),
}

impl<'a> fmt::Display for Token<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&format!("{:?}", self)[..])
    }
}

impl<'a> From<Token<'a>> for String {
    fn from(t: Token<'a>) -> String {
        use self::Token::*;
        match t {
            WSP(c) => c.to_string(),
            NO_WS_CTL(c) => c.to_string(),
            CR => '\r'.to_string(),
            LF => '\n'.to_string(),
            LPAREN => '('.to_string(),
            RPAREN => ')'.to_string(),
            LANGLE => '<'.to_string(),
            RANGLE => '>'.to_string(),
            LBRACKET => '['.to_string(),
            RBRACKET => ']'.to_string(),
            COLON => ':'.to_string(),
            SEMICOLON => ';'.to_string(),
            AT => '@'.to_string(),
            BACKSLASH => '\\'.to_string(),
            COMMA => ','.to_string(),
            DOT => '.'.to_string(),
            DQUOTE => '"'.to_string(),
            OTHER(s) => s.to_string(),
        }
    }
}

impl<'a> Token<'a> {
    pub fn to_string(self) -> String {
        self.into()
    }
}

pub(crate) struct Lexer<'input> {
    offset: usize,
    input: &'input str,
}

impl<'input> Lexer<'input> {
    pub fn new(input: &'input str) -> Self {
        Lexer { offset: 0, input }
    }
}

// 3.2.1. Primitive Tokens

// The symbols.  The default tokenizer returns &str, but we want
// chars.  So, we need to do a little dance.
//
// match {
//     // All unicode white space.
//     // 2.2.2. says that whitespace is only ' ' and '\t'.
//     r" \t" => WSP_TOKEN,
// 
//     r"(?x)
//         [\x01-\x08         # %d1-8 /
//          \x0b              # %d11 /
//          \x0c              # %d12 /
//          \x0e-\x1f         # %d14-31 /
//          \x7f              # %d127
//         ]" => NO_WS_CTL_TOKEN,
// 
//     "\r" => CR_TOKEN,
//     "\n" => LF_TOKEN,
// 
//     // specials
//     "(" => LPAREN_TOKEN,
//     ")" => RPAREN_TOKEN,
//     "<" => LANGLE_TOKEN,
//     ">" => RANGLE_TOKEN,
//     "[" => LBRACKET_TOKEN,
//     "]" => RBRACKET_TOKEN,
//     ":" => COLON_TOKEN,
//     ";" => SEMICOLON_TOKEN,
//     "@" => AT_TOKEN,
//     "\\" => BACKSLASH_TOKEN,
//     "," => COMMA_TOKEN,
//     "." => DOT_TOKEN,
//     "\"" =>  DQUOTE_TOKEN,
// } else {
//     // Everything else.
//     r"." =>  OTHER_TOKEN
// }

impl<'input> Iterator for Lexer<'input> {
    type Item = LexerItem<Token<'input>, usize, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        use self::Token::*;

        tracer!(::TRACE, "Lexer::next");

        // Returns the length of the first character in s in bytes.
        // If s is empty, returns 0.
        fn char_bytes(s: &str) -> usize {
            if let Some(c) = s.chars().next() {
                c.len_utf8()
            } else {
                0
            }
        }

        let one = |input: &'input str| -> Option<Token> {
            let c = input.chars().next()?;
            Some(match c {
                c @ ' ' | c @ '\t' => WSP(c),

                // NO-WS-CTL = %d1-8 /          ; US-ASCII control characters
                //             %d11 /    0xB    ;  that do not include the
                //             %d12 /    0xC    ;  carriage return, line feed,
                //             %d14-31 / 0xE-1F ;  and white space characters
                //             %d127     0x7F
                c @ '\x01'..='\x08'
                    | c @ '\x0B'..='\x0C'
                    | c @ '\x0E'..='\x1F'
                    | c @ '\x7F' =>
                    NO_WS_CTL(c),

                '\r' => CR,
                '\n' => LF,
                '(' => LPAREN,
                ')' => RPAREN,
                '<' => LANGLE,
                '>' => RANGLE,
                '[' => LBRACKET,
                ']' => RBRACKET,
                ':' => COLON,
                ';' => SEMICOLON,
                '@' => AT,
                '\\' => BACKSLASH,
                ',' => COMMA,
                '.' => DOT,
                '"' => DQUOTE,

                _ => OTHER(&input[0..c.len_utf8()]),
            })
        };

        let mut l = char_bytes(self.input);
        let t = match one(self.input) {
            Some(OTHER(_)) => {
                loop {
                    if let Some(OTHER(s)) = one(&self.input[l..]) {
                        l = l + char_bytes(s);
                    } else {
                        break OTHER(&self.input[..l]);
                    }
                }
            },
            Some(t) => t,
            None => return None,
        };

        self.input = &self.input[l..];

        let start = self.offset;
        let end = start + l;
        self.offset += l;

        t!("Returning token at offset {}: '{:?}'",
           start, t);

        Some(Ok((start, t, end)))
    }
}

impl<'input> From<&'input str> for Lexer<'input> {
    fn from(i: &'input str) -> Lexer<'input> {
        Lexer::new(i)
    }
}
