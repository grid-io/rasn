mod rasn {

    #[derive(Debug, PartialEq)]
    struct ParseToken<'a, T> {
        value : T,
        remainder: &'a[u8]
    }

    #[derive(Debug, PartialEq)]
    enum ASNToken<'a> {
        BeginSequence(&'a[u8]),             // the interior data of the sequence
        EndSequence,
        BeginSet(&'a[u8]),                  // the interior data of the set
        EndSet,
        GenericTLV(&'static str, &'a[u8])   // any TLV
    }

    #[derive(Debug, PartialEq)]
    enum ParseError<'a> {
        NonUniversalType(u8),
        UnsupportedUniversalType(u8),
        InsufficientBytes(usize, &'a[u8]), // the required length and the actual remaining bytes
        UnsupportedLengthByteCount(u8),
        BadLengthEncoding(u8)
    }

    type ParseResult<'a, T> = Result<ParseToken<'a, T>, ParseError<'a>>;

    fn parse_ok<T>(value : T,  remainder: &[u8]) -> ParseResult<T> {
        Ok(ParseToken { value, remainder })
    }

    fn parse_one(input: &[u8]) -> ParseResult<ASNToken> {

        fn parse_seq(input: &[u8]) -> ParseResult<ASNToken> {
            parse_length(input).and_then(
                |result|  {
                    if result.remainder.len() < result.value {
                        Err(ParseError::InsufficientBytes(result.value, result.remainder))
                    }
                    else {
                        parse_ok(ASNToken::BeginSequence(&result.remainder[0..result.value]), &result.remainder[result.value..])
                    }
                }
            )
        }

        fn parse_set(input: &[u8]) -> ParseResult<ASNToken> {
            parse_length(input).and_then(
                |result|  {
                    if result.remainder.len() < result.value {
                        Err(ParseError::InsufficientBytes(result.value, result.remainder))
                    }
                    else {
                        parse_ok(ASNToken::BeginSet(&result.remainder[0..result.value]), &result.remainder[result.value..])
                    }
                }
            )
        }

        fn parse_generic_tlv<'a>(name: &'static str, input: &'a[u8]) -> ParseResult<'a, ASNToken<'a>> {
            parse_length(input).and_then(
                |result|  {
                    if result.remainder.len() < result.value {
                        Err(ParseError::InsufficientBytes(result.value, result.remainder))
                    }
                    else {
                        parse_ok(ASNToken::GenericTLV(name, &result.remainder[0..result.value]), &result.remainder[result.value..])
                    }
                }
            )
        }

        if input.len() < 1 {
            return Err(ParseError::InsufficientBytes(1, input))
        }

        let typ = input[0];

        if typ & 0b11000000 != 0 {
            // non-universal type
            return Err(ParseError::NonUniversalType(typ))
        }

        match typ & 0b00111111 {

           0x02 => parse_generic_tlv("Integer", &input[1..]),
           0x03 => parse_generic_tlv("BitString", &input[1..]),
           0x04 => parse_generic_tlv("OctetString", &input[1..]),
           0x05 => parse_generic_tlv("Null", &input[1..]),
           0x06 => parse_generic_tlv("ObjectIdentifier", &input[1..]),
           0x0C => parse_generic_tlv("UTF8String", &input[1..]),
           0x13 => parse_generic_tlv("PrintableString", &input[1..]),
           0x14 => parse_generic_tlv("T61String", &input[1..]),
           0x16 => parse_generic_tlv("IA5String", &input[1..]),
           0x17 => parse_generic_tlv("UTCTime", &input[1..]),


           0x30 => parse_seq(&input[1..]),
           0x31 => parse_set(&input[1..]),




           x => Err(ParseError::UnsupportedUniversalType(x))
        }
    }

    fn parse_length(input: &[u8]) -> ParseResult<usize> {

        fn decode_one(input: &[u8]) -> ParseResult<usize> {
            let value = input[0];
            if value < 128 {
                Err(ParseError::BadLengthEncoding(value)) // should have been encoded in single byte
            } else {
                parse_ok(value as usize, &input[1..])
            }
        }

        fn decode_two(input: &[u8]) -> ParseResult<usize> {
           let value = (input[0] as usize) << 8 | input[1] as usize;
           parse_ok(value, &input[2..])
        }

        fn decode_three(input: &[u8]) -> ParseResult<usize> {
            let value = ((input[0] as usize) << 16) | ((input[1] as usize) << 8) | (input[2] as usize);
            parse_ok(value, &input[3..])
        }

        fn decode_four(input: &[u8]) -> ParseResult<usize> {
            let value = ((input[0] as usize) << 24) | ((input[1] as usize) << 16) | ((input[2] as usize) << 8) | (input[3] as usize);
            parse_ok(value, &input[4..])
        }

        if input.len() < 1 {
            return Err(ParseError::InsufficientBytes(1, input))
        }

        let top = input[0] & 0b10000000;
        let count = input[0] & 0b01111111;

        if top == 0 {
            parse_ok(count as usize, &input[1..])
        }
        else {

            let remainder = &input[1..];

            if remainder.len() < count as usize {
                return Err(ParseError::InsufficientBytes(count as usize, remainder))
            }

            match count {
                1 => decode_one(remainder),
                2 => decode_two(remainder),
                3 => decode_three(remainder),
                4 => decode_four(remainder),
                _ => Err(ParseError::UnsupportedLengthByteCount(count))
            }
        }
    }

    enum ParserState<'a> {
        Continue(&'a[u8]),
        EndSequence(&'a[u8]),
        EndSet(&'a[u8])
    }

    struct Parser<'a> {
        states: Vec<ParserState<'a>>
    }

    impl<'a> Parser<'a> {
        fn new(input: &'a[u8]) -> Parser {
            Parser { states: vec![ParserState::Continue(input)] }
        }
    }


    impl<'a> Iterator for Parser<'a> {

        type Item = ParseResult<'a, ASNToken<'a>>;


        fn next(&mut self) -> Option<Self::Item> {
            self.states.pop().map(
                |current| {
                    match current {
                        ParserState::Continue(pos) => {
                            match parse_one(pos) {
                                Err(e) => {
                                    self.states.clear();
                                    Err(e)
                                },
                                Ok(token) => match token.value {
                                    ASNToken::BeginSequence(contents) => {
                                        self.states.push(ParserState::EndSequence(token.remainder));
                                        if !contents.is_empty() {
                                            self.states.push(ParserState::Continue(contents));
                                        }
                                        Ok(token)
                                    },
                                    ASNToken::BeginSet(contents) => {
                                        self.states.push(ParserState::EndSet(token.remainder));
                                        if !contents.is_empty() {
                                            self.states.push(ParserState::Continue(contents));
                                        }
                                        Ok(token)
                                    }
                                    _ => {
                                        if token.remainder.len() > 0 {
                                            self.states.push(ParserState::Continue(token.remainder));
                                        }
                                        Ok(token)
                                    }
                                }
                            }
                        },
                        ParserState::EndSequence(remainder) => {
                            if !remainder.is_empty() {
                                self.states.push(ParserState::Continue(remainder));
                            }

                            parse_ok(ASNToken::EndSequence, remainder)
                        },
                        ParserState::EndSet(remainder) => {
                            if !remainder.is_empty() {
                                self.states.push(ParserState::Continue(remainder));
                            }

                            parse_ok(ASNToken::EndSet, remainder)
                        }
                    }
                }
            )
        }
    }


    #[cfg(test)]
    mod tests {
        use ::rasn::*;

        const TOP_BIT : u8 = 1 << 7;

        #[test]
        fn decode_length_on_empty_bytes_fails() {
            assert_eq!(parse_length(&[]), Err(ParseError::InsufficientBytes(1, &[])))
        }

        #[test]
        fn decode_length_on_single_byte_returns_valid_result() {
            assert_eq!(parse_length(&[127, 0xDE, 0xAD]), parse_ok(127, &[0xDE, 0xAD]))
        }

        #[test]
        fn decode_length_on_count_of_one_returns_none_if_value_less_than_128() {
            assert_eq!(parse_length(&[TOP_BIT | 1, 127]), Err(ParseError::BadLengthEncoding(127)))
        }

        #[test]
        fn decode_length_on_count_of_one_succeeds_if_value_greater_than_127() {
            assert_eq!(parse_length(&[TOP_BIT | 1, 128]), parse_ok(128, &[]))
        }

        #[test]
        fn decode_length_on_count_of_two_succeeds() {
            assert_eq!(parse_length(&[TOP_BIT | 2, 0x01, 0x02, 0x03]), parse_ok(0x0102, &[0x03]))
        }

        #[test]
        fn decode_length_on_count_of_three_succeeds() {
            assert_eq!(parse_length(&[TOP_BIT | 3, 0x01, 0x02, 0x03, 0x04]), parse_ok(0x010203, &[0x04]))
        }

        #[test]
        fn decode_length_on_count_of_four_succeeds() {
            assert_eq!(parse_length(&[TOP_BIT | 4, 0x01, 0x02, 0x03, 0x04, 0x05]), parse_ok(0x01020304, &[0x05]))
        }

        #[test]
        fn decode_length_on_count_of_five_fails() {
            assert_eq!(parse_length(&[TOP_BIT | 5, 0x01, 0x02, 0x03, 0x04, 0x05]), Err(ParseError::UnsupportedLengthByteCount(5)))
        }

        #[test]
        fn parse_one_fails_for_non_universal_type() {
            assert_eq!(parse_one(&[0xFF]), Err(ParseError::NonUniversalType(0xFF)))
        }

        #[test]
        fn parse_one_fails_for_unknown_universal_type() {
            assert_eq!(parse_one(&[0x3F]), Err(ParseError::UnsupportedUniversalType(0x3F)))
        }

        #[test]
        fn parses_sequence_correctly() {
            assert_eq!(parse_one(&[0x30, 0x03, 0x02, 0x03, 0x04, 0x05, 0x06]), parse_ok(ASNToken::BeginSequence(&[0x02, 0x03, 0x04]), &[0x05, 0x06]))
        }

        #[test]
        fn parse_sequence_fails_if_insufficient_bytes() {
            assert_eq!(parse_one(&[0x30, 0x0F, 0xDE, 0xAD]), Err(ParseError::InsufficientBytes(0x0F, &[0xDE, 0xAD])))
        }

        const CERT_DATA : [u8; 534] = [
            0x30, 0x82, 0x02, 0x12, 0x30, 0x82, 0x01, 0x7b, 0x02, 0x02, 0x0d, 0xfa, 0x30, 0x0d, 0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x81, 0x9b, 0x31, 0x0b,
            0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4a, 0x50, 0x31, 0x0e, 0x30, 0x0c, 0x06,
            0x03, 0x55, 0x04, 0x08, 0x13, 0x05, 0x54, 0x6f, 0x6b, 0x79, 0x6f, 0x31, 0x10, 0x30, 0x0e, 0x06,
            0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x43, 0x68, 0x75, 0x6f, 0x2d, 0x6b, 0x75, 0x31, 0x11, 0x30,
            0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x08, 0x46, 0x72, 0x61, 0x6e, 0x6b, 0x34, 0x44, 0x44,
            0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x0f, 0x57, 0x65, 0x62, 0x43, 0x65,
            0x72, 0x74, 0x20, 0x53, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03,
            0x55, 0x04, 0x03, 0x13, 0x0f, 0x46, 0x72, 0x61, 0x6e, 0x6b, 0x34, 0x44, 0x44, 0x20, 0x57, 0x65,
            0x62, 0x20, 0x43, 0x41, 0x31, 0x23, 0x30, 0x21, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
            0x01, 0x09, 0x01, 0x16, 0x14, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x40, 0x66, 0x72, 0x61,
            0x6e, 0x6b, 0x34, 0x64, 0x64, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x32, 0x30,
            0x38, 0x32, 0x32, 0x30, 0x35, 0x32, 0x36, 0x35, 0x34, 0x5a, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x38,
            0x32, 0x31, 0x30, 0x35, 0x32, 0x36, 0x35, 0x34, 0x5a, 0x30, 0x4a, 0x31, 0x0b, 0x30, 0x09, 0x06,
            0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4a, 0x50, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04,
            0x08, 0x0c, 0x05, 0x54, 0x6f, 0x6b, 0x79, 0x6f, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04,
            0x0a, 0x0c, 0x08, 0x46, 0x72, 0x61, 0x6e, 0x6b, 0x34, 0x44, 0x44, 0x31, 0x18, 0x30, 0x16, 0x06,
            0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
            0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x5c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
            0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x4b, 0x00, 0x30, 0x48, 0x02, 0x41, 0x00, 0x9b, 0xfc,
            0x66, 0x90, 0x79, 0x84, 0x42, 0xbb, 0xab, 0x13, 0xfd, 0x2b, 0x7b, 0xf8, 0xde, 0x15, 0x12, 0xe5,
            0xf1, 0x93, 0xe3, 0x06, 0x8a, 0x7b, 0xb8, 0xb1, 0xe1, 0x9e, 0x26, 0xbb, 0x95, 0x01, 0xbf, 0xe7,
            0x30, 0xed, 0x64, 0x85, 0x02, 0xdd, 0x15, 0x69, 0xa8, 0x34, 0xb0, 0x06, 0xec, 0x3f, 0x35, 0x3c,
            0x1e, 0x1b, 0x2b, 0x8f, 0xfa, 0x8f, 0x00, 0x1b, 0xdf, 0x07, 0xc6, 0xac, 0x53, 0x07, 0x02, 0x03,
            0x01, 0x00, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
            0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x14, 0xb6, 0x4c, 0xbb, 0x81, 0x79, 0x33, 0xe6, 0x71, 0xa4,
            0xda, 0x51, 0x6f, 0xcb, 0x08, 0x1d, 0x8d, 0x60, 0xec, 0xbc, 0x18, 0xc7, 0x73, 0x47, 0x59, 0xb1,
            0xf2, 0x20, 0x48, 0xbb, 0x61, 0xfa, 0xfc, 0x4d, 0xad, 0x89, 0x8d, 0xd1, 0x21, 0xeb, 0xd5, 0xd8,
            0xe5, 0xba, 0xd6, 0xa6, 0x36, 0xfd, 0x74, 0x50, 0x83, 0xb6, 0x0f, 0xc7, 0x1d, 0xdf, 0x7d, 0xe5,
            0x2e, 0x81, 0x7f, 0x45, 0xe0, 0x9f, 0xe2, 0x3e, 0x79, 0xee, 0xd7, 0x30, 0x31, 0xc7, 0x20, 0x72,
            0xd9, 0x58, 0x2e, 0x2a, 0xfe, 0x12, 0x5a, 0x34, 0x45, 0xa1, 0x19, 0x08, 0x7c, 0x89, 0x47, 0x5f,
            0x4a, 0x95, 0xbe, 0x23, 0x21, 0x4a, 0x53, 0x72, 0xda, 0x2a, 0x05, 0x2f, 0x2e, 0xc9, 0x70, 0xf6,
            0x5b, 0xfa, 0xfd, 0xdf, 0xb4, 0x31, 0xb2, 0xc1, 0x4a, 0x9c, 0x06, 0x25, 0x43, 0xa1, 0xe6, 0xb4,
            0x1e, 0x7f, 0x86, 0x9b, 0x16, 0x40
        ];

        #[test]
        fn iterates_over_x509() {

            let mut indent : usize = 0;

            let parser = Parser::new(&CERT_DATA);

            fn print_indent(indent: usize) {
                for i in 0..indent {
                    print!("    ");
                }
            }

            for result in parser {
                match result {
                    Err(x) => println!("{:?}", x),
                    Ok(token) => match token.value {
                       ASNToken::BeginSequence(x) => {
                           print_indent(indent);
                           println!("BeginSequence");
                           indent += 1;
                       },
                       ASNToken::EndSequence =>  {
                           indent -= 1;
                           print_indent(indent);
                           println!("EndSequence");
                       },
                        ASNToken::BeginSet(x) => {
                            print_indent(indent);
                            println!("BeginSet");
                            indent += 1;
                        },
                        ASNToken::EndSet =>  {
                            indent -= 1;
                            print_indent(indent);
                            println!("EndSet");
                        },
                       ASNToken::GenericTLV(name, contents) => {
                           print_indent(indent);
                           println!("{} ({})", name, contents.len())
                       },
                    }
                }
            }

        }


    }
}




