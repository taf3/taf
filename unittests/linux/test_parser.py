#!/usr/bin/env python
"""
@copyright Copyright (c) 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  test_parser.py

@summary  parse tools Unittests
"""

import operator
import pytest

from pygments import token

from testlib.linux.suricata import parser


_TEST_RULE = """
alert ip [221.229.166.0/24, [ ! 207.244.76.0/24 ]]
any -> $HOME_NET any
(msg:"ET DROP Dshield Block Listed Source group 1"; reference:url,feed.dshield.org/block.txt; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; flowbits:set,ET.Evil; flowbits:set,ET.DshieldIP; sid:2402000; rev:4095;)
"""


class TestParser(object):
    HOST_LEXER = parser.HostLexer()
    HOST_PARSER = parser.HostParser()

    def test_lexer_tokenizer(self):
        _str = 'alert ip [221.229.166.0/24, [207.244.76.0/24]]'
        tokens = [_t for _t in self.HOST_LEXER.get_tokens_unprocessed(_str)]
        assert list(map(operator.itemgetter(1), tokens)) == [
            parser.TT_ALERT, token.Token.Text.Whitespace,
            parser.TT_IP, token.Token.Text.Whitespace,
            parser.TT_BR_LEFT,
            parser.TT_IPv4_MASK,
            parser.TT_COMMA, token.Token.Text.Whitespace,
            parser.TT_BR_LEFT,
            parser.TT_IPv4_MASK,
            parser.TT_BR_RIGHT,
            parser.TT_BR_RIGHT]

    def test_lexer_lexem_ok(self):
        # TODO
        pass

    def test_lexer_lexem_error(self):
        # TODO
        pass

    def test_parser_syntax_ok(self):
        # TODO
        pass

    def test_parser_synax_error_unexpected_token(self):
        # TODO
        pass

    def test_parser_syntax_error_tokens_underflow(self):
        # TODO
        pass

    def test_parser_syntax_error_tokens_overflow(self):
        # TODO
        pass

    def test_parser_semantics_ok(self):
        CIDR_A = '221.229.166.0/24'
        CIDR_B = '207.244.76.0/24'
        HOME_NET = '200.244.76.0/24'
        SYMBOL_TABLE = {
            '$HOME_NET': HOME_NET
        }
        INPUT_STR = '[{0}, [{1}], !{2}]'.format(CIDR_A, CIDR_B, '$HOME_NET')

        tokens = self.HOST_LEXER.get_tokens_unprocessed(INPUT_STR)
        ast = self.HOST_PARSER.parse(tokens, ignore_ws=True)
        yes, no = self.HOST_PARSER.semantics(ast, SYMBOL_TABLE, check=True)
        assert yes == {CIDR_A, CIDR_B}
        assert no == {HOME_NET}

    def test_parser_semantics_fail_duplicates(self):
        CIDR_A = '221.229.166.0/24'
        CIDR_B = '207.244.76.0/24'
        HOME_NET = CIDR_B
        SYMBOL_TABLE = {
            '$HOME_NET': HOME_NET
        }
        INPUT_STR = '[{0}, [{1}], !{2}]'.format(CIDR_A, CIDR_B, '$HOME_NET')

        tokens = self.HOST_LEXER.get_tokens_unprocessed(INPUT_STR)
        ast = self.HOST_PARSER.parse(tokens, ignore_ws=True)

        with pytest.raises(AssertionError):
            self.HOST_PARSER.semantics(ast, SYMBOL_TABLE, check=True)
