# Copyright (c) 2016 - 2017, Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""``parser.py``

`Suricata rules parsing support`

"""

import itertools

from collections import namedtuple

from pygments import lexer
from pygments import token


class TreeNodeBase(object):
    """
    """

    def __init__(self):
        super(TreeNodeBase, self).__init__()

    def is_root(self):
        pass

    def is_leaf(self):
        pass

    def iter_nodes(self):
        pass


_TN_NO_PARENT = TreeNodeBase()


class TreeNode(TreeNodeBase):
    TN_NO_PARENT = _TN_NO_PARENT

    def __init__(self, parent=_TN_NO_PARENT, data=None):
        super(TreeNode, self).__init__()

        if not parent:
            parent = _TN_NO_PARENT
        self.parent = parent
        self.nodes = {}
        self.data = data

    def is_root(self):
        return self is self.TN_NO_PARENT

    def is_leaf(self):
        return bool(self.nodes)

    def iter_nodes(self):
        return iter(self.nodes)


class AST_Node(TreeNode):
    def is_leaf(self):
        return AST_Node_Pred.NP_IS_LEAF(self)


class AST_Node_Pred(object):
    """AST Node predicates helper.

    """
    @classmethod
    def NP_IS_TERMINAL(cls, node):
        return isinstance(node, AST_T_Node)

    @classmethod
    def NP_IS_NONTERMINAL(cls, node):
        return isinstance(node, AST_N_Node)

    @classmethod
    def NP_GEN_DATA(cls, data_predicate):
        def wrapper(node):
            return data_predicate(node.data)

    @classmethod
    def NP_IS_LEAF(cls, node):
        return cls.NP_IS_TERMINAL(node) or cls.NP_IS_NONTERMINAL(node) and not node.data


class AST_T_Node(AST_Node):
    """AST Terminal - leaf nodes.

    """

    def is_leaf(self):
        return True

    def __str__(self):
        return 'Node T: T: {}'.format(self.data)


class AST_N_Node(AST_Node):
    """AST Nonterminal nodes.

    """

    @classmethod
    def from_products(cls, products, parent=TreeNode.TN_NO_PARENT, is_terminal=None):
        _data = [AST_T_Node(parent=parent, data=p) if is_terminal(p)
                 else AST_N_Node(p, parent=parent)
                 for p in products]

        return _data

    def __init__(self, n, parent=TreeNode.TN_NO_PARENT, data=None):
        super(AST_N_Node, self).__init__(parent=parent, data=data)
        self.n = n

    def __iter__(self):
        return AST_Node_Iterator(self)

    def get_nodes(self, predicate=None, depth=None, add_self=False):
        """
        """
        nodes = []
        if 0 == depth:
            pass
        else:
            kwargs = {
                'predicate': predicate,
                'add_self': add_self,
            }
            if depth is not None:
                assert depth > 0
                kwargs['depth'] = depth - 1

            nodes = []
            for node in self.data:
                if isinstance(node, AST_N_Node):
                    nodes.extend(node.get_nodes(**kwargs))

                if not predicate or predicate(node):
                    nodes.append(node)

        if add_self:
            if not predicate or predicate(self):
                nodes.append(self)

        return nodes

    def get_child_nodes(self, **kwargs):
        kwargs['depth'] = 1
        return self.get_nodes(**kwargs)

    @classmethod
    def NP_IS_TERMINAL(cls, node):
        return isinstance(node, AST_T_Node)

    @classmethod
    def NP_IS_NONTERMINAL(cls, node):
        return isinstance(node, AST_N_Node)

    @classmethod
    def NP_GEN_DATA(cls, data_predicate):
        def wrapper(node):
            return data_predicate(node.data)

    def expand_node(self, products, is_terminal=None):
        self.data = self.from_products(products, parent=self, is_terminal=is_terminal)

    def __str__(self):
        if not self.data:
            return 'some N-T Node({})'.format(self.n)

        return 'Node N: N: {0}, {1} nodes: [ {2} ]'.format(
            self.n,
            len(self.data),
            ' '.join(map(str, self.data)))


class AST_Node_Iterator(object):
    """
    """

    def __init__(self, ast_node):
        super(AST_Node_Iterator, self).__init__()
        self.root_node = ast_node
        self.it = ast_node
        self.begin = True

    def __next__(self):
        if self.begin:
            self.begin = False
            return self.it

        try:
            while True:
                try:
                    if self.it is self.root_node.parent:
                        raise StopIteration

                    if isinstance(self.it, AST_N_Node) and self.it.data:
                        self.it = self.it.data[0]
                        break
                    _i = self.it.parent.data.index(self.it)
                    self.it = self.it.parent.data[_i + 1]  # advance sibling via parent
                    break

                except IndexError:
                    while True:
                        if self.it is self.root_node:
                            raise StopIteration

                        self.it = self.it.parent
                        try:
                            _i = self.it.parent.data.index(self.it)
                            self.it = self.it.parent.data[_i + 1]
                            break
                        except IndexError:
                            continue

                    break

        except AttributeError:
            raise StopIteration

        return self.it


AST_Node_Iterator.next = AST_Node_Iterator.__next__


class Tree(object):
    """
    """

    def __init__(self, root):
        super(Tree, self).__init__()

        self.root = root


class LL_Parser(object):
    """
    """

    __EPSILON = object()
    __DOLLAR = object()

    @classmethod
    def _format_product(cls, product):
        if cls.__EPSILON == product:
            return '"__EPSILON__"'
        if cls.__DOLLAR == product:
            return '"__DOLLAR__"'
        return '"{0}"'.format(str(product))

    def __init__(self, grammar):
        super(LL_Parser, self).__init__()
        self.N, self.T, self.R, self.S = [grammar.get(item) for item in ['N', 'T', 'R', 'S']]

        assert self._build_LL_table(grammar)

    @classmethod
    def SyntaxError(cls, node_root=None, node_ptr=None, tokens=None, got=None):
        if isinstance(node_ptr, AST_T_Node):
            node_ptr = next(iter(node_ptr.parent))

        _expected_lst = [_n for _n in node_ptr]
        _expected_str = ', '.join(map(str, [_n.data if isinstance(_n, AST_T_Node)
                                            else _n.n if isinstance(_n, AST_N_Node)
                                            else str(_n)
                                            for _n in _expected_lst]))
        raise Exception('Syntax Error: Unexpected token: {}. Expected: [{}]'
                        .format(got, _expected_str))

    def parse(self, tokens, ignore_ws=False):
        """
        """
        if ignore_ws:
            tokens = [_t for _t in tokens
                      if not token.is_token_subtype(token.Token.Text.Whitespace, _t)]

        tokens.extend([self.__DOLLAR])
        t_it = iter(tokens)
        t = next(t_it)

        _root_parent = AST_N_Node('<$>', parent=AST_Node.TN_NO_PARENT)
        ast_root = AST_N_Node(self.S, parent=_root_parent)
        _root_parent.data = [ast_root, self.__DOLLAR]
        top_node = None

        for top_node in ast_root:
            try:
                if top_node is self.__DOLLAR or t is self.__DOLLAR:
                    break

                elif isinstance(top_node, AST_T_Node):  # Terminal -> Match
                    term = top_node.data
                    if self._match_T(term, t):
                        top_node.data = t
                    else:
                        self.SyntaxError(node_root=ast_root, node_ptr=top_node,
                                         tokens=tokens, got=t)

                    t = next(t_it)

                elif isinstance(top_node, AST_N_Node):  # Nonterminal -> Predict/Expand
                    nonterm = top_node.n
                    rule = self._match_N(nonterm, t)
                    if not rule:
                        self.SyntaxError(node_root=ast_root, node_ptr=top_node,
                                         tokens=tokens, got=t)

                    production = rule[1][:]
                    if production:
                        top_node.expand_node(production, lambda p: p in self.T)
                    else:
                        top_node.expand_node([])

                else:
                    raise Exception('Lexical Error: Unknown Lexem: {0}'.format(type(top_node)))

            except StopIteration:
                break

        if top_node is self.__DOLLAR and t is self.__DOLLAR:  # ok
            pass
        elif top_node is self.__DOLLAR:  # Overflow
            self.SyntaxError(node_root=ast_root, node_ptr=top_node, tokens=tokens, got=t)
        elif t is self.__DOLLAR:  # Underflow
            self.SyntaxError(node_root=ast_root, node_ptr=top_node, tokens=tokens, got=t)
        else:
            raise Exception('Unknown Error: It: {}, Node: {}'.format(t, str(top_node)))

        _nodes = ast_root.get_nodes(depth=None)
        for _n in _nodes:
            print(str(_n.n if isinstance(_n, AST_N_Node) else _n.data))
        return ast_root

    def _match_N(self, s_top_N, _token):
        _rules_LL = self.predict[s_top_N]

        _rule = None
        for term, rule in _rules_LL.items():
            if token.is_token_subtype(_token[1], term):
                _rule = rule
                break

        return _rule

    def _match_T(self, s_top_T, _token):
        return token.is_token_subtype(_token[1], s_top_T)

    def _build_LL_table(self, grammar):
        self.first = {}
        _new_t = set()
        for t_key in self.T:
            self.first[t_key] = {t_key}
            while t_key.parent:
                if t_key.parent not in self.first:
                    self.first[t_key.parent] = set()
                self.first[t_key.parent] |= self.first[t_key]
                _new_t |= {t_key.parent}
                t_key = t_key.parent

        self.T |= _new_t

        for n in self.N:
            self.first[n] = set()

        # the First sets
        while True:
            first_changed = False

            for rule in self.R:
                left, right = rule
                assert 1 == len(left)
                n = left[0]
                assert n in self.N

                _first_products = self._first_of_products(right, self.first)
                if _first_products - self.first[n]:
                    first_changed = True
                self.first[n] |= _first_products

            if not first_changed:
                break

        # the Follow sets
        self.follow = {}
        for n in self.N:
            self.follow[n] = set()

        while True:
            follow_changed = False

            for rule in self.R:
                left, right = rule
                n = left[0]
                _r_firsts = []
                for p in reversed(right):
                    if p in self.N:
                        _first_products = self._first_of_products(_r_firsts, self.first)
                        _difference = _first_products - self.follow[p]
                        if _difference and _difference != {self.__EPSILON}:
                            follow_changed = True
                            self.follow[p] |= _difference - {self.__EPSILON}

                        if self.__EPSILON in _first_products:
                            if self.follow[n] - self.follow[p]:
                                follow_changed = True
                                self.follow[p] |= self.follow[n]

                    _r_firsts = [p] + _r_firsts

            if not follow_changed:
                break

        # the Predict sets
        self.predict = {}
        for rule in self.R:
            left, right = rule
            n = left[0]
            if not self.predict.get(n):
                self.predict[n] = {}

            _first_products = self._first_of_products(right, self.first)
            if self.__EPSILON in _first_products:
                for t in (_first_products - {self.__EPSILON}) | self.follow[n]:
                    self.predict[n][t] = rule
            else:
                for t in _first_products:
                    self.predict[n][t] = rule

        return True

    @classmethod
    def _first_of_products(cls, products, first):
        if not products:
            return {cls.__EPSILON}

        first_set = set()
        it = iter(products)
        while it:
            try:
                p = next(it)
                # assert p in first
                first_set |= first[p] - {cls.__EPSILON}

                if cls.__EPSILON not in first[p]:
                    return first_set

            except StopIteration:
                first_set |= {cls.__EPSILON}
                return first_set

        return first_set


class Semantic(object):
    pass


SuricataRule = namedtuple('SuricataRule', ['action', 'header', 'options'])
SR_Header = namedtuple(
    'SR_Header',
    ['proto',
     'src_host', 'src_port',
     'direction',
     'dst_host', 'dst_port'])


TT_ANY = token.Keyword.Any
TT_PASS = token.Keyword.Action.Pass
TT_REJECT = token.Keyword.Action.Reject
TT_DROP = token.Keyword.Action.Drop
TT_ALERT = token.Keyword.Action.Alert
TT_IP = token.Keyword.Proto.Ip
TT_TCP = token.Keyword.Proto.Tcp
TT_UDP = token.Keyword.Proto.Udp
TT_ICMP = token.Keyword.Proto.Icmp
TT_BR_LEFT = token.Operator.LeftBracket
TT_BR_RIGHT = token.Operator.RightBracket
TT_EXCLMARK = token.Operator.ExclMark
TT_COMMA = token.Operator.Comma
TT_IPv4 = token.Token.IPv4
TT_IPv4_ADDR = token.Token.IPv4.Addr
TT_IPv4_MASK = token.Token.IPv4.Addr_w_Mask
TT_VARIABLE = token.Token.Variable


class HostLexer(lexer.RegexLexer):
    """
    """
    tokens = {
        'root': [
            (r'\s+', token.Token.Text.Whitespace),

            (r'any', TT_ANY),
            (r'pass', TT_PASS),
            (r'reject', TT_REJECT),
            (r'drop', TT_DROP),
            (r'alert', TT_ALERT),

            (r'ip', TT_IP),
            (r'tcp', TT_TCP),
            (r'udp', TT_UDP),
            (r'icmp', TT_ICMP),

            (r'\[', TT_BR_LEFT),
            (r']', TT_BR_RIGHT),
            (r'!', TT_EXCLMARK),
            (r',', TT_COMMA),

            (r'\d+\.\d+\.\d+\.\d+/\d+', TT_IPv4_MASK),
            (r'\d+\.\d+\.\d+\.\d+', TT_IPv4_ADDR),
            (r'\$[\w_][\w_\d]*', TT_VARIABLE)
        ]
    }


class HostParser(LL_Parser):
    """
    """
    HOST_GRAMMAR = {
        'T': {
            TT_IPv4_ADDR,
            TT_IPv4_MASK,
            TT_VARIABLE,
            TT_BR_LEFT,
            TT_BR_RIGHT,
            TT_EXCLMARK,
            TT_COMMA
        },
        'N': {
            '<HOST_GRP>',
            '<HOST_EXPR>',
            '<HOST_PARENS_CONTD>'
        },
        'R': {
            (('<HOST_GRP>', ), ('<HOST_EXPR>', )),
            (('<HOST_GRP>', ), (TT_EXCLMARK, '<HOST_GRP>')),
            (('<HOST_GRP>', ), (TT_BR_LEFT, '<HOST_GRP>', '<HOST_PARENS_CONTD>', TT_BR_RIGHT)),

            (('<HOST_EXPR>', ), (token.Token.IPv4, )),
            (('<HOST_EXPR>', ), (TT_VARIABLE, )),

            (('<HOST_PARENS_CONTD>', ), ()),
            (('<HOST_PARENS_CONTD>', ), (TT_COMMA, '<HOST_GRP>', '<HOST_PARENS_CONTD>'))
        },
        'S': '<HOST_GRP>'
    }

    def __init__(self):
        super(HostParser, self).__init__(self.HOST_GRAMMAR)

    @classmethod
    def disjoint_sets(cls, *args):
        if len(args) < 1:
            return
        if len(args) < 2:
            return True

        _total_cnt = sum(map(len, args))
        merged = set(itertools.chain(*args))
        return _total_cnt == len(merged)

    @classmethod
    def interpret_host(cls, host_node, symbol_table):
        assert host_node
        assert isinstance(host_node, AST_T_Node)
        _pos, _type, _value = host_node.data

        if token.is_token_subtype(_type, TT_VARIABLE):
            return symbol_table[_value]

        if token.is_token_subtype(_type, TT_IPv4):
            return _value

    @classmethod
    def semantics(cls, tree_node, symbol_table, check=False):
        if isinstance(tree_node, AST_N_Node):
            if tree_node.n == '<HOST_GRP>':
                assert tree_node.data
                # if TT_EXCLMARK == tree_node.data[0][1]:  # invert
                if len(tree_node.data) == 2\
                        and isinstance(tree_node.data[0], AST_T_Node)\
                        and token.is_token_subtype(tree_node.data[0].data[1], TT_EXCLMARK):
                    _yes, _no = cls.semantics(tree_node.data[1], symbol_table, check=check)
                    return _no, _yes

                elif len(tree_node.data) >= 3\
                        and tree_node.data[1].n == '<HOST_GRP>'\
                        and tree_node.data[2].n == '<HOST_PARENS_CONTD>':
                    _gyes, _gno = cls.semantics(tree_node.data[1], symbol_table, check=check)
                    _pyes, _pno = cls.semantics(tree_node.data[2], symbol_table, check=check)
                    if check:
                        assert cls.disjoint_sets(_gyes, _gno, _pyes, _pno)

                    return _gyes | _pyes, _gno | _pno

                elif len(tree_node.data) == 1 and tree_node.data[0].n == '<HOST_EXPR>':
                    return cls.semantics(tree_node.data[0], symbol_table, check=check)
                else:
                    assert False

            elif tree_node.n == '<HOST_EXPR>':
                assert tree_node.data
                assert len(tree_node.data) == 1
                _host = cls.interpret_host(tree_node.data[0], symbol_table)
                return {_host}, set()

            elif tree_node.n == '<HOST_PARENS_CONTD>':
                if tree_node.data:
                    assert tree_node.data[1].n == '<HOST_GRP>'
                    _gyes, _gno = cls.semantics(tree_node.data[1], symbol_table, check=check)
                    if len(tree_node.data) == 3:
                        _pyes, _pno = cls.semantics(tree_node.data[2], symbol_table, check=check)
                        if check:
                            assert cls.disjoint_sets(_gyes, _gno, _pyes, _pno)

                        _gyes |= _pyes
                        _gno |= _pno
                    return _gyes, _gno

            else:
                assert False

        return set(), set()
