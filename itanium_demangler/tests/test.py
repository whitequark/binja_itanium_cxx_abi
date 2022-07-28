import unittest

from itanium_demangler import parse, _operators, _builtin_types


class TestDemangler(unittest.TestCase):
    def assertParses(self, mangled, ast):
        result = parse(mangled)
        self.assertEqual(result, ast)

    def assertDemangles(self, mangled, demangled):
        result = parse(mangled)
        if result is not None:
            result = str(result)
        self.assertEqual(result, demangled)

    def test_name(self):
        self.assertDemangles('_Z3foo', 'foo')
        self.assertDemangles('_Z3x', None)

    def test_ctor_dtor(self):
        self.assertDemangles('_ZN3fooC1E', 'foo::{ctor}')
        self.assertDemangles('_ZN3fooC2E', 'foo::{base ctor}')
        self.assertDemangles('_ZN3fooC3E', 'foo::{allocating ctor}')
        self.assertDemangles('_ZN3fooD0E', 'foo::{deleting dtor}')
        self.assertDemangles('_ZN3fooD1E', 'foo::{dtor}')
        self.assertDemangles('_ZN3fooD2E', 'foo::{base dtor}')
        self.assertDemangles('_ZN3fooC1IcEEc', 'foo::{ctor}<char>(char)')
        self.assertDemangles('_ZN3fooD1IcEEc', 'foo::{dtor}<char>(char)')

    def test_operator(self):
        for op in _operators:
            if _operators[op] in ['new', 'new[]', 'delete', 'delete[]']:
                continue
            self.assertDemangles('_Z' + op, 'operator' + _operators[op])
        self.assertDemangles('_Znw', 'operator new')
        self.assertDemangles('_Zna', 'operator new[]')
        self.assertDemangles('_Zdl', 'operator delete')
        self.assertDemangles('_Zda', 'operator delete[]')
        self.assertDemangles('_Zcvi', 'operator int')

    def test_std_substs(self):
        self.assertDemangles('_ZSt3foo', 'std::foo')
        self.assertDemangles('_ZStN3fooE', 'std::foo')
        self.assertDemangles('_ZSs', 'std::string')
        self.assertParses('_ZSt', None)
        self.assertDemangles('_Z3fooISt6vectorE', 'foo<std::vector>')
        self.assertDemangles('_ZSaIhE', 'std::allocator<unsigned char>')

    def test_nested_name(self):
        self.assertDemangles('_ZN3fooE', 'foo')
        self.assertDemangles('_ZN3foo5bargeE', 'foo::barge')
        self.assertDemangles('_ZN3fooIcE5bargeE', 'foo<char>::barge')
        self.assertDemangles('_ZNK3fooE', 'foo const')
        self.assertDemangles('_ZNV3fooE', 'foo volatile')
        self.assertDemangles('_ZNKR3fooE', 'foo const&')
        self.assertDemangles('_ZNKO3fooE', 'foo const&&')
        self.assertParses('_ZNKO3foo', None)

    def test_template_args(self):
        self.assertDemangles('_Z3fooIcE', 'foo<char>')
        self.assertDemangles('_ZN3fooIcEE', 'foo<char>')
        self.assertParses('_Z3fooI', None)

    def test_builtin_types(self):
        for ty in _builtin_types:
            self.assertDemangles('_Z1fI' + ty + 'E', 'f<' + str(_builtin_types[ty]) + '>')

    def test_qualified_type(self):
        self.assertDemangles('_Z1fIriE', 'f<int restrict>')
        self.assertDemangles('_Z1fIKiE', 'f<int const>')
        self.assertDemangles('_Z1fIViE', 'f<int volatile>')
        self.assertDemangles('_Z1fIVVViE', 'f<int volatile>')

    def test_function_type(self):
        self.assertDemangles('_Z1fv', 'f()')
        self.assertDemangles('_Z1fi', 'f(int)')
        self.assertDemangles('_Z1fic', 'f(int, char)')
        self.assertDemangles('_ZN1fEic', 'f(int, char)')
        self.assertDemangles('_ZN1fIEEic', 'int f<>(char)')
        self.assertDemangles('_ZN1fIEC1Eic', 'f<>::{ctor}(int, char)')

    def test_indirect_type(self):
        self.assertDemangles('_Z1fIPiE', 'f<int*>')
        self.assertDemangles('_Z1fIPPiE', 'f<int**>')
        self.assertDemangles('_Z1fIRiE', 'f<int&>')
        self.assertDemangles('_Z1fIOiE', 'f<int&&>')
        self.assertDemangles('_Z1fIKRiE', 'f<int& const>')
        self.assertDemangles('_Z1fIRKiE', 'f<int const&>')

    def test_literal(self):
        self.assertDemangles('_Z1fILi1EE', 'f<(int)1>')
        self.assertDemangles('_Z1fIL_Z1gEE', 'f<g>')

    def test_argpack(self):
        self.assertDemangles('_Z1fILb0EJciEE', 'f<(bool)0, char, int>')
        self.assertDemangles('_Z1fILb0EIciEE', 'f<(bool)0, char, int>')
        self.assertDemangles('_Z1fIJciEEvDpOT_', 'void f<char, int>(char, int)')
        self.assertDemangles('_Z1fIIciEEvDpOT_', 'void f<char, int>(char, int)')

    def test_special(self):
        self.assertDemangles('_ZTV1f', 'vtable for f')
        self.assertDemangles('_ZTT1f', 'vtt for f')
        self.assertDemangles('_ZTI1f', 'typeinfo for f')
        self.assertDemangles('_ZTS1f', 'typeinfo name for f')
        self.assertDemangles('_ZThn16_1fv', 'non-virtual thunk for f()')
        self.assertDemangles('_ZTv16_8_1fv', 'virtual thunk for f()')
        self.assertDemangles('_ZGV1f', 'guard variable for f')
        self.assertDemangles('_ZGTt1fv', 'transaction clone for f()')

    def test_template_param(self):
        self.assertDemangles('_ZN1fIciEEvT_PT0_', 'void f<char, int>(char, int*)')
        self.assertParses('_ZN1fIciEEvT_PT0', None)

    def test_substitution(self):
        self.assertDemangles('_Z3fooIEvS_', 'void foo<>(foo)')
        self.assertDemangles('_ZN3foo3barIES_E', 'foo::bar<>::foo')
        self.assertDemangles('_ZN3foo3barIES0_E', 'foo::bar<>::foo::bar')
        self.assertDemangles('_ZN3foo3barIES1_E', 'foo::bar<>::foo::bar<>')
        self.assertParses('_ZN3foo3barIES_ES2_', None)
        self.assertDemangles('_Z3fooIS_E', 'foo<foo>')
        self.assertDemangles('_ZSt3fooIS_E', 'std::foo<std::foo>')
        self.assertDemangles('_Z3fooIPiEvS0_', 'void foo<int*>(int*)')
        self.assertDemangles('_Z3fooISaIcEEvS0_',
                             'void foo<std::allocator<char>>(std::allocator<char>)')
        self.assertDemangles('_Z3fooI3barS0_E', 'foo<bar, bar>')
        self.assertDemangles('_ZN2n11fEPNS_1bEPNS_2n21cEPNS2_2n31dE',
                             'n1::f(n1::b*, n1::n2::c*, n1::n2::n3::d*)')
        self.assertDemangles('_ZN1f1gES_IFvvEE', 'f::g(f<void ()>)')
        self.assertDemangles('_ZplIcET_S0_', 'char operator+<char>(char)')
        self.assertParses('_ZplIcET_S1_', None)
        # Operator template results don't get added to substitutions
        self.assertParses('_ZStplIcEvS0_', None)

    def test_abi_tag(self):
        self.assertDemangles('_Z3fooB5cxx11v', 'foo[abi:cxx11]()')

    def test_const(self):
        self.assertDemangles('_ZL3foo', 'foo')

    def test_operator_template(self):
        self.assertDemangles('_ZmiIiE', 'operator-<int>')
        self.assertDemangles('_ZmiIiEvv', 'void operator-<int>()')
        self.assertDemangles('_ZmiIiEvKT_RT_', 'void operator-<int>(int const, int&)')
        self.assertDemangles('_ZcviIiE', 'operator int<int>')
        self.assertDemangles('_ZcviIiEv', 'operator int<int>()')
        self.assertDemangles('_ZcviIiET_T_', 'operator int<int>(int, int)')

    def test_array(self):
        self.assertDemangles('_Z1fA1_c', 'f(char[(int)1])')
        self.assertDemangles('_Z1fRA1_c', 'f(char(&)[(int)1])')
        self.assertDemangles('_Z1fIA1_cS0_E', 'f<char[(int)1], char[(int)1]>')
        self.assertParses('_Z1fA1c', None)

    def test_function(self):
        self.assertDemangles('_Z1fFvvE', 'f(void ())')
        self.assertDemangles('_Z1fPFvvE', 'f(void (*)())')
        self.assertDemangles('_Z1fPPFvvE', 'f(void (**)())')
        self.assertDemangles('_Z1fRPFvvE', 'f(void (*&)())')
        self.assertDemangles('_Z1fKFvvE', 'f(void () const)')

    def test_member_data(self):
        self.assertDemangles('_Z1fM3fooi', 'f(int foo::*)')
        self.assertDemangles('_Z1fMN3foo3barEi', 'f(int foo::bar::*)')
        self.assertDemangles('_Z1fM3fooN3bar1XE', 'f(bar::X foo::*)')
        self.assertDemangles('_Z1fM3fooIcE3bar', 'f(bar foo<char>::*)')
        self.assertDemangles('_Z1fM3foo3barIlE', 'f(bar<long> foo::*)')
        self.assertDemangles('_Z3fooPM2ABi', 'foo(int AB::**)')

    def test_member_function(self):
        self.assertDemangles('_Z1fM3fooFvvE', 'f(void (foo::*)())')
        self.assertDemangles('_Z1fMN3foo3barEFvvE', 'f(void (foo::bar::*)())')
        self.assertDemangles('_Z3fooRM3barFviE', 'foo(void (bar::*&)(int))')
