from binaryninja import log
from binaryninja.plugin import PluginCommand, BackgroundTaskThread
from binaryninja.binaryview import BinaryReader
from binaryninja.types import Symbol, Type, Structure, NamedTypeReference
from binaryninja.enums import SymbolType

from .demangler import parse as parse_mangled


def analyze_cxx_abi(view, start=None, length=None, task=None):
    arch = view.arch

    void_p_ty = Type.pointer(arch, Type.void())
    char_p_ty = Type.pointer(arch, Type.int(1))
    unsigned_int_ty = Type.int(arch.default_int_size, False)
    signed_int_ty = Type.int(arch.default_int_size, True)

    base_type_info_ty = Type.named_type(NamedTypeReference(name='std::type_info'))
    base_type_info_ptr_ty = Type.pointer(arch, base_type_info_ty)

    def char_array_ty(length):
        return Type.array(Type.int(1), strings[0].length)

    def type_info_ty(kind=None):
        type_info_struct = Structure()
        type_info_struct.append(void_p_ty, 'vtable')
        type_info_struct.append(char_p_ty, 'name')
        if kind == 'si_class':
            type_info_struct.append(base_type_info_ptr_ty, 'base_type')
        return Type.structure_type(type_info_struct)

    def vtable_ty(vfunc_count):
        vtable_struct = Structure()
        vtable_struct.append(signed_int_ty, 'top_offset')
        vtable_struct.append(base_type_info_ptr_ty, 'typeinfo')
        vtable_struct.append(Type.array(void_p_ty, vfunc_count), 'functions')
        return Type.structure_type(vtable_struct)

    reader = BinaryReader(view)
    def read(size):
        if size == 4:
            return reader.read32()
        elif size == 8:
            return reader.read64()
        else:
            assert False

    data_symbols = view.get_symbols_of_type(SymbolType.DataSymbol, start, length)
    function_symbols = view.get_symbols_of_type(SymbolType.FunctionSymbol, start, length)

    if task:
        task.set_total(len(data_symbols) + len(function_symbols))

    for symbol in data_symbols + function_symbols:
        if task and not task.advance():
            break

        if not symbol.raw_name.startswith('_Z'):
            continue

        is_data = (symbol.type == SymbolType.DataSymbol)
        is_code = (symbol.type == SymbolType.FunctionSymbol)

        name_ast = parse_mangled(symbol.raw_name)
        if name_ast is None:
            log.log_warn("Demangler failed on {}".format(symbol.raw_name))

        symbol = Symbol(symbol.type, symbol.address,
            short_name=str(name_ast) if name_ast else symbol.raw_name,
            full_name=None,
            raw_name=symbol.raw_name)
        view.define_auto_symbol(symbol)

        if name_ast is None:
            continue

        elif is_data and name_ast.kind == 'typeinfo_name':
            strings = view.get_strings(symbol.address, 1)
            if not strings:
                continue

            view.define_data_var(symbol.address, char_array_ty(length))

        elif is_data and name_ast.kind == 'typeinfo':
            reader.offset = symbol.address + arch.address_size * 2

            kind = None

            # heuristic: is this is an abi::__si_class_type_info?
            base_or_flags = read(arch.default_int_size)
            base_symbol = view.get_symbol_at(base_or_flags)
            if base_symbol and base_symbol.raw_name.startswith('_ZTI'):
                kind = 'si_class'

            view.define_data_var(symbol.address, type_info_ty(kind))

        elif is_data and name_ast.kind == 'vtable':
            vtable_addr = symbol.address

            reader.offset = vtable_addr + arch.address_size * 2
            while True:
                vfunc_count = 0
                check_next = True
                while True:
                    vfunc_ptr_symbol = view.get_symbol_at(reader.offset)
                    if vfunc_ptr_symbol and vfunc_ptr_symbol.raw_name.startswith('_Z'):
                        # any C++ symbol definitely terminates the vtable
                        check_next = False
                        break

                    # heuristic: existing function
                    vfunc_addr = read(arch.address_size)
                    if view.get_function_at(vfunc_addr):
                        vfunc_count += 1
                        continue

                    # explicitly reject null pointers; in position-independent code
                    # address zero can belong to the executable segment
                    if vfunc_addr == 0:
                        check_next = False
                        break

                    # heuristic: pointer to executable memory
                    vfunc_segment = view.get_segment_at(vfunc_addr)
                    if vfunc_addr != 0 and vfunc_segment and vfunc_segment.executable:
                        view.add_function(vfunc_addr)
                        vfunc_count += 1

                        log.log_info('Discovered function at {:#x} via {}'
                                     .format(vfunc_addr, symbol.full_name or symbol.short_name))
                        changed = True
                        continue

                    # we've fell off the end of the vtable
                    break

                view.define_data_var(vtable_addr, vtable_ty(vfunc_count))

                if check_next:
                    # heuristic: can another vtable follow this one? let's see if it has typeinfo,
                    # since that should be always true for when we have a virtual base
                    typeinfo_ptr = read(arch.address_size)
                    typeinfo_ptr_symbol = view.get_symbol_at(typeinfo_ptr)
                    if typeinfo_ptr_symbol and typeinfo_ptr_symbol.raw_name.startswith('_ZTI'):
                        vtable_addr = reader.offset - 2 * arch.address_size

                        # documentat it with a symbol
                        secondary_symbol_name = '{}_secondary_{:x}'.format(symbol.short_name,
                            vtable_addr - symbol.address)
                        secondary_symbol = Symbol(SymbolType.DataSymbol, vtable_addr,
                                                  short_name=secondary_symbol_name)
                        view.define_auto_symbol(secondary_symbol)
                        continue

                break

    view.update_analysis()


class CxxAbiAnalysis(BackgroundTaskThread):
    _PROGRESS_TEXT = 'Analyzing Itanium C++ ABI'

    def __init__(self, view):
        BackgroundTaskThread.__init__(self,
            initial_progress_text=self._PROGRESS_TEXT + "...", can_cancel=True)
        self._view = view
        self._total = 0
        self._current = 0

    def set_total(self, total):
        self._total = total

    def advance(self):
        self._current += 1
        self.progress = "{} ({}/{})...".format(self._PROGRESS_TEXT, self._current, self._total)
        return not self.cancelled

    def run(self):
        try:
            analyze_cxx_abi(self._view, task=self)
        finally:
            self.finish()


PluginCommand.register(
    'Analyze Itanium C++ ABI...',
    'Infer data types from C++ symbol names conforming to Itanium ABI.',
    lambda view: CxxAbiAnalysis(view).start()
)
