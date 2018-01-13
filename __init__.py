from binaryninja import log
from binaryninja.plugin import PluginCommand, BackgroundTaskThread
from binaryninja.binaryview import BinaryReader
from binaryninja.types import Symbol, Type, Structure, NamedTypeReference
from binaryninja.enums import SymbolType
from binaryninja.demangle import demangle_gnu3, get_qualified_name


def demangle(arch, raw_name):
    ty, name = demangle_gnu3(arch, raw_name)
    if isinstance(name, list):
        return get_qualified_name(name)
    else:
        return name

def analyze_cxx_abi(view, start=None, length=None, task=None):
    arch = view.arch

    def read(reader, size):
        if size == 4:
            return reader.read32()
        elif size == 8:
            return reader.read64()
        else:
            assert False

    void_p_ty = Type.pointer(arch, Type.void())
    char_p_ty = Type.pointer(arch, Type.int(1))
    unsigned_int_ty = Type.int(arch.default_int_size, False)

    base_type_info_ty = Type.named_type(NamedTypeReference(name='std::type_info'))
    base_type_info_ptr_ty = Type.pointer(arch, base_type_info_ty)

    def char_array_ty(length):
        return Type.array(Type.int(1), strings[0].length)

    def type_info_ty(kind=None):
        type_info_struct = Structure()
        type_info_struct.append(void_p_ty, 'vtbl')
        type_info_struct.append(char_p_ty, 'name')
        if kind == 'si_class':
            type_info_struct.append(base_type_info_ptr_ty, 'base_type')
        return Type.structure_type(type_info_struct)

    def vtable_ty(vfunc_count):
        vtable_struct = Structure()
        vtable_struct.append(unsigned_int_ty, 'top_offset')
        vtable_struct.append(base_type_info_ptr_ty, 'typeinfo')
        vtable_struct.append(Type.array(void_p_ty, vfunc_count), 'functions')
        return Type.structure_type(vtable_struct)

    symbols = view.get_symbols_of_type(SymbolType.DataSymbol, start, length)
    reader = BinaryReader(view)
    for n, symbol in enumerate(symbols):
        if task:
            task.update_progress(n + 1, len(symbols))
            if task.cancelled:
                break

        if symbol.raw_name.startswith('_ZTS'): # type_info name
            strings = view.get_strings(symbol.address, 1)
            if not strings:
                continue

            # _ZTS... symbols are not named correctly, fix.
            qual_name = demangle(arch, symbol.raw_name)
            view.define_auto_symbol(Symbol(symbol.type, symbol.address,
                                           short_name=qual_name, full_name=None,
                                           raw_name=symbol.raw_name))

            view.define_data_var(symbol.address, char_array_ty(length))

        elif symbol.raw_name.startswith('_ZTI'): # type_info
            reader.seek(symbol.address + arch.address_size * 2)

            kind = None

            # heuristic: is this is an abi::__si_class_type_info?
            base_or_flags = read(reader, arch.default_int_size)
            base_symbol = view.get_symbol_at(base_or_flags)
            if base_symbol and base_symbol.raw_name.startswith('_ZTI'):
                kind = 'si_class'

            view.define_data_var(symbol.address, type_info_ty(kind))

        elif symbol.raw_name.startswith('_ZTV'): # vtable
            reader.seek(symbol.address + arch.address_size * 2)

            vfunc_count = 0
            while True:
                vfunc_ptr_symbol = view.get_symbol_at(reader.offset)
                if vfunc_ptr_symbol and vfunc_ptr_symbol.raw_name.startswith('_Z'):
                    break # any C++ symbol definitely terminates the vtable

                # heuristic: existing function
                vfunc_addr = read(reader, arch.address_size)
                if view.get_function_at(vfunc_addr):
                    vfunc_count += 1
                    continue

                # explicitly reject null pointers; in position-independent code
                # address zero can belong to the executable segment
                if vfunc_addr == 0:
                    break

                # heuristic: pointer to executable memory
                vfunc_segment = view.get_segment_at(vfunc_addr)
                if vfunc_segment and vfunc_segment.executable:
                    view.add_function(vfunc_addr)
                    vfunc_count += 1

                    qual_name = demangle(arch, symbol.raw_name)
                    log.log_info('Discovered function at {:#x} via {}'
                                 .format(vfunc_addr, qual_name))
                    changed = True
                    continue

                # we've fell off the end of the vtable
                break

            view.define_data_var(symbol.address, vtable_ty(vfunc_count))

    view.update_analysis()


class CxxAbiAnalysis(BackgroundTaskThread):
    _PROGRESS_TEXT = 'Analyzing Itanium C++ ABI'

    def __init__(self, view):
        BackgroundTaskThread.__init__(self,
            initial_progress_text=self._PROGRESS_TEXT + "...", can_cancel=True)
        self._view = view

    def update_progress(self, now, total):
        self.progress = self._PROGRESS_TEXT + " ({}/{})...".format(now, total)

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
