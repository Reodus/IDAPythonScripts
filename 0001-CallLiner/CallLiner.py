from idautils import *
from idaapi import *
from idc import *

def add_extra_lines_after_call():
    for seg_ea in Segments():
        for func_ea in Functions(seg_ea, get_segm_end(seg_ea)):
            func_name = get_func_name(func_ea)
            print(f"Processing function: {func_name} at {hex(func_ea)}")
            func_end = get_func_attr(func_ea, FUNCATTR_END)
            for head in Heads(func_ea, func_end):
                if is_code(get_full_flags(head)):
                    if print_insn_mnem(head) == "call":
                        next_head_addr = head
                        if next_head_addr != BADADDR and is_code(get_full_flags(next_head_addr)):
                            extra_line = ""
                            add_extra_line(next_head_addr, False, extra_line)
                            print(f"Added extra line at {hex(next_head_addr)}: {extra_line}")

add_extra_lines_after_call()

