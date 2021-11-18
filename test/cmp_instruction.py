# coding: utf-8
import csv
import re
import sys


class BaseDisassembled:
    def __init__(self, ins_dict):
        self._ins_dict: dict = ins_dict

    def generate_ins_list(self):
        return self._ins_dict.values()

    def find_ins_by_addr(self, addr):
        if addr in self._ins_dict:
            return self._ins_dict[addr]
        else:
            return None


class BaseFunction:
    def __init__(self, name=None, address=None):
        # Function name
        self._name = name
        # Address
        self._address = address
        # Ins list of Function
        self._ins_list = list()

    @property
    def name(self):
        return self._name

    @property
    def address(self):
        return self._address

    @property
    def ins_list(self):
        return self._ins_list

    @address.setter
    def address(self, addr):
        self._address = addr


class BastInstruction:
    def __init__(self, address=None, instruction=None, data=None, op=None, ori_str=None, base_func=None):
        # Function belongs
        self.base_func: BaseFunction = base_func
        # Address
        self.address = address

        self.instruction = instruction
        # Binary data
        self.data = data
        # Operand
        self.op = op
        # Original string
        self.ori_str = ori_str

        self.is_cover = False

        self.is_match = False

        self.ref_ins = None


class OBJDumpDisassembledFunction(BaseFunction):

    @classmethod
    def from_str(cls, obj_str_line):
        ori_str = obj_str_line.replace('\n', '')

        match_func_start = re.match(r'^(\S+)\s<(\S+)>:', ori_str)

        if match_func_start is not None:
            address = int(match_func_start.group(1), 16)
            name = match_func_start.group(2)
            return OBJDumpDisassembledFunction(name, address)

        return None


# Parse assembly instructions in objdump output file
class OBJDumpDisassembledInstruct(BastInstruction):

    @classmethod
    def from_str(cls, instruction_str, from_func):
        data = None
        instruction = None
        op = None
        ori_str = instruction_str.replace('\n', '')

        match_instruction = re.match(r"^\s+(.*):\t(.*)\t(.*)", ori_str)

        if match_instruction is not None:
            # Get instructions
            match_op = re.match(r'^(\S+)\s*(.*)', match_instruction.group(3))
            data = match_instruction.group(2)
            address = int(match_instruction.group(1), 16)
            if match_op is not None:
                op = match_op.group(2)
                instruction = match_op.group(1)
            else:
                instruction = match_instruction.group(3)

            return OBJDumpDisassembledInstruct(address, instruction, data, op, ori_str, from_func)

        match_blank_instruction = re.match(r"^\s+(.*):\t(.*)", ori_str)
        if match_blank_instruction is not None:
            # Ignore blank lines
            address = int(match_blank_instruction.group(1), 16)

            return OBJDumpDisassembledInstruct(address, instruction, data, op, ori_str, from_func)

        return None


class OBJDumpDisassembled(BaseDisassembled):

    @classmethod
    def from_file(cls, obj_file):

        with open(obj_file, 'r')as f:
            instruction_dict = dict()

            temp_func = None
            no_more_inst = True
            for line in f.readlines():
                func = OBJDumpDisassembledFunction.from_str(line)
                if func is not None:
                    temp_func = func

                    no_more_inst = False
                    continue
                else:
                    instr = OBJDumpDisassembledInstruct.from_str(line, temp_func)

                    if instr is not None:

                        no_more_inst = False
                        if instr.instruction is not None:
                            if not ('nop' in instr.instruction or
                                    'data' in instr.instruction or
                                    'xchg' in instr.instruction):
                                instruction_dict[instr.address] = instr
                                temp_func.ins_list.append(instr.address)
                        continue
                    else:
                        no_more_inst = True
            f.close()
        return OBJDumpDisassembled(instruction_dict)


class LLVMDisassembledFunction(BaseFunction):
    @classmethod
    def from_str(cls, obj_str_line):
        ori_str = obj_str_line.replace('\n', '')
        # For example, parsing >> bb._GLOBAL__sub_I___cxa_allocate_exception.0xb:
        match_func_start = re.match(r'^bb\.(\S+):', ori_str)

        if match_func_start is not None:
            data = match_func_start.group(1)
            return LLVMDisassembledFunction(data.split('.')[0], None)

        return None

    pass


class LLVMDisassembledInstruct(BastInstruction):
    @classmethod
    def from_str(cls, instruction_str, from_func):
        op = None
        ori_str = instruction_str.replace('\n', '')
        # For example, parsing >> ; 0x0000000000400cbb:  mov    QWORD PTR [rip+0x22a422],0x0        # 0x62b0e8
        match_instruction = re.match(r'^\s+;\s*(\S+):\s+(.*)', ori_str)

        if match_instruction is not None:
            match_op = re.match(r'^(\S+)\s*(\S*)', match_instruction.group(2))
            address = int(match_instruction.group(1), 16)
            if match_op is not None:
                op = match_op.group(2)
                instruction = match_op.group(1)
            else:
                instruction = match_instruction.group(3)

            return LLVMDisassembledInstruct(address, instruction, None, op, ori_str, from_func)

    pass


class DisassembledLLVM(BaseDisassembled):

    @classmethod
    def from_file(cls, cmp_file_path):
        with open(cmp_file_path, 'r')as f:
            instruction_dict = dict()
            temp_func = None
            for line in f.readlines():
                func = LLVMDisassembledFunction.from_str(line)
                if func is not None:
                    temp_func = func
                    continue
                else:
                    instr = LLVMDisassembledInstruct.from_str(line, temp_func)

                    if instr is not None:
                        if instr.instruction is not None and not ('nop' in instr.instruction or
                                                                  'data' in instr.instruction or
                                                                  'xchg' in instr.instruction):

                            instruction_dict[instr.address] = instr
                            if temp_func.address is None:
                                temp_func.address = instr.address
                            temp_func.ins_list.append(instr.address)
                        continue
            f.close()
        return DisassembledLLVM(instruction_dict)


def adv_cmp_op(op1, op2):
    op_obj_to_ll_map = {'cqto': 'cqo', 'cltd': 'cdq', 'cltq': 'cdqe', 'cbtw': 'cbw', 'cwtl': 'cwde'}
    if op1 in op_obj_to_ll_map:
        return op_obj_to_ll_map[op1] == op2


def cmp_two_da(base_da: BaseDisassembled, cmp_da: BaseDisassembled, result, base_file_path, name_t: tuple, only_ins):
    csv_result_file = f'{base_file_path}.{name_t[0]}_to_{name_t[1]}.result.csv'

    csv_result = open(csv_result_file, 'w', encoding='utf-8', newline='')

    csv_result_writer = csv.writer(csv_result)

    success_count = 0

    not_success_count = 0
    not_found_count = 0
    temp_not_match_arr = []
    # Count not found Instructions in a function
    not_found_in_function_count = 0

    for base_ins in base_da.generate_ins_list():
        temp_function = base_ins.base_func
        is_found = False

        cmp_ins = cmp_da.find_ins_by_addr(base_ins.address)

        if cmp_ins is not None:
            base_ins.is_cover = True
            is_found = True
            if cmp_ins.instruction == base_ins.instruction or \
                    cmp_ins.instruction in base_ins.instruction or \
                    base_ins.instruction in cmp_ins.instruction or \
                    ('mov' in base_ins.instruction and 'mov' in cmp_ins.instruction) or \
                    adv_cmp_op(base_ins.instruction, cmp_ins.instruction) or \
                    adv_cmp_op(cmp_ins.instruction, base_ins.instruction):
                base_ins.is_match = True
                success_count += 1
            else:
                not_success_count += 1
                base_ins.ref_ins = cmp_ins
                temp_not_match_arr.append(base_ins.address)

                if only_ins:
                    result.write(
                        f'(Not matched)\n{name_t[0]}: \n{cmp_ins.ori_str}\n'
                        f'{name_t[1]}: \n{cmp_ins.ref_ins.ori_str}\n')

        if is_found is False:
            not_found_count += 1
            not_found_in_function_count += 1
            if only_ins:
                result.write(f'(Not found){base_ins.ori_str}\n')

        if base_ins.address == base_ins.base_func.ins_list[-1] and not only_ins:
            if len(temp_not_match_arr) > 0 or not_found_in_function_count != 0:
                result.write(
                    f'-----------------------------\n{hex(temp_function.address)}\t{temp_function.name}Function Info:')
                if not_found_in_function_count == len(base_ins.base_func.ins_list):
                    result.write(
                        f'Size: {len(temp_function.ins_list)}, **All not found**\n')
                else:
                    result.write('\n')
                    for obj_ins_addr in base_ins.base_func.ins_list:
                        temp_ins = base_da.find_ins_by_addr(obj_ins_addr)
                        if temp_ins.is_cover is False:
                            result.write(f'(Not found){temp_ins.ori_str}\n')
                        else:
                            if temp_ins.is_match is False:
                                result.write(
                                    f'(Not matched)\n{name_t[0]}: \n{temp_ins.ori_str}\n'
                                    f'{name_t[1]}:\n{temp_ins.ref_ins.ori_str}, '
                                    f'From {temp_ins.ref_ins.base_func.name}\n')
                    result.write(
                        f'Size: {len(temp_function.ins_list)}, '
                        f'Not found count: {not_found_in_function_count}; '
                        f'Not matched count: {len(temp_not_match_arr)}\n')
                csv_result_writer.writerow([hex(temp_function.address), temp_function.name,
                                            len(temp_function.ins_list), not_found_in_function_count,
                                            len(temp_not_match_arr)])

            temp_not_match_arr.clear()
            not_found_in_function_count = 0

    csv_result.close()
    result.write(f'Success count: {success_count}\n')
    result.write(f'Not found count: {not_found_count}\n')
    pass


def cmp_it(base_file_path):
    obj_file = base_file_path + ".obj"
    cmp_file_path = base_file_path + ".ll"
    result_file = base_file_path + ".result"
    result = open(result_file, "w", encoding='utf-8')

    obj_da = OBJDumpDisassembled.from_file(obj_file)
    ll_da = DisassembledLLVM.from_file(cmp_file_path)

    result.write(f'!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n')
    result.write(f'In .obj file, find the instruction corresponding to .ll\n')
    cmp_two_da(obj_da, ll_da, result, base_file_path, ('.obj', '.ll'), only_ins=False)

    result.write(f'\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n')
    result.write(f'In .ll file, find the instruction corresponding to .obj\n')
    cmp_two_da(ll_da, obj_da, result, base_file_path, ('.ll', '.obj'), only_ins=True)
    result.write(f'\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n')
    result.write(f'OBJDump file Ins count: {len(obj_da.generate_ins_list())}\n')

    result.write(f'.ll file Ins count: {len(ll_da.generate_ins_list())}\n')

    result.close()


if __name__ == '__main__':
    cmp_it(sys.argv[1])
