#!/usr/bin/env python
# coding=utf-8/# -*- coding: utf-8 -*-
#
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Confidential Data defensive Framework is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
#

import re
import os
import argparse


def filter_comments_strings_macros(code_line):
    """
    Removes comments, macros, and string literals from the given line of code.

    :param code_line: A line of code as a string.
    :return: The filtered line of code as a string.
    """
    # Remove macros
    code_line = re.sub(r'\s*#.*$', "", code_line)
    # Remove comments
    code_line = re.sub(r'/\*.*?\*/|//.*$', "", code_line)
    # Remove string literals
    code_line = re.sub(r'".*?"', "", code_line)
    return code_line


def filter_templates(code_line):
    """
    Removes template prefixes, types, and special characters from the given line of code.

    :param code_line: A line of code as a string.
    :return: The filtered line of code as a string.
    """
    # Remove const, volatile, typename
    code_line = re.sub(r'\b(const|volatile|typename)\b', "", code_line)
    # Remove templates
    while re.search(r'<\s*(::)?\w+(\s*::\s*\w+)*(,\s*(::)?\w+(\s*::\s*\w+)*)*([*&]\s*)?>', code_line):
        code_line = re.sub(r'<\s*(::)?\w+(\s*::\s*\w+)*(,\s*(::)?\w+(\s*::\s*\w+)*)*([*&]\s*)?>', "", code_line)
    # Remove ->, >>, <<, ::
    code_line = re.sub(r'(->|>>|<<|::)', "", code_line)
    return code_line


def has_conditionals(code_line):
    """
    Checks if the given line of code contains any conditional operators or statements.

    :param code_line: A line of code as a string.
    :return: True if conditionals are present, otherwise False.
    """
    # Check for conditional operators and statements
    new_code_line = re.sub(r'([?|!~><]|&&|==|!=|\b(if|switch|case|while|for)\b)', "", code_line)
    return len(new_code_line) < len(code_line)


class BranchFilter:
    def __init__(self, debug=False):
        self.iter_ = 0
        self.limit_ = 5
        self.macro_list = []
        self.debug_switch = debug
        self.dir_dirty_words = [
            '/llt/', '/ai/', '/vector/', '/x86/', '/sve/dev/operators/', '/test/', '/adapter/'
        ]

    def debug_log(self, *args):
        """Logs debug messages if the debug switch is enabled."""
        if self.debug_switch:
            print('[DEBUG]', *args)

    def load_file(self, file_path):
        """
        Loads the content of a file into a list of lines.

        :param file_path: Path to the file as a string.
        :return: List of lines in the file.
        """
        with open(file_path, 'r') as f:
            return f.readlines()

    def find_all_macros(self, code_lines):
        """
        Finds all macros in the given list of code lines and adds them to the macro list.

        :param code_lines: List of code lines as strings.
        """
        reg_macro = r'\s*#define\s*'
        for line in code_lines:
            line = line.rstrip()
            if re.search(reg_macro, line):
                macro = re.sub(reg_macro, "", line)
                macro = re.sub(r'\s*\\', "", macro)
                macro = re.sub(r'\(.*\)', "", macro)
                self.debug_log(macro)
                self.macro_list.append(macro)

    def find_all_code_files(self, path):
        """
        Recursively searches the given directory for C++ files and finds all macros within them.

        :param path: Directory path as a string.
        """
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                if any(word in file_path for word in self.dir_dirty_words):
                    continue

                _, ext = os.path.splitext(file)
                if ext in ('.cpp', '.h', '.hpp', '.c'):
                    self.debug_log(file_path)
                    code_lines = self.load_file(file_path)
                    self.find_all_macros(code_lines)

    def whether_counter_new_file(self, line):
        """
        Determines if the given line indicates the start of a new file.

        :param line: Line of text as a string.
        :return: True if it's the start of a new file, otherwise False.
        """
        return line.startswith('SF:')

    def get_branch_info(self, current_line):
        """
        Extracts the branch line number from the given line.

        :param current_line: Line of text containing branch information as a string.
        :return: Integer representing the line number.
        """
        branch_info = current_line.split(':')[1].split(',')[0]
        return int(branch_info)

    def get_cpp_distance_between_branches(self, i, info_lines):
        """
        Calculates the distance between two branches in terms of C++ lines.

        :param i: Current index in the list of info lines.
        :param info_lines: List of lines containing branch information.
        :return: Integer representing the distance.
        """
        current_line = info_lines[i].rstrip()
        current_cpp_line_number = self.get_branch_info(current_line)
        cpp_line_number = current_cpp_line_number
        while cpp_line_number == current_cpp_line_number:
            i += 1
            cpp_line_number = self.get_branch_info(info_lines[i].rstrip())
        return abs(cpp_line_number - current_cpp_line_number)

    def check_macros_in_ref(self, line):
        """
        Checks if the given line contains any macros that were previously collected.

        :param line: Line of text as a string.
        :return: True if it contains macros, otherwise False.
        """
        return any(key in line for key in self.macro_list)

    def process_one_line(self, info_lines, cpp_lines, new_info_data):
        """
        Processes one line of information to decide if it should be included in the output.

        :param info_lines: List of lines containing branch information.
        :param cpp_lines: List of lines from the corresponding C++ file.
        :param new_info_data: Accumulated data for the output file.
        :return: Updated new_info_data.
        """
        current_line = info_lines[self.iter_].rstrip()
        current_cpp_line_number = self.get_branch_info(current_line)
        cpp_line_number = current_cpp_line_number

        limit = min(self.limit_, self.get_cpp_distance_between_branches(self.iter_, info_lines))
        self.debug_log("limit:", limit)

        start_line = cpp_line_number - 1
        end_line = min(start_line + limit, len(cpp_lines) - 1)
        flag = False
        for iter_line in range(start_line, end_line):
            cpp_line = cpp_lines[iter_line].rstrip()
            self.debug_log(cpp_line)
            cpp_line = filter_comments_strings_macros(cpp_line)
            cpp_line = filter_templates(cpp_line)
            self.debug_log(cpp_line)
            flag = has_conditionals(cpp_line) or self.check_macros_in_ref(cpp_line)
            self.debug_log(flag)
            if flag:
                break

        while cpp_line_number == current_cpp_line_number:
            self.debug_log(info_lines[self.iter_])
            if flag:
                new_info_data += info_lines[self.iter_]
            self.iter_ += 1
            cpp_line_number = self.get_branch_info(info_lines[self.iter_].rstrip())

        return new_info_data

    def process_one_file(self, info_lines, line, new_info_data):
        """
        Processes one file worth of information lines.

        :param info_lines: List of lines containing branch information.
        :param line: Current line being processed.
        :param new_info_data: Accumulated data for the output file.
        :return: Updated new_info_data.
        """
        file_abs_path = line[3:-1]
        cpp_lines = self.load_file(file_abs_path)

        while info_lines[self.iter_][:13] != 'end_of_record':
            prefix = info_lines[self.iter_][:4]
            if prefix == 'BRDA':
                new_info_data = self.process_one_line(info_lines, cpp_lines, new_info_data)
            else:
                new_info_data += info_lines[self.iter_]
                self.iter_ += 1
        return new_info_data

    def main_loop_info(self, info_lines, new_info_file):
        """
        Iterates through the list of information lines, processes each one, and writes the output.

        :param info_lines: List of lines containing branch information.
        :param new_info_file: Path to the output file.
        """
        new_info_data = ""

        while self.iter_ < len(info_lines):
            line = info_lines[self.iter_]
            if self.whether_counter_new_file(line):
                self.debug_log('[INFO] Processing file:', line[3:-1])
                new_info_data = self.process_one_file(info_lines, line, new_info_data)
            else:
                self.iter_ += 1
                new_info_data += line

        with open(new_info_file, 'w') as f:
            f.write(new_info_data)

    def filter(self, input_file, out_file, root_dir):
        """
        Filters the information file based on the content of C++ files in the given directory.

        :param input_file: Path to the input information file.
        :param out_file: Path to the output information file.
        :param root_dir: Directory containing the C++ files.
        """
        self.find_all_code_files(root_dir)
        info_lines = self.load_file(input_file)
        self.main_loop_info(info_lines, out_file)


def main():
    """
    Parses command-line arguments and runs the BranchFilter's filter method.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True, help='Input information file.')
    parser.add_argument('--output', required=True, help='Output information file.')
    parser.add_argument('--root', required=True, help='Root directory of C++ files.')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging.')
    args = parser.parse_args()

    bf = BranchFilter(args.debug)
    bf.filter(args.input, args.output, args.root)
    print("[INFO] DONE")


if __name__ == "__main__":
    main()
