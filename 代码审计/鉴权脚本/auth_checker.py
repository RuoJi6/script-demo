#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHP鉴权脚本检测工具
检测PHP文件中是否包含指定的鉴权字符串
支持多个鉴权字符串检测，如果都不存在则记录文件路径
"""

import os
import sys
from pathlib import Path

# 全局配置：要检测的鉴权脚本字符串列表（用户可根据需要修改）
TARGET_AUTH_STRINGS = [
    'chksession()',
    # 'extends Action',
    # 可以添加更多鉴权字符串
]

# 额外检测条件配置（与敏感函数是"且"关系）
ADDITIONAL_CONDITIONS = {
    "接受参数": [
        "$_GET", "$_POST", "$_REQUEST"
    ]
    # 可以添加更多条件，如：
    # "数据库连接": ["mysql_connect", "mysqli_connect"],
    # "文件写入": ["fwrite", "file_put_contents"]
}

# PHP代码审计敏感函数分类
SENSITIVE_FUNCTIONS = {
    "文件操作": [
        "file(", "fgets(", "fgetc(", "fwrite(", "file_put_contents(",
        "file_get_contents(", "unlink(", "rmdir(", "tempnam(", "tmpfile(",
        "fopen(", "readfile(", "fread(", "rename(", "fputs("
    ],
    "目录遍历": [
        "opendir(", "readdir(", "closedir("
    ],
    "命令执行": [
        "exec(", "system(", "shell_exec(", "passthru(", "preg_replace(",
        "escapeshellcmd(", "popen(", "proc_open(", "pcntl_exec(",
        "create_function(", "array_map("
    ],
    # "文件包含": [
    #     "require(", "include(", "require_once(", "include_once("
    # ],
    "SSRF漏洞": [
        "curl_exec(", "file_get_contents(", "fopen(", "fsockopen("
    ],
    "变量覆盖": [
        "$$"
    ],
    "反序列化": [
        "unserialize(", "serialize("
    ],
    "文件下载": [
        "header('Content-Disposition:", 'header("Content-Disposition:'
    ],
    "URL跳转": [
        "header('Location:", 'header("Location:'
    ],
    "XML外部实体": [
        "simplexml_load_file(", "simplexml_load_string(", "SimpleXMLElement(",
        "DOMDocument(", "xml_parse("
    ]
}


def check_auth_and_sensitive_functions(file_path):
    """
    检查PHP文件是否包含鉴权脚本引用和敏感函数

    Args:
        file_path (str): PHP文件路径

    Returns:
        tuple: (has_auth, sensitive_functions_found)
               has_auth: bool - 是否包含鉴权脚本
               sensitive_functions_found: dict - 发现的敏感函数分类
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # 检查是否包含任何一个鉴权脚本字符串
        has_auth = any(auth_string in content for auth_string in TARGET_AUTH_STRINGS)

        # 检查敏感函数
        sensitive_functions_found = {}
        lines = content.split('\n')

        for category, functions in SENSITIVE_FUNCTIONS.items():
            found_functions = []
            for func in functions:
                if func in content:
                    # 查找包含该函数的所有行
                    func_lines = []
                    for i, line in enumerate(lines, 1):
                        if func in line:
                            func_lines.append({
                                'line_number': i,
                                'code': line.strip()
                            })

                    found_functions.append({
                        'function': func.rstrip('('),
                        'occurrences': func_lines
                    })

            if found_functions:
                sensitive_functions_found[category] = found_functions

        # 检查额外条件（与敏感函数是"且"关系）
        additional_conditions_met = True
        additional_conditions_found = {}

        for condition_name, condition_items in ADDITIONAL_CONDITIONS.items():
            if condition_items:  # 如果条件列表不为空
                found_items = []
                for item in condition_items:
                    if item in content:
                        # 查找包含该条件的所有行
                        item_lines = []
                        for i, line in enumerate(lines, 1):
                            if item in line:
                                item_lines.append({
                                    'line_number': i,
                                    'code': line.strip()
                                })

                        found_items.append({
                            'item': item,
                            'occurrences': item_lines
                        })

                if found_items:
                    additional_conditions_found[condition_name] = found_items
                else:
                    additional_conditions_met = False

        # 如果敏感函数存在但额外条件不满足，则清空敏感函数结果
        if sensitive_functions_found and not additional_conditions_met:
            sensitive_functions_found = {}
            additional_conditions_found = {}

        return has_auth, sensitive_functions_found, additional_conditions_found

    except Exception as e:
        print(f"读取文件 {file_path} 时出错: {e}")
        return False, {}


def scan_directory(directory, output_file):
    """
    递归扫描目录中的PHP文件

    Args:
        directory (str): 要扫描的目录路径
        output_file (str): 输出文件路径
    """
    missing_auth_files = []
    vulnerable_files = []
    total_php_files = 0

    print(f"开始扫描目录: {directory}")
    print("正在检测PHP文件...")

    # 递归遍历目录
    for root, dirs, files in os.walk(directory):
        for file in files:
            # 只检查PHP文件
            if file.lower().endswith(('.php', '.phtml', '.php3', '.php4', '.php5')):
                file_path = os.path.join(root, file)
                total_php_files += 1

                # 检查鉴权和敏感函数
                has_auth, sensitive_functions, additional_conditions = check_auth_and_sensitive_functions(file_path)

                if not has_auth:
                    missing_auth_files.append(file_path)
                    print(f"缺少鉴权: {file_path}")

                    # 如果缺少鉴权且存在敏感函数，记录为高危文件
                    if sensitive_functions:
                        vulnerable_files.append({
                            'file_path': file_path,
                            'sensitive_functions': sensitive_functions,
                            'additional_conditions': additional_conditions
                        })
                        print(f"  ⚠️  高危文件（含敏感函数）: {file_path}")

    # 写入结果到文件
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("PHP鉴权脚本和敏感函数检测报告\n")
            f.write("=" * 60 + "\n")
            f.write(f"扫描目录: {directory}\n")
            f.write(f"总计PHP文件数: {total_php_files}\n")
            f.write(f"缺少鉴权脚本的文件数: {len(missing_auth_files)}\n")
            f.write(f"高危文件数（缺少鉴权且含敏感函数）: {len(vulnerable_files)}\n")

            # 显示额外条件配置
            f.write("额外检测条件:\n")
            for condition_name, condition_items in ADDITIONAL_CONDITIONS.items():
                if condition_items:
                    f.write(f"  {condition_name}: {', '.join(condition_items)} (必须同时满足)\n")
                else:
                    f.write(f"  {condition_name}: 关闭\n")
            if not any(ADDITIONAL_CONDITIONS.values()):
                f.write("  无额外条件 (只检测敏感函数)\n")
            f.write("=" * 60 + "\n\n")

            # 1. 所有缺少鉴权的文件
            if missing_auth_files:
                f.write("1. 缺少鉴权脚本的文件:\n")
                f.write("-" * 40 + "\n")
                for file_path in missing_auth_files:
                    f.write(f"{file_path}\n")
                f.write("\n")

            # 2. 高危文件（缺少鉴权且含敏感函数）
            if vulnerable_files:
                f.write("2. 高危文件（缺少鉴权且含敏感函数）:\n")
                f.write("-" * 40 + "\n")
                for vuln_file in vulnerable_files:
                    f.write(f"\n文件: {vuln_file['file_path']}\n")
                    f.write("发现的敏感函数:\n")
                    for category, functions in vuln_file['sensitive_functions'].items():
                        f.write(f"  [{category}]:\n")
                        for func_info in functions:
                            f.write(f"    函数: {func_info['function']}\n")
                            for occurrence in func_info['occurrences']:
                                f.write(f"      行 {occurrence['line_number']}: {occurrence['code']}\n")
                            f.write("\n")

                    # 显示满足的额外条件
                    if vuln_file.get('additional_conditions'):
                        f.write("满足的额外条件:\n")
                        for condition_name, condition_items in vuln_file['additional_conditions'].items():
                            f.write(f"  [{condition_name}]:\n")
                            for item_info in condition_items:
                                f.write(f"    项目: {item_info['item']}\n")
                                for occurrence in item_info['occurrences']:
                                    f.write(f"      行 {occurrence['line_number']}: {occurrence['code']}\n")
                                f.write("\n")
                f.write("\n")

            if not missing_auth_files:
                f.write("✅ 所有PHP文件都包含鉴权脚本引用！\n")

        print(f"\n检测完成！结果已保存到: {output_file}")
        print(f"总计检测 {total_php_files} 个PHP文件")
        print(f"发现 {len(missing_auth_files)} 个文件缺少鉴权脚本")
        print(f"发现 {len(vulnerable_files)} 个高危文件（缺少鉴权且含敏感函数）")

    except Exception as e:
        print(f"写入输出文件时出错: {e}")


def main():
    """主函数"""
    print("PHP鉴权脚本和敏感函数检测工具")
    print("=" * 40)

    # 获取用户输入的目录
    while True:
        target_dir = input("请输入要检测的目录路径: ").strip()

        if not target_dir:
            print("目录路径不能为空，请重新输入。")
            continue

        if not os.path.exists(target_dir):
            print(f"目录 '{target_dir}' 不存在，请检查路径是否正确。")
            continue

        if not os.path.isdir(target_dir):
            print(f"'{target_dir}' 不是一个目录，请输入正确的目录路径。")
            continue

        break

    # 设置输出文件名
    output_file = "auth_check_report.txt"

    # 询问是否自定义输出文件名
    custom_output = input(f"输出文件名 (默认: {output_file}): ").strip()
    if custom_output:
        output_file = custom_output

    # 开始扫描
    try:
        scan_directory(target_dir, output_file)
    except KeyboardInterrupt:
        print("\n\n检测被用户中断。")
    except Exception as e:
        print(f"检测过程中发生错误: {e}")


if __name__ == "__main__":
    main()
