#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
参数过滤检测工具
检测PHP文件中 $_x_xxxx 类型的参数是否缺少 pe_dbhold() 和 intval() 过滤函数
"""

import os
import re
import sys
from pathlib import Path

# 全局配置：要检测的过滤函数
FILTER_FUNCTIONS = ['pe_dbhold', 'intval']

def find_unfiltered_parameters(file_path):
    """
    查找未过滤的 $_x_xxxx 参数
    
    Args:
        file_path (str): PHP文件路径
        
    Returns:
        dict: 检测结果
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        result = {
            'unfiltered_params': [],
            'filtered_params': [],
            'total_params': 0
        }
        
        # 正则表达式匹配 $_x_xxxx 模式
        # $_后面跟一个字符，然后是下划线，再跟任意数量的字符
        param_pattern = r'\$_[a-zA-Z]_[a-zA-Z0-9_]*'
        
        # 查找所有匹配的参数
        matches = re.finditer(param_pattern, content)
        
        lines = content.split('\n')
        
        for match in matches:
            param = match.group()
            start_pos = match.start()
            
            # 找到参数所在的行号
            line_number = content[:start_pos].count('\n') + 1
            line_content = lines[line_number - 1].strip() if line_number <= len(lines) else ""
            
            # 检查这个参数是否被过滤函数包围
            is_filtered = False
            filter_used = []

            # 获取当前行内容
            current_line = line_content

            # 检查当前行是否直接使用了过滤函数包围该参数
            for filter_func in FILTER_FUNCTIONS:
                # 更精确的模式匹配：只有当参数直接被过滤函数包围时才认为是过滤的
                filter_patterns = [
                    # 直接包围：pe_dbhold($_p_xxx) 或 intval($_p_xxx)
                    rf'{filter_func}\s*\(\s*\{re.escape(param)}\s*\)',
                    # 数组访问：pe_dbhold($_p_xxx['key']) 或 intval($_p_xxx['key'])
                    rf'{filter_func}\s*\(\s*\{re.escape(param)}\[.*?\]\s*\)',
                    # 赋值后立即使用：$var = pe_dbhold($_p_xxx) 在同一行
                    rf'\$\w+\s*=\s*{filter_func}\s*\(\s*\{re.escape(param)}\s*\)'
                ]

                for pattern in filter_patterns:
                    if re.search(pattern, current_line, re.IGNORECASE):
                        is_filtered = True
                        filter_used.append(filter_func)
                        break

                if is_filtered:
                    break
            
            param_info = {
                'parameter': param,
                'line_number': line_number,
                'line_content': line_content,
                'is_filtered': is_filtered,
                'filters_used': filter_used
            }
            
            if is_filtered:
                result['filtered_params'].append(param_info)
            else:
                result['unfiltered_params'].append(param_info)
            
            result['total_params'] += 1
        
        return result
        
    except Exception as e:
        print(f"读取文件 {file_path} 时出错: {e}")
        return None

def analyze_risk_level(param_info, line_content):
    """
    分析参数的风险等级
    
    Args:
        param_info (dict): 参数信息
        line_content (str): 行内容
        
    Returns:
        str: 风险等级
    """
    line_lower = line_content.lower()
    
    # 高风险：直接用于SQL查询、文件操作、命令执行
    high_risk_patterns = [
        'select', 'insert', 'update', 'delete', 'mysql_query', 'mysqli_query',
        'file_get_contents', 'fopen', 'include', 'require', 'exec', 'system',
        'shell_exec', 'eval', 'unlink', 'rmdir'
    ]
    
    # 中风险：用于数组访问、字符串拼接
    medium_risk_patterns = [
        'echo', 'print', 'header', 'setcookie', '.'
    ]
    
    for pattern in high_risk_patterns:
        if pattern in line_lower:
            return "高风险"
    
    for pattern in medium_risk_patterns:
        if pattern in line_lower:
            return "中风险"
    
    return "低风险"

def scan_directory(directory, output_file):
    """
    递归扫描目录中的PHP文件
    
    Args:
        directory (str): 要扫描的目录路径
        output_file (str): 输出文件路径
    """
    vulnerable_files = []
    total_php_files = 0
    total_unfiltered_params = 0
    high_risk_params = 0
    medium_risk_params = 0
    
    print(f"开始扫描目录: {directory}")
    print("正在检测未过滤的参数...")
    
    # 递归遍历目录
    for root, dirs, files in os.walk(directory):
        for file in files:
            # 只检查PHP文件
            if file.lower().endswith(('.php', '.phtml', '.php3', '.php4', '.php5')):
                file_path = os.path.join(root, file)
                total_php_files += 1
                
                # 检查未过滤的参数
                result = find_unfiltered_parameters(file_path)
                if result is None:
                    continue
                
                # 如果有未过滤的参数
                if result['unfiltered_params']:
                    file_info = {
                        'file_path': file_path,
                        'result': result
                    }
                    
                    # 分析每个参数的风险等级
                    for param in result['unfiltered_params']:
                        risk_level = analyze_risk_level(param, param['line_content'])
                        param['risk_level'] = risk_level
                        
                        if risk_level == "高风险":
                            high_risk_params += 1
                        elif risk_level == "中风险":
                            medium_risk_params += 1
                    
                    vulnerable_files.append(file_info)
                    total_unfiltered_params += len(result['unfiltered_params'])
                    
                    print(f"发现未过滤参数: {file_path} ({len(result['unfiltered_params'])} 个)")
    
    # 写入结果到文件
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("参数过滤检测报告\n")
            f.write("=" * 60 + "\n")
            f.write(f"扫描目录: {directory}\n")
            f.write(f"总计PHP文件数: {total_php_files}\n")
            f.write(f"存在未过滤参数的文件数: {len(vulnerable_files)}\n")
            f.write(f"未过滤参数总数: {total_unfiltered_params}\n")
            f.write(f"高风险参数数: {high_risk_params}\n")
            f.write(f"中风险参数数: {medium_risk_params}\n")
            f.write(f"检测的过滤函数: {', '.join(FILTER_FUNCTIONS)}\n")
            f.write("=" * 60 + "\n\n")
            
            if vulnerable_files:
                f.write("检测到的未过滤参数:\n")
                f.write("-" * 40 + "\n\n")
                
                for file_info in vulnerable_files:
                    f.write(f"文件: {file_info['file_path']}\n")
                    result = file_info['result']
                    
                    f.write(f"总参数数: {result['total_params']}\n")
                    f.write(f"未过滤参数数: {len(result['unfiltered_params'])}\n")
                    f.write(f"已过滤参数数: {len(result['filtered_params'])}\n\n")
                    
                    if result['unfiltered_params']:
                        f.write("未过滤的参数:\n")
                        for param in result['unfiltered_params']:
                            f.write(f"  参数: {param['parameter']}\n")
                            f.write(f"  行号: {param['line_number']}\n")
                            f.write(f"  风险等级: {param['risk_level']}\n")
                            f.write(f"  代码: {param['line_content']}\n")
                            f.write("  " + "-" * 30 + "\n")
                    
                    if result['filtered_params']:
                        f.write("\n已过滤的参数:\n")
                        for param in result['filtered_params']:
                            f.write(f"  参数: {param['parameter']}\n")
                            f.write(f"  行号: {param['line_number']}\n")
                            f.write(f"  使用的过滤函数: {', '.join(param['filters_used'])}\n")
                            f.write(f"  代码: {param['line_content']}\n")
                            f.write("  " + "-" * 30 + "\n")
                    
                    f.write("\n" + "=" * 60 + "\n\n")
            else:
                f.write("✅ 未发现未过滤的参数！\n")
                
        print(f"\n检测完成！结果已保存到: {output_file}")
        print(f"总计检测 {total_php_files} 个PHP文件")
        print(f"发现 {len(vulnerable_files)} 个文件存在未过滤参数")
        print(f"未过滤参数总数: {total_unfiltered_params}")
        print(f"其中高风险参数 {high_risk_params} 个，中风险参数 {medium_risk_params} 个")
        
    except Exception as e:
        print(f"写入输出文件时出错: {e}")

def main():
    """主函数"""
    print("参数过滤检测工具")
    print("=" * 40)
    print("检测目标：$_x_xxxx 类型参数是否缺少过滤函数")
    print(f"检测的过滤函数: {', '.join(FILTER_FUNCTIONS)}")
    print()
    
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
    output_file = "parameter_filter_report.txt"
    
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
