#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQL注入漏洞检测工具
检测PHP文件中是否使用了SQL语句但没有使用 pe_dbhold() 过滤函数
"""

import os
import re
import sys
from pathlib import Path

# 全局配置：SQL相关函数和语句模式
SQL_FUNCTIONS = [
    # 数据库连接和查询函数
    'mysql_query', 'mysqli_query', 'mysql_real_escape_string',
    'pg_query', 'sqlite_query', 'mssql_query',
    'mysqli_prepare', 'mysql_prepare',
    'PDO::query', 'PDO::prepare', 'PDO::exec',
    'db_query', 'db_select', 'db_insert', 'db_update', 'db_delete'
]

# SQL语句关键词模式
SQL_PATTERNS = [
    r'\bSELECT\s+.*\s+FROM\s+',
    r'\bINSERT\s+INTO\s+',
    r'\bUPDATE\s+.*\s+SET\s+',
    r'\bDELETE\s+FROM\s+',
    r'\bCREATE\s+TABLE\s+',
    r'\bDROP\s+TABLE\s+',
    r'\bALTER\s+TABLE\s+',
    r'["\']SELECT\s+.*\s+FROM\s+.*["\']',
    r'["\']INSERT\s+INTO\s+.*["\']',
    r'["\']UPDATE\s+.*\s+SET\s+.*["\']',
    r'["\']DELETE\s+FROM\s+.*["\']'
]

# 危险的变量拼接模式
DANGEROUS_PATTERNS = [
    r'\$\w+\s*\.\s*["\']SELECT\s+',
    r'["\']SELECT\s+.*["\']?\s*\.\s*\$\w+',
    r'\$\w+\s*\.\s*["\']INSERT\s+',
    r'["\']INSERT\s+.*["\']?\s*\.\s*\$\w+',
    r'\$\w+\s*\.\s*["\']UPDATE\s+',
    r'["\']UPDATE\s+.*["\']?\s*\.\s*\$\w+',
    r'\$\w+\s*\.\s*["\']DELETE\s+',
    r'["\']DELETE\s+.*["\']?\s*\.\s*\$\w+',
    r'\$_GET\[.*\].*["\']SELECT\s+',
    r'\$_POST\[.*\].*["\']SELECT\s+',
    r'\$_REQUEST\[.*\].*["\']SELECT\s+'
]

# 过滤函数
FILTER_FUNCTION = 'pe_dbhold'

def check_sql_injection_vulnerability(file_path):
    """
    检查PHP文件中的SQL注入漏洞
    
    Args:
        file_path (str): PHP文件路径
        
    Returns:
        dict: 检测结果
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        result = {
            'has_sql': False,
            'has_filter': False,
            'sql_functions': [],
            'sql_statements': [],
            'dangerous_patterns': [],
            'vulnerable_lines': []
        }
        
        # 检查是否使用了过滤函数
        if FILTER_FUNCTION in content:
            result['has_filter'] = True
        
        # 检查SQL函数
        for func in SQL_FUNCTIONS:
            if func in content:
                result['has_sql'] = True
                result['sql_functions'].append(func)
        
        # 检查SQL语句模式
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            line_upper = line.upper()
            
            # 检查SQL语句关键词
            for pattern in SQL_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    result['has_sql'] = True
                    result['sql_statements'].append({
                        'line_number': i,
                        'content': line.strip(),
                        'pattern': pattern
                    })
            
            # 检查危险的变量拼接
            for pattern in DANGEROUS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    result['dangerous_patterns'].append({
                        'line_number': i,
                        'content': line.strip(),
                        'pattern': pattern
                    })
                    result['vulnerable_lines'].append(i)
        
        return result
        
    except Exception as e:
        print(f"读取文件 {file_path} 时出错: {e}")
        return None

def analyze_vulnerability_risk(result):
    """
    分析漏洞风险等级
    
    Args:
        result (dict): 检测结果
        
    Returns:
        str: 风险等级
    """
    if not result['has_sql']:
        return "无风险"
    
    if result['has_filter']:
        if result['dangerous_patterns']:
            return "中风险"
        else:
            return "低风险"
    else:
        if result['dangerous_patterns']:
            return "高风险"
        elif result['sql_statements']:
            return "中风险"
        else:
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
    high_risk_files = []
    medium_risk_files = []
    
    print(f"开始扫描目录: {directory}")
    print("正在检测SQL注入漏洞...")
    
    # 递归遍历目录
    for root, dirs, files in os.walk(directory):
        for file in files:
            # 只检查PHP文件
            if file.lower().endswith(('.php', '.phtml', '.php3', '.php4', '.php5')):
                file_path = os.path.join(root, file)
                total_php_files += 1
                
                # 检查SQL注入漏洞
                result = check_sql_injection_vulnerability(file_path)
                if result is None:
                    continue
                
                # 如果有SQL语句但没有过滤函数
                if result['has_sql'] and not result['has_filter']:
                    risk_level = analyze_vulnerability_risk(result)
                    vulnerable_files.append({
                        'file_path': file_path,
                        'result': result,
                        'risk_level': risk_level
                    })
                    
                    if risk_level == "高风险":
                        high_risk_files.append(file_path)
                        print(f"🚨 高风险: {file_path}")
                    elif risk_level == "中风险":
                        medium_risk_files.append(file_path)
                        print(f"⚠️  中风险: {file_path}")
                    else:
                        print(f"⚡ 低风险: {file_path}")
    
    # 写入结果到文件
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("SQL注入漏洞检测报告\n")
            f.write("=" * 60 + "\n")
            f.write(f"扫描目录: {directory}\n")
            f.write(f"总计PHP文件数: {total_php_files}\n")
            f.write(f"存在SQL注入风险的文件数: {len(vulnerable_files)}\n")
            f.write(f"高风险文件数: {len(high_risk_files)}\n")
            f.write(f"中风险文件数: {len(medium_risk_files)}\n")
            f.write("=" * 60 + "\n\n")
            
            if vulnerable_files:
                f.write("检测到的SQL注入漏洞:\n")
                f.write("-" * 40 + "\n\n")
                
                for vuln_file in vulnerable_files:
                    f.write(f"文件: {vuln_file['file_path']}\n")
                    f.write(f"风险等级: {vuln_file['risk_level']}\n")
                    
                    result = vuln_file['result']
                    
                    if result['sql_functions']:
                        f.write(f"使用的SQL函数: {', '.join(result['sql_functions'])}\n")
                    
                    if result['sql_statements']:
                        f.write("发现的SQL语句:\n")
                        for stmt in result['sql_statements']:
                            f.write(f"  行 {stmt['line_number']}: {stmt['content']}\n")
                    
                    if result['dangerous_patterns']:
                        f.write("危险的变量拼接:\n")
                        for pattern in result['dangerous_patterns']:
                            f.write(f"  行 {pattern['line_number']}: {pattern['content']}\n")
                    
                    f.write(f"是否使用过滤函数 {FILTER_FUNCTION}: {'是' if result['has_filter'] else '否'}\n")
                    f.write("-" * 40 + "\n\n")
            else:
                f.write("✅ 未发现SQL注入漏洞！\n")
                
        print(f"\n检测完成！结果已保存到: {output_file}")
        print(f"总计检测 {total_php_files} 个PHP文件")
        print(f"发现 {len(vulnerable_files)} 个存在SQL注入风险的文件")
        print(f"其中高风险文件 {len(high_risk_files)} 个，中风险文件 {len(medium_risk_files)} 个")
        
    except Exception as e:
        print(f"写入输出文件时出错: {e}")

def main():
    """主函数"""
    print("SQL注入漏洞检测工具")
    print("=" * 40)
    print(f"检测目标：使用SQL语句但未使用 {FILTER_FUNCTION}() 过滤函数的文件")
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
    output_file = "sql_injection_report.txt"
    
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
