"""
1. 多种加密算法支持 :

   - AES, DES, 3DES, RSA
   - MD5, SHA1, SHA256, SHA512
   - HMAC, Base64, JWT
   - 加密模式和填充方式
2. 行号显示 : 每个发现都包含具体的行号信息
3. 详细上下文 : 保存完整的代码行内容和位置信息
4. AI友好输出 :

   - 生成 crypto_analysis_detailed.txt 包含所有详细信息
   - 格式化输出便于AI分析
   - 包含文件路径和行号定位
5. 分类整理 : 按加密类型分类显示结果
6. 扩展文件类型 : 支持更多编程语言文件
现在运行脚本后，会生成详细的分析文件，您可以直接将其内容提供给AI进行进一步的加密信息分析和识别。
作者: ruoji
时间: 2025-07-08
Github:https://github.com/RuoJi6/script-demo
版本: 1.0
"""
import re
import os
from pathlib import Path

def find_crypto_info_in_directory(directory_path, file_extensions=None):
    """
    在指定目录下搜索所有文件中的加密相关信息。
    
    Args:
        directory_path: 要搜索的目录路径
        file_extensions: 要搜索的文件扩展名列表，如 ['.js', '.ts', '.json']。如果为 None，则搜索所有文件
    """
    if file_extensions is None:
        file_extensions = ['.js', '.ts', '.json']
    
    # 扩展的加密相关正则表达式模式
    patterns = {
        'crypto_keys': [
            # 密钥模式 - 16-64字符的base64/hex字符串
            re.compile(r'(?:var|let|const)\s+\w+\s*=\s*["\']([a-zA-Z0-9+/=]{16,64})["\'];?'),
            re.compile(r'(?:key|Key|SECRET|secret|password|Password)\s*[=:]\s*["\']([a-zA-Z0-9+/=]{16,64})["\']'),
            re.compile(r'["\'](?:key|Key|SECRET|secret|password|Password)["\']\s*[=:]\s*["\']([a-zA-Z0-9+/=]{16,64})["\']'),
        ],
        'crypto_ivs': [
            # IV/初始向量模式
            re.compile(r'parse\(["\']([a-zA-Z0-9+/=]{16,32})["\']\)'),
            re.compile(r'(?:iv|IV|nonce|Nonce)\s*[=:]\s*["\']([a-zA-Z0-9+/=]{16,32})["\']'),
            re.compile(r'["\'](?:iv|IV|nonce|Nonce)["\']\s*[=:]\s*["\']([a-zA-Z0-9+/=]{16,32})["\']'),
        ],
        'aes_usage': [
            # AES 相关
            re.compile(r'((?:CryptoJS\.)?AES\.(?:encrypt|decrypt)\([^)]+\))'),
            re.compile(r'(createCipher(?:iv)?\(["\']aes[^)]+\))'),
        ],
        'des_usage': [
            # DES/3DES 相关
            re.compile(r'((?:CryptoJS\.)?(?:DES|TripleDES)\.(?:encrypt|decrypt)\([^)]+\))'),
            re.compile(r'(createCipher(?:iv)?\(["\']des[^)]+\))'),
        ],
        'rsa_usage': [
            # RSA 相关
            re.compile(r'((?:CryptoJS\.)?RSA\.(?:encrypt|decrypt|sign|verify)\([^)]+\))'),
            re.compile(r'(createSign\(["\']RSA[^)]+\))'),
            re.compile(r'(createVerify\(["\']RSA[^)]+\))'),
        ],
        'hash_usage': [
            # 哈希算法
            re.compile(r'((?:CryptoJS\.)?(?:MD5|SHA1|SHA256|SHA512)\([^)]+\))'),
            re.compile(r'(createHash\(["\'](?:md5|sha1|sha256|sha512)[^)]+\))'),
        ],
        'hmac_usage': [
            # HMAC
            re.compile(r'((?:CryptoJS\.)?HmacSHA(?:1|256|512)\([^)]+\))'),
            re.compile(r'(createHmac\(["\']sha[^)]+\))'),
        ],
        'base64_usage': [
            # Base64 编码/解码
            re.compile(r'((?:CryptoJS\.enc\.)?Base64\.(?:stringify|parse)\([^)]+\))'),
            re.compile(r'(btoa\([^)]+\))'),
            re.compile(r'(atob\([^)]+\))'),
        ],
        'crypto_modes': [
            # 加密模式
            re.compile(r'(mode\s*:\s*[a-zA-Z.]+(?:CBC|ECB|CFB|OFB|CTR|GCM)[a-zA-Z.]*)'),
            re.compile(r'(padding\s*:\s*[a-zA-Z.]+(?:Pkcs7|NoPadding|ZeroPadding|Iso10126)[a-zA-Z.]*)'),
        ],
        'jwt_usage': [
            # JWT 相关
            re.compile(r'(jwt\.(?:sign|verify|decode)\([^)]+\))'),
            re.compile(r'(jsonwebtoken\.(?:sign|verify|decode)\([^)]+\))'),
        ]
    }
    
    results = []
    
    def is_valid_crypto_string(s):
        """判断字符串是否可能是加密相关的密钥或IV"""
        # 长度检查：通常密钥和IV长度为16、24、32、64字符
        if len(s) not in [16, 24, 32, 64]:
            return False
        
        # 排除明显的函数名或变量名
        function_keywords = [
            'function', 'return', 'console', 'window', 'document', 'undefined',
            'null', 'true', 'false', 'this', 'prototype', 'constructor',
            'Change', 'Handle', 'Click', 'Event', 'List', 'Item', 'Data',
            'Query', 'Get', 'Set', 'Update', 'Delete', 'Create', 'Remove',
            'Component', 'Element', 'Object', 'Array', 'String', 'Number'
        ]
        
        for keyword in function_keywords:
            if keyword.lower() in s.lower():
                return False
        
        # 检查是否包含足够的随机性（密钥通常包含数字和字母的混合）
        has_digit = any(c.isdigit() for c in s)
        has_upper = any(c.isupper() for c in s)
        has_lower = any(c.islower() for c in s)
        
        return has_digit and (has_upper or has_lower)
    
    def get_line_number(content, position):
        """根据字符位置获取行号"""
        return content[:position].count('\n') + 1
    
    def search_file(file_path):
        """搜索单个文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            file_results = {
                'file': str(file_path),
                'crypto_keys': [],
                'crypto_ivs': [],
                'aes_usage': [],
                'des_usage': [],
                'rsa_usage': [],
                'hash_usage': [],
                'hmac_usage': [],
                'base64_usage': [],
                'crypto_modes': [],
                'jwt_usage': [],
                'all_findings': []  # 包含行号和上下文的所有发现
            }
            
            # 搜索所有模式
            for category, pattern_list in patterns.items():
                for pattern in pattern_list:
                    for match in pattern.finditer(content):
                        matched_text = match.group(1) if match.groups() else match.group(0)
                        line_num = get_line_number(content, match.start())
                        
                        # 获取上下文（当前行的完整内容）
                        lines = content.split('\n')
                        if line_num <= len(lines):
                            line_content = lines[line_num - 1].strip()
                        else:
                            line_content = ""
                        
                        # 对于密钥和IV，进行额外验证
                        if category in ['crypto_keys', 'crypto_ivs']:
                            if not is_valid_crypto_string(matched_text):
                                continue
                        
                        file_results[category].append(matched_text)
                        
                        # 添加到总发现列表
                        finding = {
                            'category': category,
                            'value': matched_text,
                            'line': line_num,
                            'line_content': line_content,
                            'context_start': max(1, line_num - 2),
                            'context_end': min(len(lines), line_num + 2)
                        }
                        file_results['all_findings'].append(finding)
            
            # 去重
            for category in file_results:
                if category not in ['file', 'all_findings']:
                    file_results[category] = list(set(file_results[category]))
            
            # 按行号排序所有发现
            file_results['all_findings'].sort(key=lambda x: x['line'])
            
            # 只返回有结果的文件
            has_results = any(file_results[cat] for cat in file_results if cat not in ['file', 'all_findings'])
            if has_results:
                return file_results
                
        except Exception as e:
            print(f"读取文件 {file_path} 时出错: {e}")
        
        return None
    
    # 遍历目录
    directory = Path(directory_path)
    if not directory.exists():
        print(f"目录不存在: {directory_path}")
        return []
    
    print(f"开始搜索目录: {directory_path}")
    print(f"搜索文件类型: {file_extensions}")
    print("-" * 50)
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = Path(root) / file
            
            # 检查文件扩展名
            if file_extensions and file_path.suffix.lower() not in file_extensions:
                continue
            
            result = search_file(file_path)
            if result:
                results.append(result)
    
    return results

def print_results(results):
    """格式化输出结果"""
    if not results:
        print("未找到任何加密相关信息。")
        return
    
    print(f"\n找到 {len(results)} 个包含加密信息的文件:")
    print("=" * 60)
    
    for result in results:
        print(f"\n📁 文件: {result['file']}")
        
        # 按类别显示结果
        categories = {
            'crypto_keys': '🔑 密钥',
            'crypto_ivs': '🔒 初始向量/Nonce',
            'aes_usage': '🛡️  AES加密',
            'des_usage': '🔐 DES/3DES加密',
            'rsa_usage': '🗝️  RSA加密',
            'hash_usage': '🔍 哈希算法',
            'hmac_usage': '🔏 HMAC',
            'base64_usage': '📝 Base64编码',
            'crypto_modes': '⚙️  加密模式',
            'jwt_usage': '🎫 JWT'
        }
        
        for category, icon_name in categories.items():
            if result[category]:
                print(f"{icon_name} ({len(result[category])} 个):")
                for item in result[category][:5]:  # 只显示前5个
                    print(f"    ✓ {item[:80]}{'...' if len(item) > 80 else ''}")
                if len(result[category]) > 5:
                    print(f"    ... 还有 {len(result[category]) - 5} 个")
        
        print("-" * 40)

def save_detailed_results(results, output_file):
    """保存详细结果到文件，包含行号和上下文"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("详细加密信息搜索结果\n")
        f.write("=" * 40 + "\n\n")
        f.write("格式说明：\n")
        f.write("[文件路径] 第X行 [类别] 内容\n")
        f.write("上下文：完整的代码行内容\n\n")
        f.write("=" * 40 + "\n\n")
        
        for result in results:
            f.write(f"📁 文件: {result['file']}\n")
            f.write(f"总计发现: {len(result['all_findings'])} 个加密相关项\n")
            f.write("-" * 60 + "\n")
            
            for finding in result['all_findings']:
                f.write(f"第 {finding['line']} 行 [{finding['category']}]: {finding['value']}\n")
                f.write(f"代码行: {finding['line_content']}\n")
                f.write(f"位置: {result['file']}:{finding['line']}\n")
                f.write("-" * 30 + "\n")
            
            f.write("\n" + "=" * 60 + "\n\n")

def main(search_directory):
    """主函数"""
    # 设置搜索目录（当前目录）
    
    
    # 搜索多种文件类型
    file_types = ['.js', '.ts', '.json', '.py', '.java', '.cpp', '.c', '.h']
    
    print("🔍 全面加密信息提取工具")
    print("支持: AES, DES, RSA, Hash, HMAC, Base64, JWT 等")
    print("=" * 50)
    
    # 执行搜索
    results = find_crypto_info_in_directory(search_directory, file_types)
    
    # 输出结果
    print_results(results)
    
    # 保存详细结果到文件
    if results:
        output_file = "crypto_analysis_detailed.txt"
        save_detailed_results(results, output_file)
        
        # 同时保存简化版本
        summary_file = "crypto_analysis_summary.txt"
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("加密信息搜索摘要\n")
            f.write("=" * 25 + "\n\n")
            
            for result in results:
                f.write(f"文件: {result['file']}\n")
                
                if result['crypto_keys']:
                    f.write(f"密钥: {', '.join(result['crypto_keys'][:3])}\n")
                
                if result['crypto_ivs']:
                    f.write(f"IV/Nonce: {', '.join(result['crypto_ivs'][:3])}\n")
                
                total_crypto = sum(len(result[cat]) for cat in result if cat not in ['file', 'all_findings'])
                f.write(f"总加密项: {total_crypto}\n")
                f.write("-" * 40 + "\n")
        
        print(f"\n💾 详细结果已保存到: {output_file}")
        print(f"💾 摘要结果已保存到: {summary_file}")
        print(f"\n📋 可以将 {output_file} 的内容提供给AI进行进一步分析")

if __name__ == "__main__":
    main(search_directory = "/xxxx/xxxx/xxxx/") # search_directory小程序路径