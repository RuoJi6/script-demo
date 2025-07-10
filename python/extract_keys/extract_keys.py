import re
import os
from pathlib import Path
FILENAME = "" #文件绝对路径
def find_crypto_info_in_directory(directory_path, file_extensions=None):
    """
    在指定目录下搜索所有文件中的加密相关信息。
    
    Args:
        directory_path: 要搜索的目录路径
        file_extensions: 要搜索的文件扩展名列表，如 ['.js', '.ts', '.json', '.py', '.java', '.cpp', '.c', '.h', '.xml', '.yml', '.yaml', '.env', '.config']。如果为 None，则搜索所有文件
    """
    if file_extensions is None:
        file_extensions = ['.js', '.ts', '.json', '.py', '.java', '.cpp', '.c', '.h', '.xml', '.yml', '.yaml', '.env', '.config']
    
    # 扩展的加密相关正则表达式模式
    patterns = {
        # 云服务商 AccessKey/SecretKey
        'aliyun_keys': [
            # 阿里云 AccessKey ID (LTAI开头，16-24字符)
            re.compile(r'(?:LTAI[A-Za-z0-9]{12,20})'),
            # 阿里云相关关键字匹配
            re.compile(r'(?:accessKeyId|AccessKeyId|access_key_id)\s*[=:]\s*["\']([A-Za-z0-9]{16,64})["\']'),
            re.compile(r'(?:accessKeySecret|AccessKeySecret|access_key_secret)\s*[=:]\s*["\']([A-Za-z0-9+/=]{24,64})["\']'),
            re.compile(r'(?:OSSaccessKeyId|ossAccessKeyId)\s*[=:]\s*["\']([A-Za-z0-9]{16,64})["\']'),
            re.compile(r'(?:OSSaccessKeySecret|ossAccessKeySecret)\s*[=:]\s*["\']([A-Za-z0-9+/=]{24,64})["\']'),
        ],
        'tencent_keys': [
            # 腾讯云 SecretId (AKID开头)
            re.compile(r'(?:AKID[A-Za-z0-9]{13,20})'),
            # 腾讯云相关关键字匹配
            re.compile(r'(?:secretId|SecretId|secret_id)\s*[=:]\s*["\']([A-Za-z0-9]{16,64})["\']'),
            re.compile(r'(?:secretKey|SecretKey|secret_key)\s*[=:]\s*["\']([A-Za-z0-9+/=]{32,64})["\']'),
            # 腾讯云IM相关
            re.compile(r'(?:txImSdkAppid|TxImSdkAppid|sdkAppId)\s*[=:]\s*["\']?([0-9]{8,12})["\']?'),
            re.compile(r'(?:txImSecretKey|TxImSecretKey|userSig)\s*[=:]\s*["\']([A-Za-z0-9+/=]{32,256})["\']'),
        ],
        'aws_keys': [
            # AWS AccessKey (AKIA开头)
            re.compile(r'(?:AKIA[A-Z0-9]{16})'),
            # AWS相关关键字匹配
            re.compile(r'(?:aws_access_key_id|AWS_ACCESS_KEY_ID)\s*[=:]\s*["\']([A-Z0-9]{16,32})["\']'),
            re.compile(r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']([A-Za-z0-9+/=]{32,64})["\']'),
            re.compile(r'(?:aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*["\']([A-Za-z0-9+/=]{100,500})["\']'),
        ],
        'api_keys': [
            # GitHub Token - 新增更多GitHub token格式 <mcreference link="https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/" index="1">1</mcreference>
            re.compile(r'(?:github_token|GITHUB_TOKEN)\s*[=:]\s*["\']([A-Za-z0-9_-]{40})["\']'),
            # GitHub新格式token (ghp_, gho_, ghu_, ghs_, ghr_)
            re.compile(r'(gh[poushr]_[A-Za-z0-9]{36})'),
            re.compile(r'(github_pat_[A-Za-z0-9_]{82})'),
            
            # Google API Key
            re.compile(r'(AIza[A-Za-z0-9_-]{35})'),
            re.compile(r'(?:google_api_key|GOOGLE_API_KEY)\s*[=:]\s*["\']([A-Za-z0-9_-]{32,64})["\']'),
            
            # Firebase API Key
            re.compile(r'(?:firebase_api_key|FIREBASE_API_KEY)\s*[=:]\s*["\']([A-Za-z0-9_-]{32,64})["\']'),
            
            # 微信小程序相关 - 增强匹配
            re.compile(r'(?:appId|AppId|app_id|APPID)\s*[=:]\s*["\']([a-zA-Z0-9]{16,32})["\']'),
            re.compile(r'(?:appSecret|AppSecret|app_secret|APP_SECRET)\s*[=:]\s*["\']([a-zA-Z0-9]{32,64})["\']'),
            
            # 微信支付相关
            re.compile(r'(?:mch_id|MCH_ID|mchId)\s*[=:]\s*["\']([0-9]{8,12})["\']'),
            re.compile(r'(?:api_key|API_KEY|apiKey|ApiKey)\s*[=:]\s*["\']([A-Za-z0-9_-]{16,128})["\']'),
            re.compile(r'(?:api_secret|API_SECRET|apiSecret|ApiSecret)\s*[=:]\s*["\']([A-Za-z0-9+/=_-]{16,128})["\']'),
            
            # JWT Token相关 - 增强匹配 <mcreference link="https://help.aliyun.com/zh/api-gateway/traditional-api-gateway/user-guide/jwt-based-authentication" index="5">5</mcreference>
            re.compile(r'(?:jwt_token|JWT_TOKEN|jwtToken)\s*[=:]\s*["\']([A-Za-z0-9+/=_-]{100,500})["\']'),
            re.compile(r'(?:access_token|ACCESS_TOKEN|accessToken)\s*[=:]\s*["\']([A-Za-z0-9+/=_-]{16,256})["\']'),
            re.compile(r'(?:bearer_token|BEARER_TOKEN|bearerToken)\s*[=:]\s*["\']([A-Za-z0-9+/=_-]{16,256})["\']'),
            re.compile(r'(?:refresh_token|REFRESH_TOKEN|refreshToken)\s*[=:]\s*["\']([A-Za-z0-9+/=_-]{16,256})["\']'),
            
            # OAuth相关 <mcreference link="https://www.cnblogs.com/pengxiaojie/p/17756736.html" index="1">1</mcreference>
            re.compile(r'(?:client_id|CLIENT_ID|clientId)\s*[=:]\s*["\']([A-Za-z0-9_-]{16,64})["\']'),
            re.compile(r'(?:client_secret|CLIENT_SECRET|clientSecret)\s*[=:]\s*["\']([A-Za-z0-9+/=_-]{32,128})["\']'),
            
            # 支付宝相关
            re.compile(r'(?:alipay_app_id|ALIPAY_APP_ID)\s*[=:]\s*["\']([0-9]{16,20})["\']'),
            re.compile(r'(?:alipay_private_key|ALIPAY_PRIVATE_KEY)\s*[=:]\s*["\']([A-Za-z0-9+/=\\n\\r\\s]{100,2048})["\']'),
            
            # 钉钉相关
            re.compile(r'(?:dingtalk_app_key|DINGTALK_APP_KEY)\s*[=:]\s*["\']([A-Za-z0-9]{16,32})["\']'),
            re.compile(r'(?:dingtalk_app_secret|DINGTALK_APP_SECRET)\s*[=:]\s*["\']([A-Za-z0-9]{32,64})["\']'),
            
            # 企业微信相关
            re.compile(r'(?:corp_id|CORP_ID|corpId)\s*[=:]\s*["\']([A-Za-z0-9]{16,32})["\']'),
            re.compile(r'(?:corp_secret|CORP_SECRET|corpSecret)\s*[=:]\s*["\']([A-Za-z0-9_-]{32,64})["\']'),
            
            # Slack相关
            re.compile(r'(?:slack_token|SLACK_TOKEN)\s*[=:]\s*["\']([A-Za-z0-9_-]{40,60})["\']'),
            re.compile(r'(xox[bpars]-[A-Za-z0-9-]{10,48})'),
            
            # Discord相关
            re.compile(r'(?:discord_token|DISCORD_TOKEN)\s*[=:]\s*["\']([A-Za-z0-9_.-]{50,80})["\']'),
            
            # Stripe相关
            re.compile(r'(sk_live_[A-Za-z0-9]{24,})'),
            re.compile(r'(sk_test_[A-Za-z0-9]{24,})'),
            re.compile(r'(pk_live_[A-Za-z0-9]{24,})'),
            re.compile(r'(pk_test_[A-Za-z0-9]{24,})'),
            
            # SendGrid相关
            re.compile(r'(SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43})'),
            
            # Mailgun相关
            re.compile(r'(?:mailgun_api_key|MAILGUN_API_KEY)\s*[=:]\s*["\']([A-Za-z0-9-]{32,})["\']'),
            
            # Twilio相关
            re.compile(r'(AC[a-z0-9]{32})'),  # Account SID
            re.compile(r'(?:twilio_auth_token|TWILIO_AUTH_TOKEN)\s*[=:]\s*["\']([a-z0-9]{32})["\']'),
            
            # Azure相关 <mcreference link="https://learn.microsoft.com/zh-cn/azure/azure-monitor/logs/api/access-api" index="4">4</mcreference>
            re.compile(r'(?:azure_client_id|AZURE_CLIENT_ID)\s*[=:]\s*["\']([a-f0-9-]{36})["\']'),
            re.compile(r'(?:azure_client_secret|AZURE_CLIENT_SECRET)\s*[=:]\s*["\']([A-Za-z0-9+/=_.-]{32,128})["\']'),
            
            # 百度云相关
            re.compile(r'(?:baidu_api_key|BAIDU_API_KEY)\s*[=:]\s*["\']([A-Za-z0-9]{24,32})["\']'),
            re.compile(r'(?:baidu_secret_key|BAIDU_SECRET_KEY)\s*[=:]\s*["\']([A-Za-z0-9]{32,48})["\']'),
            
            # 华为云相关
            re.compile(r'(?:huawei_access_key|HUAWEI_ACCESS_KEY)\s*[=:]\s*["\']([A-Z0-9]{20})["\']'),
            re.compile(r'(?:huawei_secret_key|HUAWEI_SECRET_KEY)\s*[=:]\s*["\']([A-Za-z0-9+/=]{40})["\']'),
            
            # 七牛云相关
            re.compile(r'(?:qiniu_access_key|QINIU_ACCESS_KEY)\s*[=:]\s*["\']([A-Za-z0-9_-]{40})["\']'),
            re.compile(r'(?:qiniu_secret_key|QINIU_SECRET_KEY)\s*[=:]\s*["\']([A-Za-z0-9_-]{40})["\']'),
            
            # 又拍云相关
            re.compile(r'(?:upyun_username|UPYUN_USERNAME)\s*[=:]\s*["\']([A-Za-z0-9_-]{4,20})["\']'),
            re.compile(r'(?:upyun_password|UPYUN_PASSWORD)\s*[=:]\s*["\']([A-Za-z0-9+/=]{16,64})["\']'),
            
            # API认证头部模式 <mcreference link="https://blog.csdn.net/weixin_42233867/article/details/130311075" index="2">2</mcreference>
            re.compile(r'(?:X-API-KEY|x-api-key)\s*[=:]\s*["\']([A-Za-z0-9_-]{16,128})["\']'),
            re.compile(r'(?:X-API-SECRET|x-api-secret)\s*[=:]\s*["\']([A-Za-z0-9+/=_-]{16,128})["\']'),
            re.compile(r'(?:Authorization)\s*[=:]\s*["\']Bearer\\s+([A-Za-z0-9+/=_-]{16,256})["\']'),
            re.compile(r'(?:Authorization)\s*[=:]\s*["\']Token\\s+([A-Za-z0-9+/=_-]{16,256})["\']'),
            re.compile(r'(?:Authorization)\s*[=:]\s*["\']Basic\\s+([A-Za-z0-9+/=]{16,256})["\']'),
            
            # 通用API Key模式 - 修复版（更精确的匹配）
            re.compile(r'(?:api_key|API_KEY|apiKey|ApiKey)\s*[=:]\s*["\']([A-Za-z0-9_-]{16,128})["\']'),  # 移除单独的'key'
            re.compile(r'(?:secret_key|SECRET_KEY|secretKey|SecretKey|api_secret|API_SECRET|apiSecret)\s*[=:]\s*["\']([A-Za-z0-9+/=_-]{16,128})["\']'),  # 移除单独的'secret'

            # 数字签名相关
            re.compile(r'(?:private_key|PRIVATE_KEY|privateKey)\s*[=:]\s*["\']([A-Za-z0-9+/=\\n\\r\\s-]{100,2048})["\']'),
            re.compile(r'(?:public_key|PUBLIC_KEY|publicKey)\s*[=:]\s*["\']([A-Za-z0-9+/=\\n\\r\\s-]{100,2048})["\']'),
        ],
        'database_keys': [
            # 数据库连接相关
            re.compile(r'(?:db_password|DB_PASSWORD|database_password)\s*[=:]\s*["\']([^"\']{6,64})["\']'),
            re.compile(r'(?:mysql_password|MYSQL_PASSWORD)\s*[=:]\s*["\']([^"\']{6,64})["\']'),
            re.compile(r'(?:redis_password|REDIS_PASSWORD)\s*[=:]\s*["\']([^"\']{6,64})["\']'),
            re.compile(r'(?:mongodb_password|MONGODB_PASSWORD)\s*[=:]\s*["\']([^"\']{6,64})["\']'),
        ],
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
    
    def is_valid_cloud_key(s, key_type):
        """验证云服务商密钥的有效性"""
        if not s:
            return False
            
        # 排除明显的占位符
        placeholders = [
            'your_access_key', 'your_secret_key', 'your_api_key',
            'ACCESS_KEY_HERE', 'SECRET_KEY_HERE', 'API_KEY_HERE',
            'xxxxxxxxxxxx', '************', 'placeholder',
            'example', 'demo', 'test', 'sample'
        ]
        
        for placeholder in placeholders:
            if placeholder.lower() in s.lower():
                return False
        
        # 根据密钥类型进行特定验证
        if key_type == 'aliyun':
            return len(s) >= 16 and not s.startswith('test')
        elif key_type == 'tencent':
            return len(s) >= 16 and not s.startswith('test')
        elif key_type == 'aws':
            return len(s) >= 16 and not s.startswith('test')
        elif key_type == 'api':
            return len(s) >= 16 and not s.startswith('test')
        
        return True
    
    def get_line_number(content, position):
        """根据字符位置获取行号"""
        return content[:position].count('\n') + 1
    
    def get_crypto_algorithms(file_results):
        """获取文件中使用的加密算法列表"""
        algorithms = []
        
        if file_results['aliyun_keys']:
            algorithms.append('阿里云AK/SK')
        if file_results['tencent_keys']:
            algorithms.append('腾讯云AK/SK')
        if file_results['aws_keys']:
            algorithms.append('AWS AK/SK')
        if file_results['api_keys']:
            algorithms.append('API密钥')
        if file_results['database_keys']:
            algorithms.append('数据库密钥')
        if file_results['aes_usage']:
            algorithms.append('AES')
        if file_results['des_usage']:
            algorithms.append('DES/3DES')
        if file_results['rsa_usage']:
            algorithms.append('RSA')
        if file_results['hash_usage']:
            algorithms.append('Hash(MD5/SHA)')
        if file_results['hmac_usage']:
            algorithms.append('HMAC')
        if file_results['base64_usage']:
            algorithms.append('Base64')
        if file_results['jwt_usage']:
            algorithms.append('JWT')
        if file_results['crypto_modes']:
            algorithms.append('加密模式配置')
            
        return algorithms
    
    def search_file(file_path):
        """搜索单个文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            file_results = {
                'file': str(file_path),
                'aliyun_keys': [],
                'tencent_keys': [],
                'aws_keys': [],
                'api_keys': [],
                'database_keys': [],
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
                'all_findings': [],  # 包含行号和上下文的所有发现
                'algorithms': []  # 新增：算法列表
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
                        
                        # 对于不同类型的密钥进行验证
                        if category in ['crypto_keys', 'crypto_ivs']:
                            if not is_valid_crypto_string(matched_text):
                                continue
                        elif category in ['aliyun_keys', 'tencent_keys', 'aws_keys', 'api_keys', 'database_keys']:
                            key_type = category.split('_')[0]
                            if not is_valid_cloud_key(matched_text, key_type):
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
                if category not in ['file', 'all_findings', 'algorithms']:
                    file_results[category] = list(set(file_results[category]))
            
            # 按行号排序所有发现
            file_results['all_findings'].sort(key=lambda x: x['line'])
            
            # 获取算法列表
            file_results['algorithms'] = get_crypto_algorithms(file_results)
            
            # 只返回有结果的文件
            has_results = any(file_results[cat] for cat in file_results if cat not in ['file', 'all_findings', 'algorithms'])
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
        
        # 显示算法信息
        if result['algorithms']:
            print(f"🔐 检测到: {', '.join(result['algorithms'])}")
        
        # 按类别显示结果
        categories = {
            'aliyun_keys': '☁️ 阿里云密钥',
            'tencent_keys': '☁️ 腾讯云密钥',
            'aws_keys': '☁️ AWS密钥',
            'api_keys': '🔑 API密钥',
            'database_keys': '🗄️ 数据库密钥',
            'crypto_keys': '🔑 加密密钥',
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
                    # 移除敏感信息遮蔽，直接显示完整内容
                    print(f"    ✓ {item}")
                if len(result[category]) > 5:
                    print(f"    ... 还有 {len(result[category]) - 5} 个")
        
        print("-" * 40)

def save_detailed_results(results, output_file):
    """保存详细结果到文件，包含行号和上下文，不遮蔽敏感信息"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("详细加密信息搜索结果（完整版）\n")
        f.write("=" * 50 + "\n\n")
        f.write("⚠️  警告：此文件包含完整的密钥信息，请妥善保管！\n\n")
        f.write("格式说明：\n")
        f.write("[文件路径] 第X行 [类别] 完整内容\n")
        f.write("上下文：完整的代码行内容\n\n")
        f.write("=" * 50 + "\n\n")
        
        # 添加统计信息
        total_files = len(results)
        total_findings = sum(len(result['all_findings']) for result in results)
        f.write(f"📊 统计信息：\n")
        f.write(f"   - 扫描文件数: {total_files}\n")
        f.write(f"   - 发现密钥总数: {total_findings}\n\n")
        
        for result in results:
            f.write(f"📁 文件: {result['file']}\n")
            if result['algorithms']:
                f.write(f"🔐 加密算法: {', '.join(result['algorithms'])}\n")
            f.write(f"总计发现: {len(result['all_findings'])} 个加密相关项\n")
            f.write("-" * 60 + "\n")
            
            # 按类别分组显示所有密钥（不遮蔽）
            categories = {
                'aliyun_keys': '☁️ 阿里云密钥',
                'tencent_keys': '☁️ 腾讯云密钥', 
                'aws_keys': '☁️ AWS密钥',
                'api_keys': '🔑 API密钥',
                'database_keys': '🗄️ 数据库密钥',
                'crypto_keys': '🔑 加密密钥',
                'crypto_ivs': '🔒 初始向量/Nonce'
            }
            
            for category, icon_name in categories.items():
                if result[category]:
                    f.write(f"\n{icon_name} ({len(result[category])} 个):\n")
                    for i, item in enumerate(result[category], 1):
                        f.write(f"  {i}. {item}\n")
            
            # 详细的行号和上下文信息
            f.write(f"\n📍 详细位置信息:\n")
            for finding in result['all_findings']:
                f.write(f"第 {finding['line']} 行 [{finding['category']}]: {finding['value']}\n")
                f.write(f"代码行: {finding['line_content']}\n")
                f.write(f"位置: {result['file']}:{finding['line']}\n")
                f.write("-" * 30 + "\n")
            
            f.write("\n" + "=" * 60 + "\n\n")

def main(search_directory):
    """主函数"""
    # 搜索多种文件类型
    file_types = ['.js', '.ts', '.json', '.py', '.java', '.cpp', '.c', '.h', '.xml', '.yml', '.yaml', '.env', '.config']
    
    print("🔍 全面加密信息提取工具 (增强版)")
    print("支持: 阿里云/腾讯云/AWS密钥, API密钥, 数据库密钥, AES, DES, RSA, Hash, HMAC, Base64, JWT 等")
    print("=" * 80)
    
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
                
                # 添加算法信息
                if result['algorithms']:
                    f.write(f"检测到: {', '.join(result['algorithms'])}\n")
                
                # 云服务商密钥统计
                cloud_keys = len(result['aliyun_keys']) + len(result['tencent_keys']) + len(result['aws_keys'])
                if cloud_keys > 0:
                    f.write(f"云服务商密钥: {cloud_keys} 个\n")
                
                # API密钥统计
                if result['api_keys']:
                    f.write(f"API密钥: {len(result['api_keys'])} 个\n")
                
                # 数据库密钥统计
                if result['database_keys']:
                    f.write(f"数据库密钥: {len(result['database_keys'])} 个\n")
                
                # 添加具体的AES使用代码
                if result['aes_usage']:
                    f.write(f"AES使用: {', '.join(result['aes_usage'][:2])}\n")  # 显示前2个AES使用
                
                # 添加具体的加密模式
                if result['crypto_modes']:
                    f.write(f"加密模式: {', '.join(result['crypto_modes'][:2])}\n")  # 显示前2个模式
                
                if result['crypto_keys']:
                    f.write(f"加密密钥: {', '.join(result['crypto_keys'][:3])}\n")
                
                if result['crypto_ivs']:
                    f.write(f"IV/Nonce: {', '.join(result['crypto_ivs'][:3])}\n")
                
                total_crypto = sum(len(result[cat]) for cat in result if cat not in ['file', 'all_findings', 'algorithms'])
                f.write(f"总加密项: {total_crypto}\n")
                f.write("-" * 40 + "\n")
        
        print(f"\n💾 详细结果已保存到: {output_file}")
        print(f"💾 摘要结果已保存到: {summary_file}")
        print(f"\n📋 可以将 {output_file} 的内容提供给AI进行进一步分析")
        print(f"\n⚠️  安全提醒: 发现的密钥信息可能包含敏感数据，请妥善保管分析结果")

if __name__ == "__main__":
    main(search_directory = FILENAME)


def export_keys_only(results, output_file):
    """导出纯密钥列表，便于进一步处理"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("提取的密钥列表\n")
        f.write("=" * 20 + "\n\n")
        
        all_keys = []
        for result in results:
            # 收集所有类型的密钥
            for category in ['aliyun_keys', 'tencent_keys', 'aws_keys', 'api_keys', 'database_keys', 'crypto_keys', 'crypto_ivs']:
                for key in result[category]:
                    all_keys.append({
                        'file': result['file'],
                        'type': category,
                        'value': key
                    })
        
        # 按类型分组输出
        from collections import defaultdict
        keys_by_type = defaultdict(list)
        for key_info in all_keys:
            keys_by_type[key_info['type']].append(key_info)
        
        for key_type, keys in keys_by_type.items():
            f.write(f"\n{key_type.upper()} ({len(keys)} 个):\n")
            f.write("-" * 30 + "\n")
            for i, key_info in enumerate(keys, 1):
                f.write(f"{i}. {key_info['value']}\n")
                f.write(f"   来源: {key_info['file']}\n\n")
    
    # 保存详细结果到文件
    if results:
        output_file = "crypto_analysis_detailed.txt"
        save_detailed_results(results, output_file)
        
        # 导出纯密钥列表
        keys_file = "extracted_keys.txt"
        export_keys_only(results, keys_file)
        
        # 同时保存简化版本
        summary_file = "crypto_analysis_summary.txt"
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("加密信息搜索摘要\n")
            f.write("=" * 25 + "\n\n")
            
            for result in results:
                f.write(f"文件: {result['file']}\n")
                
                # 添加算法信息
                if result['algorithms']:
                    f.write(f"检测到: {', '.join(result['algorithms'])}\n")
                
                # 云服务商密钥统计
                cloud_keys = len(result['aliyun_keys']) + len(result['tencent_keys']) + len(result['aws_keys'])
                if cloud_keys > 0:
                    f.write(f"云服务商密钥: {cloud_keys} 个\n")
                
                # API密钥统计
                if result['api_keys']:
                    f.write(f"API密钥: {len(result['api_keys'])} 个\n")
                
                # 数据库密钥统计
                if result['database_keys']:
                    f.write(f"数据库密钥: {len(result['database_keys'])} 个\n")
                
                # 添加具体的AES使用代码
                if result['aes_usage']:
                    f.write(f"AES使用: {', '.join(result['aes_usage'][:2])}\n")  # 显示前2个AES使用
                
                # 添加具体的加密模式
                if result['crypto_modes']:
                    f.write(f"加密模式: {', '.join(result['crypto_modes'][:2])}\n")  # 显示前2个模式
                
                if result['crypto_keys']:
                    f.write(f"加密密钥: {', '.join(result['crypto_keys'][:3])}\n")
                
                if result['crypto_ivs']:
                    f.write(f"IV/Nonce: {', '.join(result['crypto_ivs'][:3])}\n")
                
                total_crypto = sum(len(result[cat]) for cat in result if cat not in ['file', 'all_findings', 'algorithms'])
                f.write(f"总加密项: {total_crypto}\n")
                f.write("-" * 40 + "\n")
        
        print(f"\n💾 详细结果已保存到: {output_file}")
        print(f"💾 密钥列表已保存到: {keys_file}")
        print(f"\n📋 可以将 {output_file} 的内容提供给AI进行进一步分析")
        print(f"\n⚠️  安全提醒: 发现的密钥信息可能包含敏感数据，请妥善保管分析结果")