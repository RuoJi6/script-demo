# 小程序加密算法检测工具

一个用于检测和分析小程序中加密算法使用情况的Python脚本工具。

## 功能特性

### 🔍 多种加密算法支持
- **对称加密**: AES, DES, 3DES
- **非对称加密**: RSA
- **哈希算法**: MD5, SHA1, SHA256, SHA512
- **其他**: HMAC, Base64, JWT
- **加密模式和填充方式**: CBC, ECB, PKCS7等

### 📍 精确定位
- **行号显示**: 每个发现都包含具体的行号信息
- **详细上下文**: 保存完整的代码行内容和位置信息
- **文件路径**: 完整的文件路径定位

### 🤖 AI友好输出
- 生成 `crypto_analysis_detailed.txt` 包含所有详细信息
- 生成 `crypto_analysis_summary.txt` 包含摘要信息
- 格式化输出便于AI分析和二次处理
- 包含具体的加密使用代码片段

### 📂 广泛文件支持
支持多种编程语言文件类型：
- JavaScript (.js)
- TypeScript (.ts)
- Python (.py)
- Java (.java)
- C/C++ (.c, .cpp, .h)
- JSON (.json)
- 文本文件 (.txt)

### 🗂️ 智能分类
- 按加密类型分类显示结果
- 密钥和IV自动识别
- 加密模式配置提取
- 结果去重和过滤

## 安装要求

- Python 3.6+
- 无需额外依赖包（使用Python标准库）

## 使用方法

### 1. 下载脚本
```bash
git clone https://github.com/RuoJi6/script-demo.git
cd script-demo
```

### 2. 修改extract_keys.py
```python
if __name__ == "__main__":
    main(search_directory="/path/to/your/miniprogram/directory")  # 替换为您的小程序目录路径
```

### 3. 运行
```bash
python3 extract_keys.py
```
