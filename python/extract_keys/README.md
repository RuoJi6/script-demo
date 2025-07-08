# 正则匹配小程序加密算法
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

Github: https://github.com/RuoJi6/script-demo

版本: 1.0

使用，修改main中的search_directory指向指定小程序反后的目录
```python
if __name__ == "__main__":
    main(search_directory = "/xxxx/xxxx/xxxx/") # search_directory小程序路径
```


运行
``shell
python3 extract_keys.py
``
