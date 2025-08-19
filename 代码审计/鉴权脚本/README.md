# 鉴权检测工具 (auth_checker.py)

## 🔐 工具概述

`auth_checker.py` 是一个专门用于检测PHP文件中鉴权保护的安全审计工具。它能够识别缺少访问控制的文件，并检测文件中的敏感函数，帮助发现潜在的安全风险。

## 🎯 主要功能

### 1. 多鉴权模式检测
支持检测多种常见的鉴权方式：
```php
'extends apiAction'        // API控制器继承
'extends Action'           // 基础控制器继承  
'require_once("auth.php")' // 鉴权文件引入
'include("auth.php")'      // 鉴权文件包含
```

### 2. 敏感函数检测
按漏洞类型分类检测敏感函数：

#### 文件操作类
- `file()`, `fgets()`, `fgetc()`, `fwrite()`
- `file_put_contents()`, `file_get_contents()`
- `unlink()`, `rmdir()`, `fopen()`, `readfile()`

#### 命令执行类
- `exec()`, `system()`, `shell_exec()`, `passthru()`
- `popen()`, `proc_open()`, `pcntl_exec()`
- `create_function()`, `array_map()`

#### SSRF漏洞类
- `curl_exec()`, `file_get_contents()`, `fopen()`, `fsockopen()`

#### 反序列化类
- `unserialize()`, `serialize()`

#### 其他危险操作
- 变量覆盖：`$$`
- 文件下载：`header('Content-Disposition:`
- URL跳转：`header('Location:`
- XML外部实体：`simplexml_load_file()`, `DOMDocument()`

### 3. 风险等级评估
- **高危文件**：缺少鉴权且包含敏感函数
- **中危文件**：缺少鉴权但无敏感函数
- **安全文件**：包含鉴权保护

## 🚀 使用方法

### 基本使用
```bash
python auth_checker.py
```

### 交互式操作
1. 输入要检测的目录路径
2. 选择输出文件名（可选）
3. 等待扫描完成

### 示例
```bash
$ python auth_checker.py
PHP鉴权脚本和敏感函数检测工具
========================================
请输入要检测的目录路径: /var/www/html/project
输出文件名 (默认: auth_check_report.txt): 
开始扫描目录: /var/www/html/project
正在检测PHP文件...
缺少鉴权: /var/www/html/project/admin/user.php
  ⚠️  高危文件（含敏感函数）: /var/www/html/project/admin/user.php
```

## 📊 输出报告

### 报告内容
生成的 `auth_check_report.txt` 包含：

1. **统计信息**
   - 扫描目录
   - 总计PHP文件数
   - 缺少鉴权脚本的文件数
   - 高危文件数

2. **缺少鉴权的文件列表**
   - 完整文件路径
   - 实时控制台输出

3. **高危文件详情**
   - 文件路径
   - 发现的敏感函数
   - 按漏洞类型分类

### 报告示例
```
PHP鉴权脚本和敏感函数检测报告
============================================================
扫描目录: /var/www/html/project
总计PHP文件数: 156
缺少鉴权脚本的文件数: 23
高危文件数（缺少鉴权且含敏感函数）: 8
============================================================

1. 缺少鉴权脚本的文件:
----------------------------------------
/var/www/html/project/admin/user.php
/var/www/html/project/api/upload.php

2. 高危文件（缺少鉴权且含敏感函数）:
----------------------------------------

文件: /var/www/html/project/admin/user.php
发现的敏感函数:
  [文件操作]: file_get_contents, unlink
  [命令执行]: exec, system
```

## ⚙️ 配置选项

### 自定义鉴权字符串
修改 `TARGET_AUTH_STRINGS` 列表：
```python
TARGET_AUTH_STRINGS = [
    'extends apiAction',
    'extends Action', 
    'include_once("auth.php")',
    'require_once("security.php")',  # 添加自定义鉴权
    # 可以添加更多鉴权模式
]
```

### 添加敏感函数
在 `SENSITIVE_FUNCTIONS` 字典中添加新的函数类型：
```python
SENSITIVE_FUNCTIONS = {
    "自定义类型": [
        "custom_function(", "dangerous_func("
    ],
    # 其他类型...
}
```

## 🔧 技术特点

### 1. 智能检测
- 使用字符串包含检测，避免正则表达式的复杂性
- 支持多种鉴权模式的OR逻辑检测
- 只要包含任意一种鉴权方式就认为安全

### 2. 递归扫描
- 自动遍历目录及所有子目录
- 支持多种PHP文件扩展名：`.php`, `.phtml`, `.php3`, `.php4`, `.php5`

### 3. 实时反馈
- 扫描过程中实时显示发现的问题文件
- 用emoji标记高危文件：⚠️
- 显示扫描进度和统计信息

## 🛡️ 安全建议

### 发现问题后的处理步骤

1. **立即修复高危文件**
   ```php
   <?php
   // 在文件开头添加鉴权检查
   include_once("inc/auth.php");
   // 或者
   if (!isset($_SESSION['admin_id'])) {
       header('Location: login.php');
       exit;
   }
   ?>
   ```

2. **审查敏感函数使用**
   - 检查敏感函数的参数是否可控
   - 添加输入验证和过滤
   - 使用白名单限制操作范围

3. **定期检测**
   - 建议在代码提交前运行检测
   - 集成到CI/CD流程中
   - 定期对生产环境进行安全审计

## ⚠️ 注意事项

1. **误报处理**：某些文件可能使用其他鉴权方式，需要人工确认
2. **权限要求**：确保有读取目标目录的权限
3. **测试环境**：建议先在测试环境中运行
4. **文件编码**：支持UTF-8编码，其他编码可能出现乱码

## 🔄 更新日志

- **v1.0**: 基础鉴权检测功能
- **v1.1**: 添加敏感函数检测
- **v1.2**: 支持多鉴权字符串检测
- **v1.3**: 优化检测逻辑，减少误报

## 📞 技术支持

如果在使用过程中遇到问题，请检查：
1. Python版本是否为3.6+
2. 目标目录是否存在且有读取权限
3. 文件路径是否包含特殊字符

这个工具是PHP代码安全审计的第一步，建议配合其他安全检测工具一起使用！
