# 参数过滤检测工具 (parameter_filter_checker.py)

## 🔍 工具概述

`parameter_filter_checker.py` 是一个专门用于检测PHP代码中特定参数格式是否缺少安全过滤的审计工具。它专注于检测 `$_x_xxxx` 类型的参数是否使用了 `pe_dbhold()` 和 `intval()` 过滤函数。

## 🎯 主要功能

### 1. 参数模式匹配
使用正则表达式精确匹配特定格式的参数：

#### 匹配模式
```regex
\$_[a-zA-Z]_[a-zA-Z0-9_]*
```

#### 匹配示例
```php
$_a_test          // ✅ 匹配
$_b_user_id       // ✅ 匹配  
$_c_file_name     // ✅ 匹配
$_d_data_info_123 // ✅ 匹配
$_ab_test         // ❌ 不匹配（第二部分超过1个字符）
$_1_test          // ❌ 不匹配（第一部分不是字母）
```

### 2. 过滤函数检测
检测参数是否被以下安全函数包围：

#### 支持的过滤函数
- `pe_dbhold()` - 数据库转义函数
- `intval()` - 整数转换函数

#### 检测模式
```php
// 直接包围
pe_dbhold($_a_test)
intval($_b_user_id)

// 赋值使用
$var = pe_dbhold($_c_file_name)
$num = intval($_d_count)

// 数组访问
pe_dbhold($_e_data['key'])
intval($_f_info['id'])
```

### 3. 风险等级评估
根据参数的使用场景评估安全风险：

#### 高风险 🚨
参数直接用于危险操作：
```php
// SQL查询
$sql = "SELECT * FROM users WHERE id = " . $_a_user_id;

// 文件操作  
include($_b_file_name);
unlink($_c_file_path);

// 命令执行
exec($_d_command);
system($_e_cmd);
```

#### 中风险 ⚠️
参数用于输出或字符串操作：
```php
// 输出操作
echo $_a_message;
print $_b_content;

// 头部设置
header("Location: " . $_c_url);
setcookie("name", $_d_value);

// 字符串拼接
$result = "Hello " . $_e_name;
```

#### 低风险 ⚡
其他一般用途：
```php
// 简单赋值
$data = $_a_info;

// 条件判断
if ($_b_flag) { ... }

// 数组操作
$array[$_c_key] = $value;
```

## 🚀 使用方法

### 基本使用
```bash
python parameter_filter_checker.py
```

### 交互式操作
1. 输入要检测的目录路径
2. 选择输出文件名（可选）
3. 等待扫描完成

### 示例
```bash
$ python parameter_filter_checker.py
参数过滤检测工具
========================================
检测目标：$_x_xxxx 类型参数是否缺少过滤函数
检测的过滤函数: pe_dbhold, intval

请输入要检测的目录路径: /var/www/html/project
输出文件名 (默认: parameter_filter_report.txt): 
开始扫描目录: /var/www/html/project
正在检测未过滤的参数...
发现未过滤参数: /var/www/html/project/admin/user.php (3 个)
```

## 📊 输出报告

### 报告内容
生成的 `parameter_filter_report.txt` 包含：

1. **统计信息**
   - 扫描目录和文件数量
   - 未过滤参数总数
   - 各风险等级统计

2. **详细参数信息**
   - 参数名称和所在行号
   - 风险等级评估
   - 完整代码内容
   - 使用的过滤函数（如果有）

### 报告示例
```
参数过滤检测报告
============================================================
扫描目录: /var/www/html/project
总计PHP文件数: 156
存在未过滤参数的文件数: 8
未过滤参数总数: 23
高风险参数数: 5
中风险参数数: 12
检测的过滤函数: pe_dbhold, intval
============================================================

检测到的未过滤参数:
----------------------------------------

文件: /var/www/html/project/admin/user.php
总参数数: 5
未过滤参数数: 3
已过滤参数数: 2

未过滤的参数:
  参数: $_a_user_id
  行号: 15
  风险等级: 高风险
  代码: $sql = "SELECT * FROM users WHERE id = " . $_a_user_id;
  ------------------------------
  参数: $_b_message
  行号: 20
  风险等级: 中风险
  代码: echo $_b_message;
  ------------------------------

已过滤的参数:
  参数: $_c_safe_id
  行号: 25
  使用的过滤函数: intval
  代码: $id = intval($_c_safe_id);
  ------------------------------
```

## 🔧 检测原理

### 1. 正则表达式匹配
```python
# 参数匹配模式
param_pattern = r'\$_[a-zA-Z]_[a-zA-Z0-9_]*'

# 查找所有匹配的参数
matches = re.finditer(param_pattern, content)
```

### 2. 上下文分析
检查参数所在行及前后几行的代码：
```python
# 检查当前行和前后几行
check_lines = []
for i in range(max(0, line_number - 3), min(len(lines), line_number + 2)):
    check_lines.append(lines[i])
```

### 3. 过滤函数识别
```python
# 过滤函数检测模式
filter_patterns = [
    rf'{filter_func}\s*\(\s*\{re.escape(param)}\s*\)',
    rf'\$\w+\s*=\s*{filter_func}\s*\(\s*\{re.escape(param)}\s*\)',
    rf'{filter_func}\s*\(\s*\{re.escape(param)}\[.*?\]\s*\)',
]
```

### 4. 风险评估
根据代码内容中的关键词判断风险等级：
```python
# 高风险关键词
high_risk_patterns = [
    'select', 'insert', 'update', 'delete', 'mysql_query',
    'file_get_contents', 'fopen', 'include', 'require', 
    'exec', 'system', 'shell_exec'
]
```

## ⚙️ 配置选项

### 自定义过滤函数
修改 `FILTER_FUNCTIONS` 列表：
```python
FILTER_FUNCTIONS = [
    'pe_dbhold',
    'intval', 
    'mysql_real_escape_string',  # 添加其他过滤函数
    'htmlspecialchars',
    'strip_tags'
]
```

### 自定义参数模式
如果需要检测其他格式的参数，修改正则表达式：
```python
# 例如检测 $_param_xxx 格式
param_pattern = r'\$_param_[a-zA-Z0-9_]*'

# 或者检测 $global_xxx 格式  
param_pattern = r'\$global_[a-zA-Z0-9_]*'
```

### 调整风险评估
在 `analyze_risk_level` 函数中自定义风险关键词：
```python
# 添加项目特定的高风险关键词
high_risk_patterns.extend([
    'your_dangerous_function',
    'project_specific_risk'
])
```

## 🛡️ 修复建议

### 1. 添加过滤函数
```php
// 数据库操作前过滤
$safe_id = pe_dbhold($_a_user_id);
$sql = "SELECT * FROM users WHERE id = " . $safe_id;

// 整数类型转换
$safe_num = intval($_b_count);
$limit = "LIMIT " . $safe_num;
```

### 2. 输入验证
```php
// 白名单验证
$allowed_actions = ['view', 'edit', 'delete'];
if (!in_array($_c_action, $allowed_actions)) {
    die('Invalid action');
}

// 格式验证
if (!preg_match('/^[a-zA-Z0-9_]+$/', $_d_filename)) {
    die('Invalid filename format');
}
```

### 3. 类型强制转换
```php
// 强制转换为安全类型
$page = (int)$_e_page;
$limit = (float)$_f_price;
$flag = (bool)$_g_status;
```

## 🔄 最佳实践

### 1. 开发规范
- 所有用户输入必须经过过滤
- 使用类型转换函数处理数值参数
- 建立参数命名规范

### 2. 代码审查
- 将此工具集成到代码审查流程
- 定期扫描新增代码
- 重点关注高风险参数

### 3. 安全培训
- 培训开发人员正确使用过滤函数
- 建立安全编码指南
- 定期进行安全意识培训

## ⚠️ 注意事项

1. **精确匹配**：只检测特定格式的参数，可能遗漏其他格式
2. **上下文限制**：只检查参数附近的代码，可能遗漏远程过滤
3. **误报可能**：某些安全的用法可能被误判为危险
4. **人工验证**：建议对检测结果进行人工确认

## 🔧 环境要求

- Python 3.6+
- 标准库：`os`, `re`, `sys`, `pathlib`
- 无需额外依赖

这个工具专注于特定参数格式的安全检测，是PHP代码安全审计工具链中的重要组成部分！
