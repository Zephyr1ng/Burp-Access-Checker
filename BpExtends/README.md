# Burp Suite 越权扫描器

<div align="center">

![Burp Suite](https://img.shields.io/badge/Burp%20Suite-2024 compatible-blue)
![Java](https://img.shields.io/badge/Java-17-orange)
![Montoya API](https://img.shields.io/badge/Montoya%20API-Latest-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

一个功能强大的Burp Suite扩展插件，用于自动化检测Web应用中的越权访问漏洞和未授权访问漏洞。

[功能特性](#功能特性) • [安装](#安装) • [使用方法](#使用方法) • [技术架构](#技术架构) • [开发](#开发)

</div>

---

## 📌 项目简介

Burp Suite 越权扫描器是一个用于授权安全测试的自动化检测工具。它能够从Burp Proxy的历史记录中自动筛选目标接口，通过替换/删除认证信息的方式，自动检测：

- **越权漏洞**：使用用户B的认证信息访问用户A捕获的请求，验证是否存在越权访问
- **未授权访问**：删除认证信息后重放请求，验证是否存在未授权访问

<div align="center">

> ⚠️ **免责声明**：本插件仅用于授权安全测试。使用前请确保已获得目标系统所有者的书面授权。

</div>

---

## ✨ 功能特性

### 🔍 自动化漏洞检测

| 检测类型 | 检测方式 | 判定逻辑 |
|---------|---------|---------|
| **越权漏洞** | 用测试用户Cookie替换原始Cookie重放请求 | 响应相似度≥阈值 + 无权限错误提示 |
| **未授权访问** | 删除所有认证信息后重放请求 | 状态码2xx + 无登录提示 + 包含业务数据 |

### 🎯 智能过滤

- 域名过滤：支持配置多个目标域名
- 静态资源排除：自动排除图片、CSS、JS等静态文件
- 请求方法过滤：支持指定要检测的HTTP方法
- 路径模式匹配：支持正则表达式包含/排除
- 去重处理：避免重复检测相同接口

### ⚙️ 灵活配置

- **相似度阈值**：可调整响应相似度判定阈值（50%-100%）
- **并发线程**：支持1-50线程并发扫描
- **请求超时**：可配置请求超时时间
- **认证头删除**：自定义要删除的认证头列表

### 📊 结果展示

- 实时进度显示
- 风险等级分类（高危/中危/低危/信息）
- 详细响应对比视图
- 一键发送到Repeater
- 支持导出扫描结果

---

## 🚀 安装

### 前置要求

- Burp Suite 2023.1 或更高版本（支持Montoya API）
- Java 17 或更高版本

### 安装步骤

1. 下载最新版本的 [jar文件](releases)

2. 打开 Burp Suite

3. 进入 `Extender` → `Extensions` → `Add`

4. 选择 `Extension type: Java`

5. 选择下载的jar文件

6. 点击 `Next` 完成安装

7. 在Burp Suite主界面会出现 **"越权扫描"** 标签页

---

## 📖 使用方法

### 快速开始

#### 第一步：配置目标域名

```
1. 打开 "越权扫描" 标签页
2. 在 "配置" 面板中：
   - 输入目标域名（如 example.com）
   - 点击 "添加" 按钮
```

#### 第二步：配置测试凭证

```
在 "测试Cookie" 输入框中：
- 输入另一个用户的Cookie（用于越权测试）
- 点击 "添加测试凭证" 按钮
```

**注意**：原始Cookie会自动从Proxy历史记录中提取，无需手动配置。

#### 第三步：开始扫描

```
1. 确保已在Burp Proxy中浏览过目标网站
2. 点击 "开始扫描" 按钮
3. 等待扫描完成
4. 在 "结果" 面板中查看扫描结果
```

### 检测流程说明

```
┌─────────────────────────────────────────────────────────────────┐
│                    扫描检测流程                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. 用户在Burp Proxy中正常浏览目标网站                          │
│     ↓                                                           │
│  2. Proxy记录历史请求（包含用户的Cookie_A）                       │
│     ↓                                                           │
│  3. 插件自动从历史记录中提取原始凭证                              │
│     ↓                                                           │
│  4. 对每个请求执行检测：                                          │
│     ├─ 越权测试：用Cookie_B替换Cookie_A → 重放请求 → 分析响应     │
│     └─ 未授权测试：删除所有认证信息 → 重放请求 → 分析响应         │
│     ↓                                                           │
│  5. 根据响应判定是否存在漏洞                                      │
│     ↓                                                           │
│  6. 在结果面板展示发现的漏洞                                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 查看结果详情

- **单击** 选中一行结果
- **双击** 打开详情对话框，查看原始响应与测试响应对比
- 点击 **"发送到Repeater"** 可将请求发送到Burp Repeater进行深入分析

---

## 🏗️ 技术架构

### 项目结构

```
privilege-escalation-scanner/
├── src/main/java/burp/privilege/
│   ├── PrivilegeEscalationExtension.java    # 插件入口
│   ├── model/                                # 数据模型
│   │   ├── VulnerabilityType.java            # 漏洞类型枚举
│   │   ├── ScanConfig.java                  # 扫描配置
│   │   ├── ScanResult.java                  # 扫描结果
│   │   └── AuthCredential.java               # 认证凭证
│   ├── scanner/                              # 扫描引擎
│   │   ├── ScanEngine.java                  # 核心扫描引擎
│   │   ├── RequestFilter.java               # 请求过滤器
│   │   ├── ResponseAnalyzer.java            # 响应分析器
│   │   └── SimilarityCalculator.java        # 相似度计算
│   ├── ui/                                   # 用户界面
│   │   ├── MainTab.java                     # 主标签页
│   │   └── panel/
│   │       ├── ConfigPanel.java             # 配置面板
│   │       ├── ResultPanel.java             # 结果面板
│   │       └── ControlPanel.java            # 控制面板
│   └── util/                                # 工具类
│       └── HttpUtils.java                   # HTTP工具类
└── pom.xml                                  # Maven配置
```

### 核心算法

**相似度计算**：使用Levenshtein距离（编辑距离）算法

```
相似度 = (1 - 编辑距离 / 最大长度) × 100%
```

**越权判定条件**：
1. 原始请求和测试请求都返回2xx状态码
2. 响应相似度 >= 阈值（默认80%）
3. 响应中不包含权限错误提示
4. 响应中不包含登录/认证重定向

**未授权判定条件**：
1. 删除认证信息后仍返回2xx状态码
2. 响应不包含登录/权限提示
3. 响应不重定向到登录页
4. 响应包含业务数据

### 技术栈

- **Burp Suite Montoya API** - Burp Suite官方扩展API
- **Java 17** - 开发语言
- **Maven** - 项目构建
- **Swing** - UI框架

---

## 🛠️ 开发

### 构建项目

```bash
git clone https://github.com/yourusername/privilege-escalation-scanner.git
cd privilege-escalation-scanner
mvn clean package
```

### 开发环境要求

- JDK 17+
- Maven 3.6+
- Burp Suite 2023.1+
- IntelliJ IDEA（推荐）

### 贡献

欢迎提交 Issue 和 Pull Request！

---

## 📸 截图

### 配置界面
*(待添加)*

### 扫描结果
*(待添加)*

### 详情对比
*(待添加)*

---

## 🤝 致谢

- [Burp Suite](https://portswigger.net/) - 强大的Web安全测试平台
- [Montoya API](https://portswigger.net/burp/documentation) - Burp Suite扩展API

---

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

---

## ⚠️ 免责声明

本工具仅供学习和授权安全测试使用。使用本工具进行未经授权的测试属于非法行为，作者不承担任何责任。使用者应当遵守当地法律法规，确保在获得明确授权的情况下使用本工具。

---

## 📮 联系方式

- 作者：Privilege Escalation Scanner Team
- 问题反馈：[GitHub Issues](https://github.com/yourusername/privilege-escalation-scanner/issues)

---

<div align="center">

**⭐ 如果这个项目对你有帮助，请给一个 Star！⭐**

Made with ❤️ by the Security Community

</div>
