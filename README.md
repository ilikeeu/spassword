-----
注意修改tampermonkey代码.js里面的密码管理系统地址
  - **更新记录：20256.11
  - **修复误操作输错密码，历史密码恢复
  - **增加chrome扩展
  - **已安装的如果报错，请尝试删除最近的一条KV数据
  - **再次更新
  - **增加历史密码记录删除按钮
  - **修改tampermonkey脚本在检测到登录框的时候才会显示在右下角
# 🔐 密码管理器 Pro - 完整说明文档

## 🎯 项目概述

**密码管理器 Pro** 是一个基于 Cloudflare Workers 的现代化密码管理解决方案，提供安全的密码存储、智能自动填充、云备份同步等功能。

### 🌟 核心优势

  - **🔒 端到端加密**：所有密码数据采用 AES-GCM 加密
  - **☁️ 云原生架构**：基于 Cloudflare Workers + KV 存储
  - **🤖 智能自动填充**：配套 Tampermonkey 扩展实现自动填充
  - **📱 响应式设计**：完美适配桌面和移动设备
  - **🔄 WebDAV 备份**：支持多种云存储服务
  - **👥 多用户支持**：OAuth 认证 + 用户隔离

## ✨ 功能特性

#### 🔐 密码管理

  - ✅ 密码增删改查
  - ✅ 分类管理
  - ✅ 批量导入导出
  - ✅ 密码强度生成器
  - ✅ 重复检测
  - ✅ 分页浏览（50条/页）

#### 🤖 智能填充

  - ✅ 自动检测登录表单
  - ✅ 智能匹配算法（精确/子域/站名）
  - ✅ 多账户选择
  - ✅ 密码变更检测
  - ✅ 一键填充

#### ☁️ 云备份

  - ✅ WebDAV 加密备份
  - ✅ 支持 TeraCloud、坚果云、NextCloud
  - ✅ 自动去重恢复
  - ✅ 备份文件管理

#### 🔒 安全特性

  - ✅ OAuth 第三方认证
  - ✅ 用户权限控制
  - ✅ 会话管理
  - ✅ 数据加密存储

## 🚀 部署指南

### 1\. 准备工作

#### 1.1 创建 OAuth 应用

选择一个 OAuth 提供商（如 GitHub、GitLab、Google），创建 OAuth 应用：

**GitHub 示例：**

1.  访问 [GitHub Developer Settings](https://github.com/settings/developers)
2.  点击 "New OAuth App"
3.  填写应用信息：
      - **Application name**: `密码管理器 Pro`
      - **Homepage URL**: `https://your-domain.pages.dev`
      - **Authorization callback URL**: `https://your-domain.pages.dev/api/oauth/callback`
4.  获取 `Client ID` 和 `Client Secret`

#### 1.2 获取用户 ID（可选）

如果需要单用户访问控制：

1.  完成 OAuth 应用创建后
2.  访问提供商的 API 获取用户 ID
      - **GitHub 示例**：`https://api.github.com/user`

### 2\. Cloudflare Workers 部署

#### 2.1 创建 Workers 项目

```bash
# 安装 Wrangler CLI
npm install -g wrangler

# 登录 Cloudflare
wrangler auth login

# 创建项目
wrangler init password-manager
cd password-manager
```

#### 2.2 配置 `wrangler.toml`

```toml
name = "password-manager"
main = "src/worker.js"
compatibility_date = "2024-01-01"

[[kv_namespaces]]
binding = "PASSWORD_KV"
id = "your-kv-namespace-id"
preview_id = "your-preview-kv-namespace-id"

[vars]
OAUTH_BASE_URL = "https://github.com"
OAUTH_REDIRECT_URI = "https://your-domain.pages.dev/api/oauth/callback"

[env.production.vars]
OAUTH_CLIENT_ID = "your-oauth-client-id"

# 生产环境的 secrets
[env.production.secrets]
OAUTH_CLIENT_SECRET = "your-oauth-client-secret"
OAUTH_ID = "your-user-id"  # 可选：单用户访问控制
```

#### 2.3 创建 KV 命名空间

```bash
# 创建生产环境的 KV 命名空间
wrangler kv:namespace create "PASSWORD_KV"

# 创建预览环境的 KV 命名空间
wrangler kv:namespace create "PASSWORD_KV" --preview
```

#### 2.4 部署代码

1.  复制完整的 `_worker.js` 代码到 `src/worker.js`
2.  设置 Secret 环境变量：
    ```bash
    wrangler secret put OAUTH_CLIENT_SECRET
    wrangler secret put OAUTH_ID  # 可选
    ```
3.  部署：
    ```bash
    wrangler deploy
    ```

### 3\. 自定义域名（推荐）

1.  **添加域名路由**
    ```bash
    wrangler route add "your-domain.com/*" password-manager
    ```
2.  **配置 DNS**
    在 Cloudflare DNS 设置中添加 CNAME 记录：
    `CNAME` | `@` | `your-worker.your-subdomain.workers.dev`

## ⚙️ 配置说明

### 环境变量

| 变量名                | 类型     | 必需 | 说明                           |
| --------------------- | -------- | :--: | ------------------------------ |
| `OAUTH_CLIENT_ID`     | Secret   |  ✅  | OAuth 应用 Client ID           |
| `OAUTH_CLIENT_SECRET` | Secret   |  ✅  | OAuth 应用 Client Secret       |
| `OAUTH_BASE_URL`      | Variable |  ✅  | OAuth 提供商基础 URL           |
| `OAUTH_REDIRECT_URI`  | Variable |  ✅  | OAuth 回调地址                 |
| `OAUTH_ID`            | Secret   |  ❌  | 单用户访问控制的用户 ID        |

### OAuth 提供商配置

  - **GitHub**: `OAUTH_BASE_URL = "https://github.com"`
  - **GitLab**: `OAUTH_BASE_URL = "https://gitlab.com"`
  - **Google**: `OAUTH_BASE_URL = "https://accounts.google.com"`

### KV 存储结构

  - **用户会话**: `session_{token}` = `{用户信息}`
  - **密码数据**: `password_{userId}_{passwordId}` = `{加密密码数据}`
  - **分类数据**: `categories_{userId}` = `[分类列表]`
  - **WebDAV 配置**: `webdav_config_{userId}` = `{加密WebDAV配置}`
  - **OAuth 状态**: `oauth_state_{state}` = `"valid"`

## 🔧 Tampermonkey扩展

### 安装步骤

1.  **安装 Tampermonkey**
      - Chrome: [Chrome Web Store](https://chrome.google.com/webstore/detail/tampermonkey/dhdgffkkebhmkfjojejmpbldmpobfkfo)
      - Firefox: [Firefox Add-ons](https://addons.mozilla.org/firefox/addon/tampermonkey/)
      - Edge: [Microsoft Store](https://microsoftedge.microsoft.com/addons/detail/tampermonkey/iikmkjmpaadaobahmlepeloendndfphd)
2.  **添加脚本**
      - 点击 Tampermonkey 图标 → "添加新脚本"
      - 复制完整的扩展代码并粘贴
      - 保存脚本
3.  **配置扩展**
      - 访问密码管理器网站并登录
      - 扩展会自动获取登录令牌
      - 或手动设置令牌：右键 → Tampermonkey → 设置令牌

### 扩展功能

  - **🔍 自动检测**
      - 自动检测页面登录表单
      - 智能匹配已保存的账户
      - 显示匹配统计（精确/子域/站名）
  - **⚡ 快速填充**
      - 单账户：显示快速填充按钮
      - 多账户：显示账户选择列表
      - 一键填充用户名和密码
  - **💾 自动保存**
      - 检测表单提交
      - 自动保存新账户
      - 检测密码变更并提示更新
  - **🎯 智能匹配**
      - **精确匹配**：域名完全相同（优先级最高）
      - **子域匹配**：子域名匹配
      - **站名匹配**：网站名称包含关键词

### 使用技巧

  - **快捷键**
      - `Ctrl+K`：快速搜索
      - `Esc`：关闭弹窗
  - **菜单命令**
      - 打开密码管理器
      - 重新检测表单
      - 设置令牌
      - 退出登录
      - 调试信息

## 📖 API文档

### 认证相关

  - **登录授权**: `GET /api/oauth/login`
      - 返回 OAuth 授权链接
  - **OAuth 回调**: `GET /api/oauth/callback?code={code}&state={state}`
      - 处理 OAuth 回调并创建会话
  - **验证登录状态**: `GET /api/auth/verify` (`Authorization: Bearer {token}`)
  - **登出**: `POST /api/auth/logout` (`Authorization: Bearer {token}`)

### 密码管理

  - **获取密码列表**: `GET /api/passwords?page=1&limit=50&search={query}&category={category}`
  - **添加密码**: `POST /api/passwords`
    ```json
    {
      "siteName": "GitHub",
      "username": "user@example.com",
      "password": "password123",
      "url": "https://github.com",
      "category": "开发工具",
      "notes": "备注信息"
    }
    ```
  - **更新密码**: `PUT /api/passwords/{id}`
    ```json
    {
      "siteName": "GitHub",
      "password": "newpassword123"
    }
    ```
  - **删除密码**: `DELETE /api/passwords/{id}`
  - **获取明文密码**: `GET /api/passwords/{id}/reveal`

### 自动填充

  - **检测登录**: `POST /api/detect-login`
    ```json
    {
      "url": "https://github.com/login",
      "username": "user@example.com",
      "password": "password123"
    }
    ```
  - **自动填充匹配**: `POST /api/auto-fill`
    ```json
    {
      "url": "https://github.com/login"
    }
    ```

### WebDAV 备份

  - **保存配置**: `POST /api/webdav/config`
  - **测试连接**: `POST /api/webdav/test`
  - **创建备份**: `POST /api/webdav/backup`
  - **恢复备份**: `POST /api/webdav/restore`

## 📚 使用教程

1.  **首次使用**
    1.  **访问网站**：打开您部署的密码管理器网址
    2.  **开始使用**：点击 "开始使用 OAuth 登录"
    3.  **完成认证**：跳转到 OAuth 提供商，授权应用访问
    4.  **安装扩展**：安装 Tampermonkey 扩展并添加脚本，扩展会自动同步登录状态
2.  **密码管理**
      - **添加密码**: 点击 "添加密码" 标签页，填写信息并保存。可使用密码生成器创建强密码。
      - **管理密码**: 在 "密码管理" 标签页，可通过搜索、分类筛选和分页浏览所有密码。
      - **密码操作**:
          - 👁️ **查看**：显示明文密码
          - 📋 **复制**：复制密码到剪贴板
          - ✏️ **编辑**：修改密码信息
          - 🗑️ **删除**：删除密码（不可恢复）
3.  **WebDAV 备份**
    1.  **配置**: 在 "云备份" 标签页填写您的 WebDAV 服务信息，测试并保存。
    2.  **创建备份**: 设置一个备份密码，点击 "创建加密备份"。
    3.  **恢复备份**: 列出云端文件，选择备份文件，输入备份密码后即可恢复。系统会自动去重。
4.  **自动填充**
      - 访问任意登录页面，扩展会自动检测。
      - 点击右下角浮动按钮选择账户进行填充。
      - 登录成功后，新账户会自动保存，密码变更会自动提示。

## 🔒 安全说明

### 加密机制

  - **密码加密**:
      - 算法：AES-GCM 256位
      - 密钥：基于用户ID生成
      - 初始化向量：每次加密随机生成
      - 存储：Base64编码存储
  - **备份加密**:
      - 算法：AES-GCM 256位
      - 密钥：基于用户设置的备份密码
      - 双重加密：密码先用用户密钥加密，再用备份密码加密

### 安全最佳实践

  - **部署安全**: 强制 HTTPS，绑定域名，使用 Secrets 管理敏感信息，设置 `OAUTH_ID` 限制访问。
  - **使用安全**: OAuth 账户使用强密码，定期备份，不分享登录令牌，及时登出。
  - **风险提示**: 注意浏览器、网络环境和设备安全，妥善保管备份密码。

## 🛠️ 故障排除

### 常见问题

1.  **登录失败**
      - **症状**：点击登录后跳转失败或提示错误。
      - **解决方案**：检查 `wrangler.toml` 中的 OAuth 配置与回调地址是否正确；使用 `wrangler tail` 查看实时日志。
2.  **扩展无法填充**
      - **症状**：扩展检测到账户但填充失败。
      - **解决方案**：打开浏览器开发者工具查看控制台错误；确认页面字段是否可见；尝试手动刷新。
3.  **WebDAV 连接失败**
      - **症状**：测试连接时提示失败。
      - **解决方案**：确认 WebDAV 地址、用户名、密码无误；检查网络连接。

### 调试工具

  - **扩展调试**: Tampermonkey 菜单 → `调试信息`，查看控制台输出。
  - **API 调试**:
    ```bash
    # 查看 Workers 日志
    wrangler tail

    # 测试 API 端点
    curl -H "Authorization: Bearer {token}" https://your-domain.pages.dev/api/passwords
    ```
  - **KV 存储调试**:
    ```bash
    # 列出 KV 键
    wrangler kv:key list --binding=PASSWORD_KV

    # 查看特定键值
    wrangler kv:key get "session_xxx" --binding=PASSWORD_KV
    ```

## 📝 更新日志

### `v1.7.0` 

  - **新增**
      - ✅ 分页功能（50条/页）
      - ✅ 用户授权控制（`OAUTH_ID`）
      - ✅ 智能密码变更检测
      - ✅ 改进的重复检查逻辑
      - ✅ WebDAV 测试连接功能
  - **修复**
      - 🐛 Tampermonkey 全局函数作用域问题
      - 🐛 密码填充失败问题
      - 🐛 分页导航显示问题
  - **优化**
      - 🔧 更好的错误处理和日志
      - 🔧 响应式界面优化
      - 🔧 API 性能提升

### `v1.6.0` 

  - **新增**
      - ✅ WebDAV 云备份支持
      - ✅ 加密导入导出
      - ✅ 自动去重恢复

### `v1.5.0`

  - **新增**
      - ✅ Tampermonkey 扩展
      - ✅ 自动登录检测
      - ✅ 智能密码填充

### `v1.0.0` 

  - **初始发布**
      - ✅ 基础密码管理
      - ✅ OAuth 认证

## 📞 支持与反馈

  - **获取帮助**: 查看本文档，或在项目的 `Issues` 和 `Discussions` 区提问。
  - **贡献代码**: 欢迎 Fork 项目仓库，创建功能分支，并发起 Pull Request。
  - **许可证**: 本项目采用 MIT 许可证。

-----

**🔐 密码管理器 Pro - 让密码管理变得简单、安全、智能！**
