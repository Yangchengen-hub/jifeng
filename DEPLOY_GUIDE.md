# 🚀 极风工作室 (JIFENG) 部署完整指南

> 针对完全不懂部署的小白，提供 **两种方案**。强烈建议新手使用【方案B Vercel一键部署】。

---

## ⭐ 方案A：宝塔面板部署（适合有自己服务器的用户）

### 第一步：连接服务器（就是你刚才截图的界面）

1. **名称**：随便填，比如 `我的极风服务器`
2. **主机**：填你的 **服务器公网IP地址**（例如 `123.45.67.89`）
   - 👉 **IP在哪找？** 登录阿里云/腾讯云/华为云控制台，找到你的服务器实例，复制“公网IP”
3. **端口**：默认填 `22`（如果之前改过SSH端口，填修改后的）
4. **用户名**：默认填 `root`（最高权限用户）
5. **密码**：填你登录服务器的密码（如果忘了，可以在云服务商控制台重置）
6. **安装宝塔面板**：
   - 如果你的服务器是新的、还没装宝塔 → **勾选它**（宝塔会自动安装）
   - 如果已经装过宝塔 → **不要勾选**

填完后点 **「验证连接」** → 成功后点 **「确认」**。

### 第二步：在宝塔面板中配置项目

连接成功后，在宝塔面板中：

1. **安装环境**（首次连接会提示）：
   - Node.js 版本管理器（推荐 v18 或 v20）
   - Nginx（用于反向代理）
   - MySQL 或 SQLite（SQLite 已包含在项目中，可选）

2. **上传项目文件**：
   - 打开宝塔面板的「文件」菜单
   - 进入 `/www/wwwroot/` 目录
   - 新建文件夹 `jifeng`
   - 将本地 `/workspace/jifeng/` 目录下所有文件上传到服务器的 `/www/wwwroot/jifeng/` 目录

3. **安装依赖并启动**：
   - 在宝塔面板「终端」中执行：
     ```bash
     cd /www/wwwroot/jifeng
     npm install --production
     node src/app.js
     ```
   - 看到 `服务器启动在 http://localhost:3000` 说明运行成功

4. **设置开机自启**（保持服务一直运行）：
   - 宝塔面板 → 「软件商店」→「PM2管理器」→ 安装
   - 打开 PM2 → 添加项目 → 填写：
     - 项目名称：`jifeng`
     - 启动文件：`src/app.js`
     - 项目目录：`/www/wwwroot/jifeng`

5. **配置域名和HTTPS**（可选但推荐）：
   - 宝塔面板 → 「网站」→「添加站点」
   - 填入你的域名
   - PHP版本选「纯静态」
   - 创建成功后，点击域名 → 「反向代理」→ 添加：
     - 代理名称：`jifeng`
     - 目标URL：`http://127.0.0.1:3000`
   - 「SSL」菜单 → 申请Let's Encrypt免费证书 → 开启强制HTTPS

---

## ⭐⭐⭐ 方案B：Vercel 一键部署（强烈推荐新手！）

> 无需购买服务器、无需配置域名、无需懂命令行，**全程图形界面，5分钟搞定**。

### 第一步：将代码推送到 GitHub

在本地终端执行（你当前在 `/workspace/jifeng` 目录）：

```bash
# 如果你还没初始化git仓库
git init
git add .
git commit -m "初始化极风工作室项目"

# 关联远程仓库（需要你在GitHub上先创建一个空仓库）
git remote add origin https://github.com/你的用户名/jifeng.git
git push -u origin main
```

### 第二步：在 Vercel 上部署

1. 打开 [https://vercel.com](https://vercel.com) → 用 GitHub 账号登录
2. 点击右上角 **「Add New...」** → **「Project」**
3. 在列表中找到你的 `jifeng` 仓库 → 点击 **「Import」**
4. 配置项目：
   - **Framework Preset**：会自动识别为 `Node.js`
   - **Build Command**：留空（不需要构建）
   - **Output Directory**：留空
   - **Install Command**：`npm install`
5. 点击 **「Deploy」** → 等待 1-2 分钟 → 部署成功！
6. Vercel 会自动分配一个 `xxx.vercel.app` 域名，可直接访问

### 第三步（可选）：绑定自定义域名

1. 在 Vercel 项目面板 → **「Settings」** → **「Domains」**
2. 输入你的域名 → 按提示在域名服务商处配置DNS解析
3. Vercel 会自动配置SSL证书

---

## 🔧 项目配置说明

### 端口修改
- 默认端口是 `3000`，如需修改：
  ```bash
  PORT=8080 npm start
  ```

### 数据库
- 默认使用 SQLite，数据文件存储在 `data/jifeng.db`
- 迁移到 MySQL 需修改 `src/db.js` 配置

### 邮件服务
- 默认使用开发模式（不真正发送邮件）
- 生产环境需在 `src/email-service.js` 配置 SMTP：
  ```javascript
  transporter = nodemailer.createTransport({
    host: 'smtp.qq.com',
    port: 465,
    secure: true,
    auth: {
      user: '你的QQ邮箱@qq.com',
      pass: '你的SMTP授权码'
    }
  });
  ```

---

## ❓ 常见问题

**Q：连接宝塔时提示"验证失败"？**
A：检查IP是否为公网IP、端口是否开放、密码是否正确。在云服务商控制台的「安全组」中确保 22 端口已放行。

**Q：项目启动后访问不了？**
A：在云服务商安全组中放行 3000 端口；使用宝塔Nginx反向代理到 3000 端口。

**Q：Vercel 上部署后数据库在哪？**
A：Vercel 的文件系统是临时的，SQLite 数据会丢失。建议：
- 使用 Vercel Postgres（免费额度）
- 或者在宝塔服务器上部署（数据持久化）

**Q：代码混淆在哪执行？**
A：部署前执行：
```bash
node scripts/obfuscate.js
```
混淆后会生成 `.build_backup` 备份，确保生产环境只上传混淆后的代码。
