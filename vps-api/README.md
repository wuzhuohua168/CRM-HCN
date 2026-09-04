# CRM系统 VPS API 部署指南

## 📋 目录
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [详细部署步骤](#详细部署步骤)
- [配置说明](#配置说明)
- [安全建议](#安全建议)
- [常见问题](#常见问题)

## 🔧 环境要求

- **操作系统**: Ubuntu 20.04+ / CentOS 7+ / Debian 10+ 或其他Linux发行版
- **Node.js**: v16.0.0 或更高版本
- **npm**: v7.0.0 或更高版本
- **内存**: 至少 512MB RAM
- **磁盘空间**: 至少 1GB 可用空间

## 🚀 快速开始

### 1. 上传文件到VPS

将整个 `vps-api` 文件夹上传到您的VPS服务器，例如：
```bash
scp -r vps-api root@your-vps-ip:/opt/crm-api
```

### 2. 安装依赖

```bash
cd /opt/crm-api
npm install --production
```

### 3. 配置环境变量

```bash
cp .env.example .env
nano .env
```

修改以下配置：
```env
PORT=3000
NODE_ENV=production
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
API_KEY=your-api-key-here-change-this
DB_PATH=./data/crm.db
```

**⚠️ 重要**: 请务必修改 `JWT_SECRET` 和 `API_KEY` 为强密码！

### 4. 初始化数据库

```bash
npm run init-db
```

### 5. 启动服务

```bash
npm start
```

服务将在 `http://your-vps-ip:3000` 运行。

## 📖 详细部署步骤

### 使用 PM2 进程管理器（推荐）

PM2 可以让您的应用在后台持续运行，并在崩溃时自动重启。

#### 安装 PM2
```bash
npm install -g pm2
```

#### 启动应用
```bash
pm2 start server.js --name crm-api
```

#### 设置开机自启
```bash
pm2 startup
pm2 save
```

#### 常用命令
```bash
pm2 status              # 查看状态
pm2 logs crm-api        # 查看日志
pm2 restart crm-api     # 重启服务
pm2 stop crm-api        # 停止服务
pm2 delete crm-api      # 删除服务
```

### 配置 Nginx 反向代理（推荐）

使用 Nginx 可以提供 HTTPS 支持、负载均衡和更好的性能。

#### 安装 Nginx
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nginx

# CentOS/RHEL
sudo yum install epel-release
sudo yum install nginx
```

#### 创建 Nginx 配置
```bash
sudo nano /etc/nginx/sites-available/crm-api
```

添加以下内容：
```nginx
server {
    listen 80;
    server_name your-domain.com;  # 替换为您的域名或IP

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # 增加请求体大小限制（用于大数据同步）
        client_max_body_size 50m;
    }
}
```

#### 启用配置
```bash
sudo ln -s /etc/nginx/sites-available/crm-api /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 配置 HTTPS（推荐）

使用 Let's Encrypt 免费SSL证书：

```bash
# 安装 Certbot
sudo apt install certbot python3-certbot-nginx

# 获取证书
sudo certbot --nginx -d your-domain.com

# 自动续期
sudo certbot renew --dry-run
```

## ⚙️ 配置说明

### 环境变量详解

| 变量名 | 说明 | 默认值 | 必填 |
|--------|------|--------|------|
| PORT | 服务器端口 | 3000 | 否 |
| NODE_ENV | 运行环境 | production | 否 |
| JWT_SECRET | JWT密钥 | - | 是 |
| API_KEY | API访问密钥 | - | 是 |
| DB_PATH | 数据库文件路径 | ./data/crm.db | 否 |
| RATE_LIMIT_WINDOW_MS | 限流时间窗口（毫秒） | 900000 | 否 |
| RATE_LIMIT_MAX_REQUESTS | 限流最大请求数 | 100 | 否 |

### API 接口说明

#### 健康检查
```
GET /api/health
```

#### 同步数据到云端
```
POST /api/sync
Headers:
  X-API-Key: your-api-key
  X-User-ID: user-id
Body:
  {
    "data": [...],           // CRM数据数组
    "dataType": "crm_records" // 数据类型
  }
```

#### 从云端恢复数据
```
GET /api/restore?dataType=crm_records
Headers:
  X-API-Key: your-api-key
  X-User-ID: user-id
```

#### 查询数据状态
```
GET /api/status
Headers:
  X-API-Key: your-api-key
  X-User-ID: user-id
```

#### 删除数据
```
DELETE /api/data?dataType=crm_records
Headers:
  X-API-Key: your-api-key
  X-User-ID: user-id
```

## 🔒 安全建议

### 1. 防火墙配置

```bash
# Ubuntu UFW
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 80/tcp      # HTTP
sudo ufw allow 443/tcp     # HTTPS
sudo ufw enable

# CentOS Firewalld
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

### 2. 生成强密码

```bash
# 生成API密钥（32位随机字符串）
openssl rand -base64 32

# 生成JWT密钥（64位随机字符串）
openssl rand -base64 64
```

### 3. 定期备份数据库

创建备份脚本：
```bash
nano ~/backup-crm.sh
```

内容：
```bash
#!/bin/bash
BACKUP_DIR="/root/backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_PATH="/opt/crm-api/data/crm.db"

mkdir -p $BACKUP_DIR
cp $DB_PATH $BACKUP_DIR/crm_$DATE.db

# 保留最近30天的备份
find $BACKUP_DIR -name "crm_*.db" -mtime +30 -delete

echo "Backup completed: crm_$DATE.db"
```

设置定时任务：
```bash
chmod +x ~/backup-crm.sh
crontab -e
```

添加：
```
0 2 * * * /root/backup-crm.sh >> /var/log/crm-backup.log 2>&1
```

### 4. 限制API访问

如果只允许特定IP访问，可以修改 Nginx 配置：
```nginx
location /api/ {
    allow 1.2.3.4;      # 允许的IP
    allow 5.6.7.8;      # 允许的IP
    deny all;           # 拒绝其他所有IP
    
    proxy_pass http://localhost:3000;
    # ... 其他配置
}
```

## 🎯 前端配置

### 在CRM系统中配置API

1. 打开 `index.html`
2. 点击 "⚙️ API设置" 按钮
3. 点击 "添加配置"
4. 填写以下信息：
   - **配置名称**: 例如 "我的VPS"
   - **API URL**: `https://your-domain.com` 或 `http://your-vps-ip:3000`
   - **API Key**: 您在 `.env` 文件中设置的 `API_KEY`
5. 点击 "保存"
6. 点击 "选择" 按钮激活此配置

### 测试连接

配置完成后，点击 "📤 同步到云端" 按钮测试上传，或点击 "📥 从云端恢复" 测试下载。

## ❓ 常见问题

### 1. 端口被占用
```bash
# 查看端口占用
sudo lsof -i :3000

# 修改端口
nano .env
# 修改 PORT=3001
```

### 2. 数据库权限错误
```bash
sudo chown -R $USER:$USER /opt/crm-api/data
chmod -R 755 /opt/crm-api/data
```

### 3. Nginx 502 Bad Gateway
```bash
# 检查API服务是否运行
pm2 status

# 检查Nginx配置
sudo nginx -t

# 查看Nginx错误日志
sudo tail -f /var/log/nginx/error.log
```

### 4. API密钥无效
- 确保 `.env` 文件中的 `API_KEY` 与前端配置的一致
- 重启服务：`pm2 restart crm-api`

### 5. 数据同步失败
- 检查网络连接
- 查看服务器日志：`pm2 logs crm-api`
- 确认API密钥正确
- 检查请求体大小（默认限制50MB）

## 📊 性能优化

### 1. 启用 Gzip 压缩
已在 `server.js` 中自动启用 `compression` 中间件。

### 2. 数据库优化
```bash
# 定期执行VACUUM优化数据库
sqlite3 /opt/crm-api/data/crm.db "VACUUM;"
```

### 3. 日志轮转
PM2 自带日志轮转功能：
```bash
pm2 install pm2-logrotate
pm2 set pm2-logrotate:max_size 10M
pm2 set pm2-logrotate:retain 7
```

## 📞 技术支持

如遇到问题，请检查：
1. 服务器日志：`pm2 logs crm-api`
2. Nginx日志：`/var/log/nginx/error.log`
3. 数据库文件是否存在：`ls -la /opt/crm-api/data/`

---

**🎉 部署完成后，您的CRM系统就可以实现云端数据同步了！**
