# CRM VPS API 快速开始指南

## 🎯 5分钟快速部署

### 方法一：自动部署（推荐）

1. **上传文件到VPS**
   ```bash
   scp -r vps-api root@your-vps-ip:/root/
   ```

2. **运行部署脚本**
   ```bash
   ssh root@your-vps-ip
   cd /root/vps-api
   chmod +x deploy.sh
   ./deploy.sh
   ```

3. **保存API密钥**
   
   脚本会自动生成并显示API密钥，请务必保存！

4. **配置前端**
   - 打开CRM系统
   - 点击 "⚙️ API设置"
   - 添加配置，填入API地址和密钥
   - 开始使用！

### 方法二：手动部署

#### 1. 安装Node.js
```bash
# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# CentOS/RHEL
curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
sudo yum install -y nodejs
```

#### 2. 上传并安装
```bash
# 上传文件
scp -r vps-api root@your-vps-ip:/opt/crm-api

# 安装依赖
cd /opt/crm-api
npm install --production
```

#### 3. 配置
```bash
# 复制配置文件
cp .env.example .env

# 编辑配置
nano .env

# 生成API密钥
openssl rand -base64 32
```

#### 4. 启动
```bash
# 安装PM2
npm install -g pm2

# 启动服务
pm2 start server.js --name crm-api

# 设置开机自启
pm2 startup
pm2 save
```

## 📱 前端配置步骤

### 1. 打开API设置
在CRM系统中点击 "⚙️ API设置" 按钮

### 2. 添加配置
- **配置名称**: 我的VPS
- **API URL**: `http://your-vps-ip:3000` 或您的域名
- **API Key**: 部署时生成的密钥

### 3. 测试连接
点击 "📤 同步到云端" 测试上传功能

## 🔧 常用命令

```bash
# 查看服务状态
pm2 status

# 查看日志
pm2 logs crm-api

# 重启服务
pm2 restart crm-api

# 停止服务
pm2 stop crm-api

# 查看API密钥
cat /opt/crm-api/.env | grep API_KEY
```

## 🌐 配置域名（可选）

### 使用Nginx反向代理

1. **安装Nginx**
   ```bash
   sudo apt install nginx
   ```

2. **创建配置**
   ```bash
   sudo nano /etc/nginx/sites-available/crm-api
   ```

   内容：
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://localhost:3000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           client_max_body_size 50m;
       }
   }
   ```

3. **启用配置**
   ```bash
   sudo ln -s /etc/nginx/sites-available/crm-api /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx
   ```

4. **配置SSL（可选）**
   ```bash
   sudo apt install certbot python3-certbot-nginx
   sudo certbot --nginx -d your-domain.com
   ```

## ❓ 遇到问题？

### 端口被占用
```bash
# 查看端口占用
sudo lsof -i :3000

# 修改端口
nano /opt/crm-api/.env
# 修改 PORT=3001
pm2 restart crm-api
```

### 无法访问
```bash
# 检查防火墙
sudo ufw allow 3000/tcp

# 检查服务状态
pm2 status
pm2 logs crm-api
```

### API密钥错误
```bash
# 查看当前密钥
cat /opt/crm-api/.env | grep API_KEY

# 生成新密钥
openssl rand -base64 32

# 更新配置
nano /opt/crm-api/.env
pm2 restart crm-api
```

## 📞 获取帮助

详细文档请查看: [README.md](README.md)

---

**🎉 部署完成后，您就可以在CRM系统中使用云端同步功能了！**
