#!/bin/bash

echo "🚀 CRM VPS API 快速部署脚本"
echo "================================"

# 检查是否为root用户
if [ "$EUID" -ne 0 ]; then 
    echo "❌ 请使用 root 用户或 sudo 运行此脚本"
    exit 1
fi

# 检测操作系统
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
else
    echo "❌ 无法检测操作系统"
    exit 1
fi

echo "📋 检测到操作系统: $OS"

# 安装 Node.js
echo ""
echo "📦 正在安装 Node.js..."
if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]]; then
    curl -fsSL https://rpm.nodesource.com/setup_18.x | bash -
    yum install -y nodejs
else
    echo "❌ 不支持的操作系统，请手动安装 Node.js"
    exit 1
fi

# 验证安装
node --version
npm --version

# 安装 PM2
echo ""
echo "📦 正在安装 PM2..."
npm install -g pm2

# 创建项目目录
PROJECT_DIR="/opt/crm-api"
echo ""
echo "📁 创建项目目录: $PROJECT_DIR"
mkdir -p $PROJECT_DIR

# 复制文件（假设脚本在项目目录中运行）
if [ -f "server.js" ]; then
    cp -r ./* $PROJECT_DIR/
else
    echo "❌ 请在 vps-api 目录中运行此脚本"
    exit 1
fi

cd $PROJECT_DIR

# 安装依赖
echo ""
echo "📦 安装项目依赖..."
npm install --production

# 配置环境变量
echo ""
echo "⚙️  配置环境变量..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    
    # 生成随机密钥
    API_KEY=$(openssl rand -base64 32)
    JWT_SECRET=$(openssl rand -base64 64)
    
    # 更新 .env 文件
    sed -i "s/your-api-key-here-change-this/$API_KEY/" .env
    sed -i "s/your-super-secret-jwt-key-change-this-in-production/$JWT_SECRET/" .env
    
    echo "✅ 已生成安全的 API_KEY 和 JWT_SECRET"
    echo ""
    echo "🔑 您的 API 密钥是: $API_KEY"
    echo "⚠️  请妥善保存此密钥，配置前端时需要使用！"
else
    echo "⚠️  .env 文件已存在，跳过配置"
fi

# 初始化数据库
echo ""
echo "🗄️  初始化数据库..."
npm run init-db

# 启动服务
echo ""
echo "🚀 启动服务..."
pm2 start server.js --name crm-api
pm2 startup
pm2 save

# 配置防火墙
echo ""
echo "🔒 配置防火墙..."
if command -v ufw &> /dev/null; then
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 3000/tcp
    echo "✅ UFW 防火墙已配置"
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    firewall-cmd --permanent --add-port=3000/tcp
    firewall-cmd --reload
    echo "✅ Firewalld 防火墙已配置"
fi

# 显示状态
echo ""
echo "================================"
echo "✅ 部署完成！"
echo ""
echo "📊 服务状态:"
pm2 status
echo ""
echo "🌐 访问地址:"
echo "   本地: http://localhost:3000"
echo "   外网: http://$(curl -s ifconfig.me):3000"
echo ""
echo "📝 常用命令:"
echo "   查看日志: pm2 logs crm-api"
echo "   重启服务: pm2 restart crm-api"
echo "   停止服务: pm2 stop crm-api"
echo ""
echo "📖 下一步："
echo "   1. 在浏览器中打开 CRM 系统"
echo "   2. 点击 '⚙️ API设置' 按钮"
echo "   3. 添加配置，填入上面的 API 密钥"
echo "   4. 开始使用云端同步功能！"
echo ""
