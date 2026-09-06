#!/bin/bash
# CRM-HCN 一键部署脚本
# 用法: bash deploy-crm.sh
set -e

REPO_DIR="/root/CRM-HCN"
WEB_DIR="/var/www/crm"

echo "🚀 CRM 前端部署开始..."

if [ ! -d "$REPO_DIR" ]; then
    echo "❌ 找不到仓库目录: $REPO_DIR"
    exit 1
fi

cd "$REPO_DIR"

echo "📥 拉取最新代码..."
git pull

echo "📁 复制前端文件到网站目录..."
cp index.html "$WEB_DIR/"
cp -r optimized-assets/* "$WEB_DIR/optimized-assets/"

echo ""
echo "========================================"
echo "✅ 部署完成！"
echo "🌐 请刷新浏览器查看效果"
echo "   (若页面仍显示旧版，按 Ctrl+F5 / Cmd+Shift+R 强制刷新)"
