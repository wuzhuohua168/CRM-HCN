#!/usr/bin/env node

/**
 * VPS API测试脚本
 * 用于检查VPS服务状态和API key配置
 */

const https = require('https');
const http = require('http');

// 测试配置
const TEST_CONFIGS = [
    {
        name: '默认配置',
        url: 'https://crm.wubairan.com',
        key: 'crm2024secretkey123'
    },
    {
        name: '本地配置',
        url: 'http://localhost:3000',
        key: 'crm2024secretkey123'
    }
];

// 发送测试请求
function testApi(name, url, apiKey) {
    return new Promise((resolve) => {
        console.log(`\n========== 测试 ${name} ==========`);
        console.log(`URL: ${url}`);
        console.log(`API Key: ${apiKey.substring(0, 8)}...`);
        
        const client = url.startsWith('https') ? https : http;
        
        const options = {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            },
            timeout: 10000
        };
        
        const req = client.request(`${url}/api/health`, options, (res) => {
            let data = '';
            
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                console.log(`状态码: ${res.statusCode}`);
                console.log(`响应: ${data}`);
                
                if (res.statusCode === 200) {
                    console.log('✅ 健康检查通过');
                    resolve(true);
                } else {
                    console.log('❌ 健康检查失败');
                    resolve(false);
                }
            });
        });
        
        req.on('error', (error) => {
            console.log(`❌ 请求失败: ${error.message}`);
            resolve(false);
        });
        
        req.on('timeout', () => {
            console.log('❌ 请求超时');
            req.destroy();
            resolve(false);
        });
        
        req.end();
    });
}

// 测试备份接口
function testBackup(name, url, apiKey) {
    return new Promise((resolve) => {
        console.log(`\n========== 测试备份接口 ${name} ==========`);
        
        const client = url.startsWith('https') ? https : http;
        
        const options = {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            },
            timeout: 10000
        };
        
        const req = client.request(`${url}/api/backup`, options, (res) => {
            let data = '';
            
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                console.log(`状态码: ${res.statusCode}`);
                
                if (res.statusCode === 200) {
                    console.log('✅ 备份接口认证成功');
                    try {
                        const result = JSON.parse(data);
                        console.log(`数据: ${JSON.stringify(result, null, 2).substring(0, 200)}...`);
                    } catch (e) {
                        console.log(`响应: ${data.substring(0, 200)}...`);
                    }
                    resolve(true);
                } else if (res.statusCode === 401) {
                    console.log('❌ API密钥无效');
                    console.log(`响应: ${data}`);
                    resolve(false);
                } else {
                    console.log('❌ 备份接口失败');
                    console.log(`响应: ${data}`);
                    resolve(false);
                }
            });
        });
        
        req.on('error', (error) => {
            console.log(`❌ 请求失败: ${error.message}`);
            resolve(false);
        });
        
        req.on('timeout', () => {
            console.log('❌ 请求超时');
            req.destroy();
            resolve(false);
        });
        
        req.end();
    });
}

// 主测试函数
async function main() {
    console.log('========================================');
    console.log('VPS API 测试工具');
    console.log('========================================');
    
    for (const config of TEST_CONFIGS) {
        const healthOk = await testApi(config.name, config.url, config.key);
        
        if (healthOk) {
            await testBackup(config.name, config.url, config.key);
        }
    }
    
    console.log('\n========================================');
    console.log('测试完成');
    console.log('========================================');
}

main().catch(console.error);
