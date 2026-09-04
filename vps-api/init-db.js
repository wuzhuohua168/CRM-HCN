require('dotenv').config();
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = process.env.DB_PATH || path.join(dataDir, 'crm.db');
const db = new Database(dbPath);

console.log('🔧 初始化数据库...');

const initSql = `
CREATE TABLE IF NOT EXISTS crm_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    data_type TEXT NOT NULL DEFAULT 'crm_records',
    data_json TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, data_type)
);

CREATE INDEX IF NOT EXISTS idx_user_id ON crm_data(user_id);
CREATE INDEX IF NOT EXISTS idx_data_type ON crm_data(data_type);
CREATE INDEX IF NOT EXISTS idx_updated_at ON crm_data(updated_at);

CREATE TABLE IF NOT EXISTS sync_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    record_count INTEGER DEFAULT 0,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sync_log_user ON sync_log(user_id);
CREATE INDEX IF NOT EXISTS idx_sync_log_created ON sync_log(created_at);
`;

try {
    db.exec(initSql);
    console.log('✅ 数据库表创建成功');
    
    const tables = db.prepare(`
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name NOT LIKE 'sqlite_%'
    `).all();
    
    console.log('\n📋 已创建的表:');
    tables.forEach(table => {
        console.log(`   - ${table.name}`);
    });
    
    console.log('\n✨ 数据库初始化完成！');
    console.log(`📍 数据库位置: ${dbPath}`);
    
} catch (error) {
    console.error('❌ 数据库初始化失败:', error);
    process.exit(1);
} finally {
    db.close();
}
