require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = process.env.DB_PATH || path.join(dataDir, 'crm.db');
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');

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

CREATE TABLE IF NOT EXISTS system_auth (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_token TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_token ON auth_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_session_expires ON auth_sessions(expires_at);
`;

db.exec(initSql);

const defaultPassword = '198903';
const defaultPasswordHash = crypto.createHash('sha256').update(defaultPassword + 'crm_salt_2024').digest('hex');
const now = new Date().toISOString();

try {
    const existingPassword = db.prepare('SELECT id FROM system_auth WHERE id = 1').get();
    if (!existingPassword) {
        db.prepare(`
            INSERT INTO system_auth (id, password_hash, created_at, updated_at)
            VALUES (1, ?, ?, ?)
        `).run(defaultPasswordHash, now, now);
        console.log('默认密码已设置');
    }
} catch (e) {
    console.log('检查默认密码时出错:', e.message);
}

app.use(helmet());
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    message: { error: '请求过于频繁，请稍后再试' }
});
app.use('/api/', limiter);

const authenticateAPI = (req, res, next) => {
    let apiKey = req.headers['x-api-key'] || req.query.apiKey;
    
    if (!apiKey) {
        const authHeader = req.headers['authorization'] || '';
        if (authHeader.startsWith('Bearer ')) {
            apiKey = authHeader.substring(7);
        }
    }
    
    // 支持默认API key fallback，避免新部署或环境变量缺失时直接返回未授权
    const validApiKey = process.env.API_KEY || 'crm2024secretkey123';
    
    if (!apiKey || apiKey !== validApiKey) {
        return res.status(401).json({ 
            error: '无效的API密钥',
            code: 'INVALID_API_KEY'
        });
    }
    
    req.userId = req.headers['x-user-id'] || 'default_user';
    next();
};

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

function hashPassword(password) {
    return crypto.createHash('sha256').update(password + 'crm_salt_2024').digest('hex');
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function cleanExpiredSessions() {
    const stmt = db.prepare('DELETE FROM auth_sessions WHERE expires_at < ?');
    stmt.run(new Date().toISOString());
}

app.get('/api/auth/check', (req, res) => {
    try {
        const row = db.prepare('SELECT id FROM system_auth WHERE id = 1').get();
        res.json({
            success: true,
            hasPassword: !!row
        });
    } catch (error) {
        res.status(500).json({ error: '检查失败' });
    }
});

app.post('/api/auth/set-password', (req, res) => {
    try {
        const { password } = req.body;
        
        if (!password || password.length < 4) {
            return res.status(400).json({ 
                error: '密码至少需要4位',
                code: 'INVALID_PASSWORD'
            });
        }
        
        const existing = db.prepare('SELECT id FROM system_auth WHERE id = 1').get();
        if (existing) {
            return res.status(400).json({ 
                error: '密码已设置，请使用修改密码功能',
                code: 'PASSWORD_EXISTS'
            });
        }
        
        const passwordHash = hashPassword(password);
        const now = new Date().toISOString();
        
        db.prepare(`
            INSERT INTO system_auth (id, password_hash, created_at, updated_at)
            VALUES (1, ?, ?, ?)
        `).run(passwordHash, now, now);
        
        res.json({
            success: true,
            message: '密码设置成功'
        });
        
    } catch (error) {
        console.error('设置密码错误:', error);
        res.status(500).json({ error: '设置密码失败' });
    }
});

app.post('/api/auth/login', (req, res) => {
    try {
        cleanExpiredSessions();
        
        const { password } = req.body;
        
        if (!password) {
            return res.status(400).json({ 
                error: '请输入密码',
                code: 'MISSING_PASSWORD'
            });
        }
        
        const row = db.prepare('SELECT password_hash FROM system_auth WHERE id = 1').get();
        
        if (!row) {
            return res.status(400).json({ 
                error: '系统未初始化，请先设置密码',
                code: 'NOT_INITIALIZED'
            });
        }
        
        const inputHash = hashPassword(password);
        
        if (inputHash !== row.password_hash) {
            return res.status(401).json({ 
                error: '密码错误',
                code: 'INVALID_PASSWORD'
            });
        }
        
        const token = generateToken();
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        
        db.prepare(`
            INSERT INTO auth_sessions (session_token, expires_at)
            VALUES (?, ?)
        `).run(token, expiresAt.toISOString());
        
        res.json({
            success: true,
            token: token,
            expiresAt: expiresAt.toISOString()
        });
        
    } catch (error) {
        console.error('登录错误:', error);
        res.status(500).json({ error: '登录失败' });
    }
});

app.post('/api/auth/verify', (req, res) => {
    try {
        cleanExpiredSessions();
        
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({ 
                valid: false,
                error: '缺少token'
            });
        }
        
        const row = db.prepare(`
            SELECT expires_at FROM auth_sessions 
            WHERE session_token = ? AND expires_at > ?
        `).get(token, new Date().toISOString());
        
        res.json({
            valid: !!row
        });
        
    } catch (error) {
        console.error('验证错误:', error);
        res.status(500).json({ valid: false, error: '验证失败' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    try {
        const { token } = req.body;
        
        if (token) {
            db.prepare('DELETE FROM auth_sessions WHERE session_token = ?').run(token);
        }
        
        res.json({ success: true });
        
    } catch (error) {
        res.status(500).json({ error: '登出失败' });
    }
});

app.post('/api/auth/change-password', (req, res) => {
    try {
        const { oldPassword, newPassword, token } = req.body;
        
        if (!oldPassword || !newPassword) {
            return res.status(400).json({ 
                error: '请填写完整信息',
                code: 'MISSING_FIELDS'
            });
        }
        
        if (newPassword.length < 4) {
            return res.status(400).json({ 
                error: '新密码至少需要4位',
                code: 'INVALID_PASSWORD'
            });
        }
        
        const session = db.prepare(`
            SELECT id FROM auth_sessions 
            WHERE session_token = ? AND expires_at > ?
        `).get(token, new Date().toISOString());
        
        if (!session) {
            return res.status(401).json({ 
                error: '未登录或会话已过期',
                code: 'UNAUTHORIZED'
            });
        }
        
        const row = db.prepare('SELECT password_hash FROM system_auth WHERE id = 1').get();
        
        if (hashPassword(oldPassword) !== row.password_hash) {
            return res.status(401).json({ 
                error: '当前密码错误',
                code: 'INVALID_OLD_PASSWORD'
            });
        }
        
        const newHash = hashPassword(newPassword);
        const now = new Date().toISOString();
        
        db.prepare(`
            UPDATE system_auth 
            SET password_hash = ?, updated_at = ?
            WHERE id = 1
        `).run(newHash, now);
        
        res.json({
            success: true,
            message: '密码修改成功'
        });
        
    } catch (error) {
        console.error('修改密码错误:', error);
        res.status(500).json({ error: '修改密码失败' });
    }
});

app.post('/api/sync', authenticateAPI, (req, res) => {
    try {
        const { data, dataType = 'crm_records' } = req.body;
        
        if (!data) {
            return res.status(400).json({ 
                error: '缺少数据',
                code: 'MISSING_DATA'
            });
        }

        const dataJson = JSON.stringify(data);
        const now = new Date().toISOString();
        
        const stmt = db.prepare(`
            INSERT INTO crm_data (user_id, data_type, data_json, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, data_type) 
            DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at
        `);
        
        stmt.run(req.userId, dataType, dataJson, now);

        const logStmt = db.prepare(`
            INSERT INTO sync_log (user_id, action, record_count, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        `);
        
        const recordCount = Array.isArray(data) ? data.length : 1;
        logStmt.run(req.userId, 'upload', recordCount, req.ip, req.get('user-agent'));

        res.json({ 
            success: true, 
            message: '数据同步成功',
            recordCount,
            timestamp: now
        });
        
    } catch (error) {
        console.error('同步错误:', error);
        res.status(500).json({ 
            error: '数据同步失败',
            code: 'SYNC_ERROR',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

app.post('/api/sync-all', authenticateAPI, (req, res) => {
    try {
        const allData = req.body;
        
        if (!allData || typeof allData !== 'object') {
            return res.status(400).json({ 
                error: '缺少数据',
                code: 'MISSING_DATA'
            });
        }

        const now = new Date().toISOString();
        const dataJson = JSON.stringify(allData);
        
        const stmt = db.prepare(`
            INSERT INTO crm_data (user_id, data_type, data_json, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, data_type) 
            DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at
        `);
        
        stmt.run(req.userId, 'all_data', dataJson, now);

        const logStmt = db.prepare(`
            INSERT INTO sync_log (user_id, action, record_count, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        `);
        
        const recordCount = allData.orders ? allData.orders.length : 1;
        logStmt.run(req.userId, 'sync_all', recordCount, req.ip, req.get('user-agent'));

        res.json({ 
            success: true, 
            message: '数据同步成功',
            recordCount,
            timestamp: now
        });
        
    } catch (error) {
        console.error('同步错误:', error);
        res.status(500).json({ 
            error: '数据同步失败',
            code: 'SYNC_ERROR'
        });
    }
});

app.get('/api/backup', authenticateAPI, (req, res) => {
    try {
        const stmt = db.prepare(`
            SELECT data_json, updated_at 
            FROM crm_data 
            WHERE user_id = ? AND data_type = 'all_data'
        `);
        
        const row = stmt.get(req.userId);
        
        if (!row) {
            return res.status(404).json({ 
                error: '未找到备份数据',
                code: 'NOT_FOUND'
            });
        }

        const logStmt = db.prepare(`
            INSERT INTO sync_log (user_id, action, ip_address, user_agent)
            VALUES (?, ?, ?, ?)
        `);
        logStmt.run(req.userId, 'backup_restore', req.ip, req.get('user-agent'));

        res.json({
            success: true,
            data: JSON.parse(row.data_json),
            lastUpdated: row.updated_at,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('恢复错误:', error);
        res.status(500).json({ 
            error: '数据恢复失败',
            code: 'RESTORE_ERROR'
        });
    }
});

app.get('/api/restore', authenticateAPI, (req, res) => {
    try {
        const dataType = req.query.dataType || 'crm_records';
        
        const stmt = db.prepare(`
            SELECT data_json, updated_at 
            FROM crm_data 
            WHERE user_id = ? AND data_type = ?
        `);
        
        const row = stmt.get(req.userId, dataType);
        
        if (!row) {
            return res.status(404).json({ 
                error: '未找到数据',
                code: 'NOT_FOUND'
            });
        }

        const logStmt = db.prepare(`
            INSERT INTO sync_log (user_id, action, ip_address, user_agent)
            VALUES (?, ?, ?, ?)
        `);
        logStmt.run(req.userId, 'download', req.ip, req.get('user-agent'));

        res.json({
            success: true,
            data: JSON.parse(row.data_json),
            lastUpdated: row.updated_at,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('恢复错误:', error);
        res.status(500).json({ 
            error: '数据恢复失败',
            code: 'RESTORE_ERROR',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

app.get('/api/status', authenticateAPI, (req, res) => {
    try {
        const stmt = db.prepare(`
            SELECT data_type, updated_at, 
                   LENGTH(data_json) as size_bytes
            FROM crm_data 
            WHERE user_id = ?
        `);
        
        const rows = stmt.all(req.userId);
        
        res.json({
            success: true,
            dataTypes: rows.map(row => ({
                dataType: row.data_type,
                lastUpdated: row.updated_at,
                sizeBytes: row.size_bytes
            })),
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('状态查询错误:', error);
        res.status(500).json({ 
            error: '状态查询失败',
            code: 'STATUS_ERROR'
        });
    }
});

app.delete('/api/data', authenticateAPI, (req, res) => {
    try {
        const dataType = req.query.dataType || 'crm_records';
        
        const stmt = db.prepare(`
            DELETE FROM crm_data 
            WHERE user_id = ? AND data_type = ?
        `);
        
        const result = stmt.run(req.userId, dataType);
        
        res.json({
            success: true,
            message: '数据删除成功',
            deletedCount: result.changes
        });
        
    } catch (error) {
        console.error('删除错误:', error);
        res.status(500).json({ 
            error: '数据删除失败',
            code: 'DELETE_ERROR'
        });
    }
});

app.get('/api/tracking', (req, res) => {
    try {
        const stmt = db.prepare(`
            SELECT data_json, updated_at 
            FROM crm_data 
            WHERE user_id = ? AND data_type = 'all_data'
        `);
        
        const row = stmt.get('default_user');
        
        if (!row) {
            return res.json([]);
        }
        
        const allData = JSON.parse(row.data_json);
        const orders = allData.orders || [];
        
        const trackingData = orders
            .map(order => ({
                id: order.id,
                orderno: order.orderno,
                clientOrderNo: order.clientOrderNo,
                mbl: order.mbl,
                hbl: order.hbl,
                shipMode: order.shipMode,
                pol: order.pol,
                pod: order.pod,
                recvaddr: order.recvaddr,
                goods: order.goods,
                billWeight: order.billWeight || (order.fees && order.fees.billWeight),
                cbm: order.cbm,
                ctype: order.ctype,
                cqty: order.cqty,
                status: order.status,
                etd: order.etd,
                eta: order.eta,
                ata: order.ata,
                signed: order.signed,
                warehouse: order.warehouse,
                flight: order.flight,
                airSigned: order.airSigned,
                airAta: order.airAta,
                airClearedDate: order.airClearedDate,
                airBookedDate: order.airBookedDate,
                tracking: order.tracking,
                carrierType: order.carrierType,
                bookedDate: order.bookedDate,
                loadedDate: order.loadedDate,
                clearedDate: order.clearedDate,
                pickup: order.pickup,
                deliveryDate: order.deliveryDate,
                statusHistory: order.statusHistory,
                createdAt: order.createdAt,
                updatedAt: order.updatedAt
            }));
        
        res.json(trackingData);
        
    } catch (error) {
        console.error('Tracking查询错误:', error);
        res.status(500).json({ 
            error: '查询失败',
            code: 'TRACKING_ERROR'
        });
    }
});

app.use((err, req, res, next) => {
    console.error('服务器错误:', err);
    res.status(500).json({ 
        error: '服务器内部错误',
        code: 'INTERNAL_ERROR'
    });
});

process.on('SIGINT', () => {
    console.log('\n正在关闭数据库连接...');
    db.close();
    process.exit(0);
});

app.listen(PORT, () => {
    console.log(`🚀 CRM API服务器运行在端口 ${PORT}`);
    console.log(`📊 数据库路径: ${dbPath}`);
    console.log(`🔒 API密钥已配置: ${process.env.API_KEY ? '是' : '否'}`);
});

module.exports = app;
