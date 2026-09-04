const PASSWORD_KEY = 'crm_system_password_hash';
    const SESSION_KEY = 'crm_system_session';
    const AUTH_TOKEN_KEY = 'crm_auth_token';
    const LOCK_TIMEOUT = 8 * 60 * 60 * 1000;
    const SESSION_ACTIVITY_SYNC_MS = 15000;
    let lastActivityTime = Date.now();
    let lastSessionSyncTime = 0;
    let modulesInitialized = false;
    let dashboardNowTimer = null;
    let autoBackupTimer = null;
    let vpsHasPassword = null;

    function simpleHash(str){
        let hash = 0;
        for(let i = 0; i < str.length; i++){
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString(16);
    }

    function getAuthToken() {
        return localStorage.getItem(AUTH_TOKEN_KEY);
    }

    function setAuthToken(token) {
        localStorage.setItem(AUTH_TOKEN_KEY, token);
    }

    function clearAuthToken() {
        localStorage.removeItem(AUTH_TOKEN_KEY);
    }

    function getAuthApiUrl() {
        const customAuthUrl = localStorage.getItem('crm_auth_api_url');
        if (customAuthUrl) return customAuthUrl;
        return 'http://107.173.7.180:3000';
    }

    function saveLocalPasswordHash(password) {
        if (!password) return;
        try {
            localStorage.setItem(PASSWORD_KEY, simpleHash(password));
        } catch (e) {}
    }

    async function checkVpsHasPassword() {
        const apiUrl = getAuthApiUrl();
        if (!apiUrl) {
            return { hasPassword: localStorage.getItem(PASSWORD_KEY) !== null, useLocal: true };
        }
        
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);
            
            const response = await fetch(apiUrl + '/api/auth/check', {
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                return { hasPassword: localStorage.getItem(PASSWORD_KEY) !== null, useLocal: true };
            }
            
            const result = await response.json();
            vpsHasPassword = result.hasPassword;
            return { hasPassword: result.hasPassword, useLocal: false };
        } catch (error) {
            console.error('检查VPS密码状态失败:', error);
            return { hasPassword: localStorage.getItem(PASSWORD_KEY) !== null, useLocal: true, error: true };
        }
    }

    function hasPassword(){
        if (vpsHasPassword !== null) return vpsHasPassword;
        return localStorage.getItem(PASSWORD_KEY) !== null;
    }

    function getSessionData(){
        const session = sessionStorage.getItem(SESSION_KEY);
        if(!session) return null;
        try {
            const data = JSON.parse(session);
            return data && typeof data === 'object' ? data : null;
        } catch(e) {
            return null;
        }
    }

    function checkSession(){
        return !!getSessionData();
    }

    function createSession(activeAt = Date.now()){
        const payload = {
            timestamp: activeAt,
            activeAt
        };
        sessionStorage.setItem(SESSION_KEY, JSON.stringify(payload));
        lastSessionSyncTime = activeAt;
    }

    function syncSessionActivity(force = false){
        const now = Date.now();
        if (!checkSession()) {
            createSession(now);
            return;
        }
        if (!force && now - lastSessionSyncTime < SESSION_ACTIVITY_SYNC_MS) return;
        createSession(now);
    }

    function isSessionExpired(sessionData = getSessionData()){
        if (!sessionData) return false;
        const lastActiveAt = Number(sessionData.activeAt || sessionData.timestamp || 0);
        if (!lastActiveAt) return false;
        return Date.now() - lastActiveAt > LOCK_TIMEOUT;
    }

    function clearSession(){
        sessionStorage.removeItem(SESSION_KEY);
    }

    function ensureSession(){
        if (!checkSession()) {
            createSession();
        }
    }

    function showLoginForm(){
        document.getElementById('login-screen').classList.remove('hidden');
        document.getElementById('login-form').style.display = 'block';
        document.getElementById('set-password-form').style.display = 'none';
        document.getElementById('login-password').value = '';
        document.getElementById('login-error').style.display = 'none';
        document.body.classList.add('locked');
    }

    function showSetPasswordForm(){
        document.getElementById('login-screen').classList.remove('hidden');
        document.getElementById('login-form').style.display = 'none';
        document.getElementById('set-password-form').style.display = 'block';
        document.getElementById('new-password').value = '';
        document.getElementById('confirm-password').value = '';
        document.getElementById('set-pwd-error').style.display = 'none';
        document.body.classList.add('locked');
    }

    function hideLoginScreen(){
        document.getElementById('login-screen').classList.add('hidden');
        document.body.classList.remove('locked');
    }

    async function handleLogin(){
        const password = document.getElementById('login-password').value;
        const apiUrl = getAuthApiUrl();
        
        if (apiUrl) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 10000);
                
                const response = await fetch(apiUrl + '/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password }),
                    signal: controller.signal
                });
                clearTimeout(timeoutId);
                
                if (!response.ok) {
                    const storedHash = localStorage.getItem(PASSWORD_KEY);
                    const inputHash = simpleHash(password);
                    
                    if(inputHash === storedHash){
                        createSession();
                        hideLoginScreen();
                        await ensureModulesInitialized();
                    } else {
                        document.getElementById('login-error').textContent = '密码错误，请重试';
                        document.getElementById('login-error').style.display = 'block';
                        document.getElementById('login-password').value = '';
                        document.getElementById('login-password').focus();
                    }
                    document.getElementById('login-error').textContent = response.status === 404 ? '认证接口不存在，已尝试本地密码' : '认证接口不可用，已尝试本地密码';
                    return;
                }
                
                const result = await response.json();
                
                if (result.success) {
                    saveLocalPasswordHash(password);
                    setAuthToken(result.token);
                    createSession();
                    hideLoginScreen();
                    await ensureModulesInitialized();
                } else if (result.code === 'NOT_INITIALIZED') {
                    showSetPasswordForm();
                } else {
                    document.getElementById('login-error').textContent = result.error || '密码错误';
                    document.getElementById('login-error').style.display = 'block';
                    document.getElementById('login-password').value = '';
                    document.getElementById('login-password').focus();
                }
            } catch (error) {
                console.error('登录失败:', error);
                const storedHash = localStorage.getItem(PASSWORD_KEY);
                const inputHash = simpleHash(password);
                
                if(inputHash === storedHash){
                    createSession();
                    hideLoginScreen();
                    await ensureModulesInitialized();
                } else {
                    document.getElementById('login-error').textContent = '连接服务器失败，请检查网络或使用本地密码';
                    document.getElementById('login-error').style.display = 'block';
                }
            }
        } else {
            const storedHash = localStorage.getItem(PASSWORD_KEY);
            const inputHash = simpleHash(password);
            
            if(inputHash === storedHash){
                createSession();
                hideLoginScreen();
                await ensureModulesInitialized();
            } else {
                document.getElementById('login-error').textContent = '密码错误，请重试';
                document.getElementById('login-error').style.display = 'block';
                document.getElementById('login-password').value = '';
                document.getElementById('login-password').focus();
            }
        }
    }

    async function setNewPassword(){
        const newPwd = document.getElementById('new-password').value;
        const confirmPwd = document.getElementById('confirm-password').value;
        
        if(newPwd.length < 4 || newPwd !== confirmPwd){
            document.getElementById('set-pwd-error').style.display = 'block';
            return;
        }
        
        const apiUrl = getAuthApiUrl();
        
        if (apiUrl) {
            try {
                const response = await fetch(apiUrl + '/api/auth/set-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: newPwd })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    vpsHasPassword = true;
                    saveLocalPasswordHash(newPwd);
                    createSession();
                    hideLoginScreen();
                    await ensureModulesInitialized();
                    showToast('密码设置成功');
                } else {
                    document.getElementById('set-pwd-error').textContent = result.error || '设置失败';
                    document.getElementById('set-pwd-error').style.display = 'block';
                }
            } catch (error) {
                console.error('设置密码失败:', error);
                document.getElementById('set-pwd-error').textContent = '连接服务器失败';
                document.getElementById('set-pwd-error').style.display = 'block';
            }
        } else {
            saveLocalPasswordHash(newPwd);
            createSession();
            hideLoginScreen();
            await ensureModulesInitialized();
            showToast('密码设置成功');
        }
    }

    function lockSystem(){
        clearSession();
        clearAuthToken();
        showLoginForm();
    }

    async function changePassword(){
        const oldPwd = document.getElementById('change-old-pwd').value;
        const newPwd = document.getElementById('change-new-pwd').value;
        const confirmPwd = document.getElementById('change-confirm-pwd').value;
        const errorEl = document.getElementById('change-pwd-error');
        
        if(newPwd.length < 4){
            errorEl.textContent = '新密码至少需要4位';
            errorEl.style.display = 'block';
            return;
        }
        
        if(newPwd !== confirmPwd){
            errorEl.textContent = '两次输入的新密码不一致';
            errorEl.style.display = 'block';
            return;
        }
        
        const apiUrl = getAuthApiUrl();
        
        if (apiUrl) {
            try {
                const token = getAuthToken();
                const response = await fetch(apiUrl + '/api/auth/change-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        oldPassword: oldPwd, 
                        newPassword: newPwd,
                        token: token
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    saveLocalPasswordHash(newPwd);
                    document.getElementById('change-old-pwd').value = '';
                    document.getElementById('change-new-pwd').value = '';
                    document.getElementById('change-confirm-pwd').value = '';
                    errorEl.style.display = 'none';
                    showToast('密码修改成功');
                } else {
                    errorEl.textContent = result.error || '修改失败';
                    errorEl.style.display = 'block';
                }
            } catch (error) {
                console.error('修改密码失败:', error);
                errorEl.textContent = '连接服务器失败';
                errorEl.style.display = 'block';
            }
        } else {
            const storedHash = localStorage.getItem(PASSWORD_KEY);
            const oldHash = simpleHash(oldPwd);
            
            if(oldHash !== storedHash){
                errorEl.textContent = '当前密码错误';
                errorEl.style.display = 'block';
                return;
            }
            
            saveLocalPasswordHash(newPwd);
            
            document.getElementById('change-old-pwd').value = '';
            document.getElementById('change-new-pwd').value = '';
            document.getElementById('change-confirm-pwd').value = '';
            errorEl.style.display = 'none';
            
            showToast('密码修改成功');
        }
    }

    function updateActivity(){
        lastActivityTime = Date.now();
        ensureSession();
        syncSessionActivity();
    }

    function checkAutoLock(){
        if(!hasPassword()) return;
        const sessionData = getSessionData();
        if (!sessionData) {
            ensureSession();
            return;
        }
        if (Date.now() - lastActivityTime > LOCK_TIMEOUT && isSessionExpired(sessionData)) {
            lockSystem();
        }
    }

    document.addEventListener('click', updateActivity);
    document.addEventListener('keydown', updateActivity);
    document.addEventListener('mousemove', updateActivity);
    document.addEventListener('touchstart', updateActivity);

    setInterval(() => {
        const sessionData = getSessionData();
        if(hasPassword() && sessionData && Date.now() - lastActivityTime > LOCK_TIMEOUT && isSessionExpired(sessionData)){
            lockSystem();
        }
    }, 60000);

    document.addEventListener('visibilitychange', () => {
        if(document.visibilityState === 'visible'){
            updateActivity();
            checkAutoLock();
        }
    });

    async function initAuth(){
        const apiUrl = getAuthApiUrl();
        
        if (!apiUrl) {
            const localHasPwd = localStorage.getItem(PASSWORD_KEY) !== null;
            if(!localHasPwd){
                showSetPasswordForm();
            } else if(checkSession()){
                hideLoginScreen();
                lastActivityTime = Date.now();
                syncSessionActivity(true);
                await ensureModulesInitialized();
            } else {
                showLoginForm();
            }
            return;
        }
        
        let result;
        try {
            result = await checkVpsHasPassword();
        } catch (e) {
            result = { hasPassword: false, useLocal: true, error: true };
        }
        
        if (result.error) {
            const localHasPwd = localStorage.getItem(PASSWORD_KEY) !== null;
            if (!localHasPwd) {
                showSetPasswordForm();
            } else if (checkSession()) {
                hideLoginScreen();
                lastActivityTime = Date.now();
                syncSessionActivity(true);
                await ensureModulesInitialized();
            } else {
                showLoginForm();
            }
            return;
        }
        
        if (!result.hasPassword) {
            showSetPasswordForm();
        } else if(checkSession()){
            hideLoginScreen();
            lastActivityTime = Date.now();
            syncSessionActivity(true);
            await ensureModulesInitialized();
        } else {
            showLoginForm();
        }
    }

    let currDate = new Date(), rates = {}, memos = JSON.parse(localStorage.getItem('hcn_calendar_memos') || '{}');
    let selectedCountry = 'JP';
    let trendDays = 30;
    let trendPoints = [];
    const APP_STATE_KEY = 'logistics_workbench_state_v1';
    const APP_DB_NAME = 'logistics_workbench_db';
    const APP_DB_STORE = 'kv';
    const APP_EXTRA_STORAGE_KEYS = ['hcn_calendar_memos','hcn_rates_cache','shipment_notes_v1','dashboard_todos_v1','freight_air_cache_v1','freight_fcl_cache_v1','hgcd_crm_fcl_v1','macro_manual_overrides','macro_consistency_history','macro_ui_state','macro_score_state','macro_alloc_state','macro_cache_last','logistics_client_data','logistics_supplier_data','logistics_reminder_data','logistics_reconciliation_data','logistics_freight_data','cloudflare_api_url','cloudflare_api_key','crm_auto_sync','crm_sync_other','crm_api_configs','crm_current_api_id'];
    let saveTimer = null;
    let cloudFileHandle = null;
    let lastSavedAt = '';
    let homeQuoteObserver = null;

    const HOME_QUOTE_SYMBOLS = [
        { label: '布伦特原油', symbol: 'TVC:UKOIL' },
        { label: 'WTI原油', symbol: 'TVC:USOIL' },
        { label: '股油比', symbol: 'SP500/WTI' },
        { label: '铜油比', symbol: 'COPPER/WTI' },
        { label: '金油比', symbol: 'XAUUSD/WTI' },
        { label: 'VIX', symbol: 'VIX' },
        { label: 'HY利差', symbol: 'BAMLH0A0HYM2' },
        { label: '通胀预期', symbol: 'FRED:T5YIE' }
    ];


    function openAppDb() {
        return new Promise((resolve, reject) => {
            if (!window.indexedDB) {
                resolve(null);
                return;
            }
            const request = indexedDB.open(APP_DB_NAME, 1);
            request.onupgradeneeded = () => {
                const db = request.result;
                if (!db.objectStoreNames.contains(APP_DB_STORE)) db.createObjectStore(APP_DB_STORE);
            };
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async function idbSet(key, value) {
        const db = await openAppDb();
        if (!db) return;
        await new Promise((resolve, reject) => {
            const tx = db.transaction(APP_DB_STORE, 'readwrite');
            tx.objectStore(APP_DB_STORE).put(value, key);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
            tx.onabort = () => reject(tx.error);
        });
        db.close();
    }

    async function idbGet(key) {
        const db = await openAppDb();
        if (!db) return null;
        const value = await new Promise((resolve, reject) => {
            const tx = db.transaction(APP_DB_STORE, 'readonly');
            const req = tx.objectStore(APP_DB_STORE).get(key);
            req.onsuccess = () => resolve(req.result ?? null);
            req.onerror = () => reject(req.error);
        }).catch(() => null);
        db.close();
        return value;
    }

    async function idbDelete(key) {
        const db = await openAppDb();
        if (!db) return;
        await new Promise((resolve, reject) => {
            const tx = db.transaction(APP_DB_STORE, 'readwrite');
            tx.objectStore(APP_DB_STORE).delete(key);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
            tx.onabort = () => reject(tx.error);
        }).catch(() => null);
        db.close();
    }

    function clearSensitiveLocalCache() {
        const keys = [APP_STATE_KEY, ...APP_EXTRA_STORAGE_KEYS];
        keys.forEach(key => localStorage.removeItem(key));
        memos = {};
        lastSavedAt = '';
    }

    async function purgePersistedAppState() {
        clearSensitiveLocalCache();
        await idbDelete(APP_STATE_KEY);
    }

    function gatherExtraStorageState() {
        const extras = {};
        APP_EXTRA_STORAGE_KEYS.forEach(key => {
            const value = localStorage.getItem(key);
            if (value !== null) extras[key] = value;
        });
        return extras;
    }

    function restoreExtraStorageState(extras) {
        if (!extras || typeof extras !== 'object') return;
        Object.entries(extras).forEach(([key, value]) => {
            if (typeof value === 'string') localStorage.setItem(key, value);
        });
    }

    const HOME_QUOTE_TV_SYMBOL_MAP = {
        'TVC:UKOIL': 'TVC:UKOIL',
        'TVC:USOIL': 'TVC:USOIL',
        'SP500/WTI': 'SP500/WTI',
        'COPPER/WTI': 'COPPER/WTI',
        'XAUUSD/WTI': 'XAUUSD/WTI',
        'VIX': 'VIX',
        'BAMLH0A0HYM2': 'BAMLH0A0HYM2',
        'FRED:T5YIE': 'FRED:T5YIE'
    };

    const TRUCK_DATA = [
        { model: '面包车', size: '1.8 × 1.3 × 1.2 m', volume: '约 2-3 m3', weight: '约 0.5 吨', usage: '同城小件、急件、样品件' },
        { model: '依维柯 / 小型厢车', size: '2.5 × 1.5 × 1.5 m', volume: '约 5-6 m3', weight: '约 1 吨', usage: '城市配送、小批量门店补货' },
        { model: '2.7米厢车', size: '2.7 × 1.5 × 1.7 m', volume: '约 6-7 m3', weight: '约 1 吨', usage: '短途配送、家电百货' },
        { model: '3.3米厢车', size: '3.3 × 1.7 × 1.7 m', volume: '约 9-10 m3', weight: '约 1.5 吨', usage: '同城配送、小型搬运' },
        { model: '3.8米厢车', size: '3.8 × 1.8 × 1.8 m', volume: '约 12-13 m3', weight: '约 1.5-2 吨', usage: '中短途配送、零担拼货' },
        { model: '4.2米厢车', size: '4.2 × 1.9 × 1.9 m', volume: '约 15 m3', weight: '约 1.5-2 吨', usage: '城市配送、电商件、小批量零担' },
        { model: '5.2米厢车', size: '5.2 × 2.1 × 2.1 m', volume: '约 22-24 m3', weight: '约 3-5 吨', usage: '中短途零担、工厂配送' },
        { model: '6.8米高栏/厢车', size: '6.8 × 2.3 × 2.4 m', volume: '约 35-38 m3', weight: '约 8-10 吨', usage: '专线常用、中型普货' },
        { model: '7.6米高栏/厢车', size: '7.6 × 2.3 × 2.5 m', volume: '约 43-45 m3', weight: '约 8-12 吨', usage: '中长途普货、轻泡货' },
        { model: '8.7米高栏/厢车', size: '8.7 × 2.35 × 2.5 m', volume: '约 50-55 m3', weight: '约 10-15 吨', usage: '区域干线、整车运输' },
        { model: '9.6米高栏/厢车', size: '9.6 × 2.35 × 2.5 m', volume: '约 56-60 m3', weight: '约 12-18 吨', usage: '干线运输、重泡货兼顾' },
        { model: '13米半挂', size: '13.0 × 2.4 × 2.6 m', volume: '约 80-85 m3', weight: '约 30-32 吨', usage: '长途干线、大票普货' },
        { model: '17.5米大板', size: '17.5 × 2.8 × 3.0 m', volume: '约 130-140 m3', weight: '约 28-32 吨', usage: '轻泡货、大件货、超长货' }
    ];

    const JP_TRUCK_DATA = [
        { model: '轻四轮 Van', size: '1.8 × 1.3 × 1.2 m', volume: '约 2-3 m3', weight: '约 0.35 吨', usage: '市内急送、小件配送' },
        { model: '1T Van', size: '2.2 × 1.5 × 1.3 m', volume: '约 4-5 m3', weight: '约 1 吨', usage: '门店补货、小批量配送' },
        { model: '2T 平车/厢车', size: '3.1 × 1.6 × 1.7 m', volume: '约 8 m3', weight: '约 1.5 吨', usage: '尾端派送、家具家电' },
        { model: '3T 厢车', size: '4.2 × 1.8 × 1.9 m', volume: '约 12-14 m3', weight: '约 2-3 吨', usage: '区域配送、中小批量货物' },
        { model: '4T 平车/厢车', size: '6.2 × 2.1 × 2.2 m', volume: '约 15 m3', weight: '约 3 吨', usage: '日本尾端干线衔接、常规普货' },
        { model: '6T 厢车', size: '6.5 × 2.2 × 2.3 m', volume: '约 20-24 m3', weight: '约 6 吨', usage: '中距干线、整托运输' },
        { model: '10T 大型车', size: '9.6 × 2.35 × 2.6 m', volume: '约 30 m3', weight: '约 8.9 吨', usage: '长途干线、大批量整车' },
        { model: '13T Wing 车', size: '9.6 × 2.4 × 2.6 m', volume: '约 30-32 m3', weight: '约 13 吨', usage: '托盘货、装卸效率优先' }
    ];

    const KR_TRUCK_DATA = [
        { model: '1T Truck', size: '2.8 × 1.6 × 1.6 m', volume: '约 7 m3', weight: '约 1 吨', usage: '市内配送、小型商业补货' },
        { model: '1.4T Truck', size: '3.1 × 1.7 × 1.7 m', volume: '约 9 m3', weight: '约 1.4 吨', usage: '短途配送、建材零担' },
        { model: '2.5T Truck', size: '4.3 × 2.0 × 2.0 m', volume: '约 17 m3', weight: '约 2.5 吨', usage: '区域配送、中小批量货物' },
        { model: '3.5T Truck', size: '4.8 × 2.1 × 2.1 m', volume: '约 21 m3', weight: '约 3.5 吨', usage: '城市到区域中转' },
        { model: '5T Truck', size: '6.2 × 2.3 × 2.3 m', volume: '约 32 m3', weight: '约 5 吨', usage: '干线普货、托盘货' },
        { model: '8T Truck', size: '8.5 × 2.35 × 2.4 m', volume: '约 48 m3', weight: '约 8 吨', usage: '长途干线、大宗货物' },
        { model: '11T Wing Body', size: '9.6 × 2.4 × 2.5 m', volume: '约 57 m3', weight: '约 11 吨', usage: '托盘货、快速装卸' }
    ];

    const SG_TRUCK_DATA = [
        { model: '10ft Lorry', size: '3.1 × 1.55 × 1.9 m', volume: '约 5.6-8.5 m3', weight: '约 1-1.5 吨', usage: '最后一公里、住宅配送' },
        { model: '14ft Lorry', size: '4.26 × 1.9 × 2.1 m', volume: '约 11.3-14.2 m3', weight: '约 2-3 吨', usage: '商业配送、搬家、门店补货' },
        { model: '24ft Lorry', size: '7.4 × 2.4 × 2.3 m', volume: '约 19.8-25.5 m3', weight: '约 4-9 吨', usage: '仓到仓、大宗工业货物' },
        { model: '10ft Tailgate Truck', size: '3.1 × 1.55 × 1.9 m', volume: '约 6-8 m3', weight: '约 1 吨', usage: '需要尾板的市区配送' },
        { model: '14ft Box Truck', size: '4.26 × 1.9 × 2.1 m', volume: '约 12-15 m3', weight: '约 3 吨', usage: '带箱防雨配送、零售补货' }
    ];

    const US_TRUCK_DATA = [
        { model: 'Cargo Van', size: '3.0 × 1.7 × 1.7 m', volume: '约 8-10 m3', weight: '约 0.7-1.5 吨', usage: '同城配送、快件、工具车' },
        { model: '16ft Box Truck', size: '4.9 × 2.44 × 2.29 m', volume: '约 27 m3 / 960 cu ft', weight: '约 3.4 吨 / 7,500 lbs', usage: '中小搬家、商业配送' },
        { model: '20ft Box Truck', size: '6.1 × 2.5 × 2.5 m', volume: '约 43-46 m3 / 1,500-1,600 cu ft', weight: '约 4.5 吨 / 10,000 lbs', usage: '中型搬家、区域配送' },
        { model: '24ft Box Truck', size: '7.3 × 2.59 × 2.59 m', volume: '约 42-48 m3 / 1,500-1,700 cu ft', weight: '约 4.5 吨 / 10,000 lbs', usage: '仓配、重货搬运' },
        { model: '26ft Box Truck', size: '7.9 × 2.59 × 2.59 m', volume: '约 48-51 m3 / 1,700-1,800 cu ft', weight: '约 4.5 吨 / 10,000 lbs', usage: '大型搬家、区域干线' },
        { model: '53ft Trailer', size: '16.15 × 2.59 × 2.8 m', volume: '约 90-100 m3 / 3,200-3,500 cu ft', weight: '约 20-22 吨', usage: '长途整车、干线运输' }
    ];

    const SHIPPING_DATA = [
        {
            name: '地中海航运 / MSC / Mediterranean Shipping Company',
            country: '瑞士',
            background: 'Aponte 家族控制的全球班轮集团',
            feature: '全球舱位体量大，航线覆盖广，适合常规大宗订舱',
            freeTime: '干柜常见 5-10 天，部分航线可谈到 10-14 天'
        },
        {
            name: '马士基 / Maersk / A.P. Moller - Maersk',
            country: '丹麦',
            background: 'A.P. Moller 集团体系，母集团为 A.P. Moller Holding',
            feature: '服务体系成熟，数字化和可视化较强',
            freeTime: '干柜常见 5-7 天，优质客户或指定项目可延长'
        },
        {
            name: '达飞轮船 / CMA CGM / CMA CGM Group',
            country: '法国',
            background: 'Saadé 家族控制的班轮集团',
            feature: '欧美、地中海、非洲等航线布局强',
            freeTime: '干柜常见 5-10 天，个别市场可更长'
        },
        {
            name: '中远海运 / COSCO Shipping Lines',
            country: '中国',
            background: '中国远洋海运集团体系',
            feature: '中国出运资源强，亚洲及美线布局成熟',
            freeTime: '干柜常见 7-10 天，协议客户有时可争取更长'
        },
        {
            name: '东方海外 / OOCL / Orient Overseas Container Line',
            country: '中国香港',
            background: '东方海外（国际）及中远海运体系',
            feature: '系统成熟，亚洲和跨太平洋线较常见',
            freeTime: '干柜常见 7-10 天'
        },
        {
            name: '海洋网联船务 / ONE / Ocean Network Express',
            country: '总部新加坡，日本背景',
            background: '股东为 NYK、MOL、K Line',
            feature: '日本相关航线和跨太平洋航线配载常见',
            freeTime: '干柜常见 5-7 天，日本相关线和协议客户可到 7-10 天'
        },
        {
            name: '赫伯罗特 / Hapag-Lloyd / Hapag-Lloyd AG',
            country: '德国',
            background: '德国班轮公司，长期有 Kühne Maritime 等资本支持',
            feature: '欧洲、跨大西洋和部分美线稳定',
            freeTime: '干柜常见 5-7 天，部分项目可延长'
        },
        {
            name: '长荣海运 / Evergreen / Evergreen Marine Corporation',
            country: '中国台湾',
            background: '长荣集团体系',
            feature: '亚洲和美线活跃，价格和舱位较有竞争力',
            freeTime: '干柜常见 7-10 天，旺季和紧张港口会收紧'
        },
        {
            name: '现代商船 / HMM / HMM Co., Ltd.',
            country: '韩国',
            background: '长期由韩国产业银行等政策性资本支持',
            feature: '韩系主力班轮公司，东北亚和美线有一定优势',
            freeTime: '干柜常见 7-10 天，东北亚区域有时较灵活'
        },
        {
            name: '太平船务 / PIL / Pacific International Lines',
            country: '新加坡',
            background: '新加坡老牌航运集团',
            feature: '东南亚、南亚、中东、非洲等航线布局常见',
            freeTime: '东南亚区域常见 7-14 天'
        },
        {
            name: '美森轮船 / Matson / Matson, Inc.',
            country: '美国',
            background: '美国上市航运物流集团，运营主体 Matson Navigation Company',
            feature: '美线时效型代表船司之一',
            freeTime: '美线快船和美西港口多见 3-7 天'
        },
        {
            name: '以星航运 / ZIM / ZIM Integrated Shipping Services',
            country: '以色列',
            background: '以色列班轮公司，纽交所上市',
            feature: '灵活度较高，部分航线速度有优势',
            freeTime: '干柜常见 5-7 天，快线产品通常更短'
        }
    ];

    const PORT_CODE_DATA = [
        { code: 'PVG', type: '机场', name: '上海浦东国际机场', country: '中国' },
        { code: 'SHA', type: '机场', name: '上海虹桥国际机场', country: '中国' },
        { code: 'CAN', type: '机场', name: '广州白云国际机场', country: '中国' },
        { code: 'SZX', type: '机场', name: '深圳宝安国际机场', country: '中国' },
        { code: 'NRT', type: '机场', name: '东京成田国际机场', country: '日本' },
        { code: 'HND', type: '机场', name: '东京羽田机场', country: '日本' },
        { code: 'KIX', type: '机场', name: '大阪关西国际机场', country: '日本' },
        { code: 'ICN', type: '机场', name: '仁川国际机场', country: '韩国' },
        { code: 'GMP', type: '机场', name: '金浦国际机场', country: '韩国' },
        { code: 'SIN', type: '机场', name: '新加坡樟宜机场', country: '新加坡' },
        { code: 'LAX', type: '机场', name: '洛杉矶国际机场', country: '美国' },
        { code: 'JFK', type: '机场', name: '纽约肯尼迪国际机场', country: '美国' },
        { code: 'ORD', type: '机场', name: '芝加哥奥黑尔国际机场', country: '美国' },
        { code: 'CNSHA', type: '港口', name: '上海港', country: '中国' },
        { code: 'CNNGB', type: '港口', name: '宁波港', country: '中国' },
        { code: 'CNSZX', type: '港口', name: '深圳港', country: '中国' },
        { code: 'JPTYO', type: '港口', name: '东京港', country: '日本' },
        { code: 'JPUKB', type: '港口', name: '神户港', country: '日本' },
        { code: 'KRINC', type: '港口', name: '仁川港', country: '韩国' },
        { code: 'KRPUS', type: '港口', name: '釜山港', country: '韩国' },
        { code: 'SGSIN', type: '港口', name: '新加坡港', country: '新加坡' },
        { code: 'USLAX', type: '港口', name: '洛杉矶港', country: '美国' },
        { code: 'USLGB', type: '港口', name: '长滩港', country: '美国' },
        { code: 'USNYC', type: '港口', name: '纽约/新泽西港', country: '美国' }
    ];

    const INCOTERM_DATA = [
        { term: 'EXW', owner: '买方负责提货后绝大部分费用和风险', note: '卖方只负责备货，最偏卖方术语' },
        { term: 'FOB', owner: '卖方负责出口清关并装上船，海运后买方负责', note: '海运最常见，适合整柜/散货出口' },
        { term: 'CIF', owner: '卖方负责海运和保险到目的港，进口后买方负责', note: '海运常见，但目的港费用通常不含' },
        { term: 'DAP', owner: '卖方负责运输到指定地点，进口税费通常买方负责', note: '适合门到门但不包税' },
        { term: 'DDP', owner: '卖方负责运输、清关和税费直到交货', note: '最偏买方体验，但卖方责任最重' }
    ];

    const SENSITIVE_CARGO_RULES = {
        '带电池': {
            docs: ['MSDS', 'UN38.3', '电池规格书'],
            risks: ['确认电池类型（内置/配套/纯电）', '确认是否需要危包或特殊标签']
        },
        '液体': {
            docs: ['MSDS', '成分说明', '运输鉴定或非危声明（视品类）'],
            risks: ['确认是否易燃、腐蚀', '注意包装防漏和航空限制']
        },
        '粉末': {
            docs: ['MSDS', '成分说明', '运输鉴定（视渠道）'],
            risks: ['粉末类容易触发额外安检', '需确认是否涉及化工品或食品类监管']
        },
        '磁性': {
            docs: ['磁检报告'],
            risks: ['空运前通常要确认磁性是否超标', '包装方式会影响检测结果']
        },
        '食品': {
            docs: ['成分表', '标签信息', '原产地/卫生类资料（按国家要求）'],
            risks: ['确认目的国准入和标签规范', '注意保质期和温控需求']
        },
        '化妆品': {
            docs: ['成分表', 'MSDS（部分渠道）', '品牌/备案资料（按国家要求）'],
            risks: ['注意液体、膏体、酒精含量', '目的国可能要求备案或标签审核']
        },
        '木制品': {
            docs: ['熏蒸证明（如适用）', '材质说明'],
            risks: ['确认是否为实木/原木', '部分国家对木质包装和木制成品要求严格']
        },
        '品牌货': {
            docs: ['品牌授权书', '采购凭证/销售链路证明'],
            risks: ['注意知识产权和海关扣货风险', '渠道不同对品牌审核要求差异大']
        }
    };

    const SENSITIVE_KEYWORDS = {
        '带电池': ['电池', '锂电', '纽扣电池', '充电', '蓝牙', '耳机', '充电宝', 'battery', 'lithium'],
        '液体': ['液体', '液', '精华', '香水', '乳液', '面霜', '洗发水', '饮料', 'oil', 'liquid'],
        '粉末': ['粉末', '粉', '奶粉', '调味粉', 'powder'],
        '磁性': ['磁', '磁铁', '扬声器', '喇叭', '马达', '电机', 'magnet'],
        '食品': ['食品', '零食', '糖果', '饼干', '茶', '咖啡', '奶粉', 'food', 'snack'],
        '化妆品': ['化妆品', '面膜', '口红', '面霜', '乳液', '精华', '香水', 'cosmetic', 'skincare'],
        '木制品': ['木', '木制', '木头', '木质', '原木', 'plywood', 'wood'],
        '品牌货': ['品牌', '授权', 'nike', 'adidas', 'apple', 'sony', '迪士尼', 'hello kitty']
    };

    const PORT_RECOMMENDATION_RULES = [
        { keywords: ['洋浦', '儋州', '澄迈', '海口', '海南'], primary: '洋浦港', secondary: '海口港', reason: '海南整柜出口通常优先洋浦港，主干线和政策配套更成熟；海口港可作为就近短驳和区域补充方案。' },
        { keywords: ['防城港', '钦州', '北海', '南宁', '广西'], primary: '钦州港', secondary: '防城港', reason: '广西出运通常优先钦州港，集装箱主线更成熟；防城港适合部分区域和项目型货源。' },
        { keywords: ['湛江'], primary: '湛江港', secondary: '南沙港', reason: '粤西货源可优先湛江港；若要比较主干航线和班次，常会同时看南沙港。' },
        { keywords: ['茂名', '阳江', '江门'], primary: '南沙港', secondary: '深圳港', reason: '珠江西岸及粤西货源多数优先南沙港；若主线或船司资源更合适可比较深圳港。' },
        { keywords: ['深圳', '东莞', '惠州', '佛山', '中山', '珠海'], primary: '深圳港', secondary: '南沙港', reason: '深圳港就近且船期密；广州南沙港常作为价格和舱位备选。' },
        { keywords: ['广州', '番禺', '顺德', '肇庆', '清远', '韶关'], primary: '南沙港', secondary: '深圳港', reason: '广州及珠江西岸常优先南沙港；若主线价格更优可比较深圳港。' },
        { keywords: ['汕头', '揭阳', '潮州', '梅州'], primary: '汕头港', secondary: '深圳港', reason: '粤东就近可走汕头；主干航线和成本综合可比较深圳港。' },
        { keywords: ['厦门', '泉州', '漳州'], primary: '厦门港', secondary: '福州港', reason: '厦门港是福建主力出口港之一，航线成熟；若舱位紧张可考虑福州港。' },
        { keywords: ['福州', '福建'], primary: '福州港', secondary: '厦门港', reason: '福州就近拖柜方便，但福州港部分航线偏港；厦门港通常主干航线更密、运价更有竞争力。' },
        { keywords: ['温州'], primary: '宁波港', secondary: '上海港', reason: '温州货源通常优先比较宁波港；若主线或舱位优势明显可比上海港。' },
        { keywords: ['宁波', '绍兴', '台州', '义乌', '金华'], primary: '宁波港', secondary: '上海港', reason: '宁波港就近且航线丰富；上海港作为备选，班次更多但拖车半径可能更远。' },
        { keywords: ['杭州', '嘉兴', '湖州'], primary: '上海港', secondary: '宁波港', reason: '杭嘉湖区域常同时比较上海港和宁波港；若追求主线密度通常优先上海港。' },
        { keywords: ['上海', '苏州', '昆山', '无锡', '常州', '南通'], primary: '上海港', secondary: '宁波港', reason: '上海港主干线和舱位最丰富；若价格或舱位不理想，可比较宁波港。' },
        { keywords: ['连云港', '徐州', '宿迁', '淮安', '盐城'], primary: '连云港港', secondary: '上海港', reason: '苏北及连云港周边可优先连云港港；若主干航线不足可比较上海港。' },
        { keywords: ['青岛', '潍坊', '临沂', '济南', '淄博'], primary: '青岛港', secondary: '日照港', reason: '山东中西部及胶东南线通常优先青岛港；大宗或区域项目也会比较日照港。' },
        { keywords: ['烟台', '威海'], primary: '烟台港', secondary: '青岛港', reason: '胶东北部就近可走烟台港；若需更丰富主线则比较青岛港。' },
        { keywords: ['日照'], primary: '日照港', secondary: '青岛港', reason: '鲁南货源可优先日照港；主线和综合服务可比较青岛港。' },
        { keywords: ['天津', '北京', '廊坊', '唐山', '保定'], primary: '天津港', secondary: '青岛港', reason: '天津港是华北主力出口港；部分航线也可比较青岛港。' },
        { keywords: ['石家庄', '邯郸', '邢台'], primary: '天津港', secondary: '青岛港', reason: '河北内陆货源通常优先天津港；若价格或船期更优可比较青岛港。' },
        { keywords: ['秦皇岛'], primary: '天津港', secondary: '大连港', reason: '秦皇岛周边集装箱通常优先天津港；东北方向项目可比较大连港。' },
        { keywords: ['大连'], primary: '大连港', secondary: '营口港', reason: '大连周边出口通常优先大连港；辽宁中部货源也可比较营口港。' },
        { keywords: ['沈阳', '鞍山', '本溪', '抚顺', '辽阳'], primary: '营口港', secondary: '大连港', reason: '辽宁中部货源常优先营口港；若主线和班次更优可比较大连港。' },
        { keywords: ['长春', '吉林', '哈尔滨', '齐齐哈尔', '牡丹江'], primary: '大连港', secondary: '营口港', reason: '东北腹地出口多数优先大连港；亦会根据铁路/公路成本比较营口港。' },
        { keywords: ['武汉', '宜昌', '荆州', '襄阳'], primary: '上海港', secondary: '宁波港', reason: '长江流域多通过江海联运衔接上海港；宁波港可作为班次或价格备选。' },
        { keywords: ['长沙', '株洲', '湘潭', '岳阳'], primary: '深圳港', secondary: '上海港', reason: '湖南货源常向华南口岸集拼，也会根据船期和拖车成本比较上海。' },
        { keywords: ['南昌', '九江', '赣州'], primary: '厦门港', secondary: '深圳港', reason: '江西货源常比较厦门港与深圳港；赣南货源也会偏向深圳方向。' },
        { keywords: ['郑州', '洛阳', '开封', '许昌'], primary: '青岛港', secondary: '上海港', reason: '河南货源常通过铁路/公路衔接青岛港；若南向或主线优势明显也会比较上海港。' },
        { keywords: ['西安', '咸阳', '宝鸡'], primary: '青岛港', secondary: '上海港', reason: '西北货源常通过铁路联运衔接青岛港；若航线和时效更优也会比较上海港。' },
        { keywords: ['重庆'], primary: '上海港', secondary: '深圳港', reason: '重庆多通过江海联运衔接上海港；若华南航线和船司资源更优可比较深圳港。' },
        { keywords: ['成都', '绵阳', '德阳', '乐山'], primary: '深圳港', secondary: '上海港', reason: '四川货源常南下经深圳港，也会根据班期和联运成本比较上海港。' },
        { keywords: ['昆明', '曲靖', '玉溪'], primary: '深圳港', secondary: '钦州港', reason: '云南货源常向华南口岸集拼；面向东盟或西南物流链也会比较钦州港。' },
        { keywords: ['贵阳', '遵义'], primary: '深圳港', secondary: '钦州港', reason: '贵州货源通常优先比较华南口岸，面向西南/东盟亦可看钦州港。' }
    ];

    const DESTINATION_PORT_RULES = [
        { keywords: ['东京', '千叶', '埼玉', '神奈川', '横滨', '川崎', '群马', '栃木', '茨城'], primary: '东京港', secondary: '横滨港', reason: '关东收货地址通常优先东京港，若班期或成本更优可比较横滨港。' },
        { keywords: ['静冈', '山梨', '长野'], primary: '横滨港', secondary: '东京港', reason: '关东西缘和部分中部货源常比较横滨港与东京港，横滨港对部分项目更顺路。' },
        { keywords: ['大阪', '京都', '兵库', '神户', '奈良', '和歌山', '滋贺'], primary: '大阪港', secondary: '神户港', reason: '关西区域多优先大阪港，神户港常作为就近且成熟的备选。' },
        { keywords: ['名古屋', '爱知', '岐阜', '三重'], primary: '名古屋港', secondary: '大阪港', reason: '中部区域优先名古屋港，若主线/价格不理想可比较关西主港。' },
        { keywords: ['广岛', '冈山', '山口'], primary: '神户港', secondary: '大阪港', reason: '日本中国地区常通过关西主港中转或到港，神户港通常更具综合性。' },
        { keywords: ['福冈', '熊本', '大分', '佐贺', '长崎'], primary: '博多港', secondary: '门司港', reason: '九州区域优先博多港，北九州方向可比较门司港。' },
        { keywords: ['札幌', '北海道'], primary: '苫小牧港', secondary: '东京港', reason: '北海道区域多看苫小牧港；部分国际干线也会通过东京转运。' },
        { keywords: ['釜山', '大邱', '蔚山', '庆尚', '昌原'], primary: '釜山港', secondary: '仁川港', reason: '韩国东南部和全国主干多优先釜山港；若是首都圈项目也可比较仁川港。' },
        { keywords: ['首尔', '仁川', '京畿', '水原', '坡州', '富川'], primary: '仁川港', secondary: '釜山港', reason: '韩国首都圈优先仁川港，若船期或干线优势更明显也会比较釜山港。' },
        { keywords: ['大田', '清州', '忠清'], primary: '平泽港', secondary: '仁川港', reason: '韩国中部区域常比较平泽港与仁川港，需看末端派送和班期。' },
        { keywords: ['新加坡'], primary: '新加坡港', secondary: '巴西班让港区', reason: '新加坡收货通常直接走新加坡主港，具体靠泊点由船司安排。' },
        { keywords: ['洛杉矶', '长滩', '加州', '圣地亚哥', '拉斯维加斯', '凤凰城'], primary: '洛杉矶/长滩港', secondary: '奥克兰港', reason: '美国西海岸和西南内陆多优先洛杉矶/长滩港，北加项目可比较奥克兰港。' },
        { keywords: ['旧金山', '奥克兰', '萨克拉门托', '圣何塞', '硅谷'], primary: '奥克兰港', secondary: '洛杉矶/长滩港', reason: '北加州项目通常优先奥克兰港；若主线和班期更优也可比较洛杉矶/长滩港。' },
        { keywords: ['西雅图', '塔科马', '波特兰'], primary: '西雅图/塔科马港', secondary: '温哥华港', reason: '美国西北区域通常优先西雅图/塔科马港，若联运更优也会比较温哥华。' },
        { keywords: ['纽约', '新泽西', '波士顿', '费城', '巴尔的摩', '华盛顿'], primary: '纽约/新泽西港', secondary: '萨凡纳港', reason: '美国东北和中大西洋区域优先纽约/新泽西港，若船期和成本更合适可比较萨凡纳港。' },
        { keywords: ['萨凡纳', '亚特兰大', '夏洛特', '杰克逊维尔', '奥兰多', '迈阿密'], primary: '萨凡纳港', secondary: '纽约/新泽西港', reason: '美国东南区域通常优先萨凡纳港，部分项目也会比较杰克逊维尔或纽约/新泽西。' },
        { keywords: ['芝加哥', '底特律', '克利夫兰', '哥伦布', '明尼阿波利斯', '印第安纳波利斯'], primary: '纽约/新泽西港', secondary: '洛杉矶/长滩港', reason: '美国中西部常比较美东与美西双通道，需结合内陆转运成本综合判断。' },
        { keywords: ['休斯敦', '达拉斯', '奥斯汀', '圣安东尼奥'], primary: '休斯敦港', secondary: '洛杉矶/长滩港', reason: '德州项目通常优先休斯敦港；若走美西再内陆派送更经济，也可比较美西港。' },
        { keywords: ['新奥尔良', '孟菲斯'], primary: '休斯敦港', secondary: '萨凡纳港', reason: '美国南部和密西西比流域项目常比较休斯敦港与美东/东南港口。' }
    ];

    const BOOKING_CARRIER_RULES = [
        { match: ['日本', '东京', '大阪', '神户', '横滨'], cost: ['MSC', 'EMC', 'COSCO'], speed: ['ONE', 'MSC', 'EMC'], balanced: ['ONE', 'COSCO', 'MSC'] },
        { match: ['韩国', '首尔', '釜山', '仁川'], cost: ['HMM', 'MSC', 'COSCO'], speed: ['HMM', 'ONE', 'MSC'], balanced: ['HMM', 'COSCO', 'MSC'] },
        { match: ['新加坡'], cost: ['PIL', 'MSC', 'CMA CGM'], speed: ['CMA CGM', 'MSC', 'PIL'], balanced: ['PIL', 'CMA CGM', 'MSC'] },
        { match: ['美国', '洛杉矶', '长滩', '纽约', '新泽西', '休斯敦', '芝加哥'], cost: ['MSC', 'CMA CGM', 'COSCO'], speed: ['Matson', 'ZIM', 'Maersk'], balanced: ['Maersk', 'CMA CGM', 'MSC'] }
    ];

    const PREFS = [
        '北海道','青森県','岩手県','宮城県','秋田県','山形県','福島県',
        '茨城県','栃木県','群馬県','埼玉県','千葉県','東京都','神奈川県',
        '新潟県','富山県','石川県','福井県','山梨県','長野県','岐阜県','静岡県','愛知県',
        '三重県','滋賀県','京都府','大阪府','兵庫県','奈良県','和歌山県',
        '鳥取県','島根県','岡山県','広島県','山口県',
        '徳島県','香川県','愛媛県','高知県',
        '福岡県','佐賀県','長崎県','熊本県','大分県','宮崎県','鹿児島県','沖縄県'
    ];

    function autoClearCache() {
        const CACHE_KEYS = [
            'hcn_rates_cache',
            'hcn_air_freight_cache',
            'hcn_fcl_freight_cache',
            'hcn_calendar_memos',
            'hcn_shipment_notes',
            'hcn_dashboard_todos'
        ];
        const now = Date.now();
        const ONE_DAY = 24 * 60 * 60 * 1000;
        
        CACHE_KEYS.forEach(key => {
            try {
                const cached = localStorage.getItem(key);
                if (cached) {
                    const data = JSON.parse(cached);
                    if (data && data.ts && (now - data.ts > ONE_DAY)) {
                        localStorage.removeItem(key);
                    }
                }
            } catch (e) {}
        });
        
        const lastClear = localStorage.getItem('hcn_last_cache_clear');
        if (!lastClear || (now - parseInt(lastClear)) > ONE_DAY) {
            localStorage.setItem('hcn_last_cache_clear', now.toString());
        }
    }

    function autoBackup() {
        const BACKUP_KEY = 'hcn_auto_backup';
        const BACKUP_INTERVAL = 30 * 60 * 1000;
        const now = Date.now();
        
        try {
            const lastBackup = localStorage.getItem('hcn_last_auto_backup');
            if (lastBackup && (now - parseInt(lastBackup)) < BACKUP_INTERVAL) {
                return;
            }
            
            const backupData = {
                ts: now,
                version: '1.0',
                data: {}
            };
            
            const KEYS_TO_BACKUP = [
                'hgcd_crm_fcl_v1',
                'logistics_client_data',
                'logistics_supplier_data',
                'logistics_reminder_data',
                'logistics_reconciliation_data',
                'logistics_freight_data',
                'freight_air_cache_v1',
                'freight_fcl_cache_v1',
                'dashboard_todos_v1',
                'hcn_calendar_memos',
                'shipment_notes_v1',
                'logistics_workbench_state_v1'
            ];
            
            KEYS_TO_BACKUP.forEach(key => {
                const value = localStorage.getItem(key);
                if (value) {
                    backupData.data[key] = value;
                }
            });
            
            localStorage.setItem(BACKUP_KEY, JSON.stringify(backupData));
            localStorage.setItem('hcn_last_auto_backup', now.toString());
            
            const backups = JSON.parse(localStorage.getItem('hcn_auto_backups') || '[]');
            backups.unshift({ ts: now, size: JSON.stringify(backupData).length });
            if (backups.length > 10) backups.pop();
            localStorage.setItem('hcn_auto_backups', JSON.stringify(backups));
            
        } catch (e) {
            console.warn('Auto backup failed:', e);
        }
    }

    async function ensureModulesInitialized() {
        if (modulesInitialized) return;
        modulesInitialized = true;
        await initAllModules();
    }

    async function initAllModules(){
        autoClearCache();
        autoBackup();
        if (!autoBackupTimer) autoBackupTimer = setInterval(autoBackup, 30 * 60 * 1000);
        initLanguage();
        await initRates();
        restoreAppState();
        renderContainerTable();
        renderShippingTable();
        renderTruckTable();
        renderJpTruckTable();
        renderKrTruckTable();
        renderSgTruckTable();
        renderUsTruckTable();
        renderIncotermTable();
        renderPortSearch();
        renderGlobalSearch();
        loadShipmentNotes();
        loadDashboardTodos();
        changeCountry();
        loadJpyTrend(30);
        initTimezoneInput();
        updateDashboard();
        updateDashboardNow();
        if (!dashboardNowTimer) dashboardNowTimer = setInterval(updateDashboardNow, 1000);
        updateStorageStatus();
        initNewModules();
    }

    function switchTab(idx) {
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        document.querySelectorAll('.tab-item').forEach(i => i.classList.remove('active'));
        const tabEl = document.getElementById('tab' + idx);
        if(tabEl) tabEl.classList.add('active');
        const order = {9: 0, 3: 1, 4: 2, 15: 3, 6: 4, 7: 5};
        if (order[idx] !== undefined) {
            const tabItems = document.querySelectorAll('.tab-item');
            if(tabItems[order[idx]]) tabItems[order[idx]].classList.add('active');
        }
        const tabBar = document.querySelector('.tab-bar');
        if (tabBar) {
            if ([5, 10, 11, 12, 13, 14].includes(idx)) tabBar.classList.add('hidden');
            else tabBar.classList.remove('hidden');
        }
        if (idx === 10) ensureEmbeddedFrameLoaded('quotation-tool-frame');
        if (idx === 11) ensureEmbeddedFrameLoaded('fee-tool-frame');
        if (idx === 14) ensureEmbeddedFrameLoaded('label-tool-mobile-frame');
        if (idx === 22) initShippingLabel();
        if (idx !== 9) {
            const panel = document.getElementById('timeis-panel');
            const btn = document.getElementById('timeis-toggle-btn');
            if (panel) panel.style.display = 'none';
            if (btn) btn.innerText = '时间';
        }
        if(idx === 4) initCalendar();
        if(idx === 3 && !trendPoints.length) loadJpyTrend(trendDays);
        if(idx === 7) renderContainerTable();
        if(idx === 7) renderShippingTable();
        if(idx === 8) {
            renderTruckTable();
            renderJpTruckTable();
            renderKrTruckTable();
            renderSgTruckTable();
            renderUsTruckTable();
        }
        if(idx === 9) {
            renderGlobalSearch();
            renderPortSearch();
            renderIncotermTable();
            updateDashboardNow();
        }
        if(idx === 15) crmRender();
        if(idx === 16) clientRender();
        if(idx === 17) supplierRender();
        if(idx === 18) { reminderGenerateFromCRM(); reminderRefresh(); }
        if(idx === 19) { reconciliationGenerateFromCRM(); reconciliationRender(); }
        if(idx === 20) { freightRender(); freightInitTrendRoutes(); }
        if(idx === 21) financeRefresh();
    }

    // ===================== 财务分析模块 =====================
    let financeCharts = {};

    function financeGetFilteredData() {
        const data = crmLoad();
        const period = document.getElementById('finance-period')?.value || 'all';
        const now = new Date();
        const thisMonth = now.getMonth();
        const thisYear = now.getFullYear();
        const thisQuarter = Math.floor(thisMonth / 3);
        
        return data.filter(r => {
            if (period === 'all') return true;
            if (!r.createdAt) return false;
            const d = new Date(r.createdAt);
            if (period === 'month') {
                return d.getMonth() === thisMonth && d.getFullYear() === thisYear;
            }
            if (period === 'quarter') {
                const q = Math.floor(d.getMonth() / 3);
                return q === thisQuarter && d.getFullYear() === thisYear;
            }
            if (period === 'year') {
                return d.getFullYear() === thisYear;
            }
            return true;
        });
    }

    function financeRefresh() {
        const data = financeGetFilteredData();
        
        const totalOrders = data.length;
        const withCosts = data.filter(r => r.costs && r.costs._total);
        let totalReceivable = 0;
        let totalPayable = 0;
        let totalProfit = 0;
        let validMarginCount = 0;
        let marginSum = 0;
        
        data.forEach(r => {
            const rec = parseFloat(r.receivable) || parseFloat((r.fees || {}).total) || 0;
            totalReceivable += rec;
        });
        
        withCosts.forEach(r => {
            const rec = parseFloat(r.receivable) || parseFloat((r.fees || {}).total) || 0;
            const pay = parseFloat(r.payable) || parseFloat((r.costs || {})._total) || 0;
            const prof = parseFloat(r.profit) || (rec - pay);
            const marg = parseFloat(r.margin) || (rec > 0 ? prof / rec : 0);
            totalPayable += pay;
            totalProfit += prof;
            if (marg > 0 || marg < 0) {
                marginSum += marg;
                validMarginCount++;
            }
        });
        
        const avgMargin = withCosts.length > 0 ? (totalProfit / totalReceivable) : 0;
        
        document.getElementById('finance-total-orders').textContent = totalOrders + '票 (含' + withCosts.length + '票有应付数据)';
        document.getElementById('finance-total-receivable').textContent = '¥' + totalReceivable.toLocaleString();
        document.getElementById('finance-total-payable').textContent = '¥' + totalPayable.toLocaleString();
        document.getElementById('finance-total-profit').textContent = '¥' + totalProfit.toLocaleString();
        document.getElementById('finance-avg-margin').textContent = (avgMargin * 100).toFixed(1) + '%';
        
        financeRenderMonthlyChart(data);
        financeRenderStatusChart(data);
        financeRenderShipModeChart(data);
        financeRenderClientChart(data);
        financeRenderClientTable(data);
        financeRenderMonthlyTable(data);
    }

    function financeRenderMonthlyChart(data) {
        const ctx = document.getElementById('finance-chart-monthly');
        if (!ctx) return;
        
        if (financeCharts.monthly) financeCharts.monthly.destroy();
        
        const withCosts = data.filter(r => r.costs && r.costs._total);
        const monthlyData = {};
        data.forEach(r => {
            if (!r.createdAt) return;
            const month = r.createdAt.slice(0, 7);
            if (!monthlyData[month]) {
                monthlyData[month] = { receivable: 0, payable: 0, profit: 0, count: 0 };
            }
            const rec = parseFloat(r.receivable) || parseFloat((r.fees || {}).total) || 0;
            monthlyData[month].receivable += rec;
            monthlyData[month].count++;
        });
        
        withCosts.forEach(r => {
            if (!r.createdAt) return;
            const month = r.createdAt.slice(0, 7);
            const rec = parseFloat(r.receivable) || parseFloat((r.fees || {}).total) || 0;
            const pay = parseFloat(r.payable) || parseFloat((r.costs || {})._total) || 0;
            const prof = parseFloat(r.profit) || (rec - pay);
            monthlyData[month].payable += pay;
            monthlyData[month].profit += prof;
        });
        
        const sortedMonths = Object.keys(monthlyData).sort();
        const labels = sortedMonths.map(m => m.slice(5) + '月');
        
        financeCharts.monthly = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: '应收',
                        data: sortedMonths.map(m => monthlyData[m].receivable),
                        borderColor: '#27ae60',
                        backgroundColor: 'rgba(39,174,96,0.1)',
                        tension: 0.3,
                        fill: true
                    },
                    {
                        label: '毛利',
                        data: sortedMonths.map(m => monthlyData[m].profit),
                        borderColor: '#9b59b6',
                        backgroundColor: 'rgba(155,89,182,0.1)',
                        tension: 0.3,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom' } },
                scales: { y: { beginAtZero: true } }
            }
        });
    }

    function financeRenderStatusChart(data) {
        const ctx = document.getElementById('finance-chart-status');
        if (!ctx) return;
        
        if (financeCharts.status) financeCharts.status.destroy();
        
        const statusCount = {};
        data.forEach(r => {
            const s = r.status || '未知';
            statusCount[s] = (statusCount[s] || 0) + 1;
        });
        
        const colors = ['#4a90e2', '#27ae60', '#e74c3c', '#f39c12', '#9b59b6', '#1abc9c', '#34495e', '#e67e22', '#95a5a6'];
        
        financeCharts.status = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: Object.keys(statusCount),
                datasets: [{
                    data: Object.values(statusCount),
                    backgroundColor: colors.slice(0, Object.keys(statusCount).length)
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom' } }
            }
        });
    }

    function financeRenderShipModeChart(data) {
        const ctx = document.getElementById('finance-chart-shipmode');
        if (!ctx) return;
        
        if (financeCharts.shipmode) financeCharts.shipmode.destroy();
        
        const modeCount = {};
        data.forEach(r => {
            const m = r.shipMode || '未知';
            modeCount[m] = (modeCount[m] || 0) + 1;
        });
        
        const colors = ['#4a90e2', '#27ae60', '#e74c3c', '#f39c12', '#9b59b6'];
        
        financeCharts.shipmode = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: Object.keys(modeCount),
                datasets: [{
                    data: Object.values(modeCount),
                    backgroundColor: colors.slice(0, Object.keys(modeCount).length)
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom' } }
            }
        });
    }

    function financeRenderClientChart(data) {
        const ctx = document.getElementById('finance-chart-client');
        if (!ctx) return;
        
        if (financeCharts.client) financeCharts.client.destroy();
        
        const clientProfit = {};
        data.forEach(r => {
            const c = r.client || '未知';
            if (!clientProfit[c]) clientProfit[c] = 0;
            clientProfit[c] += parseFloat(r.profit) || 0;
        });
        
        const sorted = Object.entries(clientProfit).sort((a, b) => b[1] - a[1]).slice(0, 10);
        
        financeCharts.client = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: sorted.map(s => s[0].length > 6 ? s[0].slice(0, 6) + '...' : s[0]),
                datasets: [{
                    label: '毛利',
                    data: sorted.map(s => s[1]),
                    backgroundColor: '#9b59b6'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: { x: { beginAtZero: true } }
            }
        });
    }

    function financeRenderClientTable(data) {
        const tbody = document.getElementById('finance-client-table');
        if (!tbody) return;
        
        const withCosts = data.filter(r => r.costs && r.costs._total);
        const clientData = {};
        data.forEach(r => {
            const c = r.client || '未知';
            if (!clientData[c]) {
                clientData[c] = { count: 0, receivable: 0, payable: 0, profit: 0 };
            }
            const rec = parseFloat(r.receivable) || parseFloat((r.fees || {}).total) || 0;
            clientData[c].count++;
            clientData[c].receivable += rec;
        });
        
        withCosts.forEach(r => {
            const c = r.client || '未知';
            const rec = parseFloat(r.receivable) || parseFloat((r.fees || {}).total) || 0;
            const pay = parseFloat(r.payable) || parseFloat((r.costs || {})._total) || 0;
            const prof = parseFloat(r.profit) || (rec - pay);
            clientData[c].payable += pay;
            clientData[c].profit += prof;
        });
        
        const sorted = Object.entries(clientData).sort((a, b) => b[1].profit - a[1].profit);
        
        tbody.innerHTML = sorted.map((item, idx) => {
            const c = item[0];
            const d = item[1];
            const margin = d.receivable > 0 ? ((d.profit / d.receivable) * 100).toFixed(1) : '0.0';
            return `<tr>
                <td style="padding:8px; border-bottom:1px solid #eee;">${idx + 1}</td>
                <td style="padding:8px; border-bottom:1px solid #eee;">${c}</td>
                <td style="padding:8px; border-bottom:1px solid #eee; text-align:right;">${d.count}</td>
                <td style="padding:8px; border-bottom:1px solid #eee; text-align:right;">¥${d.receivable.toLocaleString()}</td>
                <td style="padding:8px; border-bottom:1px solid #eee; text-align:right;">¥${d.payable.toLocaleString()}</td>
                <td style="padding:8px; border-bottom:1px solid #eee; text-align:right; color:#9b59b6; font-weight:bold;">¥${d.profit.toLocaleString()}</td>
                <td style="padding:8px; border-bottom:1px solid #eee; text-align:right;">${margin}%</td>
            </tr>`;
        }).join('');
    }

    function financeRenderMonthlyTable(data) {
        const tbody = document.getElementById('finance-monthly-table');
        if (!tbody) return;
        
        const withCosts = data.filter(r => r.costs && r.costs._total);
        const monthlyData = {};
        data.forEach(r => {
            if (!r.createdAt) return;
            const month = r.createdAt.slice(0, 7);
            if (!monthlyData[month]) {
                monthlyData[month] = { count: 0, receivable: 0, payable: 0, profit: 0 };
            }
            const rec = parseFloat(r.receivable) || parseFloat((r.fees || {}).total) || 0;
            monthlyData[month].count++;
            monthlyData[month].receivable += rec;
        });
        
        withCosts.forEach(r => {
            if (!r.createdAt) return;
            const month = r.createdAt.slice(0, 7);
            const rec = parseFloat(r.receivable) || parseFloat((r.fees || {}).total) || 0;
            const pay = parseFloat(r.payable) || parseFloat((r.costs || {})._total) || 0;
            const prof = parseFloat(r.profit) || (rec - pay);
            monthlyData[month].payable += pay;
            monthlyData[month].profit += prof;
        });
        
        const sorted = Object.entries(monthlyData).sort((a, b) => a[0].localeCompare(b[0]));
        
        tbody.innerHTML = sorted.map(item => {
            const m = item[0];
            const d = item[1];
            const margin = d.receivable > 0 ? ((d.profit / d.receivable) * 100).toFixed(1) : '0.0';
            return `<tr>
                <td style="padding:8px; border-bottom:1px solid #eee;">${m}</td>
                <td style="padding:8px; border-bottom:1px solid #eee; text-align:right;">${d.count}</td>
                <td style="padding:8px; border-bottom:1px solid #eee; text-align:right;">¥${d.receivable.toLocaleString()}</td>
                <td style="padding:8px; border-bottom:1px solid #eee; text-align:right;">¥${d.payable.toLocaleString()}</td>
                <td style="padding:8px; border-bottom:1px solid #eee; text-align:right; color:#9b59b6; font-weight:bold;">¥${d.profit.toLocaleString()}</td>
                <td style="padding:8px; border-bottom:1px solid #eee; text-align:right;">${margin}%</td>
            </tr>`;
        }).join('');
    }

    async function financeExportPDF() {
        const data = financeGetFilteredData();
        if (data.length === 0) {
            showToast('暂无数据可导出');
            return;
        }
        
        showToast('正在生成PDF...');
        
        const withCosts = data.filter(r => r.costs && r.costs._total);
        let totalReceivable = 0, totalPayable = 0, totalProfit = 0;
        data.forEach(r => {
            const rec = parseFloat(r.receivable) || parseFloat((r.fees || {}).total) || 0;
            totalReceivable += rec;
        });
        withCosts.forEach(r => {
            const rec = parseFloat(r.receivable) || parseFloat((r.fees || {}).total) || 0;
            const pay = parseFloat(r.payable) || parseFloat((r.costs || {})._total) || 0;
            const prof = parseFloat(r.profit) || (rec - pay);
            totalPayable += pay;
            totalProfit += prof;
        });
        
        const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>财务分析报告</title>
        <style>
            body { font-family: -apple-system, Arial, sans-serif; padding: 40px; background: #fff; }
            h1 { color: #2c3e50; border-bottom: 3px solid #4a90e2; padding-bottom: 10px; }
            .summary { display: flex; gap: 20px; margin: 20px 0; }
            .card { padding: 15px 25px; border-radius: 8px; text-align: center; }
            .card h3 { margin: 0 0 5px; font-size: 14px; color: #666; }
            .card .value { font-size: 24px; font-weight: bold; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
            th { background: #f5f5f7; }
            .text-right { text-align: right; }
            .profit { color: #9b59b6; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>📊 财务分析报告</h1>
        <p style="color:#888;">生成时间：${new Date().toLocaleString()}</p>
        
        <div class="summary">
            <div class="card" style="background:#4a90e222;">
                <h3>总订单数</h3>
                <div class="value" style="color:#4a90e2;">${data.length}</div>
            </div>
            <div class="card" style="background:#27ae6022;">
                <h3>总应收</h3>
                <div class="value" style="color:#27ae60;">¥${totalReceivable.toLocaleString()}</div>
            </div>
            <div class="card" style="background:#e74c3c22;">
                <h3>总应付</h3>
                <div class="value" style="color:#e74c3c;">¥${totalPayable.toLocaleString()}</div>
            </div>
            <div class="card" style="background:#9b59b622;">
                <h3>总毛利</h3>
                <div class="value" style="color:#9b59b6;">¥${totalProfit.toLocaleString()}</div>
            </div>
        </div>
        
        <h2 style="margin-top:30px; color:#2c3e50;">客户贡献明细</h2>
        <table>
            <thead><tr><th>客户</th><th class="text-right">订单数</th><th class="text-right">应收</th><th class="text-right">应付</th><th class="text-right">毛利</th></tr></thead>
            <tbody>
                ${financeGetClientRows(data)}
            </tbody>
        </table>
    </body>
    </html>`;
        
        const wrap = document.createElement('div');
        wrap.style.cssText = 'position:fixed;left:-9999px;top:0;width:800px;background:#fff;';
        wrap.innerHTML = html;
        document.body.appendChild(wrap);
        
        try {
            const canvas = await html2canvas(wrap, { scale: 2, backgroundColor: '#ffffff' });
            const { jsPDF } = window.jspdf;
            const pdf = new jsPDF('p', 'mm', 'a4');
            const imgData = canvas.toDataURL('image/png');
            const pageWidth = 210;
            const imgWidth = pageWidth - 20;
            const imgHeight = (canvas.height * imgWidth) / canvas.width;
            pdf.addImage(imgData, 'PNG', 10, 10, imgWidth, imgHeight);
            pdf.save('财务分析报告_' + new Date().toISOString().slice(0,10) + '.pdf');
            showToast('PDF已下载');
        } catch (e) {
            console.error(e);
            showToast('PDF生成失败');
        } finally {
            wrap.remove();
        }
    }

    function financeGetClientRows(data) {
        const withCosts = data.filter(r => r.costs && r.costs._total);
        const clientData = {};
        data.forEach(r => {
            const c = r.client || '未知';
            if (!clientData[c]) clientData[c] = { count: 0, receivable: 0, payable: 0, profit: 0 };
            clientData[c].count++;
            const rec = parseFloat(r.receivable) || parseFloat((r.fees || {}).total) || 0;
            clientData[c].receivable += rec;
        });
        withCosts.forEach(r => {
            const c = r.client || '未知';
            const rec = parseFloat(r.receivable) || parseFloat((r.fees || {}).total) || 0;
            const pay = parseFloat(r.payable) || parseFloat((r.costs || {})._total) || 0;
            const prof = parseFloat(r.profit) || (rec - pay);
            clientData[c].payable += pay;
            clientData[c].profit += prof;
        });
        return Object.entries(clientData).sort((a, b) => b[1].profit - a[1].profit).slice(0, 20).map(item => {
            const d = item[1];
            return `<tr><td>${item[0]}</td><td class="text-right">${d.count}</td><td class="text-right">¥${d.receivable.toLocaleString()}</td><td class="text-right">¥${d.payable.toLocaleString()}</td><td class="text-right profit">¥${d.profit.toLocaleString()}</td></tr>`;
        }).join('');
    }

    function financeExportCSV() {
        const data = financeGetFilteredData();
        if (data.length === 0) {
            showToast('暂无数据可导出');
            return;
        }
        
        const withCosts = data.filter(r => r.costs && r.costs._total);
        const clientData = {};
        data.forEach(r => {
            const c = r.client || '未知';
            if (!clientData[c]) clientData[c] = { count: 0, receivable: 0, payable: 0, profit: 0 };
            clientData[c].count++;
            const rec = parseFloat(r.receivable) || parseFloat((r.fees || {}).total) || 0;
            clientData[c].receivable += rec;
        });
        withCosts.forEach(r => {
            const c = r.client || '未知';
            const rec = parseFloat(r.receivable) || parseFloat((r.fees || {}).total) || 0;
            const pay = parseFloat(r.payable) || parseFloat((r.costs || {})._total) || 0;
            const prof = parseFloat(r.profit) || (rec - pay);
            clientData[c].payable += pay;
            clientData[c].profit += prof;
        });
        
        const rows = [['客户', '订单数', '应收', '应付', '毛利', '利润率']];
        Object.entries(clientData).sort((a, b) => b[1].profit - a[1].profit).forEach(item => {
            const d = item[1];
            const margin = d.receivable > 0 ? ((d.profit / d.receivable) * 100).toFixed(1) + '%' : '0%';
            rows.push([item[0], d.count, d.receivable, d.payable, d.profit, margin]);
        });
        
        const csv = rows.map(r => r.map(c => '"' + c + '"').join(',')).join('\n');
        const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = '财务分析_' + new Date().toISOString().slice(0,10) + '.csv';
        a.click();
        URL.revokeObjectURL(url);
        showToast('CSV已下载');
    }

    // 汇率转换功能
    const FALLBACK_RATES = {
        USD: 1,
        CNY: 7.24,
        JPY: 149.5,
        EUR: 0.92,
        GBP: 0.79,
        HKD: 7.82,
        KRW: 1350,
        SGD: 1.34,
        AUD: 1.53,
        CAD: 1.36,
        CHF: 0.88,
        THB: 35.8,
        MYR: 4.72,
        VND: 25400,
        INR: 83.5,
        PHP: 56.5,
        TWD: 32.4,
        NZD: 1.68
    };

    function getSeriesPointValue(entry, base, symbol) {
        if (entry == null) return null;
        if (typeof entry === 'number') return entry;
        if (typeof entry === 'object') {
            const direct = Number(entry[symbol]);
            if (Number.isFinite(direct) && direct > 0) return direct;
            const pair = Number(entry[`${base}${symbol}`]);
            if (Number.isFinite(pair) && pair > 0) return pair;
            if (entry.quotes) return getSeriesPointValue(entry.quotes, base, symbol);
            if (entry.rates) return getSeriesPointValue(entry.rates, base, symbol);
        }
        return null;
    }

    async function initRates() {
        try {
            const res = await fetch('https://open.er-api.com/v6/latest/USD');
            const data = await res.json();
            if (data && data.rates) {
                rates = data.rates;
                localStorage.setItem('hcn_rates_cache', JSON.stringify({ ts: Date.now(), rates }));
            }
        } catch(e) {}
        if (!rates.USD) {
            const cached = localStorage.getItem('hcn_rates_cache');
            if (cached) {
                try {
                    const obj = JSON.parse(cached);
                    if (obj && obj.rates) rates = obj.rates;
                } catch(e) {}
            }
        }
        if (!rates.USD) rates = { ...FALLBACK_RATES };
        convertRate('left');
        convertTriple('JPY');
        updateDashboard();
        const el = document.getElementById('rate-status');
        if (el) el.innerText = rates.USD ? '汇率已加载' : '使用备用汇率';
    }

    function getSafeRate(code) {
        const value = Number(rates?.[code]);
        return Number.isFinite(value) && value > 0 ? value : null;
    }

    function convertRate(dir) {
        if(!rates.USD) {
            rates = { ...FALLBACK_RATES };
        }
        const fromEl = document.getElementById('cur-left');
        const toEl = document.getElementById('cur-right');
        const l = document.getElementById('val-left');
        const r = document.getElementById('val-right');
        if (!fromEl || !toEl || !l || !r) return;
        const from = fromEl.value;
        const to = toEl.value;
        const fromRate = getSafeRate(from);
        const toRate = getSafeRate(to);
        if (!fromRate || !toRate) {
            setRateStatus('部分币种汇率缺失');
            return;
        }
        if(dir === 'left') {
            const lv = parseFloat(l.value);
            if (isNaN(lv)) { r.value = ''; return; }
            r.value = (lv / fromRate * toRate).toFixed(2);
        } else {
            const rv = parseFloat(r.value);
            if (isNaN(rv)) { l.value = ''; return; }
            l.value = (rv / toRate * fromRate).toFixed(2);
        }
        setRateStatus(`实时汇率：1 ${from} ≈ ${(toRate / fromRate).toFixed(4)} ${to}`);
        updateDashboard();
    }

    function setRateStatus(msg) {
        const el = document.getElementById('rate-status');
        if (el) el.innerText = msg;
    }

    function convertTriple(src) {
        if(!rates.USD) {
            rates = { ...FALLBACK_RATES };
        }
        const jpyInput = document.getElementById('val-jpy-link');
        const cnyInput = document.getElementById('val-cny-link');
        const usdInput = document.getElementById('val-usd-link');
        if (!jpyInput || !cnyInput || !usdInput) return;
        const jpyRate = getSafeRate('JPY');
        const cnyRate = getSafeRate('CNY');
        const usdRate = getSafeRate('USD') || 1;
        if (!jpyRate || !cnyRate) return;

        let baseUsd = 0;
        if (src === 'JPY') {
            const v = parseFloat(jpyInput.value);
            if (isNaN(v)) { cnyInput.value = ''; usdInput.value = ''; return; }
            baseUsd = v / jpyRate;
        } else if (src === 'CNY') {
            const v = parseFloat(cnyInput.value);
            if (isNaN(v)) { jpyInput.value = ''; usdInput.value = ''; return; }
            baseUsd = v / cnyRate;
        } else {
            const v = parseFloat(usdInput.value);
            if (isNaN(v)) { jpyInput.value = ''; cnyInput.value = ''; return; }
            baseUsd = v / usdRate;
        }

        if (src !== 'JPY') jpyInput.value = (baseUsd * jpyRate).toFixed(2);
        if (src !== 'CNY') cnyInput.value = (baseUsd * cnyRate).toFixed(2);
        if (src !== 'USD') usdInput.value = (baseUsd * usdRate).toFixed(2);
    }

    async function loadJpyTrend(days) {
        trendDays = days;
        updateTrendButtons(days);
        setJpyTrendStatus('走势图加载中...');
        const end = new Date();
        const start = new Date();
        start.setDate(end.getDate() - days + 1);
        const startStr = formatDate(start);
        const endStr = formatDate(end);

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 8000);
            const url = `https://api.frankfurter.dev/v2/rates?from=${startStr}&to=${endStr}&base=JPY&quotes=CNY`;
            const res = await fetch(url, { signal: controller.signal });
            clearTimeout(timeoutId);
            const data = await res.json();
            const points = [];
            if (Array.isArray(data)) {
                data.forEach(item => {
                    const value = Number(item?.rate);
                    if (item && item.quote === 'CNY' && Number.isFinite(value)) {
                        points.push({ date: item.date, value });
                    }
                });
            } else if (data && typeof data === 'object' && data.rates && typeof data.rates === 'object') {
                Object.entries(data.rates).forEach(([date, entry]) => {
                    const value = getSeriesPointValue(entry, 'JPY', 'CNY');
                    if (Number.isFinite(value) && value > 0) {
                        points.push({ date, value });
                    }
                });
            }
            trendPoints = points.sort((a, b) => a.date.localeCompare(b.date));

            if (!trendPoints.length) throw new Error('empty trend data');
            drawJpyTrendChart(trendPoints);
            updateTrendSummary(trendPoints);
            setJpyTrendStatus(`近${days}天 JPY/CNY 历史汇率`);
        } catch (e) {
            trendPoints = [];
            clearTrendCanvas();
            setJpyTrendStatus('走势图加载失败');
            const summaryEl = document.getElementById('jpy-trend-summary');
            if (summaryEl) summaryEl.innerText = '历史汇率接口暂不可用';
        }
    }

    function updateTrendButtons(days) {
        [7, 30, 90].forEach(item => {
            const btn = document.getElementById(`trend-btn-${item}`);
            if (btn) btn.classList.toggle('active', item === days);
        });
    }

    function setJpyTrendStatus(text) {
        const el = document.getElementById('jpy-trend-status');
        if (el) el.innerText = text;
    }

    function updateTrendSummary(points) {
        const values = points.map(item => item.value);
        const latest = values[values.length - 1];
        const min = Math.min(...values);
        const max = Math.max(...values);
        const first = values[0];
        const change = latest - first;
        const changeText = `${change >= 0 ? '+' : ''}${change.toFixed(4)}`;
        document.getElementById('jpy-trend-summary').innerText = `最新 ${latest.toFixed(4)} | 区间 ${min.toFixed(4)}-${max.toFixed(4)} | 变化 ${changeText}`;
    }

    function clearTrendCanvas() {
        const canvas = document.getElementById('jpy-trend-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
    }

    function drawJpyTrendChart(points) {
        const canvas = document.getElementById('jpy-trend-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const cssWidth = canvas.clientWidth || 600;
        const cssHeight = 180;
        canvas.width = cssWidth * dpr;
        canvas.height = cssHeight * dpr;
        ctx.setTransform(1, 0, 0, 1, 0, 0);
        ctx.scale(dpr, dpr);
        ctx.clearRect(0, 0, cssWidth, cssHeight);

        const padding = { top: 14, right: 44, bottom: 26, left: 42 };
        const width = cssWidth - padding.left - padding.right;
        const height = cssHeight - padding.top - padding.bottom;
        const values = points.map(item => item.value);
        const min = Math.min(...values);
        const max = Math.max(...values);
        const range = max - min || 0.0001;

        ctx.fillStyle = '#7a8a99';
        ctx.font = '10px sans-serif';
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        for (let i = 0; i <= 3; i++) {
            const y = padding.top + (height / 3) * i;
            const val = max - (range / 3) * i;
            ctx.fillText(val.toFixed(4), padding.left - 6, y);
        }

        ctx.strokeStyle = '#e6edf5';
        ctx.lineWidth = 1;
        for (let i = 0; i <= 3; i++) {
            const y = padding.top + (height / 3) * i;
            ctx.beginPath();
            ctx.moveTo(padding.left, y);
            ctx.lineTo(padding.left + width, y);
            ctx.stroke();
        }

        ctx.beginPath();
        points.forEach((point, index) => {
            const x = padding.left + (width * index) / Math.max(points.length - 1, 1);
            const y = padding.top + height - ((point.value - min) / range) * height;
            if (index === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.strokeStyle = '#4a90e2';
        ctx.lineWidth = 2;
        ctx.stroke();

        const lastPoint = points[points.length - 1];
        const lastX = padding.left + width;
        const lastY = padding.top + height - ((lastPoint.value - min) / range) * height;
        ctx.fillStyle = '#4a90e2';
        ctx.beginPath();
        ctx.arc(lastX, lastY, 3.5, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = '#4a90e2';
        ctx.font = '10px sans-serif';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'middle';
        ctx.fillText(lastPoint.value.toFixed(4), lastX + 6, lastY);

        ctx.fillStyle = '#7a8a99';
        ctx.font = '11px sans-serif';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'alphabetic';
        ctx.fillText(points[0].date.slice(5), padding.left, cssHeight - 8);
        ctx.textAlign = 'right';
        ctx.fillText(lastPoint.date.slice(5), padding.left + width, cssHeight - 8);
    }

    function formatDate(date) {
        const y = date.getFullYear();
        const m = String(date.getMonth() + 1).padStart(2, '0');
        const d = String(date.getDate()).padStart(2, '0');
        return `${y}-${m}-${d}`;
    }

    // 农历日历
    function initCalendar() {
        const grid = document.getElementById('calendar-grid'); grid.innerHTML = '';
        const year = currDate.getFullYear(), month = currDate.getMonth();
        document.getElementById('cal-month-title').innerText = `${year}年 ${month + 1}月`;
        ['日','一','二','三','四','五','六'].forEach(l => grid.innerHTML += `<div class="cal-cell cal-weekday">${l}</div>`);
        const first = new Date(year, month, 1).getDay(), days = new Date(year, month + 1, 0).getDate();
        
        reminderLoadData();
        if (!reminderData.length) reminderGenerateFromCRM();
        
        for(let i=0; i<first; i++) grid.innerHTML += `<div class="cal-cell"></div>`;
        for(let d=1; d<=days; d++) {
            const key = `${year}-${month+1}-${d}`,
                isToday = new Date().toDateString() === new Date(year, month, d).toDateString();
            const lunarDate = Lunar.fromDate(new Date(year, month, d));
            const holiday = getHolidayInfo(year, month + 1, d);
            const marketClosures = getMarketClosures(year, month + 1, d);
            
            const dateStr = `${year}-${String(month+1).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
            const dayReminders = reminderData.filter(r => r.date === dateStr);
            const hasReminders = dayReminders.length > 0;
            
            const cell = document.createElement('div'); cell.className = 'cal-cell';
            if (holiday?.type === 'jp') cell.classList.add('cal-cell-holiday-jp');
            if (holiday?.type === 'intl') cell.classList.add('cal-cell-holiday-intl');
            if (hasReminders) cell.classList.add('cal-cell-reminder');
            cell.innerHTML = `
                ${isToday?'<div class="today-circle">'+d+'</div>':d}
                <div class="lunar-text">${lunarDate.getJieQi() || lunarDate.getDayInChinese()}</div>
                ${holiday ? `<div class="holiday-text ${holiday.type === 'jp' ? 'holiday-jp' : 'holiday-intl'}" title="${holiday.name}">${holiday.name}</div>` : ''}
                ${marketClosures.map(item => `<div class="market-text ${item.className}" title="${item.tip}">${item.label}</div>`).join('')}
                ${memos[key]?'<div class="event-dot"></div>':''}
                ${hasReminders ? `<div class="crm-reminder-dot" title="${dayReminders.map(r => r.title).join('\n')}">🔔</div>` : ''}
            `;
            cell.onclick = (e) => {
                if (hasReminders && e.target.classList.contains('crm-reminder-dot')) {
                    switchTab(18);
                    return;
                }
                const tags = [];
                if (holiday) tags.push(holiday.name);
                marketClosures.forEach(item => tags.push(item.tip));
                if (hasReminders) tags.push(...dayReminders.map(r => r.title));
                const promptTitle = tags.length ? `备注（${tags.join(' / ')}）:` : '备注:';
                const n = prompt(promptTitle, memos[key]||"");
                if(n!==null) {
                    if(!n.trim()) delete memos[key];
                    else memos[key]=n;
                    localStorage.setItem('hcn_calendar_memos', JSON.stringify(memos));
                    queueSaveAppState();
                    updateStorageStatus();
                    initCalendar();
                }
            };
            grid.appendChild(cell);
        }
        updateMonthEarningsList(year, month + 1);
    }
    function changeMonth(d) { currDate.setMonth(currDate.getMonth() + d); initCalendar(); }

    function updateMonthEarningsList(year, month) {
        const listEl = document.getElementById('cal-month-earnings-list');
        if (!listEl) return;
        
        const earnings = [];
        
        const aShareEarnings = {
            '1-31': { label: 'A股年报预告截止', tip: 'A股年报业绩预告披露截止日' },
            '4-30': { label: 'A股一季报截止', tip: 'A股一季报披露截止日' },
            '7-15': { label: 'A股中报预告截止', tip: 'A股半年报业绩预告披露截止日' },
            '8-31': { label: 'A股半年报截止', tip: 'A股半年报披露截止日' },
            '10-31': { label: 'A股三季报截止', tip: 'A股三季报披露截止日' }
        };
        
        Object.keys(aShareEarnings).forEach(key => {
            const [m, d] = key.split('-');
            if (parseInt(m) === month) {
                earnings.push({
                    date: `${month}月${d}日`,
                    label: aShareEarnings[key].label,
                    type: 'a'
                });
            }
        });
        
        const usEarningsWindows = {
            1: '美股Q4财报季',
            2: '美股Q4财报季',
            3: '美股Q4财报季',
            4: '美股Q1财报季',
            5: '美股Q1财报季',
            6: '美股Q1财报季',
            7: '美股Q2财报季',
            8: '美股Q2财报季',
            9: '美股Q2财报季',
            10: '美股Q3财报季',
            11: '美股Q3财报季',
            12: '美股Q3财报季'
        };
        
        if (usEarningsWindows[month]) {
            earnings.push({
                date: '全月',
                label: usEarningsWindows[month],
                type: 'us'
            });
        }
        
        if (earnings.length === 0) {
            listEl.innerHTML = '<div style="color: var(--text-tertiary);">本月无财报日期</div>';
            return;
        }
        
        listEl.innerHTML = earnings.map(e => `
            <div class="cal-earnings-item">
                <span class="cal-earnings-date ${e.type}">${e.date}</span>
                <span class="cal-earnings-label">${e.label}</span>
            </div>
        `).join('');
    }

    function getHolidayInfo(year, month, day) {
        const jp = getJapaneseHoliday(year, month, day);
        if (jp) return { type: 'jp', name: jp };
        const intl = getInternationalHoliday(month, day);
        if (intl) return { type: 'intl', name: intl };
        return null;
    }

    function getJapaneseHoliday(year, month, day) {
        const fixed = {
            '1-1': '元日',
            '2-11': '建国記念の日',
            '2-23': '天皇誕生日',
            '4-29': '昭和の日',
            '5-3': '憲法記念日',
            '5-4': 'みどりの日',
            '5-5': 'こどもの日',
            '8-11': '山の日',
            '11-3': '文化の日',
            '11-23': '勤労感謝の日'
        };
        const key = `${month}-${day}`;
        if (fixed[key]) return fixed[key];

        if (month === 1 && day === getNthWeekday(year, 1, 1, 2)) return '成人の日';
        if (month === 7 && day === getNthWeekday(year, 7, 1, 3)) return '海の日';
        if (month === 9 && day === getNthWeekday(year, 9, 1, 3)) return '敬老の日';
        if (month === 10 && day === getNthWeekday(year, 10, 1, 2)) return 'スポーツの日';
        if (month === 3 && day === getSpringEquinoxDay(year)) return '春分の日';
        if (month === 9 && day === getAutumnEquinoxDay(year)) return '秋分の日';

        return '';
    }

    function getInternationalHoliday(month, day) {
        const holidays = {
            '1-1': 'New Year',
            '2-14': 'Valentine\'s Day',
            '3-8': 'Women\'s Day',
            '4-22': 'Earth Day',
            '5-1': 'Labor Day',
            '6-1': 'Children\'s Day',
            '10-31': 'Halloween',
            '12-24': 'Christmas Eve',
            '12-25': 'Christmas',
            '12-31': 'New Year\'s Eve'
        };
        return holidays[`${month}-${day}`] || '';
    }

    const MARKET_HOLIDAYS = {
        2025: {
            aShareClosed: {
                '1-1': 'A股休市',
                '1-2': 'A股休市',
                '1-3': 'A股休市',
                '1-28': 'A股休市',
                '1-29': 'A股休市',
                '1-30': 'A股休市',
                '1-31': 'A股休市',
                '2-1': 'A股休市',
                '2-2': 'A股休市',
                '2-3': 'A股休市',
                '2-4': 'A股休市',
                '4-4': 'A股休市',
                '4-5': 'A股休市',
                '4-6': 'A股休市',
                '5-1': 'A股休市',
                '5-2': 'A股休市',
                '5-3': 'A股休市',
                '5-4': 'A股休市',
                '5-5': 'A股休市',
                '5-31': 'A股休市',
                '6-1': 'A股休市',
                '6-2': 'A股休市',
                '10-1': 'A股休市',
                '10-2': 'A股休市',
                '10-3': 'A股休市',
                '10-4': 'A股休市',
                '10-5': 'A股休市',
                '10-6': 'A股休市',
                '10-7': 'A股休市',
                '10-8': 'A股休市'
            },
            usClosed: {
                '1-1': '美股休市',
                '1-20': '美股休市',
                '2-17': '美股休市',
                '4-18': '美股休市',
                '5-26': '美股休市',
                '6-19': '美股休市',
                '7-4': '美股休市',
                '9-1': '美股休市',
                '11-27': '美股休市',
                '12-25': '美股休市'
            },
            usEarlyClose: {
                '11-28': '美股13:00收市',
                '12-24': '美股13:00收市'
            }
        },
        2026: {
            aShareClosed: {
                '1-1': 'A股休市',
                '1-2': 'A股休市',
                '1-3': 'A股休市',
                '2-15': 'A股休市',
                '2-16': 'A股休市',
                '2-17': 'A股休市',
                '2-18': 'A股休市',
                '2-19': 'A股休市',
                '2-20': 'A股休市',
                '2-21': 'A股休市',
                '2-22': 'A股休市',
                '2-23': 'A股休市',
                '4-4': 'A股休市',
                '4-5': 'A股休市',
                '4-6': 'A股休市',
                '5-1': 'A股休市',
                '5-2': 'A股休市',
                '5-3': 'A股休市',
                '5-4': 'A股休市',
                '5-5': 'A股休市',
                '6-19': 'A股休市',
                '6-20': 'A股休市',
                '6-21': 'A股休市',
                '9-25': 'A股休市',
                '9-26': 'A股休市',
                '9-27': 'A股休市',
                '10-1': 'A股休市',
                '10-2': 'A股休市',
                '10-3': 'A股休市',
                '10-4': 'A股休市',
                '10-5': 'A股休市',
                '10-6': 'A股休市',
                '10-7': 'A股休市',
                '10-8': 'A股休市'
            },
            usClosed: {
                '1-1': '美股休市',
                '1-19': '美股休市',
                '2-16': '美股休市',
                '4-3': '美股休市',
                '5-25': '美股休市',
                '6-19': '美股休市',
                '7-3': '美股休市',
                '9-7': '美股休市',
                '11-26': '美股休市',
                '12-25': '美股休市'
            },
            usEarlyClose: {
                '11-27': '美股13:00收市',
                '12-24': '美股13:00收市'
            }
        }
    };

    function getMarketClosures(year, month, day) {
        const y = MARKET_HOLIDAYS[year];
        if (!y) return [];
        const key = `${month}-${day}`;
        const result = [];
        if (y.aShareClosed[key]) {
            result.push({ label: 'A股休市', tip: 'A股休市（09:30-11:30，13:00-15:00 停盘）', className: 'market-a' });
        }
        if (y.usClosed[key]) {
            result.push({ label: '美股休市', tip: '美股休市（常规 09:30-16:00 美东时间）', className: 'market-us' });
        }
        if (y.usEarlyClose[key]) {
            result.push({ label: '美股早收', tip: '美股提前收市，13:00 收市（美东时间）', className: 'market-us-early' });
        }
        
        const earnings = getEarningsDates(year, month, day);
        earnings.forEach(e => result.push(e));
        
        return result;
    }

    function getEarningsDates(year, month, day) {
        const result = [];
        
        const aShareEarnings = {
            '1-31': { label: 'A股年报预告截止', tip: 'A股年报业绩预告披露截止日（有条件强制）' },
            '4-30': { label: 'A股一季报截止', tip: 'A股一季报披露截止日' },
            '7-15': { label: 'A股中报预告截止', tip: 'A股半年报业绩预告披露截止日（有条件强制）' },
            '8-31': { label: 'A股半年报截止', tip: 'A股半年报披露截止日' },
            '10-31': { label: 'A股三季报截止', tip: 'A股三季报披露截止日' }
        };
        
        const usEarningsWindows = {
            1: { label: '美股Q4财报季', tip: '美股Q4财报披露窗口（1月下旬-3月）' },
            2: { label: '美股Q4财报季', tip: '美股Q4财报披露窗口（1月下旬-3月）' },
            3: { label: '美股Q4财报季', tip: '美股Q4财报披露窗口（1月下旬-3月）' },
            4: { label: '美股Q1财报季', tip: '美股Q1财报披露窗口（4月下旬-6月）' },
            5: { label: '美股Q1财报季', tip: '美股Q1财报披露窗口（4月下旬-6月）' },
            6: { label: '美股Q1财报季', tip: '美股Q1财报披露窗口（4月下旬-6月）' },
            7: { label: '美股Q2财报季', tip: '美股Q2财报披露窗口（7月下旬-9月）' },
            8: { label: '美股Q2财报季', tip: '美股Q2财报披露窗口（7月下旬-9月）' },
            9: { label: '美股Q2财报季', tip: '美股Q2财报披露窗口（7月下旬-9月）' },
            10: { label: '美股Q3财报季', tip: '美股Q3财报披露窗口（10月下旬-12月）' },
            11: { label: '美股Q3财报季', tip: '美股Q3财报披露窗口（10月下旬-12月）' },
            12: { label: '美股Q3财报季', tip: '美股Q3财报披露窗口（10月下旬-12月）' }
        };
        
        const aKey = `${month}-${day}`;
        if (aShareEarnings[aKey]) {
            result.push({ 
                label: aShareEarnings[aKey].label, 
                tip: aShareEarnings[aKey].tip, 
                className: 'market-earnings-a' 
            });
        }
        
        if (day === 15 && usEarningsWindows[month]) {
            result.push({ 
                label: usEarningsWindows[month].label, 
                tip: usEarningsWindows[month].tip, 
                className: 'market-earnings-us' 
            });
        }
        
        return result;
    }

    function getNthWeekday(year, month, weekday, nth) {
        const firstDay = new Date(year, month - 1, 1).getDay();
        const delta = (weekday - firstDay + 7) % 7;
        return 1 + delta + (nth - 1) * 7;
    }

    function getSpringEquinoxDay(year) {
        return Math.floor(20.8431 + 0.242194 * (year - 1980)) - Math.floor((year - 1980) / 4);
    }

    function getAutumnEquinoxDay(year) {
        return Math.floor(23.2488 + 0.242194 * (year - 1980)) - Math.floor((year - 1980) / 4);
    }

    function changeCountry() {
        selectedCountry = document.getElementById('country-select').value;
        const title = document.getElementById('address-title');
        const zipLabel = document.getElementById('zip-label');
        const detailLabel = document.getElementById('address-detail-label');
        const searchTitle = document.getElementById('search-title');
        const searchLabel = document.getElementById('search-label');
        const zipInput = document.getElementById('zip-jp');
        const regionInput = document.getElementById('region-jp');
        const localityInput = document.getElementById('locality-jp');
        const streetInput = document.getElementById('street-jp');
        const tip = document.getElementById('zip-tip');
        const countryName = document.querySelector('.p-country-name');
        const addressCard = document.querySelector('#tab6 .module-card.h-adr, #tab6 .module-card[data-address-card="1"]');

        const config = {
            JP: {
                title: '📮 日本地址查询 (邮编)',
                zipLabel: '邮政区号 (7位数字自动查询)',
                detailLabel: '地址详情',
                zipPlaceholder: '例：1000001',
                searchTitle: '🔎 日本地址查询',
                searchLabel: '地址关键词（可不完整）',
                searchPlaceholder: '例：新宿 西新宿 2-8',
                regionPlaceholder: '都道府县',
                localityPlaceholder: '市区町村',
                streetPlaceholder: '街道',
                tip: '日本支持邮编自动回填；也可输入地址关键词查询。',
                countryName: 'Japan'
            },
            KR: {
                title: '📮 韩国地址查询',
                zipLabel: '邮政编码 / 地址关键词',
                detailLabel: '韩国地址详情',
                zipPlaceholder: '例：04524 / Seoul Gangnam',
                searchTitle: '🔎 韩国地址查询',
                searchLabel: '地址关键词或邮编',
                searchPlaceholder: '例：Seoul Gangnam / 04524',
                regionPlaceholder: '州 / 特别市',
                localityPlaceholder: '城市 / 区',
                streetPlaceholder: '街道 / 详细地址',
                tip: '韩国请输入邮编或地址关键词后点击“查询”。',
                countryName: 'South Korea'
            },
            SG: {
                title: '📮 新加坡地址查询',
                zipLabel: '邮政编码 / 地址关键词',
                detailLabel: '新加坡地址详情',
                zipPlaceholder: '例：018989 / Marina Bay',
                searchTitle: '🔎 新加坡地址查询',
                searchLabel: '地址关键词或邮编',
                searchPlaceholder: '例：Marina Bay / 018989',
                regionPlaceholder: '国家 / 区域',
                localityPlaceholder: '城市 / 区',
                streetPlaceholder: '街道 / 详细地址',
                tip: '新加坡请输入邮编或地址关键词后点击“查询”。',
                countryName: 'Singapore'
            },
            US: {
                title: '📮 美国地址查询',
                zipLabel: '邮政编码 / 地址关键词',
                detailLabel: '美国地址详情',
                zipPlaceholder: '例：10001 / Los Angeles',
                searchTitle: '🔎 美国地址查询',
                searchLabel: '地址关键词或邮编',
                searchPlaceholder: '例：Los Angeles / 10001',
                regionPlaceholder: '州',
                localityPlaceholder: '城市 / 县',
                streetPlaceholder: '街道 / 详细地址',
                tip: '美国请输入 ZIP Code 或地址关键词后点击“查询”。',
                countryName: 'United States'
            }
        }[selectedCountry];

        title.innerText = config.title;
        zipLabel.innerText = config.zipLabel;
        detailLabel.innerText = config.detailLabel;
        searchTitle.innerText = config.searchTitle;
        searchLabel.innerText = config.searchLabel;
        zipInput.placeholder = config.zipPlaceholder;
        document.getElementById('addr-query').placeholder = config.searchPlaceholder;
        regionInput.placeholder = config.regionPlaceholder;
        localityInput.placeholder = config.localityPlaceholder;
        streetInput.placeholder = config.streetPlaceholder;
        tip.innerText = config.tip;
        countryName.innerText = config.countryName;

        if (addressCard) {
            addressCard.dataset.addressCard = '1';
            if (selectedCountry === 'JP') addressCard.classList.add('h-adr');
            else addressCard.classList.remove('h-adr');
        }
        if (selectedCountry === 'JP') {
            zipInput.classList.add('p-postal-code');
            regionInput.classList.add('p-region');
            localityInput.classList.add('p-locality');
            streetInput.classList.add('p-street-address');
            regionInput.readOnly = true;
            localityInput.readOnly = true;
        } else {
            zipInput.classList.remove('p-postal-code');
            regionInput.classList.remove('p-region');
            localityInput.classList.remove('p-locality');
            streetInput.classList.remove('p-street-address');
            regionInput.readOnly = false;
            localityInput.readOnly = false;
        }

        zipInput.value = '';
        regionInput.value = '';
        localityInput.value = '';
        streetInput.value = '';
        clearAddressResults();
    }

    // 邮编复制
    function copyJpAddress() {
        const zip = document.getElementById('zip-jp').value.trim();
        const region = document.getElementById('region-jp').value.trim();
        const locality = document.getElementById('locality-jp').value.trim();
        const street = document.getElementById('street-jp').value.trim();
        const prefix = selectedCountry === 'JP' && zip ? `〒${zip} ` : (zip ? `${zip} ` : '');
        navigator.clipboard.writeText(`${prefix}${region} ${locality} ${street}`.trim())
            .then(() => showToast("地址已复制"));
    }

    // 地址模糊查询
    function extractPrefecture(text) {
        if (!text) return '';
        for (const p of PREFS) {
            if (text.includes(p)) return p;
        }
        return '';
    }

    async function searchAddress() {
        const q = document.getElementById('addr-query').value.trim() || document.getElementById('zip-jp').value.trim();
        const box = document.getElementById('addr-results');
        if (!q) return alert('请输入地址关键词或邮编');
        box.innerText = '查询中...';
        try {
            const url = selectedCountry === 'JP'
                ? 'https://msearch.gsi.go.jp/address-search/AddressSearch?q=' + encodeURIComponent(q)
                : 'https://nominatim.openstreetmap.org/search?format=jsonv2&addressdetails=1&limit=8&countrycodes=' + selectedCountry.toLowerCase() + '&q=' + encodeURIComponent(q);
            const res = await fetch(url);
            const data = await res.json();
            if (!Array.isArray(data) || data.length === 0) {
                box.innerText = '未找到结果';
                return;
            }
            renderAddressResults(data.slice(0, 8));
        } catch (e) {
            box.innerText = '查询失败，请稍后再试';
        }
    }

    function renderAddressResults(list) {
        const box = document.getElementById('addr-results');
        box.innerHTML = '';
        list.forEach(item => {
            const title = selectedCountry === 'JP'
                ? ((item && item.properties && item.properties.title) || item.title || '')
                : (item.display_name || '');
            const pref = selectedCountry === 'JP'
                ? (extractPrefecture(title) || '未识别')
                : extractRegion(item);

            const wrap = document.createElement('div');
            wrap.className = 'result-item';

            const t = document.createElement('div');
            t.className = 'result-title';
            t.innerText = title || '（无标题）';

            const p = document.createElement('div');
            p.innerHTML = `所在区域：<span class="result-pref">${pref || '未识别'}</span>`;

            const btnRow = document.createElement('div');
            btnRow.style.display = 'flex';
            btnRow.style.gap = '8px';
            btnRow.style.marginTop = '8px';

            const btnPref = document.createElement('button');
            btnPref.className = 'btn-main';
            btnPref.style.background = '#27ae60';
            btnPref.style.flex = '1';
            btnPref.innerText = selectedCountry === 'JP' ? '复制县名' : '复制区域';
            btnPref.onclick = () => copyText(pref);

            const btnAddr = document.createElement('button');
            btnAddr.className = 'btn-main';
            btnAddr.style.background = '#8e44ad';
            btnAddr.style.flex = '1';
            btnAddr.innerText = '复制地址';
            btnAddr.onclick = () => copyText(title);

            btnRow.appendChild(btnPref);
            btnRow.appendChild(btnAddr);
            if (selectedCountry !== 'JP') {
                const btnUse = document.createElement('button');
                btnUse.className = 'btn-main';
                btnUse.style.background = '#e67e22';
                btnUse.style.flex = '1';
                btnUse.innerText = '带入上方';
                btnUse.onclick = () => fillAddressFromResult(item);
                btnRow.appendChild(btnUse);
            }

            wrap.appendChild(t);
            wrap.appendChild(p);
            wrap.appendChild(btnRow);

            box.appendChild(wrap);
        });
    }

    function extractRegion(item) {
        const addr = (item && item.address) || {};
        return addr.state || addr.region || addr.county || addr.city || addr.country || '';
    }

    function fillAddressFromResult(item) {
        if (selectedCountry === 'JP') return;
        const addr = (item && item.address) || {};
        const zip = addr.postcode || '';
        const region = addr.state || addr.region || addr.country || '';
        const locality = addr.city || addr.town || addr.county || addr.suburb || '';
        const street = [
            addr.road,
            addr.house_number,
            addr.neighbourhood,
            addr.quarter
        ].filter(Boolean).join(' ');

        document.getElementById('zip-jp').value = zip;
        document.getElementById('region-jp').value = region;
        document.getElementById('locality-jp').value = locality;
        document.getElementById('street-jp').value = street || (item.display_name || '');
    }

    function clearAddressResults() {
        document.getElementById('addr-query').value = '';
        document.getElementById('addr-results').innerHTML = '';
    }

    function copyText(text) {
        if (!text) return;
        navigator.clipboard.writeText(text).then(() => showToast('已复制'));
    }

    function showToast(msg) {
        const t = document.getElementById('toast');
        t.innerText = msg;
        t.classList.add('show');
        setTimeout(() => t.classList.remove('show'), 2000);
    }

    const FC_DATA = [
        { code: 'KIX1', name: '堺', address: '〒590-8589 大阪府堺市堺区築港八幡町138-7', jpy2: 75000, jpy4: 90000, jpy10: 111000 },
        { code: 'KIX2', name: '大東', address: '〒574-8531 大阪府大東市緑が丘2-1-1', jpy2: 72000, jpy4: 88000, jpy10: 110000 },
        { code: 'KIX3', name: '茨木', address: '〒567-8507 大阪府茨木市松下町2-1', jpy2: 72000, jpy4: 88000, jpy10: 110000 },
        { code: 'KIX4', name: '藤井寺', address: '〒583-8533 大阪府藤井寺市津堂4-435', jpy2: 75000, jpy4: 90000, jpy10: 111000 },
        { code: 'KIX5', name: '京田辺', address: '〒610-0342 京都府京田辺市松井台1', jpy2: 70000, jpy4: 86000, jpy10: 108000 },
        { code: 'KIX6', name: '尼崎', address: '〒660-0843 兵庫県尼崎市海岸町20-1 ロジフロント尼崎 II', jpy2: 75000, jpy4: 90000, jpy10: 111000 },
        { code: 'TPB3', name: '西区', address: '〒651-2228 兵庫県神戸市西区見津が丘一丁目26', jpy2: 81000, jpy4: 96000, jpy10: 115000 },
        { code: 'TPB6', name: '川西市', address: '〒666-0117 兵庫県川西市東畦野字長尾1-38', jpy2: 75000, jpy4: 90000, jpy10: 111000 },
        { code: 'TPF3', name: '高槻', address: '〒569-0823 大阪府高槻市芝生町1-52-2', jpy2: 72000, jpy4: 78000, jpy10: 110000 },
        { code: 'VJNC', name: '門真', address: '〒571-0034 大阪府門真市東田町5-18', jpy2: 72000, jpy4: 88000, jpy10: 110000 },
        { code: 'VJNB', name: '神戸', address: '〒658-0023 兵庫県神戸市東灘区深江浜町65 株式会社ナカノ商', jpy2: 79000, jpy4: 94000, jpy10: 114000 },

        { code: 'NGO2', name: '多治見', address: '〒507-8585 岐阜県多治見市旭ヶ丘10-6', jpy2: 55000, jpy4: 70000, jpy10: 88000 },
        { code: 'TPF4', name: '稲沢', address: '〒492-8224 愛知県稲沢市奥田大沢町2-1', jpy2: 58000, jpy4: 75000, jpy10: 96000 },

        { code: 'TYO6', name: '坂戸', address: '〒350-0282 埼玉県坂戸市西インター1丁目2-1', jpy2: 25000, jpy4: 28000, jpy10: 40000 },
        { code: 'TYO7', name: '上尾', address: '〒362-8508 埼玉県上尾市大字堤崎字前谷85番地 (MCUD上尾)', jpy2: 25000, jpy4: 28000, jpy10: 40000 },
        { code: 'TPFC', name: '戸田', address: '〒335-0026 埼玉県戸田市新曽南4丁目3番76号', jpy2: 25000, jpy4: 28000, jpy10: 40000 },
        { code: 'TYO1', name: '川口', address: '〒332-0004 埼玉県川口市領家5-14-35', jpy2: 27000, jpy4: 30000, jpy10: 42000 },
        { code: 'TYO2', name: '久喜', address: '〒346-8511 埼玉県久喜市上清久字城敷1000-1', jpy2: 27000, jpy4: 30000, jpy10: 42000 },
        { code: 'NRT5', name: '川越', address: '〒350-1182 埼玉県川越市南台1-10-15', jpy2: 23000, jpy4: 25000, jpy10: 38000 },
        { code: 'HND3', name: '川島', address: '〒350-0195 埼玉県比企郡川島町かわじま2-1-1 2F', jpy2: 25000, jpy4: 28000, jpy10: 40000 },
        { code: 'TPF2', name: '吉見', address: '〒355-0157 埼玉県比企郡吉見町西吉見480 GLP 吉見', jpy2: 25000, jpy4: 28000, jpy10: 40000 },

        { code: 'TYO3', name: '府中', address: '〒183-8570 東京都府中市四谷5丁目23-62', jpy2: 27000, jpy4: 30000, jpy10: 42000 },
        { code: 'TYO4', name: '青梅', address: '〒198-8501 東京都青梅市末広町2-9-14 ランドポート青梅 III', jpy2: 25000, jpy4: 28000, jpy10: 40000 },
        { code: 'TPB5', name: '青梅', address: '〒198-8501 東京都青梅市末広町6丁目1-6-2', jpy2: 25000, jpy4: 28000, jpy10: 40000 },

        { code: 'TPX2', name: '印西', address: '〒270-1380 千葉県印西市松崎台2-4-3 アイミッションズパーク', jpy2: 33000, jpy4: 36000, jpy10: 48000 },
        { code: 'QCB4', name: '美浜区', address: '〒261-8528 千葉県千葉市美浜区新港68番1', jpy2: 33000, jpy4: 37000, jpy10: 50000 },
        { code: 'NRT1', name: '市川', address: '〒272-0193 千葉県市川市塩浜2-13-1', jpy2: 33000, jpy4: 36000, jpy10: 48000 },
        { code: 'NRT2', name: '八千代', address: '〒276-8525 千葉県八千代市上高野2036', jpy2: 33000, jpy4: 37000, jpy10: 50000 },
        { code: 'VJNA', name: '柏', address: '〒277-0931 千葉県柏市藤ヶ谷1823 ナカノ商会沼南物流', jpy2: 31000, jpy4: 34000, jpy10: 46000 },
        { code: 'QCB1', name: '流山', address: '〒270-0196 千葉県流山市西深井字早稲田1603 番地 1DPL 流山', jpy2: 31000, jpy4: 34000, jpy10: 46000 },

        { code: 'FSZ1', name: '小田原', address: '〒250-8560 神奈川県小田原市扇町4-5-1', jpy2: 35000, jpy4: 39000, jpy10: 52000 },
        { code: 'HFY1', name: '金沢', address: '神奈川県横浜市金沢区昭和町3-1 7-4', jpy2: 35000, jpy4: 39000, jpy10: 52000 },
        { code: 'TYO8', name: '相模原中央', address: '〒252-5220 神奈川県相模原市中央区田名字白雨台3532-10', jpy2: 32000, jpy4: 35000, jpy10: 47000 },
        { code: 'QCB5', name: '相模原', address: '〒252-5213 神奈川県相模原市中央区田名字白雨台3532-13', jpy2: 32000, jpy4: 35000, jpy10: 47000 },
        { code: 'TPFB', name: '伊勢原', address: '〒259-1116 神奈川県伊勢原市石田100', jpy2: 33000, jpy4: 37000, jpy10: 50000 },
        { code: 'VJNE', name: '平塚', address: '〒254-0012 神奈川県平塚市大神455-1', jpy2: 33000, jpy4: 37000, jpy10: 50000 },
        { code: 'XJE2', name: '厚木', address: '神奈川県愛甲郡愛川町中津4025番1 Orix厚木 II 5階', jpy2: 33000, jpy4: 36000, jpy10: 48000 },
        { code: 'XJE1', name: '海老名', address: '神奈川県海老名市中新田3290 MFLP海老名1 2階', jpy2: 33000, jpy4: 36000, jpy10: 48000 },
        { code: 'HND9', name: '川崎', address: '〒213-8517 神奈川県川崎市高津区北見方3-14-1', jpy2: 29000, jpy4: 32000, jpy10: 44000 },
        { code: 'HND6', name: '川崎', address: '〒213-8517 神奈川県川崎市高津区北見方3-14-1', jpy2: 29000, jpy4: 32000, jpy10: 44000 }
    ];

    let currentFc = null;
    let containerLang = 'zh';

    const CONTAINER_DATA = [
        {
            typeZh: '20尺普柜 20GP', typeEn: '20GP (General Purpose)',
            ext: '6.058 × 2.438 × 2.591', int: '5.898 × 2.350 × 2.390',
            door: '2.280 × 2.340', vol: '≈ 33', payload: '≈ 28,000',
            remarkZh: '最常用标准柜', remarkEn: 'Most common standard container'
        },
        {
            typeZh: '40尺普柜 40GP', typeEn: '40GP (General Purpose)',
            ext: '12.192 × 2.438 × 2.591', int: '12.032 × 2.350 × 2.390',
            door: '2.280 × 2.340', vol: '≈ 67', payload: '≈ 26,000',
            remarkZh: '常规柜型', remarkEn: 'Standard container'
        },
        {
            typeZh: '40尺高柜 40HQ/40HC', typeEn: '40HQ / 40HC (High Cube)',
            ext: '12.192 × 2.438 × 2.896', int: '12.032 × 2.350 × 2.695',
            door: '2.580 × 2.340', vol: '≈ 76', payload: '≈ 26,000',
            remarkZh: '比40GP高0.3米', remarkEn: '0.3m higher than 40GP'
        },
        {
            typeZh: '45尺高柜 45HQ/45HC', typeEn: '45HQ / 45HC (High Cube)',
            ext: '13.716 × 2.438 × 2.896', int: '13.556 × 2.350 × 2.695',
            door: '2.580 × 2.340', vol: '≈ 86', payload: '≈ 26,000',
            remarkZh: '大体积轻泡货常用', remarkEn: 'Common for bulky/light cargo'
        },
        {
            typeZh: '20尺高柜 20HQ/20HC', typeEn: '20HQ / 20HC (High Cube)',
            ext: '6.058 × 2.438 × 2.896', int: '5.898 × 2.350 × 2.695',
            door: '2.585 × 2.340', vol: '≈ 37–38', payload: '≈ 28,000',
            remarkZh: '特种柜，少见，部分航线使用', remarkEn: 'Special, rare, used on some routes'
        },
        {
            typeZh: '20尺开顶柜 20OT', typeEn: '20OT (Open Top)',
            ext: '6.058 × 2.438 × 2.591', int: '5.898 × 2.350 × 2.348',
            door: '顶部敞开', vol: '≈ 32', payload: '≈ 28,000',
            remarkZh: '顶部可吊装货物', remarkEn: 'Open top for top loading'
        },
        {
            typeZh: '40尺开顶柜 40OT', typeEn: '40OT (Open Top)',
            ext: '12.192 × 2.438 × 2.591', int: '12.032 × 2.350 × 2.348',
            door: '顶部敞开', vol: '≈ 66', payload: '≈ 26,000',
            remarkZh: '装载超高货物', remarkEn: 'For over-height cargo'
        },
        {
            typeZh: '20尺框架柜 20FR', typeEn: '20FR (Flat Rack)',
            ext: '6.058 × 2.438 × 2.591（无顶无侧）', int: '平台型',
            door: '无门', vol: '—', payload: '≈ 30,000',
            remarkZh: '大型机械设备使用', remarkEn: 'For large machinery'
        },
        {
            typeZh: '40尺框架柜 40FR', typeEn: '40FR (Flat Rack)',
            ext: '12.192 × 2.438 × 2.591（无顶无侧）', int: '平台型',
            door: '无门', vol: '—', payload: '≈ 40,000',
            remarkZh: '用于超长、超宽货物', remarkEn: 'For oversized cargo'
        }
    ];

    function toggleContainerLang() {
        containerLang = containerLang === 'zh' ? 'en' : 'zh';
        renderContainerTable();
    }

    function renderContainerTable() {
        const q = (document.getElementById('container-search')?.value || '').trim().toLowerCase();
        const body = document.getElementById('container-table-body');
        if (!body) return;
        body.innerHTML = '';

        const data = CONTAINER_DATA.filter(row => {
            if (!q) return true;
            const hay = [
                row.typeZh, row.typeEn, row.ext, row.int, row.door, row.vol, row.payload, row.remarkZh, row.remarkEn
            ].join(' ').toLowerCase();
            return hay.includes(q);
        });

        if (!data.length) {
            body.innerHTML = `<tr><td colspan="8" style="padding:12px; text-align:center; color:#999; border:1px solid #e6efe0;">未找到匹配的柜型数据</td></tr>`;
            return;
        }

        data.forEach((row, idx) => {
            const tr = document.createElement('tr');
            const bg = idx % 2 === 1 ? 'background:#f6fbf1;' : '';

            const typeText = containerLang === 'zh' ? row.typeZh : row.typeEn;
            const remarkText = containerLang === 'zh' ? row.remarkZh : row.remarkEn;
            const extText = row.ext;
            const intText = row.int;
            const doorText = row.door;
            const volText = row.vol;
            const payloadText = row.payload;

            const copyTextLine = `${typeText} | 外部:${extText} | 内部:${intText} | 门:${doorText} | 体积:${volText} | 载重:${payloadText} | 备注:${remarkText}`;

            tr.innerHTML = `
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${typeText}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${extText}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${intText}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${doorText}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${volText}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${payloadText}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${remarkText}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">
                    <button class="btn-main" style="background:#27ae60; padding:6px 8px; font-size:12px;" onclick="copyText('${copyTextLine.replace(/'/g, "\\'")}')">复制</button>
                </td>
            `;
            body.appendChild(tr);
        });
    }

    function renderShippingTable() {
        const body = document.getElementById('shipping-table-body');
        if (!body) return;
        body.innerHTML = '';

        SHIPPING_DATA.forEach((row, idx) => {
            const bg = idx % 2 === 1 ? 'background:#fffaf0;' : '';
            const copyLine = `${row.name} | 国家/地区:${row.country} | 背后企业/股东:${row.background} | 特点:${row.feature} | 免柜期参考:${row.freeTime}`;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="padding:8px; border:1px solid #ead59b; ${bg}">${row.name}</td>
                <td style="padding:8px; border:1px solid #ead59b; ${bg}">${row.country}</td>
                <td style="padding:8px; border:1px solid #ead59b; ${bg}">${row.background}</td>
                <td style="padding:8px; border:1px solid #ead59b; ${bg}">${row.feature}</td>
                <td style="padding:8px; border:1px solid #ead59b; ${bg}">${row.freeTime}</td>
                <td style="padding:8px; border:1px solid #ead59b; ${bg}">
                    <button class="btn-main" style="background:#27ae60; padding:6px 8px; font-size:12px;" onclick="copyText('${copyLine.replace(/'/g, "\\'")}')">复制</button>
                </td>
            `;
            body.appendChild(tr);
        });
    }

    function renderTruckTable() {
        const body = document.getElementById('truck-table-body');
        if (!body) return;
        body.innerHTML = '';
        const q = (document.getElementById('truck-search')?.value || '').trim().toLowerCase();
        const data = TRUCK_DATA.filter(row => {
            if (!q) return true;
            return [row.model, row.size, row.volume, row.weight, row.usage].join(' ').toLowerCase().includes(q);
        });

        if (!data.length) {
            body.innerHTML = `<tr><td colspan="6" style="padding:12px; text-align:center; color:#999; border:1px solid #e6efe0;">未找到匹配的货车数据</td></tr>`;
            return;
        }

        data.forEach((row, idx) => {
            const bg = idx % 2 === 1 ? 'background:#f6fbf1;' : '';
            const copyLine = `${row.model} | 尺寸:${row.size} | 方数:${row.volume} | 载重:${row.weight} | 用途:${row.usage}`;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.model}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.size}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.volume}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.weight}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.usage}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">
                    <button class="btn-main" style="background:#27ae60; padding:6px 8px; font-size:12px;" onclick="copyText('${copyLine.replace(/'/g, "\\'")}')">复制</button>
                </td>
            `;
            body.appendChild(tr);
        });
    }

    function renderJpTruckTable() {
        const body = document.getElementById('jp-truck-table-body');
        if (!body) return;
        body.innerHTML = '';
        const q = (document.getElementById('jp-truck-search')?.value || '').trim().toLowerCase();
        const data = JP_TRUCK_DATA.filter(row => {
            if (!q) return true;
            return [row.model, row.size, row.volume, row.weight, row.usage].join(' ').toLowerCase().includes(q);
        });

        if (!data.length) {
            body.innerHTML = `<tr><td colspan="6" style="padding:12px; text-align:center; color:#999; border:1px solid #e6efe0;">未找到匹配的日本货车数据</td></tr>`;
            return;
        }

        data.forEach((row, idx) => {
            const bg = idx % 2 === 1 ? 'background:#f5f9ff;' : '';
            const copyLine = `${row.model} | 尺寸:${row.size} | 方数:${row.volume} | 载重:${row.weight} | 用途:${row.usage}`;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.model}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.size}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.volume}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.weight}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.usage}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">
                    <button class="btn-main" style="background:#27ae60; padding:6px 8px; font-size:12px;" onclick="copyText('${copyLine.replace(/'/g, "\\'")}')">复制</button>
                </td>
            `;
            body.appendChild(tr);
        });
    }

    function renderKrTruckTable() {
        renderGenericTruckTable('kr-truck-search', 'kr-truck-table-body', KR_TRUCK_DATA, '未找到匹配的韩国货车数据', '#f5f9ff');
    }

    function renderSgTruckTable() {
        renderGenericTruckTable('sg-truck-search', 'sg-truck-table-body', SG_TRUCK_DATA, '未找到匹配的新加坡货车数据', '#f3fbf6');
    }

    function renderUsTruckTable() {
        renderGenericTruckTable('us-truck-search', 'us-truck-table-body', US_TRUCK_DATA, '未找到匹配的美国货车数据', '#fff6f6');
    }

    function renderGenericTruckTable(searchId, bodyId, dataset, emptyText, altBg) {
        const body = document.getElementById(bodyId);
        if (!body) return;
        body.innerHTML = '';
        const q = (document.getElementById(searchId)?.value || '').trim().toLowerCase();
        const data = dataset.filter(row => {
            if (!q) return true;
            return [row.model, row.size, row.volume, row.weight, row.usage].join(' ').toLowerCase().includes(q);
        });

        if (!data.length) {
            body.innerHTML = `<tr><td colspan="6" style="padding:12px; text-align:center; color:#999; border:1px solid #e6efe0;">${emptyText}</td></tr>`;
            return;
        }

        data.forEach((row, idx) => {
            const bg = idx % 2 === 1 ? `background:${altBg};` : '';
            const copyLine = `${row.model} | 尺寸:${row.size} | 方数:${row.volume} | 载重:${row.weight} | 用途:${row.usage}`;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.model}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.size}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.volume}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.weight}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.usage}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">
                    <button class="btn-main" style="background:#27ae60; padding:6px 8px; font-size:12px;" onclick="copyText('${copyLine.replace(/'/g, "\\'")}')">复制</button>
                </td>
            `;
            body.appendChild(tr);
        });
    }

    function searchFcByCode() {
        const code = document.getElementById('fc-code').value.trim().toUpperCase();
        if (!code) {
            currentFc = null;
            document.getElementById('fc-result').innerHTML = '';
            return;
        }
        currentFc = FC_DATA.find(x => x.code === code) || null;
        renderFcResult();
    }

    function renderFcResult() {
        const box = document.getElementById('fc-result');
        if (!currentFc) {
            if (document.getElementById('fc-code').value.trim()) {
                box.innerHTML = '<div class="result-item">未找到该仓库代码</div>';
            } else {
                box.innerHTML = '';
            }
            return;
        }

        const rate = parseFloat(document.getElementById('jpy-rate').value || '0');
        const toCny = (jpy) => rate ? (jpy * 1.1 * rate).toFixed(2) : '--';

        box.innerHTML = `
            <div class="result-item">
                <div class="result-title">${currentFc.code} · ${currentFc.name}</div>
                <div style="margin-bottom:6px;">${currentFc.address}</div>
                <div>2t：¥${currentFc.jpy2.toLocaleString()}（含税¥${Math.round(currentFc.jpy2 * 1.1).toLocaleString()}） → ${toCny(currentFc.jpy2)} CNY</div>
                <div>4t：¥${currentFc.jpy4.toLocaleString()}（含税¥${Math.round(currentFc.jpy4 * 1.1).toLocaleString()}） → ${toCny(currentFc.jpy4)} CNY</div>
                <div>10t：¥${currentFc.jpy10.toLocaleString()}（含税¥${Math.round(currentFc.jpy10 * 1.1).toLocaleString()}） → ${toCny(currentFc.jpy10)} CNY</div>
            </div>
        `;
    }

    function calcVolumetric() {
        const raw = document.getElementById('vol-size').value.trim().replace(/[xX*]/g, ' ');
        const parts = raw.split(/\s+/).map(Number).filter(Boolean);
        const qty = parseFloat(document.getElementById('vol-qty').value || '0');
        const actual = parseFloat(document.getElementById('vol-actual').value || '0');
        const divisor = parseFloat(document.getElementById('vol-divisor').value || '6000');
        const box = document.getElementById('vol-result');
        if (parts.length !== 3 || !qty) {
            box.innerText = '请输入完整的长宽高和件数';
            return;
        }
        const [l, w, h] = parts;
        const volumeCm = l * w * h * qty;
        const volumeM3 = volumeCm / 1000000;
        const volumetric = volumeCm / divisor;
        const chargeable = Math.max(actual, volumetric);
        box.innerText = `总体积：${volumeM3.toFixed(3)} m3\n材积重：${volumetric.toFixed(2)} kg\n实际重：${actual.toFixed(2)} kg\n计费重：${chargeable.toFixed(2)} kg`;
    }

    function detectCountryFromText(text) {
        const rules = [
            { code: 'JP', labels: ['日本', '东京', '大阪', '横滨', '神户', '名古屋'] },
            { code: 'KR', labels: ['韩国', '首尔', '釜山', '仁川'] },
            { code: 'SG', labels: ['新加坡', 'singapore', 'sg'] },
            { code: 'US', labels: ['美国', 'usa', 'us', 'los angeles', 'new york', 'chicago', 'houston'] },
            { code: 'CN', labels: ['中国', '国内', '大陆', 'china'] }
        ];
        const lower = text.toLowerCase();
        const matched = rules.find(rule => rule.labels.some(label => lower.includes(label.toLowerCase())));
        return matched ? matched.code : '';
    }

    function detectDivisorFromText(text) {
        const lower = text.toLowerCase();
        if (/(快递|express|courier|fedex|dhl|ups)/i.test(lower)) return '5000';
        if (/(特殊|special)/i.test(lower)) return '7000';
        if (/(空运|air|airfreight|air freight)/i.test(lower)) return '6000';
        return '';
    }

    function parseSmartCalcInput(text) {
        const normalized = text
            .replace(/[，、；;]+/g, ' ')
            .replace(/[（]/g, '(')
            .replace(/[）]/g, ')')
            .replace(/[×xX＊*]/g, '*')
            .replace(/\s+/g, ' ')
            .trim();

        let size = null;
        let volumeM3 = null;
        let weightKg = null;
        let qty = null;
        let country = detectCountryFromText(normalized);
        const divisor = detectDivisorFromText(normalized);

        const groups = [];
        const sizeRegex = /(\d+(?:\.\d+)?)\s*(cm|厘米|mm|毫米|m|米)?\s*\*\s*(\d+(?:\.\d+)?)\s*(cm|厘米|mm|毫米|m|米)?\s*\*\s*(\d+(?:\.\d+)?)\s*(cm|厘米|mm|毫米|m|米)?(?:\s*(?:\/|x|\+|,)?\s*(\d+(?:\.\d+)?)\s*(件|箱|票|托|托盘|木箱|板|ctn|carton|cartons|pcs|packages?))?/ig;
        let match;
        while ((match = sizeRegex.exec(normalized)) !== null) {
            const unitA = match[2] || '';
            const unitB = match[4] || '';
            const unitC = match[6] || '';
            const unit = unitA || unitB || unitC || 'cm';
            const factor = String(unit).toLowerCase() === 'm' || unit === '米'
                ? 100
                : (String(unit).toLowerCase() === 'mm' || unit === '毫米' ? 0.1 : 1);
            const dims = [
                parseFloat(match[1]) * factor,
                parseFloat(match[3]) * factor,
                parseFloat(match[5]) * factor
            ];
            let groupQty = parseFloat(match[7] || '1');
            let packageType = match[8] || '件';
            if (!match[7]) {
                const prefixText = normalized.slice(Math.max(0, match.index - 18), match.index);
                const prefixMatch = prefixText.match(/(\d+(?:\.\d+)?)\s*(件|箱|票|托|托盘|木箱|板|ctn|carton|cartons|pcs|packages?)\s*$/i);
                if (prefixMatch) {
                    groupQty = parseFloat(prefixMatch[1]);
                    packageType = prefixMatch[2];
                }
            }
            groups.push({
                size: dims,
                qty: groupQty,
                packageType,
                volumeM3: (dims[0] * dims[1] * dims[2] * groupQty) / 1000000
            });
        }

        if (groups.length) {
            size = groups[0].size;
            qty = groups.reduce((sum, item) => sum + item.qty, 0);
            volumeM3 = groups.reduce((sum, item) => sum + item.volumeM3, 0);
        }

        const qtyMatch = normalized.match(/(?:数量|件数|共|合计)?\s*(\d+(?:\.\d+)?)\s*(?:件|箱|票|托|托盘|ctn|carton|cartons|pcs|packages?)/i)
            || normalized.match(/(?:件数|数量)[:：]?\s*(\d+(?:\.\d+)?)/i);
        if (qtyMatch && !qty) qty = parseFloat(qtyMatch[1]);

        const tonMatch = normalized.match(/(?:重量|总货重|实重|总重|毛重)?[:：]?\s*(\d+(?:\.\d+)?)\s*(?:吨|t)\b/i);
        const kgMatch = normalized.match(/(?:重量|总货重|实重|总重|毛重)?[:：]?\s*(\d+(?:\.\d+)?)\s*(?:kg|kgs|公斤)\b/i);
        if (tonMatch) weightKg = parseFloat(tonMatch[1]) * 1000;
        else if (kgMatch) weightKg = parseFloat(kgMatch[1]);

        const cbmMatch = normalized.match(/(?:体积|方数|立方|cbm|m3|m³)[:：]?\s*(\d+(?:\.\d+)?)/i)
            || normalized.match(/(\d+(?:\.\d+)?)\s*(?:方|立方|cbm|m3|m³)\b/i);
        if (cbmMatch) volumeM3 = parseFloat(cbmMatch[1]);

        if (!volumeM3 && size && qty) {
            volumeM3 = (size[0] * size[1] * size[2] * qty) / 1000000;
        }

        return { size, qty, weightKg, volumeM3, country, divisor, groups };
    }

    function smartFillHighFreqCalc() {
        const text = (document.getElementById('smart-calc-input').value || '').trim();
        const box = document.getElementById('smart-calc-result');
        if (!text) {
            box.innerText = '请先输入货物描述、尺寸、件数、重量或目的国家信息。';
            return;
        }

        const parsed = parseSmartCalcInput(text);
        const actions = [];

        if (parsed.size) {
            document.getElementById('vol-size').value = parsed.size.map(v => Number.isInteger(v) ? v : v.toFixed(1)).join('*');
            actions.push(`尺寸 ${document.getElementById('vol-size').value} cm`);
        }
        if (parsed.qty) {
            document.getElementById('vol-qty').value = parsed.qty;
            actions.push(`件数 ${parsed.qty}`);
        }
        if (parsed.divisor) {
            document.getElementById('vol-divisor').value = parsed.divisor;
            const divisorLabel = { '5000': '快递 5000', '6000': '空运 6000', '7000': '特殊 7000' };
            actions.push(`计费系数 ${divisorLabel[parsed.divisor] || parsed.divisor}`);
        }
        if (parsed.weightKg !== null) {
            document.getElementById('vol-actual').value = parsed.weightKg;
            document.getElementById('cbm-weight').value = parsed.weightKg;
            document.getElementById('truck-kg').value = parsed.weightKg;
            actions.push(`重量 ${parsed.weightKg.toFixed(0)} kg`);
        }
        if (parsed.volumeM3 !== null) {
            document.getElementById('cbm-total').value = parsed.volumeM3.toFixed(3);
            document.getElementById('truck-vol').value = parsed.volumeM3.toFixed(3);
            actions.push(`体积 ${parsed.volumeM3.toFixed(3)} m3`);
        }
        if (parsed.country) {
            document.getElementById('truck-country').value = parsed.country;
            const countryLabels = { CN: '中国', JP: '日本', KR: '韩国', SG: '新加坡', US: '美国' };
            actions.push(`国家/地区 ${countryLabels[parsed.country]}`);
        }

        if (parsed.groups && parsed.groups.length > 1) {
            const actual = parsed.weightKg || 0;
            const divisor = parseFloat(document.getElementById('vol-divisor').value || '6000');
            const volumeCm = parsed.groups.reduce((sum, item) => sum + (item.size[0] * item.size[1] * item.size[2] * item.qty), 0);
            const volumetric = volumeCm / divisor;
            const chargeable = Math.max(actual, volumetric);
            const breakdown = parsed.groups.map((item, index) => `${index + 1}. ${item.size.map(v => Number.isInteger(v) ? v : v.toFixed(1)).join('*')} cm × ${item.qty}${item.packageType}`).join('\n');
            document.getElementById('vol-result').innerText = `识别到多组包装：\n${breakdown}\n总体积：${(volumeCm / 1000000).toFixed(3)} m3\n材积重：${volumetric.toFixed(2)} kg\n实际重：${actual.toFixed(2)} kg\n计费重：${chargeable.toFixed(2)} kg`;
            actions.push(`多组包装 ${parsed.groups.length} 组`);
        } else if (parsed.size && parsed.qty) {
            calcVolumetric();
        }
        if (parsed.volumeM3 !== null) calcContainerFit();
        if (parsed.volumeM3 !== null) recommendTruck();

        if (!actions.length) {
            box.innerText = '暂未识别到可用字段，请尽量带上尺寸、件数、体积、重量或国家，例如：60*40*50cm 12箱 180kg 日本，或 2托 120*100*150cm + 4箱 60*40*50cm。';
            return;
        }

        box.innerText = `已识别并带入：${actions.join('；')}\n已自动刷新可用计算结果。`;
        queueSaveAppState();
    }

    function clearSmartCalcInput() {
        document.getElementById('smart-calc-input').value = '';
        document.getElementById('smart-calc-result').innerText = '';
    }

    function calcContainerFit() {
        const cbm = parseFloat(document.getElementById('cbm-total').value || '0');
        const kg = parseFloat(document.getElementById('cbm-weight').value || '0');
        const candidates = CONTAINER_DATA.filter(row => row.vol !== '—').map(row => ({
            name: row.typeZh,
            vol: parseFloat(String(row.vol).replace(/[^\d.]/g, '')) || 0,
            payload: parseFloat(String(row.payload).replace(/[^\d.]/g, '').replace(',', '')) || 0
        }));
        const matched = candidates.filter(row => cbm <= row.vol && kg <= row.payload);
        const box = document.getElementById('cbm-result');
        if (!cbm) {
            box.innerText = '请输入总方数';
            return;
        }
        if (!matched.length) {
            box.innerText = '当前方数/重量可能超过单柜常规范围，建议拆柜或核对特种柜方案';
            return;
        }
        box.innerText = `推荐优先：${matched[0].name}\n可选柜型：${matched.map(x => x.name).join(' / ')}\n输入：${cbm.toFixed(2)} m3，${kg.toFixed(0)} kg`;
    }

    function recommendTruck() {
        const country = document.getElementById('truck-country').value;
        const vol = parseFloat(document.getElementById('truck-vol').value || '0');
        const kg = parseFloat(document.getElementById('truck-kg').value || '0');
        const datasets = { CN: TRUCK_DATA, JP: JP_TRUCK_DATA, KR: KR_TRUCK_DATA, SG: SG_TRUCK_DATA, US: US_TRUCK_DATA };
        const data = datasets[country] || [];
        const candidates = data.map(item => ({
            ...item,
            maxVol: parseFloat(String(item.volume).replace(/[^\d.]/g, '')) || 0,
            maxKg: (parseFloat(String(item.weight).replace(/[^\d.]/g, '')) || 0) * 1000
        })).filter(item => vol <= item.maxVol && kg <= item.maxKg);
        const box = document.getElementById('truck-rec-result');
        if (!vol) {
            box.innerText = '请输入总体积';
            return;
        }
        if (!candidates.length) {
            box.innerText = '未找到直接匹配车型，建议提高车型级别或拆单配送';
            return;
        }
        const best = candidates[0];
        box.innerText = `推荐车型：${best.model}\n尺寸：${best.size}\n参考方数：${best.volume}\n参考载重：${best.weight}\n用途：${best.usage}`;
    }

    function initTimezoneInput() {
        const now = new Date();
        const local = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
        const input = document.getElementById('tz-cn');
        if (input && !input.value) input.value = local;
    }

    function convertTimezones() {
        const value = document.getElementById('tz-cn').value;
        const box = document.getElementById('tz-result');
        if (!value) {
            box.innerText = '请选择中国时间';
            return;
        }
        const date = new Date(value);
        const map = [
            ['中国', 'Asia/Shanghai'],
            ['日本', 'Asia/Tokyo'],
            ['韩国', 'Asia/Seoul'],
            ['新加坡', 'Asia/Singapore'],
            ['美国西部', 'America/Los_Angeles'],
            ['美国东部', 'America/New_York']
        ];
        box.innerText = map.map(([label, tz]) => `${label}：${date.toLocaleString('zh-CN', { timeZone: tz, hour12: false })}`).join('\n');
    }

    function renderIncotermTable() {
        const body = document.getElementById('incoterm-table-body');
        if (!body) return;
        body.innerHTML = '';
        INCOTERM_DATA.forEach((row, idx) => {
            const bg = idx % 2 === 1 ? 'background:#f7fbff;' : '';
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.term}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.owner}</td>
                <td style="padding:8px; border:1px solid #e6efe0; ${bg}">${row.note}</td>
            `;
            body.appendChild(tr);
        });
    }

    function renderPortSearch() {
        const q = (document.getElementById('port-search')?.value || '').trim().toLowerCase();
        const box = document.getElementById('port-search-results');
        if (!box) return;
        const data = PORT_CODE_DATA.filter(row => !q || [row.code, row.type, row.name, row.country].join(' ').toLowerCase().includes(q));
        box.innerHTML = data.slice(0, 12).map(item => `
            <div class="result-item">
                <div class="result-title">${item.code} · ${item.name}</div>
                <div>${item.type} · ${item.country}</div>
            </div>
        `).join('') || '<div class="result-item">未找到结果</div>';
    }

    const GlobalSearchRegistry = {
        _handlers: [],
        
        register: function(config) {
            this._handlers.push({
                name: config.name,
                icon: config.icon || '🔍',
                keywords: config.keywords || [],
                storageKey: config.storageKey || null,
                staticData: config.staticData || null,
                searchFields: config.searchFields || [],
                formatResult: config.formatResult || ((item, name, icon) => `${icon} ${name}：${item.name || '-'}`),
                colorField: config.colorField || null,
                colorMap: config.colorMap || {}
            });
            this._updatePlaceholder();
        },
        
        _updatePlaceholder: function() {
            const names = this._handlers.map(h => h.name).join('、');
            const box = document.getElementById('global-search-results');
            if (box) {
                box.setAttribute('data-placeholder', `可搜索：${names}`);
            }
        },
        
        search: function(query) {
            const q = query.trim().toLowerCase();
            const results = [];
            
            this._handlers.forEach(handler => {
                try {
                    let data = [];
                    if (handler.storageKey) {
                        data = JSON.parse(localStorage.getItem(handler.storageKey) || '[]');
                    } else if (handler.staticData) {
                        data = handler.staticData;
                    } else if (typeof handler.getData === 'function') {
                        data = handler.getData();
                    }
                    
                    if (!Array.isArray(data)) {
                        if (typeof data === 'object' && data !== null) {
                            data = Object.entries(data).map(([key, value]) => ({ _key: key, _value: value }));
                        } else {
                            return;
                        }
                    }
                    
                    data.forEach(item => {
                        const searchValues = handler.searchFields.map(field => {
                            if (field === '_key') return item._key;
                            if (field === '_value') return item._value;
                            return item[field] || '';
                        });
                        
                        const searchStr = searchValues.join(' ').toLowerCase();
                        
                        if (searchStr.includes(q)) {
                            let color = null;
                            if (handler.colorField && handler.colorMap) {
                                const colorKey = item[handler.colorField];
                                color = handler.colorMap[colorKey];
                            }
                            
                            const result = handler.formatResult(item, handler.name, handler.icon, color);
                            if (result) results.push(result);
                        }
                    });
                } catch(e) {
                    console.warn(`搜索 ${handler.name} 时出错:`, e);
                }
            });
            
            return results.slice(0, 30);
        },
        
        getHandlerNames: function() {
            return this._handlers.map(h => h.name);
        }
    };

    GlobalSearchRegistry.register({
        name: '仓库',
        icon: '🏭',
        staticData: typeof FC_DATA !== 'undefined' ? FC_DATA : [],
        searchFields: ['code', 'name', 'address'],
        formatResult: (item, name, icon) => `${icon} ${name}：${item.code} ${item.name}`
    });

    GlobalSearchRegistry.register({
        name: '柜型',
        icon: '📦',
        staticData: typeof CONTAINER_DATA !== 'undefined' ? CONTAINER_DATA : [],
        searchFields: ['typeZh', 'typeEn', 'remarkZh'],
        formatResult: (item, name, icon) => `${icon} ${name}：${item.typeZh}`
    });

    GlobalSearchRegistry.register({
        name: '船司',
        icon: '🚢',
        staticData: typeof SHIPPING_DATA !== 'undefined' ? SHIPPING_DATA : [],
        searchFields: ['name', 'country', 'background'],
        formatResult: (item, name, icon) => `${icon} ${name}：${item.name}`
    });

    GlobalSearchRegistry.register({
        name: '货车',
        icon: '🚚',
        getData: function() {
            const all = [];
            if (typeof TRUCK_DATA !== 'undefined') all.push(...TRUCK_DATA);
            if (typeof JP_TRUCK_DATA !== 'undefined') all.push(...JP_TRUCK_DATA);
            if (typeof KR_TRUCK_DATA !== 'undefined') all.push(...KR_TRUCK_DATA);
            if (typeof SG_TRUCK_DATA !== 'undefined') all.push(...SG_TRUCK_DATA);
            if (typeof US_TRUCK_DATA !== 'undefined') all.push(...US_TRUCK_DATA);
            return all;
        },
        searchFields: ['model', 'size', 'usage'],
        formatResult: (item, name, icon) => `${icon} ${name}：${item.model}`
    });

    GlobalSearchRegistry.register({
        name: '港口',
        icon: '🌐',
        staticData: typeof PORT_CODE_DATA !== 'undefined' ? PORT_CODE_DATA : [],
        searchFields: ['code', 'name', 'country'],
        formatResult: (item, name, icon) => `${icon} ${name}：${item.code} ${item.name}`
    });

    GlobalSearchRegistry.register({
        name: 'CRM订单',
        icon: '📋',
        storageKey: 'hgcd_crm_fcl_v1',
        searchFields: ['orderno', 'mbl', 'hbl', 'client', 'pol', 'pod', 'shipaddr', 'recvaddr', 'status', 'carrier'],
        colorField: 'status',
        colorMap: {'询价':'#8e44ad','已下单':'#2980b9','已入库':'#3498db','已审单':'#9b59b6','已装柜':'#e67e22','已开船':'#16a085','已到港':'#27ae60','已清关':'#1f7a5c','已完结':'#7f8c8d','取消':'#c0392b'},
        formatResult: (item, name, icon, color) => {
            const c = color || '#95a5a6';
            return `<span style="color:${c};">${icon} ${name}</span>：${item.orderno || '-'} | ${item.client || '?'} | ${item.pol || '?'}→${item.pod || '?'} | <b style="color:${c};">${item.status || '-'}</b>`;
        }
    });

    GlobalSearchRegistry.register({
        name: '客户',
        icon: '👤',
        storageKey: 'logistics_client_data',
        searchFields: ['name', 'contact', 'phone', 'email', 'route', 'address'],
        colorField: 'level',
        colorMap: {'A':'#e74c3c','B':'#27ae60','C':'#f39c12'},
        formatResult: (item, name, icon, color) => {
            const c = color || '#3498db';
            return `<span style="color:${c};">${icon} ${name}</span>：${item.name} (${item.level || 'B'}级) | 联系人：${item.contact || '-'} | 航线：${item.route || '-'}`;
        }
    });

    GlobalSearchRegistry.register({
        name: '供应商',
        icon: '🏭',
        storageKey: 'logistics_supplier_data',
        searchFields: ['name', 'type', 'contact', 'phone', 'address'],
        formatResult: (item, name, icon) => `${icon} ${name}：${item.name} | 类型：${item.type || '-'} | 联系人：${item.contact || '-'}`
    });

    GlobalSearchRegistry.register({
        name: '运价',
        icon: '💰',
        storageKey: 'logistics_freight_data',
        searchFields: ['route', 'carrier', 'pol', 'pod', 'type'],
        formatResult: (item, name, icon) => `${icon} ${name}：${item.route || '-'} | 船司：${item.carrier || '-'} | 类型：${item.type || '-'}`
    });

    GlobalSearchRegistry.register({
        name: '提醒',
        icon: '🔔',
        storageKey: 'logistics_reminder_data',
        searchFields: ['title', 'content', 'client'],
        formatResult: (item, name, icon) => {
            const statusText = item.status === 'urgent' ? '紧急' : item.status === 'warning' ? '警告' : '正常';
            return `${icon} ${name}：${item.title} | 客户：${item.client || '-'} | 状态：${statusText}`;
        }
    });

    GlobalSearchRegistry.register({
        name: '待办',
        icon: '📝',
        storageKey: 'dashboard_todos_v1',
        searchFields: ['text'],
        formatResult: (item, name, icon) => {
            const done = item.done ? '✅' : '⬜';
            return `${icon} ${name}：${done} ${item.text}`;
        }
    });

    GlobalSearchRegistry.register({
        name: '日历备忘',
        icon: '📅',
        storageKey: 'hcn_calendar_memos',
        searchFields: ['_key', '_value'],
        formatResult: (item, name, icon) => {
            const text = item._value || '';
            return `${icon} ${name}：${item._key} - ${text.substring(0, 30)}${text.length > 30 ? '...' : ''}`;
        }
    });

    function renderGlobalSearch() {
        const q = (document.getElementById('global-search')?.value || '').trim().toLowerCase();
        const box = document.getElementById('global-search-results');
        if (!box) return;
        
        const names = GlobalSearchRegistry.getHandlerNames().join('、');
        
        if (!q) {
            box.innerHTML = `<div class="tool-result">可搜索：${names}</div>`;
            return;
        }
        
        const results = GlobalSearchRegistry.search(q);
        box.innerHTML = results.map(item => `<div class="result-item">${item}</div>`).join('') || '<div class="result-item">未找到匹配内容</div>';
    }

    function checkSensitiveCargo() {
        const checked = Array.from(document.querySelectorAll('.check-grid input:checked')).map(el => el.value);
        const box = document.getElementById('sensitive-result');
        if (!checked.length) {
            box.innerText = '当前未勾选敏感项，按普通货初步判断；正式出货前仍建议复核。';
            return;
        }
        const docs = new Set();
        const risks = [];

        checked.forEach(item => {
            const rule = SENSITIVE_CARGO_RULES[item];
            if (!rule) return;
            (rule.docs || []).forEach(doc => docs.add(doc));
            (rule.risks || []).forEach(risk => risks.push(`${item}：${risk}`));
        });

        box.innerText = [
            `已勾选：${checked.join('、')}`,
            `建议资料：${Array.from(docs).join('、') || '请人工确认'}`,
            `重点提醒：${risks.join('；') || '请结合具体货物再确认'}`
        ].join('\n');
    }

    function analyzeSensitiveProduct() {
        const text = (document.getElementById('sensitive-product-input').value || '').trim().toLowerCase();
        const box = document.getElementById('sensitive-result');
        if (!text) {
            box.innerText = '请输入客户产品信息后再识别。';
            return;
        }

        const matched = Object.entries(SENSITIVE_KEYWORDS)
            .filter(([, keywords]) => keywords.some(keyword => text.includes(keyword.toLowerCase())))
            .map(([type]) => type);

        document.querySelectorAll('.check-grid input[type="checkbox"]').forEach(el => {
            el.checked = matched.includes(el.value);
        });

        if (!matched.length) {
            box.innerText = '未识别到明确敏感特征，按普通货初步判断；建议人工再确认是否涉及带电、液体、粉末、品牌或特殊监管。';
            return;
        }

        checkSensitiveCargo();
        const current = box.innerText;
        box.innerText = `智能识别结果：${matched.join('、')}\n${current}`;
    }

    function clearSensitiveChecks() {
        document.getElementById('sensitive-product-input').value = '';
        document.querySelectorAll('.check-grid input[type="checkbox"]').forEach(el => {
            el.checked = false;
        });
        document.getElementById('sensitive-result').innerText = '';
    }

    function calcFees() {
        const ids = ['ocean', 'truck', 'customs', 'dest-port', 'clearance', 'delivery'];
        const labels = {
            ocean: '海运费+国内港杂',
            truck: '拖车费',
            customs: '报关费',
            'dest-port': '目的港杂',
            clearance: '清关费',
            delivery: '派送费'
        };
        let total = 0;
        const lines = ids.map(id => {
            const val = parseFloat(document.getElementById(`fee-${id}`).value || '0');
            total += val;
            return `${labels[id]}：${Math.round(val)}`;
        });
        lines.push(`总计：${Math.round(total)}`);
        document.getElementById('fee-result').innerText = lines.join('\n');
    }

    function saveShipmentNotes() {
        const value = document.getElementById('shipment-notes').value;
        localStorage.setItem('shipment_notes_v1', value);
        queueSaveAppState();
        updateStorageStatus();
        showToast('记录已保存');
    }

    function loadShipmentNotes() {
        const value = localStorage.getItem('shipment_notes_v1') || '';
        const box = document.getElementById('shipment-notes');
        if (box) box.value = value;
    }

    function copyToolResult(id) {
        const el = document.getElementById(id);
        if (el) copyText(el.innerText);
    }

    function copyJapanLawProducts() {
        const products = [
            '一、6岁以下儿童用品：产品包装上明显标注6岁以下儿童玩具、奶瓶、奶嘴、口水兜等',
            '二、与装食品器具和厨房用具（走货前先单询）：磨刀石、蛋糕模具、烤盘、刀具、锅碗瓢盆等直接或间接与食物接触的工具',
            '三、与医药、医疗器具相关：药型香片（如樟脑丸等）、针筒、冲牙器、医疗箱、药瓶药罐、B超仪、血压仪、按摩仪等',
            '四、与美容美发相关（走货前先单询）：修甲器、孔清洁器、美容仪、黑头神器、脱毛器、喷雾器、卷发器、直发器、电推剪、美甲',
            '五、与皮肤有渗透性接触的产品：肥皂、各类涂抹在皮肤上的产品',
            '六、含有有毒挥发性物质的产品：含有丙烯酸的颜料、含有化学物质的油墨类',
            '七、涉及到华盛顿条约的产品：珍稀动植物类的材质制成的产品等',
            '八、各类涉及知财的产品：品牌权、外观侵权、形象侵权等'
        ];
        const text = products.join('\n');
        copyText(text);
    }

    function updateDashboard() {
        const rateEl = document.getElementById('dashboard-rates-info');
        if (rateEl) {
            const cnyRate = getSafeRate('CNY');
            const jpyRate = getSafeRate('JPY');
            const usdRate = getSafeRate('USD') || 1;
            if (cnyRate && jpyRate) {
                const jpyCny = (cnyRate / jpyRate).toFixed(4);
                const usdCny = (cnyRate / usdRate).toFixed(4);
                rateEl.innerText = `JPY→CNY ${jpyCny} | USD→CNY ${usdCny}`;
            } else {
                rateEl.innerText = '使用备用汇率中...';
            }
        }

        const titleEl = document.getElementById('dashboard-holiday-title');
        const infoEl = document.getElementById('dashboard-holiday-info');
        if (titleEl && infoEl) {
            reminderLoadData();
            if (!reminderData.length) reminderGenerateFromCRM();
            
            const now = new Date();
            const year = now.getFullYear();
            const month = now.getMonth() + 1;
            const allReminders = [];
            
            // 添加CRM订单提醒
            const crmReminders = reminderData
                .slice()
                .sort((a, b) => a.daysLeft - b.daysLeft)
                .slice(0, 3)
                .map(item => `${item.date} ${item.title}`);
            allReminders.push(...crmReminders);
            
            // 添加本月财报季提醒（整个月都显示）
            const usEarningsWindows = {
                1: '美股Q4财报季', 2: '美股Q4财报季', 3: '美股Q4财报季',
                4: '美股Q1财报季', 5: '美股Q1财报季', 6: '美股Q1财报季',
                7: '美股Q2财报季', 8: '美股Q2财报季', 9: '美股Q2财报季',
                10: '美股Q3财报季', 11: '美股Q3财报季', 12: '美股Q3财报季'
            };
            if (usEarningsWindows[month] && allReminders.length < 5) {
                allReminders.push(`全月 ${usEarningsWindows[month]}`);
            }
            
            // 添加休市提醒
            const days = new Date(year, month, 0).getDate();
            for (let d = now.getDate(); d <= days && allReminders.length < 5; d++) {
                const holiday = getHolidayInfo(year, month, d);
                const market = getMarketClosures(year, month, d);
                if (holiday) allReminders.push(`${month}/${d} ${holiday.name}`);
                if (market.length) market.forEach(item => {
                    if (allReminders.length < 5 && (item.label.includes('休市') || item.label.includes('早收'))) {
                        allReminders.push(`${month}/${d} ${item.label}`);
                    }
                });
            }
            
            if (allReminders.length) {
                titleEl.innerText = '本月提醒';
                infoEl.innerText = allReminders.join(' | ');
            } else {
                titleEl.innerText = '本月平稳';
                infoEl.innerText = '本月暂无更多提醒';
            }
        }
    }

    function loadDashboardTodos() {
        const raw = localStorage.getItem('dashboard_todos_v1');
        const todos = raw ? JSON.parse(raw) : [];
        renderDashboardTodos(todos);
    }

    function saveDashboardTodos(todos) {
        localStorage.setItem('dashboard_todos_v1', JSON.stringify(todos));
        renderDashboardTodos(todos);
        queueSaveAppState();
        updateStorageStatus();
    }

    function addDashboardTodo() {
        const input = document.getElementById('dashboard-todo-input');
        const text = (input?.value || '').trim();
        if (!text) return;
        const raw = localStorage.getItem('dashboard_todos_v1');
        const todos = raw ? JSON.parse(raw) : [];
        todos.unshift({ id: Date.now(), text, done: false });
        saveDashboardTodos(todos);
        input.value = '';
    }

    function toggleDashboardTodo(id) {
        const raw = localStorage.getItem('dashboard_todos_v1');
        const todos = raw ? JSON.parse(raw) : [];
        const next = todos.map(item => item.id === id ? { ...item, done: !item.done } : item);
        saveDashboardTodos(next);
    }

    function removeDashboardTodo(id) {
        const raw = localStorage.getItem('dashboard_todos_v1');
        const todos = raw ? JSON.parse(raw) : [];
        saveDashboardTodos(todos.filter(item => item.id !== id));
    }

    function renderDashboardTodos(todos) {
        const box = document.getElementById('dashboard-todo-list');
        if (!box) return;
        if (!todos.length) {
            box.innerHTML = '<div class="tool-result">暂无待办，可把订舱、拖车、报关、派送提醒放这里。</div>';
            return;
        }
        box.innerHTML = todos.slice(0, 8).map(item => `
            <div class="todo-item">
                <div class="todo-left">
                    <input type="checkbox" ${item.done ? 'checked' : ''} onchange="toggleDashboardTodo(${item.id})">
                    <span class="${item.done ? 'todo-done' : ''}">${item.text}</span>
                </div>
                <button class="btn-main" style="background:#95a5a6; padding:4px 8px; font-size:12px; width:auto;" onclick="removeDashboardTodo(${item.id})">删除</button>
            </div>
        `).join('');
    }

    function initAutoSave() {
        document.addEventListener('input', handleAutoSaveEvent, true);
        document.addEventListener('change', handleAutoSaveEvent, true);
        document.addEventListener('visibilitychange', handleAutoBackupLifecycle, true);
        window.addEventListener('pagehide', handleAutoBackupLifecycle, true);
        window.addEventListener('beforeunload', handleAutoBackupLifecycle, true);
    }

    function handleAutoBackupLifecycle(evt) {
        // 页面隐藏/关闭时自动保存
        if (evt.type === 'pagehide' || evt.type === 'beforeunload' ||
            (evt.type === 'visibilitychange' && document.visibilityState === 'hidden')) {
            try {
                const payload = saveAppStateSync();
                localStorage.setItem(APP_STATE_KEY, payload);
            } catch(e) {}
        }
    }

    function handleAutoSaveEvent(event) {
        // 跳过 file input 和 iframe 内部事件
        if (!event.target || event.target.type === 'file') return;
        if (!document.getElementById(event.target.id || '_')) return;
        clearTimeout(saveTimer);
        saveTimer = setTimeout(() => {
            saveAppStateToLocal().catch(() => {});
        }, 2000);
    }

    function queueSaveAppState() {
        return;
    }

    function gatherAppState() {
        const controls = {};
        document.querySelectorAll('input[id], select[id], textarea[id]').forEach(el => {
            if (el.type === 'file') return;
            if (el.type === 'checkbox') controls[el.id] = el.checked;
            else controls[el.id] = el.value;
        });
        return {
            version: 1,
            savedAt: new Date().toISOString(),
            controls,
            memos,
            shipmentNotes: document.getElementById('shipment-notes')?.value || '',
            dashboardTodos: JSON.parse(localStorage.getItem('dashboard_todos_v1') || '[]'),
            extras: gatherExtraStorageState()
        };
    }

    function saveAppStateSync() {
        const state = gatherAppState();
        const payload = JSON.stringify(state);
        lastSavedAt = state.savedAt;
        return payload;
    }

    async function saveAppStateToLocal() {
        const payload = saveAppStateSync();
        try {
            localStorage.setItem(APP_STATE_KEY, payload);
            await idbSet(APP_STATE_KEY, payload);
        } catch (e) {}
    }

    async function saveAppStateNow() {
        await saveAppStateToLocal();
        updateStorageStatus();
        showToast('本地数据已保存');
    }

    async function restoreAppState() {
        try {
            let raw = localStorage.getItem(APP_STATE_KEY);
            if (!raw) {
                raw = await idbGet(APP_STATE_KEY);
            }
            if (!raw) return;
            const state = JSON.parse(raw);
            applyAppState(state);
            renderDashboardTodos(JSON.parse(localStorage.getItem('dashboard_todos_v1') || '[]'));
            loadShipmentNotes();
            crmRender();
            updateStorageStatus();
        } catch (e) {}
    }

    function applyAppState(state) {
        if (!state || !state.controls) return;
        Object.entries(state.controls).forEach(([id, value]) => {
            const el = document.getElementById(id);
            if (!el) return;
            if (el.type === 'file') return;
            if (el.type === 'checkbox') el.checked = !!value;
            else el.value = value;
        });
        if (state.memos && typeof state.memos === 'object') {
            memos = state.memos;
            localStorage.setItem('hcn_calendar_memos', JSON.stringify(memos));
        }
        if (typeof state.shipmentNotes === 'string') {
            localStorage.setItem('shipment_notes_v1', state.shipmentNotes);
        }
        if (Array.isArray(state.dashboardTodos)) {
            localStorage.setItem('dashboard_todos_v1', JSON.stringify(state.dashboardTodos));
        }
        restoreExtraStorageState(state.extras);
    }

    function exportAppState() {
        const state = gatherAppState();
        const blob = new Blob([JSON.stringify(state, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `logistics-workbench-${formatDate(new Date())}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(a.href);
        showToast('已导出 JSON');
    }

    function quickBackup() {
        try {
            const state = gatherAppState();
            const now = new Date();
            const timestamp = `${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}_${String(now.getHours()).padStart(2,'0')}${String(now.getMinutes()).padStart(2,'0')}`;
            const filename = `物流系统备份_${timestamp}.json`;
            const blob = new Blob([JSON.stringify(state, null, 2)], { type: 'application/json' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(a.href);
            showToast('✅ 备份已下载: ' + filename);
        } catch(e) {
            console.error('备份失败:', e);
            showToast('备份失败，请重试', true);
        }
    }

    function showQuickBackupModal(){
        const modal = document.getElementById('quick-backup-modal');
        const info = document.getElementById('quick-backup-info');
        modal.style.display = 'flex';
        const crmCount = crmLoad().length;
        const freightCount = freightData.length;
        const clientCount = clientData.length;
        const supplierCount = supplierData.length;
        const reminderCount = reminderData.length;
        const now = new Date();
        const timestamp = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')} ${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;
        info.innerHTML = `
            <div style="margin-bottom:10px;"><b>备份时间：</b>${timestamp}</div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
                <div>📦 CRM订单: <b>${crmCount}</b></div>
                <div>💰 运价记录: <b>${freightCount}</b></div>
                <div>👥 客户档案: <b>${clientCount}</b></div>
                <div>🏭 供应商: <b>${supplierCount}</b></div>
                <div>⏰ 提醒事项: <b>${reminderCount}</b></div>
            </div>
        `;
    }

    function hideQuickBackupModal(){
        document.getElementById('quick-backup-modal').style.display = 'none';
    }

    function executeQuickBackup(){
        updateActivity();
        hideQuickBackupModal();
        quickBackup();
    }

    function triggerImportState() {
        const input = document.getElementById('state-import-file');
        if (input) input.click();
    }

    async function importAppStateFromFile(event) {
        const file = event.target.files && event.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = async () => {
            try {
                const state = JSON.parse(reader.result);
                applyAppState(state);
                await saveAppStateToLocal();
                renderDashboardTodos(JSON.parse(localStorage.getItem('dashboard_todos_v1') || '[]'));
                loadShipmentNotes();
                renderGlobalSearch();
                renderPortSearch();
                renderContainerTable();
                renderShippingTable();
                renderTruckTable();
                renderJpTruckTable();
                renderKrTruckTable();
                renderSgTruckTable();
                renderUsTruckTable();
                initCalendar();
                updateDashboard();
                updateStorageStatus();
                crmRender();
                clientLoadData();
                clientRender();
                supplierLoadData();
                supplierRender();
                reminderLoadData();
                reminderRefresh();
                reconciliationLoadData();
                reconciliationGenerateFromCRM();
                reconciliationRender();
                freightLoadData();
                freightRender();
                showToast('已导入数据');
            } catch (e) {
                showToast('导入失败');
            }
            event.target.value = '';
        };
        reader.readAsText(file, 'utf-8');
    }

    async function bindCloudFile() {
        if (!window.showSaveFilePicker) {
            showToast('当前浏览器不支持云端文件绑定');
            return;
        }
        try {
            cloudFileHandle = await window.showSaveFilePicker({
                suggestedName: 'logistics-workbench-data.json',
                types: [{ description: 'JSON Files', accept: { 'application/json': ['.json'] } }]
            });
            updateStorageStatus();
            showToast('已绑定文件，可放在 iCloud Drive');
        } catch (e) {}
    }

    async function syncToCloudFile() {
        if (!cloudFileHandle) {
            showToast('请先绑定文件');
            return;
        }
        try {
            const writable = await cloudFileHandle.createWritable();
            await writable.write(JSON.stringify(gatherAppState(), null, 2));
            await writable.close();
            lastSavedAt = new Date().toISOString();
            updateStorageStatus();
            showToast('已同步到文件');
        } catch (e) {
            showToast('同步失败');
        }
    }

    function clearCloudBinding() {
        cloudFileHandle = null;
        updateStorageStatus();
        showToast('已清除云端绑定');
    }

    async function updateStorageStatus() {
        const el = document.getElementById('storage-status');
        if (!el) return;
        let localState = localStorage.getItem(APP_STATE_KEY);
        if (!localState) {
            try {
                localState = await idbGet(APP_STATE_KEY);
            } catch (e) {}
        }
        const cloudName = cloudFileHandle ? cloudFileHandle.name : '未绑定';
        const inlineEl = document.getElementById('dashboard-backup-inline');
        let localInfo = '本地自动保存：已关闭';
        let inlineText = '备份时间：未记录';
        if (localState) {
            try {
                const state = JSON.parse(localState);
                const savedText = formatReadableTime(state.savedAt || lastSavedAt);
                localInfo = `本地手动保存：已存在
    最后保存：${savedText}`;
                inlineText = `备份时间：${savedText}`;
            } catch (e) {
                localInfo = '本地手动保存：已存在';
                inlineText = '手动备份：已存在';
            }
        }
        el.innerText = `${localInfo}
    云端文件：${cloudName}`;
        if (inlineEl) inlineEl.innerText = inlineText;
    }
    function formatReadableTime(iso) {
        if (!iso) return '未记录';
        const date = new Date(iso);
        if (Number.isNaN(date.getTime())) return '未记录';
        return date.toLocaleString('zh-CN', { hour12: false });
    }

    function updateDashboardNow() {
        const el = document.getElementById('dashboard-now');
        if (!el) return;
        const now = new Date();
        el.innerText = now.toLocaleString('zh-CN', {
            hour12: false,
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }

    function appendHomeQuoteWidget(container, symbol, tile) {
        const loadingEl = document.createElement('div');
        loadingEl.className = 'quote-widget-loading';
        loadingEl.innerHTML = '<span style="font-size:11px;color:#888;">加载中...</span>';
        container.appendChild(loadingEl);
        
        const script = document.createElement('script');
        script.type = 'text/javascript';
        script.src = 'https://s3.tradingview.com/external-embedding/embed-widget-single-quote.js';
        script.async = true;
        const isDark = document.body.classList.contains('dark-mode');
        script.innerHTML = JSON.stringify({
            symbol: HOME_QUOTE_TV_SYMBOL_MAP[symbol] || symbol,
            width: '100%',
            colorTheme: isDark ? 'dark' : 'light',
            isTransparent: true,
            locale: 'zh_CN',
            showSymbolLogo: false
        });
        
        let loaded = false;
        const timeout = setTimeout(() => {
            if (!loaded) {
                loadingEl.innerHTML = '<button onclick="this.parentElement._retry()" style="font-size:10px;color:#e74c3c;background:none;border:1px solid #e74c3c;padding:2px 6px;border-radius:4px;cursor:pointer;">重试</button>';
                loadingEl._retry = () => {
                    loadingEl.innerHTML = '<span style="font-size:11px;color:#888;">加载中...</span>';
                    appendHomeQuoteWidget(container, symbol, tile);
                };
            }
        }, 10000);
        
        script.onload = script.onerror = function() {
            loaded = true;
            clearTimeout(timeout);
            setTimeout(() => {
                if (loadingEl.parentNode) loadingEl.remove();
            }, 500);
        };
        
        container.appendChild(script);
    }

    function buildQuoteModalUrl(label, symbol) {
        const base = 'https://hg-inves3-0.vercel.app/';
        const params = new URLSearchParams({
            from: 'workbench-quote',
            focusLabel: label,
            focusSymbol: HOME_QUOTE_TV_SYMBOL_MAP[symbol] || symbol
        });
        return `${base}?${params.toString()}`;
    }

    function openQuoteModal(label, symbol) {
        const modal = document.getElementById('quote-modal');
        const title = document.getElementById('quote-modal-title');
        const frame = document.getElementById('quote-modal-frame');
        const loading = document.getElementById('quote-modal-loading');
        if (!modal || !title || !frame) return;
        title.innerText = `${label} · 原页面`;
        if (loading) loading.classList.remove('hidden');
        frame.src = buildQuoteModalUrl(label, symbol);
        frame.onload = function() {
            if (loading) loading.classList.add('hidden');
        };
        modal.classList.add('show');
        document.body.style.overflow = 'hidden';
    }

    function closeQuoteModal(event) {
        if (event && event.target && event.target !== event.currentTarget) return;
        const modal = document.getElementById('quote-modal');
        const frame = document.getElementById('quote-modal-frame');
        const loading = document.getElementById('quote-modal-loading');
        if (!modal || !frame) return;
        modal.classList.remove('show');
        frame.src = 'about:blank';
        frame.onload = null;
        if (loading) loading.classList.remove('hidden');
        document.body.style.overflow = '';
    }

    function renderHomeQuoteGrid() {
        const grid = document.getElementById('home-quote-grid');
        if (!grid || grid.dataset.ready === 'true') return;
        grid.innerHTML = '';

        HOME_QUOTE_SYMBOLS.forEach((item, index) => {
            const tile = document.createElement('div');
            tile.className = 'market-quote-tile';
            tile.dataset.symbol = item.symbol;
            tile.dataset.index = index;

            const label = document.createElement('div');
            label.className = 'market-quote-label';
            label.textContent = item.label;

            const widgetWrap = document.createElement('div');
            widgetWrap.className = 'market-quote-widget tradingview-widget-container';
            widgetWrap.dataset.symbol = item.symbol;

            const widgetTarget = document.createElement('div');
            widgetTarget.className = 'tradingview-widget-container__widget';
            widgetWrap.appendChild(widgetTarget);

            const loadingEl = document.createElement('div');
            loadingEl.className = 'quote-widget-loading';
            loadingEl.innerHTML = '<span style="font-size:11px;color:#888;">等待加载...</span>';
            widgetWrap.appendChild(loadingEl);

            const overlay = document.createElement('button');
            overlay.type = 'button';
            overlay.className = 'market-quote-overlay';
            overlay.setAttribute('aria-label', `${item.label} 原页面`);
            overlay.onclick = () => openQuoteModal(item.label, item.symbol);

            tile.appendChild(label);
            tile.appendChild(widgetWrap);
            tile.appendChild(overlay);
            grid.appendChild(tile);
            
            if (index < 4) {
                loadingEl.innerHTML = '<span style="font-size:11px;color:#888;">加载中...</span>';
                appendHomeQuoteWidget(widgetWrap, item.symbol, tile);
            }
        });

        grid.dataset.ready = 'true';
        
        if (homeQuoteObserver) homeQuoteObserver.disconnect();
        homeQuoteObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const tile = entry.target;
                    const index = parseInt(tile.dataset.index);
                    if (index < 4) return;
                    
                    const symbol = tile.dataset.symbol;
                    const widgetWrap = tile.querySelector('.market-quote-widget');
                    const loadingEl = widgetWrap.querySelector('.quote-widget-loading');
                    
                    if (loadingEl && loadingEl.innerHTML.includes('等待加载')) {
                        loadingEl.innerHTML = '<span style="font-size:11px;color:#888;">加载中...</span>';
                        appendHomeQuoteWidget(widgetWrap, symbol, tile);
                    }
                    homeQuoteObserver.unobserve(tile);
                }
            });
        }, { rootMargin: '100px', threshold: 0.1 });
        
        grid.querySelectorAll('.market-quote-tile').forEach(tile => {
            const index = parseInt(tile.dataset.index);
            if (index >= 4) {
                homeQuoteObserver.observe(tile);
            }
        });
    }

    function toggleTimeIsPanel() {
        switchTab(9);
        const panel = document.getElementById('timeis-panel');
        const btn = document.getElementById('timeis-toggle-btn');
        if (!panel || !btn) return;
        const opening = panel.style.display === 'none' || !panel.style.display;
        panel.style.display = opening ? 'block' : 'none';
        btn.innerText = opening ? '返回首页' : '时间';
        if (opening) {
            panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } else {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
    }

    function toggleToolSection(name) {
        const section = document.getElementById(`section-${name}`);
        const button = document.getElementById(`toggle-${name}`);
        if (!section || !button) return;
        const opening = section.style.display === 'none';
        section.style.display = opening ? 'block' : 'none';
        button.innerText = opening ? '折叠' : '展开';
        button.style.background = opening ? '#95a5a6' : '#1f7a5c';
    }

    function openStoragePanel() {
        const storageSection = document.getElementById('section-storage');
        const storageBtn = document.getElementById('toggle-storage');
        if (storageSection && storageBtn && storageSection.style.display === 'none') {
            toggleToolSection('storage');
        }
        const tab = document.getElementById('tab9');
        if (tab) {
            tab.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        const storageCard = document.getElementById('section-storage');
        if (storageCard) {
            storageCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }

    function openLabelTool() {
        switchTab(14);
    }






    function ensureEmbeddedFrameLoaded(frameId) {
        const frame = document.getElementById(frameId);
        if (!frame) return;
        const templateId = frame.dataset.template;
        if (!templateId) return;
        const template = document.getElementById(templateId);
        if (!template) return;
        if (frame.dataset.loaded === 'true') return;
        frame.srcdoc = template.innerHTML;
        frame.dataset.loaded = 'true';
    }

    function setNewsBrowser(type) {
        const frame = document.getElementById('news-browser-frame');
        if (!frame) return;
        const sources = {
            war: 'https://iran.immersivetranslate.com/zh-CN/'
        };
        frame.src = sources[type] || sources.war;
    }

    function openNewsBrowser(type = 'war') {
        switchTab(13);
        setNewsBrowser(type);
    }

    // 清除投资工具缓存
    function clearInvestmentToolsCache() {
        if (!confirm('确定要清除投资工具的所有缓存吗？\n\n这将清除：\n- LocalStorage\n- SessionStorage\n- IndexedDB\n- Service Worker缓存\n\n清除后建议刷新页面。')) {
            return;
        }

        const clearLog = [];
        
        try {
            // 1. 清除LocalStorage
            localStorage.clear();
            clearLog.push('✅ LocalStorage已清除');
        } catch (e) {
            clearLog.push('❌ LocalStorage清除失败: ' + e.message);
        }
        
        try {
            // 2. 清除SessionStorage
            sessionStorage.clear();
            clearLog.push('✅ SessionStorage已清除');
        } catch (e) {
            clearLog.push('❌ SessionStorage清除失败: ' + e.message);
        }
        
        try {
            // 3. 清除IndexedDB（投资工具数据库）
            if (window.indexedDB) {
                indexedDB.deleteDatabase('macro_persistence_v2');
                indexedDB.deleteDatabase('macro_state_v2');
                indexedDB.deleteDatabase('rsi_state_v2');
                clearLog.push('✅ IndexedDB已清除');
            }
        } catch (e) {
            clearLog.push('❌ IndexedDB清除失败: ' + e.message);
        }
        
        // 4. 清除Service Worker缓存（异步）
        if ('caches' in window) {
            caches.keys().then(names => {
                names.forEach(name => {
                    caches.delete(name);
                });
                clearLog.push('✅ Service Worker缓存已清除');
                showResult();
            }).catch(e => {
                clearLog.push('❌ Service Worker缓存清除失败: ' + e.message);
                showResult();
            });
        } else {
            showResult();
        }
        
        function showResult() {
            alert('缓存清除完成！\n\n' + clearLog.join('\n') + '\n\n请刷新页面以使更改生效。');
            
            // 刷新iframe
            try {
                const investFrame = document.getElementById('invest-online-frame');
                const macroFrame = document.getElementById('macro-online-frame');
                
                if (investFrame) {
                    investFrame.src = investFrame.src;
                }
                if (macroFrame) {
                    macroFrame.src = macroFrame.src;
                }
            } catch (e) {
                console.log('刷新iframe失败:', e);
            }
        }
    }

    // 加载快捷报价
    function loadQuickQuotes() {
        const quotes = document.querySelectorAll('.quick-quote-item .tradingview-widget-container');
        quotes.forEach(container => {
            const symbol = container.dataset.symbol;
            if (!symbol) return;
            
            // 创建TradingView single-quote widget
            const script = document.createElement('script');
            script.src = 'https://s3.tradingview.com/external-embedding/embed-widget-single-quote.js';
            script.async = true;
            script.innerHTML = JSON.stringify({
                symbol: symbol,
                width: '100%',
                colorTheme: 'light',
                isTransparent: true,
                locale: 'zh_CN',
                showSymbolLogo: false
            });
            
            container.innerHTML = '';
            container.appendChild(script);
        });
    }

    function resolveOriginPort(address) {
        const rule = PORT_RECOMMENDATION_RULES.find(item => item.keywords.some(key => address.includes(key)));
        if (!rule) {
            return {
                primary: '需人工判断',
                secondary: '比较最近主港与邻近主干港',
                reason: '未命中内置起运地规则，建议先比较拖车费、港杂费、船期和实际海运费。'
            };
        }
        return rule;
    }

    function resolveDestinationPort(address) {
        const rule = DESTINATION_PORT_RULES.find(item => item.keywords.some(key => address.includes(key)));
        if (!rule) {
            return {
                primary: '需人工判断',
                secondary: '比较最近主港与常见主干港',
                reason: '未命中内置目的地规则，建议结合清关便利性、末端派送距离和船期判断。'
            };
        }
        return rule;
    }

    function runBookingAdvisor() {
        const origin = (document.getElementById('booking-origin').value || '').trim();
        const destination = (document.getElementById('booking-destination').value || '').trim();
        const container = document.getElementById('booking-container').value;
        const weight = parseFloat(document.getElementById('booking-weight').value || '0');
        const priority = document.getElementById('booking-priority').value;
        const note = (document.getElementById('booking-note').value || '').trim();
        const box = document.getElementById('booking-result');

        if (!origin || !destination) {
            box.innerText = '请输入起运地址和目的收货地址';
            return;
        }

        const originRule = resolveOriginPort(origin);
        const destRule = resolveDestinationPort(destination);
        const carriers = getCarrierSuggestions(destination, priority);
        const strategy = priority === 'cost'
            ? '成本优先：主看主港/干线港的海运费、港杂费和舱位弹性'
            : priority === 'speed'
                ? '时效优先：优先直达或快线，免柜期通常更紧，需更早锁舱'
                : '平衡型：在海运费、拖车费、船期稳定性之间做综合比较';

        const checks = [
            '比较主推荐港与备选港的拖车费和港杂费',
            '确认船司放舱节奏、截关时间、免柜期',
            '核对目的港清关便利性与末端派送距离',
            '根据柜型和重量确认是否有重柜/偏港附加费风险'
        ];

        box.innerText = [
            `起运地址：${origin}`,
            `目的地址：${destination}`,
            `柜型/重量：${container} / ${weight.toFixed(0)} kg`,
            `时效偏好：${priority === 'cost' ? '成本优先' : priority === 'speed' ? '时效优先' : '平衡成本与时效'}`,
            `建议出口港：${originRule.primary}`,
            `出口港备选：${originRule.secondary}`,
            `建议目的港：${destRule.primary}`,
            `目的港备选：${destRule.secondary}`,
            `推荐逻辑：起运地 ${originRule.reason} | 目的地 ${destRule.reason}`,
            `建议船司：${carriers.join(' / ')}`,
            `策略建议：${strategy}`,
            `操作检查：${checks.join('；')}${note ? `\n补充备注：${note}` : ''}`,
            '提示：这是规则型订舱助手，适合前期判断；正式订舱前仍建议核对实时海运费、拖车费、港杂费、船期和免柜期。'
        ].join('\n');
    }

    function getCarrierSuggestions(destination, priority) {
        const matched = BOOKING_CARRIER_RULES.find(item => item.match.some(key => destination.includes(key)));
        if (!matched) {
            return priority === 'speed' ? ['Maersk', 'CMA CGM', 'MSC'] : priority === 'cost' ? ['MSC', 'COSCO', 'EMC'] : ['MSC', 'Maersk', 'COSCO'];
        }
        return matched[priority] || matched.balanced;
    }

    // =====================================================
    // CRM 整柜台账系统
    // =====================================================
    const CRM_KEY = 'hgcd_crm_fcl_v1';

    const CRM_STATUS_COLOR = {
        '询价':   '#8e44ad',
        '已下单': '#2980b9',
        '已入库': '#3498db',
        '已审单': '#9b59b6',
        '已装柜': '#e67e22',
        '已开船': '#16a085',
        '已到港': '#27ae60',
        '已清关': '#1f7a5c',
        '已完结': '#7f8c8d',
        '取消':   '#c0392b',
    };

    function crmLoad() {
        try { 
            const data = JSON.parse(localStorage.getItem(CRM_KEY) || '[]');
            return data.map(r => {
                const fixed = { ...r };
                if (!fixed.id) {
                    fixed.id = crypto.randomUUID();
                }
                if (!fixed.bizType) {
                    fixed.bizType = 'fcl';
                }
                if (!fixed.status) {
                    fixed.status = '询价';
                }
                if (!fixed.createdAt) {
                    fixed.createdAt = new Date().toISOString();
                }
                if (!fixed.updatedAt) {
                    fixed.updatedAt = new Date().toISOString();
                }
                if (!fixed.statusHistory) {
                    fixed.statusHistory = [];
                }
                // 修复tags字段：确保始终是数组
                if (!fixed.tags) {
                    fixed.tags = [];
                } else if (typeof fixed.tags === 'string') {
                    // 如果tags是字符串，转换为数组
                    fixed.tags = fixed.tags.split(',').map(t => t.trim()).filter(t => t);
                } else if (!Array.isArray(fixed.tags)) {
                    // 如果tags既不是字符串也不是数组，设为空数组
                    fixed.tags = [];
                }
                return fixed;
            });
        } catch(e) { return []; }
    }
    function crmSave(data) {
        localStorage.setItem(CRM_KEY, JSON.stringify(data));
        crmAutoSync();
    }

    function isSettlementPaid(status) {
        return status === '已结算';
    }

    function getSettlementPaidAmount(total, status) {
        if (!total) return 0;
        if (status === '已结算' || status === '已收款' || status === '已付款') return total;
        if (status === '部分结算' || status === '部分收款' || status === '部分付款') return total / 2;
        return 0;
    }

    let autoSyncTimeout = null;
    function crmAutoSync() {
        const autoSync = localStorage.getItem('crm_auto_sync') === 'true';
        if (!autoSync) return;
        
        if (autoSyncTimeout) {
            clearTimeout(autoSyncTimeout);
        }
        
        autoSyncTimeout = setTimeout(() => {
            // 使用兼容逻辑获取API配置
            const apiUrl = getEffectiveApiUrl();
            const apiKey = getEffectiveApiKey();
            
            if (!apiUrl || !apiKey) return;
            
            const data = crmLoad();
            if (!data.length) return;
            
            const syncData = data.map(r => ({
                id: r.id || crypto.randomUUID(),
                bizType: r.bizType || 'fcl',
                client: r.client || '',
                orderno: r.orderno || '',
                clientOrderNo: r.clientOrderNo || '',
                mbl: r.mbl || '',
                hbl: r.hbl || '',
                shipMode: r.shipMode || '',
                pol: r.pol || '',
                pod: r.pod || '',
                shipaddr: r.shipaddr || '',
                recvaddr: r.recvaddr || '',
                ctype: r.ctype || '',
                cqty: r.cqty || 1,
                carrier: r.carrier || '',
                vessel: r.vessel || '',
                goods: r.goods || '',
                weight: r.weight || 0,
                pkgs: r.pkgs || 0,
                cbm: r.cbm || 0,
                billWeight: r.billWeight || 0,
                unitPrice: r.unitPrice || 0,
                bookedDate: r.bookedDate || '',
                loadedDate: r.loadedDate || '',
                cutoff: r.cutoff || '',
                etd: r.etd || '',
                eta: r.eta || '',
                ata: r.ata || '',
                clearedDate: r.clearedDate || '',
                pickup: r.pickup || '',
                deliveryDate: r.deliveryDate || '',
                freetime: r.freetime || '',
                signed: r.signed || '',
                warehouse: r.warehouse || '',
                flight: r.flight || '',
                airSigned: r.airSigned || '',
                airBookedDate: r.airBookedDate || '',
                airAta: r.airAta || '',
                airClearedDate: r.airClearedDate || '',
                tracking: r.tracking || '',
                carrierType: r.carrierType || '',
                status: r.status || '',
                settlementStatus: r.settlementStatus || '未结算',
                incoterm: r.incoterm || '',
                tags: r.tags || [],
                notes: r.notes || '',
                fees: r.fees || null,
                costs: r.costs || null,
                receivable: r.receivable || 0,
                payable: r.payable || 0,
                profit: r.profit || 0,
                margin: r.margin || 0,
                statusHistory: r.statusHistory || [],
                createdAt: r.createdAt || new Date().toISOString(),
                updatedAt: r.updatedAt || new Date().toISOString()
            }));
            
            const allData = collectCloudBackupData();
            allData.orders = syncData;

            fetch(apiUrl + '/api/sync-all', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${apiKey}`
                },
                body: JSON.stringify(allData)
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    console.log('自动同步成功:', result.message);
                }
            })
            .catch(error => {
                console.error('自动同步失败:', error);
            });
        }, 3000);
    }

    function safeReadJsonStorage(key, fallback) {
        try {
            const raw = localStorage.getItem(key);
            return raw ? JSON.parse(raw) : fallback;
        } catch(e) {
            return fallback;
        }
    }

    function collectCloudBackupData() {
        const allData = {
            orders: crmLoad(),
            clients: safeReadJsonStorage('logistics_client_data', []),
            suppliers: safeReadJsonStorage('logistics_supplier_data', []),
            airQuotes: [],
            fclQuotes: [],
            todos: safeReadJsonStorage('dashboard_todos_v1', []),
            calendarMemos: [],
            shipmentNotes: null,
            appState: null,
            apiConfigs: getApiConfigs(),
            currentApiId: localStorage.getItem('crm_current_api_id') || 'default'
        };

        const airQuotesData = safeReadJsonStorage('freight_air_cache_v1', null);
        if (airQuotesData) allData.airQuotes = [{ id: '1', data: airQuotesData }];

        const fclQuotesData = safeReadJsonStorage('freight_fcl_cache_v1', null);
        if (fclQuotesData) allData.fclQuotes = [{ id: '1', data: fclQuotesData }];

        const memosData = safeReadJsonStorage('hcn_calendar_memos', null);
        if (memosData && typeof memosData === 'object') {
            allData.calendarMemos = Object.entries(memosData).map(([date, content]) => ({
                id: (crypto && crypto.randomUUID) ? crypto.randomUUID() : `${Date.now()}-${date}`,
                date,
                content
            }));
        }

        const shipmentNotes = localStorage.getItem('shipment_notes_v1');
        if (shipmentNotes) allData.shipmentNotes = shipmentNotes;

        allData.appState = safeReadJsonStorage('logistics_workbench_state_v1', null);

        return allData;
    }

    function crmGenerateTrackingData() {
        const orders = crmLoad();
        
        if (orders.length === 0) {
            showToast('❌ 没有订单数据');
            return;
        }
        
        const sixtyDaysAgo = new Date();
        sixtyDaysAgo.setDate(sixtyDaysAgo.getDate() - 60);
        
        const filteredOrders = orders.filter(order => {
            const orderDate = new Date(order.updatedAt || order.createdAt);
            return orderDate >= sixtyDaysAgo;
        });
        
        const cleanData = filteredOrders.map(order => ({
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
            airBookedDate: order.airBookedDate,
            airAta: order.airAta,
            airClearedDate: order.airClearedDate,
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
        
        const jsonStr = JSON.stringify(cleanData, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'tracking-data.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        showToast(`✅ 已生成轨迹数据文件（${cleanData.length}条订单）`);
    }

    const CRM_STATUS_CONFIG = {
        '询价': { color: '#8e44ad', icon: '📋', order: 1 },
        '已下单': { color: '#2980b9', icon: '📝', order: 2 },
        '已入库': { color: '#3498db', icon: '📦', order: 3 },
        '已审单': { color: '#9b59b6', icon: '📝', order: 4 },
        '已装柜': { color: '#e67e22', icon: '🚛', order: 5 },
        '已开船': { color: '#16a085', icon: '🚢', order: 6 },
        '已到港': { color: '#27ae60', icon: '⚓', order: 7 },
        '已清关': { color: '#1f7a5c', icon: '✓', order: 8 },
        '已完结': { color: '#7f8c8d', icon: '🎉', order: 9 },
        '取消': { color: '#c0392b', icon: '✗', order: 0 }
    };

    function crmCloseTimelineModal() {
        const modal = document.getElementById('crm-timeline-modal');
        modal.style.display = 'none';
    }

    function crmBuildTimelineHtml(order) {
        const currentStatusOrder = (CRM_STATUS_CONFIG[order.status] || {}).order || 0;
        const shipMode = order.shipMode || '';
        const isAir = shipMode === '空运';
        const isExpress = shipMode === '快递';
        const isFcl = shipMode === '海运整柜' || shipMode === '整柜';
        const isLcl = shipMode === '普船拼箱' || shipMode === '快船拼柜' || shipMode === '拼箱' || shipMode === '海运散货';
        
        const statusHistory = order.statusHistory || [];
        const statusTimestamps = {};
        statusHistory.forEach(entry => {
            statusTimestamps[entry.status] = entry.timestamp;
        });
        
        function getStatusDate(status, fallbackDate) {
            return statusTimestamps[status] || fallbackDate;
        }
        
        function formatDate(dateStr) {
            if (!dateStr) return null;
            try {
                const date = new Date(dateStr);
                if (isNaN(date.getTime())) return null;
                return {
                    date: date.toLocaleDateString('zh-CN', { month: '2-digit', day: '2-digit' }),
                    time: date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
                };
            } catch(e) {
                return null;
            }
        }
        
        let milestones = [];
        
        if (isFcl) {
            milestones = [
                { key: 'created', label: '订单创建', date: getStatusDate('询价', order.createdAt), icon: '📋', status: '询价' },
                { key: 'booked', label: '已下单', date: getStatusDate('已下单', order.bookedDate), icon: '📝', status: '已下单' },
                { key: 'loaded', label: '已装柜', date: getStatusDate('已装柜', order.loadedDate), icon: '🚛', status: '已装柜' },
                { key: 'departed', label: '已开船', date: getStatusDate('已开船', order.etd), icon: '🚢', status: '已开船' },
                { key: 'arrived', label: '已到港', date: getStatusDate('已到港', order.ata || order.eta), icon: '⚓', status: '已到港' },
                { key: 'cleared', label: '已清关', date: getStatusDate('已清关', order.clearedDate), icon: '✓', status: '已清关' },
                { key: 'pickup', label: '提柜', date: order.pickup, icon: '🚚', status: '已到港' },
                { key: 'delivery', label: '派送', date: order.deliveryDate, icon: '📦', status: '已清关' },
                { key: 'delivered', label: '已签收', date: getStatusDate('已完结', order.signed), icon: '🎉', status: '已完结' }
            ];
        } else {
            milestones = [
                { key: 'created', label: '订单创建', date: getStatusDate('询价', order.createdAt), icon: '📋', status: '询价' },
                { key: 'ordered', label: '已下单', date: getStatusDate('已下单', order.airBookedDate || order.bookedDate), icon: '📝', status: '已下单' },
                { key: 'received', label: '已收货', date: getStatusDate('已入库', order.warehouse), icon: '📦', status: '已入库' },
                { key: 'shipped', label: '已发出', date: getStatusDate('已审单', null), icon: '🚚', status: '已审单' },
                { key: 'flight', label: isAir ? '飞行中' : '运输中', date: getStatusDate('已开船', order.flight), icon: isAir ? '✈️' : '🚛', status: '已开船' },
                { key: 'arrived', label: '已到港', date: getStatusDate('已到港', order.airAta || order.ata || order.eta), icon: '⚓', status: '已到港' },
                { key: 'cleared', label: '已清关', date: getStatusDate('已清关', order.airClearedDate || order.clearedDate), icon: '✓', status: '已清关' },
                { key: 'express', label: '快递派送', date: order.tracking ? `单号: ${order.tracking}` : null, icon: '📦', status: '已清关', extra: order.carrierType ? `承运商: ${order.carrierType}` : null },
                { key: 'delivered', label: '已签收', date: getStatusDate('已完结', order.airSigned || order.signed), icon: '🎉', status: '已完结' }
            ];
        }
        
        const orderInfoHtml = `
            <div class="crm-timeline-order-info">
                <h3>📦 ${order.orderno || '订单'} - ${order.status || '未知状态'}</h3>
                ${order.clientOrderNo && order.clientOrderNo.trim() ? `<p><strong>客户单号：</strong>${order.clientOrderNo}</p>` : ''}
                <p><strong>航线：</strong>${order.pol || '—'} → ${order.pod || '—'}</p>
                <p><strong>运输方式：</strong>${order.shipMode || '—'}</p>
                ${order.goods ? `<p><strong>货物：</strong>${order.goods}</p>` : ''}
            </div>
        `;
        
        const visibleMilestones = milestones.filter(m => {
            const statusOrder = (CRM_STATUS_CONFIG[m.status] || {}).order || 0;
            const isCompleted = currentStatusOrder > statusOrder;
            const isCurrent = currentStatusOrder === statusOrder;
            const dateInfo = formatDate(m.date);
            const hasDate = dateInfo && dateInfo.date;
            
            if (m.date && typeof m.date === 'string' && !m.date.includes('T') && (m.date.includes('单号') || m.date.includes(':'))) {
                return true;
            }
            
            if (!hasDate && !isCompleted && !isCurrent) {
                return false;
            }
            
            return true;
        });
        
        const timelineHtml = visibleMilestones.map(m => {
            const statusOrder = (CRM_STATUS_CONFIG[m.status] || {}).order || 0;
            const isCompleted = currentStatusOrder > statusOrder;
            const isCurrent = currentStatusOrder === statusOrder;
            const dateInfo = formatDate(m.date);
            const hasDate = dateInfo && dateInfo.date;
            
            let itemClass = 'crm-timeline-item';
            if (isCompleted) itemClass += ' completed';
            if (isCurrent) itemClass += ' current';
            
            let dateDisplay = '';
            if (hasDate) {
                dateDisplay = `<span class="crm-timeline-date">${dateInfo.date} ${dateInfo.time}</span>`;
            } else if (m.date && typeof m.date === 'string' && !m.date.includes('T')) {
                dateDisplay = `<span class="crm-timeline-date">${m.date}</span>`;
            } else if (isCompleted) {
                dateDisplay = '<span class="crm-timeline-status completed">✓ 已完成</span>';
            } else if (isCurrent) {
                dateDisplay = '<span class="crm-timeline-status current">● 进行中</span>';
            } else {
                dateDisplay = '<span class="crm-timeline-status pending">○ 待处理</span>';
            }
            
            const dotIcon = isCompleted ? '✓' : isCurrent ? m.icon : m.icon;
            
            return `
                <div class="${itemClass}">
                    <div class="crm-timeline-header">
                        <div class="crm-timeline-dot">${dotIcon}</div>
                        <div class="crm-timeline-title">${m.label}</div>
                    </div>
                    <div style="margin-left:30px;">
                        ${dateDisplay}
                        ${m.extra ? `<span class="crm-timeline-date" style="margin-left:8px;">${m.extra}</span>` : ''}
                    </div>
                </div>
            `;
        }).join('');
        
        return orderInfoHtml + `<div class="crm-timeline-grid">${timelineHtml}</div>`;
    }

    let crmCurrentTimelineOrder = null;

    function crmShowTimelineModal() {
        const selectedIds = Array.from(crmSelectedIds);
        
        if (selectedIds.length === 0) {
            showToast('❌ 请先勾选一个订单');
            return;
        }
        
        if (selectedIds.length > 1) {
            showToast('❌ 每次只能选择一个订单生成轨迹图');
            return;
        }
        
        const orders = crmLoad();
        const order = orders.find(o => String(o.id) === String(selectedIds[0]));
        
        if (!order) {
            showToast('❌ 未找到订单');
            return;
        }
        
        crmCurrentTimelineOrder = order;
        
        const modal = document.getElementById('crm-timeline-modal');
        const content = document.getElementById('crm-timeline-content');
        
        content.innerHTML = crmBuildTimelineHtml(order);
        modal.style.display = 'block';
    }

    async function crmShareTimelineAsImage() {
        console.log('crmShareTimelineAsImage called');
        const content = document.getElementById('crm-timeline-content');
        const shareBtns = document.getElementById('crm-timeline-share-btns');
        
        if (!content) {
            showToast('❌ 未找到内容区域');
            return;
        }
        
        console.log('html2canvas type:', typeof html2canvas);
        if (typeof html2canvas === 'undefined') {
            showToast('❌ 图片生成库未加载，请刷新页面重试');
            return;
        }
        
        shareBtns.style.display = 'none';
        showToast('正在生成图片...');
        
        const isDarkMode = document.body.classList.contains('dark-mode');
        console.log('isDarkMode:', isDarkMode);
        
        try {
            if (isDarkMode) {
                document.body.classList.remove('dark-mode');
                await new Promise(r => requestAnimationFrame(r));
                await new Promise(r => setTimeout(r, 100));
            }
            
            console.log('Starting html2canvas...');
            const canvas = await html2canvas(content, {
                scale: 2,
                backgroundColor: '#ffffff',
                useCORS: true,
                logging: false
            });
            console.log('html2canvas completed, canvas:', canvas);
            
            if (isDarkMode) {
                document.body.classList.add('dark-mode');
            }
            
            const order = crmCurrentTimelineOrder || {};
            const orderNo = order.orderno || order.mbl || 'tracking';
            const fileName = `轨迹图_${orderNo}.png`;
            
            canvas.toBlob(function(blob) {
                if (!blob) {
                    showToast('❌ 图片生成失败');
                    shareBtns.style.display = 'flex';
                    return;
                }
                
                const file = new File([blob], fileName, { type: 'image/png' });
                
                if (navigator.share && navigator.canShare && navigator.canShare({ files: [file] })) {
                    navigator.share({
                        title: `订单轨迹 - ${orderNo}`,
                        text: `订单 ${orderNo} 的物流轨迹`,
                        files: [file]
                    }).then(() => {
                        showToast('✅ 分享成功！');
                    }).catch((err) => {
                        console.log('分享取消:', err);
                        crmDownloadTimelineImage(canvas, orderNo);
                    }).finally(() => {
                        shareBtns.style.display = 'flex';
                    });
                } else {
                    crmDownloadTimelineImage(canvas, orderNo);
                    shareBtns.style.display = 'flex';
                }
            }, 'image/png');
        } catch (error) {
            if (isDarkMode) {
                document.body.classList.add('dark-mode');
            }
            console.error('图片生成失败:', error);
            showToast('❌ 图片生成失败: ' + error.message);
            shareBtns.style.display = 'flex';
        }
    }

    function crmDownloadTimelineImage(canvas, orderNo) {
        try {
            const link = document.createElement('a');
            link.download = `轨迹图_${orderNo}.png`;
            link.href = canvas.toDataURL('image/png');
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            showToast('✅ 图片已下载！');
        } catch (e) {
            showToast('❌ 下载失败，请长按图片保存');
        }
    }

    async function crmShareTimelineAsPDF() {
        const content = document.getElementById('crm-timeline-content');
        const shareBtns = document.getElementById('crm-timeline-share-btns');
        
        if (!content) {
            showToast('❌ 未找到内容区域');
            return;
        }
        
        if (typeof html2canvas === 'undefined' || typeof window.jspdf === 'undefined') {
            showToast('❌ PDF生成库未加载，请刷新页面重试');
            return;
        }
        
        shareBtns.style.display = 'none';
        showToast('正在生成PDF...');
        
        try {
            const canvas = await html2canvas(content, {
                scale: 2,
                backgroundColor: '#ffffff',
                useCORS: true,
                logging: false
            });
            
            const imgData = canvas.toDataURL('image/png');
            const { jsPDF } = window.jspdf;
            const pdf = new jsPDF('p', 'mm', 'a4');
            
            const pageWidth = 210;
            const pageHeight = 297;
            const margin = 10;
            const imgWidth = pageWidth - margin * 2;
            const imgHeight = (canvas.height * imgWidth) / canvas.width;
            
            let heightLeft = imgHeight;
            let position = margin;
            
            pdf.addImage(imgData, 'PNG', margin, position, imgWidth, imgHeight);
            heightLeft -= (pageHeight - margin * 2);
            
            while (heightLeft > 0) {
                position = heightLeft - imgHeight + margin;
                pdf.addPage();
                pdf.addImage(imgData, 'PNG', margin, position, imgWidth, imgHeight);
                heightLeft -= (pageHeight - margin * 2);
            }
            
            const order = crmCurrentTimelineOrder || {};
            const shipMode = order.shipMode || '海运';
            const orderNo = order.orderno || order.mbl || 'tracking';
            const date = new Date().toISOString().slice(0, 10);
            const fileName = `${shipMode}_${orderNo}_${date}.pdf`;
            
            const pdfBlob = pdf.output('blob');
            const pdfFile = new File([pdfBlob], fileName, { type: 'application/pdf' });
            
            let shared = false;
            if (navigator.share && navigator.canShare && navigator.canShare({ files: [pdfFile] })) {
                try {
                    await navigator.share({ 
                        files: [pdfFile], 
                        title: `订单轨迹 - ${orderNo}`,
                        text: `订单 ${orderNo} 的物流轨迹PDF`
                    });
                    shared = true;
                    showToast('✅ PDF分享成功！');
                } catch (shareErr) {
                    console.log('分享取消:', shareErr);
                }
            }
            
            if (!shared) {
                pdf.save(fileName);
                showToast('✅ PDF已下载！');
            }
        } catch (error) {
            console.error('PDF生成失败:', error);
            showToast('❌ PDF生成失败: ' + error.message);
        }
        
        shareBtns.style.display = 'flex';
    }

    function crmToggleShipMode() {
        const modalTitle = document.getElementById('crm-modal-title');
        const editId = document.getElementById('crm-edit-id')?.value;
        const shipMode = document.getElementById('crm-f-shipmode')?.value || '';
        const isLcl = shipMode === '普船拼箱' || shipMode === '快船拼柜' || shipMode === '空运' || shipMode === '快递';
        const isFcl = shipMode === '海运整柜';
        const isAirOrExpress = shipMode === '空运' || shipMode === '快递';
        
        if (modalTitle) modalTitle.textContent = editId ? `编辑${shipMode || '订单'}` : `新增${shipMode || '订单'}`;
        const routeTitle = document.getElementById('crm-route-title');
        const cargoTitle = document.getElementById('crm-cargo-title');
        if (routeTitle) routeTitle.textContent = isFcl ? '航线 & 柜型' : '航线 & 运输';
        if (cargoTitle) cargoTitle.textContent = isFcl ? '货物信息' : '货物信息 & 计费';
        
        const ctypeWrap = document.getElementById('crm-ctype-wrap');
        const cqtyWrap = document.getElementById('crm-cqty-wrap');
        const billWeightWrap = document.getElementById('crm-bill-weight-wrap');
        const unitPriceWrap = document.getElementById('crm-unit-price-wrap');
        const fclFeeArea = document.getElementById('crm-fcl-fee-area');
        const lclFeeArea = document.getElementById('crm-lcl-fee-area');
        
        if (ctypeWrap) ctypeWrap.style.display = isFcl ? 'block' : 'none';
        if (cqtyWrap) cqtyWrap.style.display = isFcl ? 'block' : 'none';
        if (billWeightWrap) billWeightWrap.style.display = 'block';
        if (unitPriceWrap) unitPriceWrap.style.display = 'block';
        if (fclFeeArea) fclFeeArea.style.display = isFcl ? 'block' : 'none';
        if (lclFeeArea) lclFeeArea.style.display = isLcl ? 'block' : 'none';
        
        const mblWrap = document.getElementById('crm-mbl-wrap');
        const hblWrap = document.getElementById('crm-hbl-wrap');
        const polWrap = document.getElementById('crm-pol-wrap');
        const podWrap = document.getElementById('crm-pod-wrap');
        const carrierWrap = document.getElementById('crm-carrier-wrap');
        const vesselWrap = document.getElementById('crm-vessel-wrap');
        
        if (mblWrap) mblWrap.style.display = isAirOrExpress ? 'none' : 'block';
        if (hblWrap) hblWrap.style.display = isAirOrExpress ? 'none' : 'block';
        if (polWrap) polWrap.style.display = isAirOrExpress ? 'none' : 'block';
        if (podWrap) podWrap.style.display = isAirOrExpress ? 'none' : 'block';
        if (carrierWrap) carrierWrap.style.display = isAirOrExpress ? 'none' : 'block';
        if (vesselWrap) vesselWrap.style.display = isAirOrExpress ? 'none' : 'block';
        
        crmToggleKeyDates();
        crmUpdateFeeTotal();
    }

    function crmToggleKeyDates() {
        const shipMode = document.getElementById('crm-f-shipmode')?.value || '';
        const isAirOrExpress = shipMode === '空运' || shipMode === '快递';
        
        const seaDates = document.getElementById('crm-sea-dates');
        const airDates = document.getElementById('crm-air-dates');
        
        if (isAirOrExpress) {
            if (seaDates) seaDates.style.display = 'none';
            if (airDates) airDates.style.display = 'grid';
        } else {
            if (seaDates) seaDates.style.display = 'grid';
            if (airDates) airDates.style.display = 'none';
        }
    }
    function crmNextId(data) {
        const max = data.reduce((m, r) => Math.max(m, r.id || 0), 0);
        return max + 1;
    }

    function crmGenOrderNo() {
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
        const orderNo = `HGCD-${year}${month}${day}-${random}`;
        document.getElementById('crm-f-orderno').value = orderNo;
    }

    function crmShowAddModal() {
        ['crm-f-client','crm-f-orderno','crm-f-clientorderno','crm-f-mbl','crm-f-hbl','crm-f-pol','crm-f-pod','crm-f-shipaddr','crm-f-recvaddr','crm-f-shipmode',
        'crm-f-carrier','crm-f-vessel','crm-f-goods','crm-f-weight','crm-f-pkgs','crm-f-cbm',
        'crm-f-billweight','crm-f-unitprice','crm-f-bookeddate','crm-f-loadeddate','crm-f-cutoff','crm-f-etd','crm-f-eta','crm-f-ata','crm-f-cleareddate','crm-f-pickup','crm-f-deliverydate','crm-f-freetime','crm-f-signed',
        'crm-f-warehouse','crm-f-flight','crm-f-air-signed','crm-f-air-bookeddate','crm-f-air-ata','crm-f-air-cleareddate',
        'crm-f-lcl-billweight','crm-f-lcl-price','crm-f-lcl-extra','crm-f-lcl-tax','crm-f-lcl-commodity','crm-f-lcl-fumigation','crm-f-lcl-delivery','crm-f-lcl-cost-price','crm-f-lcl-cost-extra','crm-f-lcl-cost-tax','crm-f-lcl-cost-delivery',
        'crm-f-fee-ocean','crm-f-fee-truck','crm-f-fee-customs','crm-f-fee-tax','crm-f-fee-inspection','crm-f-fee-commodity','crm-f-fee-fumigation','crm-f-fee-other',
        'crm-f-tracking','crm-f-carrier-type',
        'crm-f-notes'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
        document.getElementById('crm-f-shipmode').value = '海运整柜';
        document.getElementById('crm-f-ctype').value = '';
        document.getElementById('crm-f-cqty').value = '1';
        document.getElementById('crm-f-status').value = '询价';
        document.getElementById('crm-f-incoterm').value = '';
        document.getElementById('crm-edit-id').value = '';
        document.getElementById('crm-f-fee-total').textContent = '¥ 0';
        document.getElementById('crm-modal-title').textContent = '新增整柜';
        crmRenderFeeFxRows({});
        crmRenderCostRows({});
        crmToggleShipMode();
        document.getElementById('crm-modal').style.display = 'block';
        crmBindFeeCalc();
    }

    function crmCloseModal() {
        document.getElementById('crm-modal').style.display = 'none';
    }

    function crmBindFeeCalc() {
        ['crm-f-fee-ocean','crm-f-fee-truck','crm-f-fee-customs','crm-f-fee-tax','crm-f-fee-inspection','crm-f-fee-commodity','crm-f-fee-fumigation','crm-f-fee-other'].forEach(id => {
            const el = document.getElementById(id);
            if(el) el.oninput = crmUpdateFeeTotal;
        });
        ['crm-f-lcl-billweight','crm-f-lcl-price','crm-f-lcl-extra','crm-f-lcl-tax','crm-f-lcl-commodity','crm-f-lcl-fumigation','crm-f-lcl-delivery','crm-f-lcl-cost-price','crm-f-lcl-cost-extra','crm-f-lcl-cost-tax','crm-f-lcl-cost-delivery','crm-f-billweight','crm-f-unitprice'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.oninput = crmUpdateFeeTotal;
        });
        CRM_FEE_FX_ITEMS.forEach(item => crmFeeFxLineCalc(item.key));
    }

    function crmUpdateFeeTotal() {
        const shipMode = document.getElementById('crm-f-shipmode')?.value || '';
        const isLcl = shipMode === '普船拼箱' || shipMode === '快船拼柜' || shipMode === '空运' || shipMode === '快递';
        
        if (isLcl) {
            const billWeight = parseFloat(document.getElementById('crm-f-lcl-billweight')?.value || '0') || 0;
            const price = parseFloat(document.getElementById('crm-f-lcl-price')?.value || '0') || 0;
            const extra = parseFloat(document.getElementById('crm-f-lcl-extra')?.value || '0') || 0;
            const tax = parseFloat(document.getElementById('crm-f-lcl-tax')?.value || '0') || 0;
            const commodity = parseFloat(document.getElementById('crm-f-lcl-commodity')?.value || '0') || 0;
            const fumigation = parseFloat(document.getElementById('crm-f-lcl-fumigation')?.value || '0') || 0;
            const delivery = parseFloat(document.getElementById('crm-f-lcl-delivery')?.value || '0') || 0;
            const total = billWeight * price + extra + tax + commodity + fumigation + delivery;
            const totalEl = document.getElementById('crm-f-lcl-total');
            const mirrorTotalEl = document.getElementById('crm-f-fee-total');
            if (totalEl) totalEl.textContent = '¥ ' + total.toLocaleString('zh-CN', { maximumFractionDigits: 2 });
            if (mirrorTotalEl) mirrorTotalEl.textContent = '¥ ' + total.toLocaleString('zh-CN', { maximumFractionDigits: 2 });
            crmUpdateCostTotal();
            return;
        }
        const ids = ['crm-f-fee-ocean','crm-f-fee-truck','crm-f-fee-customs','crm-f-fee-tax','crm-f-fee-inspection','crm-f-fee-commodity','crm-f-fee-fumigation','crm-f-fee-other'];
        const simpleReceivable = ids.reduce((s, id) => s + (parseFloat(document.getElementById(id)?.value)||0), 0);
        const fxReceivable = CRM_FEE_FX_ITEMS.reduce((s, item) => s + crmGetFeeFxLine(item.key).cny, 0);
        const revenue = simpleReceivable + fxReceivable;
        const totalEl = document.getElementById('crm-f-fee-total');
        if (totalEl) totalEl.textContent = '¥ ' + revenue.toLocaleString('zh-CN', {minimumFractionDigits:0, maximumFractionDigits:0});
        crmUpdateCostTotal();
    }

    const CRM_COST_ITEMS = [
        { key: 'shipping_agent', label: '船代理费' },
        { key: 'truck',          label: '拖车费' },
        { key: 'customs_export', label: '报关费' },
        { key: 'customs_import', label: '清关费' },
        { key: 'tax',            label: '税金' },
        { key: 'inspection',     label: '查验费' },
        { key: 'commodity',      label: '商检费' },
        { key: 'fumigation',     label: '熏蒸费' },
        { key: 'delivery',       label: '尾程派送费' },
        { key: 'other',          label: '其他成本' },
    ];
    const CRM_CURRENCIES = ['CNY','JPY','USD','EUR','HKD','TWD'];
    const CRM_FEE_FX_ITEMS = [
        { key: 'arrival_notice', label: 'ARRIVAL NOTICE費用' },
        { key: 'clearance',      label: '清关费' },
        { key: 'delivery',       label: '尾程派送费' },
    ];

    function crmGetFeeFxLine(key) {
        const amt = parseFloat(document.getElementById('crm-f-fee-amt-' + key)?.value) || 0;
        const cur = document.getElementById('crm-f-fee-cur-' + key)?.value || 'CNY';
        let rate = 1;
        
        if (cur === 'CNY') {
            rate = 1;
        } else {
            const rateValue = parseFloat(document.getElementById('crm-f-fee-rate-' + key)?.value);
            if (rateValue && rateValue > 0) {
                rate = rateValue;
            } else {
                rate = 1;
            }
        }
        
        const cny = amt * rate;
        return { amt, cur, rate, cny };
    }

    function crmRenderFeeFxRows(feesFx) {
        feesFx = feesFx || {};
        const container = document.getElementById('crm-fee-fx-rows');
        if (!container) return;
        container.innerHTML = CRM_FEE_FX_ITEMS.map(item => {
            const c = feesFx[item.key] || {};
            const amt = c.amt || '';
            const cur = c.cur || 'CNY';
            const rate = c.rate || (cur === 'CNY' ? 1 : '');
            const cnyVal = c.cny || '';
            return `<div style="margin-bottom:10px;">
                <div style="font-size:11px; color:#27ae60; font-weight:bold; margin-bottom:5px;">${item.label}</div>
                <div style="display:grid; grid-template-columns:2fr 1fr 1.2fr 1.5fr; gap:6px; align-items:center;">
                    <input type="number" id="crm-f-fee-amt-${item.key}" value="${amt}" placeholder="金额"
                        oninput="crmFeeFxLineCalc('${item.key}')"
                        style="padding:8px; border:1px solid #bfe3cb; border-radius:7px; font-size:13px; width:100%;">
                    <select id="crm-f-fee-cur-${item.key}" onchange="crmFeeFxLineCalc('${item.key}')"
                        style="padding:8px; border:1px solid #bfe3cb; border-radius:7px; font-size:12px; background:#fff; width:100%;">
                        ${CRM_CURRENCIES.map(c2 => `<option${c2===cur?' selected':''}>${c2}</option>`).join('')}
                    </select>
                    <input type="number" id="crm-f-fee-rate-${item.key}" value="${rate}" placeholder="汇率" step="0.0001"
                        oninput="crmFeeFxLineCalc('${item.key}')"
                        style="padding:8px; border:1px solid #bfe3cb; border-radius:7px; font-size:12px; width:100%;">
                    <div id="crm-f-fee-cny-${item.key}" style="padding:8px; background:#f0fff4; border:1px solid #bfe3cb; border-radius:7px; font-size:12px; font-weight:bold; color:#27ae60; text-align:right;">
                        ${cnyVal ? '¥'+Number(cnyVal).toLocaleString() : '—'}
                    </div>
                </div>
                <div style="display:flex; gap:4px; font-size:9px; color:#97b5a0; margin-top:2px; padding:0 1px;">
                    <span style="flex:2;">原币金额</span><span style="flex:1;">币种</span><span style="flex:1.2;">汇率</span><span style="flex:1.5; text-align:right;">≈ CNY</span>
                </div>
            </div>`;
        }).join('');
    }

    function crmFeeFxLineCalc(key) {
        const cur = document.getElementById('crm-f-fee-cur-' + key)?.value || 'CNY';
        const rateEl = document.getElementById('crm-f-fee-rate-' + key);
        if (cur === 'CNY' && rateEl) rateEl.value = 1;
        const line = crmGetFeeFxLine(key);
        const display = document.getElementById('crm-f-fee-cny-' + key);
        if (display) display.textContent = line.cny > 0 ? '¥' + line.cny.toLocaleString('zh-CN', { maximumFractionDigits: 0 }) : '—';
        crmUpdateFeeTotal();
    }

    function crmRenderCostRows(costs) {
        costs = costs || {};
        const container = document.getElementById('crm-cost-rows');
        if (!container) return;
        container.innerHTML = CRM_COST_ITEMS.map(item => {
            const c = costs[item.key] || {};
            const amt   = c.amt   || '';
            const cur   = c.cur   || 'CNY';
            const rate  = c.rate  || (cur === 'CNY' ? 1 : '');
            const cnyVal = c.cny  || '';
            return `<div style="margin-bottom:10px;">
                <div style="font-size:11px; color:#c0762a; font-weight:bold; margin-bottom:5px;">${item.label}</div>
                <div style="display:grid; grid-template-columns:2fr 1fr 1.2fr 1.5fr; gap:6px; align-items:center;">
                    <input type="number" id="crm-cost-amt-${item.key}" value="${amt}" placeholder="金额"
                        oninput="crmCostLineCalc('${item.key}')"
                        style="padding:8px; border:1px solid #f0d0a0; border-radius:7px; font-size:13px; width:100%;">
                    <select id="crm-cost-cur-${item.key}" onchange="crmCostLineCalc('${item.key}')"
                        style="padding:8px; border:1px solid #f0d0a0; border-radius:7px; font-size:12px; background:#fff; width:100%;">
                        ${CRM_CURRENCIES.map(c2 => `<option${c2===cur?' selected':''}>${c2}</option>`).join('')}
                    </select>
                    <input type="number" id="crm-cost-rate-${item.key}" value="${rate}" placeholder="汇率" step="0.0001"
                        oninput="crmCostLineCalc('${item.key}')"
                        style="padding:8px; border:1px solid #f0d0a0; border-radius:7px; font-size:12px; width:100%;">
                    <div id="crm-cost-cny-${item.key}" style="padding:8px; background:#fff8f0; border:1px solid #f0d0a0; border-radius:7px; font-size:12px; font-weight:bold; color:#e67e22; text-align:right;">
                        ${cnyVal ? '¥'+Number(cnyVal).toLocaleString() : '—'}
                    </div>
                </div>
                <div style="display:flex; gap:4px; font-size:9px; color:#bbb; margin-top:2px; padding:0 1px;">
                    <span style="flex:2;">原币金额</span><span style="flex:1;">币种</span><span style="flex:1.2;">汇率</span><span style="flex:1.5; text-align:right;">≈ CNY</span>
                </div>
            </div>`;
        }).join('');
    }

    function crmCostLineCalc(key) {
        const amt  = parseFloat(document.getElementById('crm-cost-amt-'+key)?.value) || 0;
        const cur  = document.getElementById('crm-cost-cur-'+key)?.value || 'CNY';
        const rateEl = document.getElementById('crm-cost-rate-'+key);
        let rate = parseFloat(rateEl?.value) || 0;
        // auto-set rate=1 when CNY selected
        if (cur === 'CNY') { if (rateEl) rateEl.value = 1; rate = 1; }
        const cny = amt * rate;
        const display = document.getElementById('crm-cost-cny-'+key);
        if (display) display.textContent = cny > 0 ? '¥' + cny.toLocaleString('zh-CN',{maximumFractionDigits:0}) : '—';
        crmUpdateCostTotal();
    }

    function crmUpdateCostTotal() {
        const shipMode = document.getElementById('crm-f-shipmode')?.value || '';
        const isLcl = shipMode === '普船拼箱' || shipMode === '快船拼柜' || shipMode === '空运' || shipMode === '快递';
        
        if (isLcl) {
            const billWeight = parseFloat(document.getElementById('crm-f-lcl-billweight')?.value || '0') || 0;
            const revenuePrice = parseFloat(document.getElementById('crm-f-lcl-price')?.value || '0') || 0;
            const revenueExtra = parseFloat(document.getElementById('crm-f-lcl-extra')?.value || '0') || 0;
            const revenueTax   = parseFloat(document.getElementById('crm-f-lcl-tax')?.value   || '0') || 0;
            const revenueCommodity = parseFloat(document.getElementById('crm-f-lcl-commodity')?.value || '0') || 0;
            const revenueFumigation = parseFloat(document.getElementById('crm-f-lcl-fumigation')?.value || '0') || 0;
            const revenueDelivery = parseFloat(document.getElementById('crm-f-lcl-delivery')?.value || '0') || 0;
            const revenue = billWeight * revenuePrice + revenueExtra + revenueTax + revenueCommodity + revenueFumigation + revenueDelivery;
            const costPrice = parseFloat(document.getElementById('crm-f-lcl-cost-price')?.value || '0') || 0;
            const costExtra = parseFloat(document.getElementById('crm-f-lcl-cost-extra')?.value || '0') || 0;
            const costTax   = parseFloat(document.getElementById('crm-f-lcl-cost-tax')?.value   || '0') || 0;
            const costDelivery = parseFloat(document.getElementById('crm-f-lcl-cost-delivery')?.value || '0') || 0;
            const costTotal = billWeight * costPrice + costExtra + costTax + costDelivery;
            const ctEl = document.getElementById('crm-f-lcl-cost-total');
            const mirrorCostEl = document.getElementById('crm-f-cost-total');
            if (ctEl) ctEl.textContent = '¥ ' + costTotal.toLocaleString('zh-CN', { maximumFractionDigits: 2 });
            if (mirrorCostEl) mirrorCostEl.textContent = '¥ ' + costTotal.toLocaleString('zh-CN', { maximumFractionDigits: 2 });

            const profit = revenue - costTotal;
            const margin = revenue > 0 ? (profit / revenue * 100) : 0;
            const profitEl = document.getElementById('crm-f-lcl-profit');
            const marginEl = document.getElementById('crm-f-lcl-margin');
            const mirrorProfitEl = document.getElementById('crm-f-profit');
            const mirrorMarginEl = document.getElementById('crm-f-margin');
            [profitEl, mirrorProfitEl].forEach(el => {
                if (!el) return;
                el.textContent = (profit >= 0 ? '¥ ' : '- ¥ ') + Math.abs(profit).toLocaleString('zh-CN', { maximumFractionDigits: 2 });
                el.style.color = profit >= 0 ? '#1f7a5c' : '#e74c3c';
            });
            [marginEl, mirrorMarginEl].forEach(el => {
                if (!el) return;
                el.textContent = margin.toFixed(1) + '%';
                el.style.background = profit >= 0 ? '#d4f1e4' : '#fde8e8';
                el.style.color = profit >= 0 ? '#27ae60' : '#e74c3c';
            });
            return;
        }
        let costTotal = 0;
        CRM_COST_ITEMS.forEach(item => {
            const amt  = parseFloat(document.getElementById('crm-cost-amt-'+item.key)?.value) || 0;
            const cur  = document.getElementById('crm-cost-cur-'+item.key)?.value || 'CNY';
            const rate = cur === 'CNY' ? 1 : (parseFloat(document.getElementById('crm-cost-rate-'+item.key)?.value) || 0);
            costTotal += amt * rate;
        });
        const ctEl = document.getElementById('crm-f-cost-total');
        if (ctEl) ctEl.textContent = '¥ ' + costTotal.toLocaleString('zh-CN',{maximumFractionDigits:0});

        // revenue
        const revIds = ['crm-f-fee-ocean','crm-f-fee-truck','crm-f-fee-customs','crm-f-fee-tax','crm-f-fee-other'];
        const simpleReceivable = revIds.reduce((s, id) => s + (parseFloat(document.getElementById(id)?.value)||0), 0);
        const fxReceivable = CRM_FEE_FX_ITEMS.reduce((s, item) => s + crmGetFeeFxLine(item.key).cny, 0);
        const revenue = simpleReceivable + fxReceivable;

        const profit = revenue - costTotal;
        const margin = revenue > 0 ? (profit / revenue * 100) : 0;
        const profitEl = document.getElementById('crm-f-profit');
        const marginEl = document.getElementById('crm-f-margin');
        if (profitEl) {
            profitEl.textContent = (profit >= 0 ? '¥ ' : '- ¥ ') + Math.abs(profit).toLocaleString('zh-CN',{maximumFractionDigits:0});
            profitEl.style.color = profit >= 0 ? '#1f7a5c' : '#e74c3c';
        }
        if (marginEl) {
            marginEl.textContent = margin.toFixed(1) + '%';
            marginEl.style.background = profit >= 0 ? '#d4f1e4' : '#fde8e8';
            marginEl.style.color = profit >= 0 ? '#27ae60' : '#e74c3c';
        }
    }

    function crmValidateRecord(rec) {
        const errors = [];
        if (!rec.client || !rec.client.trim()) {
            errors.push('请填写客户名称');
        }
        if (!rec.shipMode) {
            errors.push('请选择运输方式');
        }
        if (rec.weight !== undefined && rec.weight !== null && rec.weight < 0) {
            errors.push('毛重不能为负数');
        }
        if (rec.cbm !== undefined && rec.cbm !== null && rec.cbm < 0) {
            errors.push('体积不能为负数');
        }
        if (rec.pkgs !== undefined && rec.pkgs !== null && rec.pkgs < 0) {
            errors.push('件数不能为负数');
        }
        if (rec.billWeight !== undefined && rec.billWeight !== null && rec.billWeight < 0) {
            errors.push('计费重不能为负数');
        }
        if (rec.etd && rec.eta) {
            const etdDate = new Date(rec.etd);
            const etaDate = new Date(rec.eta);
            if (etaDate < etdDate) {
                errors.push('ETA日期不能早于ETD日期');
            }
        }
        if (rec.etd && rec.ata) {
            const etdDate = new Date(rec.etd);
            const ataDate = new Date(rec.ata);
            if (ataDate < etdDate) {
                errors.push('ATA日期不能早于ETD日期');
            }
        }
        return errors;
    }

    function crmValidateField(fieldId, rules) {
        const el = document.getElementById(fieldId);
        if (!el) return true;
        const value = el.value.trim();
        let isValid = true;
        let errorMsg = '';
        if (rules.required && !value) {
            isValid = false;
            errorMsg = rules.requiredMsg || '此字段为必填项';
        }
        if (isValid && rules.numeric && value) {
            const num = parseFloat(value);
            if (isNaN(num)) {
                isValid = false;
                errorMsg = '请输入有效的数字';
            } else if (rules.min !== undefined && num < rules.min) {
                isValid = false;
                errorMsg = '数值不能小于 ' + rules.min;
            } else if (rules.max !== undefined && num > rules.max) {
                isValid = false;
                errorMsg = '数值不能大于 ' + rules.max;
            }
        }
        if (isValid && rules.date && value) {
            const datePattern = /^\d{4}-\d{2}-\d{2}$/;
            if (!datePattern.test(value)) {
                isValid = false;
                errorMsg = '请输入有效的日期格式 (YYYY-MM-DD)';
            }
        }
        if (!isValid) {
            el.style.borderColor = '#e74c3c';
            el.style.backgroundColor = '#fdf2f2';
            showToast(errorMsg);
        } else {
            el.style.borderColor = '#ddd';
            el.style.backgroundColor = '#fff';
        }
        return isValid;
    }

    function crmFormToRecord() {
        const g = id => (document.getElementById(id)?.value || '').trim();
        const n = id => parseFloat(document.getElementById(id)?.value) || 0;
        const shipMode = g('crm-f-shipmode') || '';
        const isFcl = shipMode === '海运整柜';
        const isLcl = shipMode === '普船拼箱' || shipMode === '快船拼柜' || shipMode === '空运' || shipMode === '快递';
        const fees = isLcl
            ? {
                billWeight: parseFloat(document.getElementById('crm-f-lcl-billweight').value || '0') || 0,
                unitPrice: parseFloat(document.getElementById('crm-f-lcl-price').value || '0') || 0,
                extra: n('crm-f-lcl-extra'),
                tax: n('crm-f-lcl-tax'),
                commodity: n('crm-f-lcl-commodity'),
                fumigation: n('crm-f-lcl-fumigation'),
                delivery: n('crm-f-lcl-delivery'),
                mode: 'lcl_simple'
            }
            : { ocean: n('crm-f-fee-ocean'), truck: n('crm-f-fee-truck'), customs: n('crm-f-fee-customs'), tax: n('crm-f-fee-tax'), inspection: n('crm-f-fee-inspection'), commodity: n('crm-f-fee-commodity'), fumigation: n('crm-f-fee-fumigation'), other: n('crm-f-fee-other') };
        const feesFx = {};
        if (isLcl) {
            fees.total = (fees.billWeight || 0) * (fees.unitPrice || 0) + (fees.extra || 0) + (fees.tax || 0) + (fees.commodity || 0) + (fees.fumigation || 0) + (fees.delivery || 0);
        } else {
            CRM_FEE_FX_ITEMS.forEach(item => {
                const line = crmGetFeeFxLine(item.key);
                fees[item.key] = line.cny;
                if (line.amt) feesFx[item.key] = line;
            });
            fees.fx = feesFx;
            fees.total = fees.ocean + fees.truck + fees.customs + fees.tax + fees.other +
                CRM_FEE_FX_ITEMS.reduce((s, item) => s + (fees[item.key] || 0), 0);
        }
        // gather costs
        const costs = {};
        let costTotal = 0;
        if (isLcl) {
            const billWeight = fees.billWeight || 0;
            const unitPrice = n('crm-f-lcl-cost-price');
            const extra = n('crm-f-lcl-cost-extra');
            const tax = n('crm-f-lcl-cost-tax');
            const delivery = n('crm-f-lcl-cost-delivery');
            costTotal = billWeight * unitPrice + extra + tax + delivery;
            costs.mode = 'lcl_simple';
            costs.billWeight = billWeight;
            costs.unitPrice = unitPrice;
            costs.extra = extra;
            costs.tax = tax;
            costs.delivery = delivery;
        } else {
            CRM_COST_ITEMS.forEach(item => {
                const amt  = parseFloat(document.getElementById('crm-cost-amt-'+item.key)?.value) || 0;
                const cur  = document.getElementById('crm-cost-cur-'+item.key)?.value || 'CNY';
                const rate = cur === 'CNY' ? 1 : (parseFloat(document.getElementById('crm-cost-rate-'+item.key)?.value) || 0);
                const cny  = amt * rate;
                if (amt) { costs[item.key] = { amt, cur, rate, cny }; costTotal += cny; }
            });
        }
        costs._total = costTotal;
        const profit = fees.total - costTotal;
        const margin = fees.total > 0 ? profit / fees.total : 0;
        const bizType = isFcl ? 'fcl' : 'lcl';
        return {
            bizType,
            client:   g('crm-f-client'),
            orderno:  g('crm-f-orderno'),
            clientOrderNo: g('crm-f-clientorderno'),
            mbl:      g('crm-f-mbl'),
            hbl:      g('crm-f-hbl'),
            shipMode: g('crm-f-shipmode'),
            pol:      g('crm-f-pol'),
            pod:      g('crm-f-pod'),
            shipaddr: g('crm-f-shipaddr'),
            recvaddr: g('crm-f-recvaddr'),
            ctype:    g('crm-f-ctype'),
            cqty:     parseInt(document.getElementById('crm-f-cqty').value) || 1,
            carrier:  g('crm-f-carrier'),
            vessel:   g('crm-f-vessel'),
            goods:    g('crm-f-goods'),
            weight:   n('crm-f-weight'),
            pkgs:     n('crm-f-pkgs'),
            cbm:      parseFloat(document.getElementById('crm-f-cbm').value) || 0,
            billWeight: parseFloat(document.getElementById('crm-f-billweight').value) || 0,
            unitPrice:  parseFloat(document.getElementById('crm-f-unitprice').value) || 0,
            bookedDate: g('crm-f-bookeddate'),
            loadedDate: g('crm-f-loadeddate'),
            cutoff:   g('crm-f-cutoff'),
            etd:      g('crm-f-etd'),
            eta:      g('crm-f-eta'),
            ata:      g('crm-f-ata'),
            clearedDate: g('crm-f-cleareddate'),
            pickup:   g('crm-f-pickup'),
            deliveryDate: g('crm-f-deliverydate'),
            freetime: g('crm-f-freetime'),
            signed:   g('crm-f-signed'),
            warehouse: g('crm-f-warehouse'),
            flight:   g('crm-f-flight'),
            airSigned: g('crm-f-air-signed'),
            airBookedDate: g('crm-f-air-bookeddate'),
            airAta: g('crm-f-air-ata'),
            airClearedDate: g('crm-f-air-cleareddate'),
            tracking: g('crm-f-tracking'),
            carrierType: g('crm-f-carrier-type'),
            fees,
            costs,
            receivable: fees.total || 0,
            payable: costTotal || 0,
            profit,
            margin,
            settlementStatus: g('crm-f-settlement-status') || '未结算',
            status:   g('crm-f-status'),
            incoterm: g('crm-f-incoterm'),
            tags:     g('crm-f-tags').split(',').map(t => t.trim()).filter(t => t),
            notes:    g('crm-f-notes'),
            updatedAt: new Date().toISOString(),
        };
    }

    function crmRecordToForm(r) {
        const s = (id, v) => { const el = document.getElementById(id); if(el) el.value = v || ''; };
        let shipMode = r.shipMode || '';
        if (shipMode === '整柜' || (!shipMode && r.bizType === 'fcl')) shipMode = '海运整柜';
        if (shipMode === '拼箱' || shipMode === '海运散货' || (!shipMode && r.bizType === 'lcl')) shipMode = '普船拼箱';
        if (!shipMode) shipMode = '海运整柜';
        s('crm-f-shipmode', shipMode);
        s('crm-f-client', r.client); s('crm-f-orderno', r.orderno); s('crm-f-clientorderno', r.clientOrderNo); s('crm-f-mbl', r.mbl); s('crm-f-hbl', r.hbl);
        s('crm-f-pol', r.pol); s('crm-f-pod', r.pod); s('crm-f-shipaddr', r.shipaddr); s('crm-f-recvaddr', r.recvaddr); s('crm-f-ctype', r.ctype); s('crm-f-cqty', r.cqty || 1);
        s('crm-f-carrier', r.carrier); s('crm-f-vessel', r.vessel); s('crm-f-goods', r.goods);
        s('crm-f-weight', r.weight || ''); s('crm-f-pkgs', r.pkgs || ''); s('crm-f-cbm', r.cbm || '');
        s('crm-f-billweight', r.billWeight || ''); s('crm-f-unitprice', r.unitPrice || '');
        s('crm-f-lcl-billweight', (r.fees||{}).billWeight || r.billWeight || '');
        s('crm-f-lcl-price', (r.fees||{}).unitPrice || r.unitPrice || '');
        s('crm-f-lcl-extra', (r.fees||{}).extra || '');
        s('crm-f-lcl-tax', (r.fees||{}).tax || '');
        s('crm-f-lcl-commodity', (r.fees||{}).commodity || '');
        s('crm-f-lcl-fumigation', (r.fees||{}).fumigation || '');
        s('crm-f-lcl-delivery', (r.fees||{}).delivery || '');
        s('crm-f-lcl-cost-price', (r.costs||{}).unitPrice || '');
        s('crm-f-lcl-cost-extra', (r.costs||{}).extra || '');
        s('crm-f-lcl-cost-tax', (r.costs||{}).tax || '');
        s('crm-f-lcl-cost-delivery', (r.costs||{}).delivery || '');
        s('crm-f-bookeddate', r.bookedDate); s('crm-f-loadeddate', r.loadedDate);
        s('crm-f-cutoff', r.cutoff); s('crm-f-etd', r.etd); s('crm-f-eta', r.eta); s('crm-f-ata', r.ata);
        s('crm-f-cleareddate', r.clearedDate);
        s('crm-f-pickup', r.pickup); s('crm-f-deliverydate', r.deliveryDate); s('crm-f-freetime', r.freetime); s('crm-f-signed', r.signed);
        s('crm-f-warehouse', r.warehouse); s('crm-f-flight', r.flight); s('crm-f-air-signed', r.airSigned);
        s('crm-f-air-bookeddate', r.airBookedDate); s('crm-f-air-ata', r.airAta); s('crm-f-air-cleareddate', r.airClearedDate);
        crmToggleShipMode();
        s('crm-f-fee-ocean', (r.fees||{}).ocean || ''); s('crm-f-fee-truck', (r.fees||{}).truck || '');
        s('crm-f-fee-customs', (r.fees||{}).customs || ''); s('crm-f-fee-tax', (r.fees||{}).tax || '');
        s('crm-f-fee-inspection', (r.fees||{}).inspection || '');
        s('crm-f-fee-commodity', (r.fees||{}).commodity || ''); s('crm-f-fee-fumigation', (r.fees||{}).fumigation || '');
        s('crm-f-fee-other', (r.fees||{}).other || '');
        const legacyFeesFx = {};
        if ((r.fees||{}).delivery && !((r.fees||{}).fx || {}).delivery) {
            legacyFeesFx.delivery = { amt: (r.fees||{}).delivery, cur: 'CNY', rate: 1, cny: (r.fees||{}).delivery };
        }
        if ((r.fees||{}).clearance && !((r.fees||{}).fx || {}).clearance) {
            legacyFeesFx.clearance = { amt: (r.fees||{}).clearance, cur: 'CNY', rate: 1, cny: (r.fees||{}).clearance };
        }
        if ((r.fees||{}).arrival_notice && !((r.fees||{}).fx || {}).arrival_notice) {
            legacyFeesFx.arrival_notice = { amt: (r.fees||{}).arrival_notice, cur: 'CNY', rate: 1, cny: (r.fees||{}).arrival_notice };
        }
        crmRenderFeeFxRows({ ...legacyFeesFx, ...((r.fees||{}).fx || {}) });
        s('crm-f-tracking', r.tracking); s('crm-f-carrier-type', r.carrierType);
        s('crm-f-status', r.status); s('crm-f-settlement-status', r.settlementStatus || '未结算'); s('crm-f-incoterm', r.incoterm); s('crm-f-tags', (r.tags || []).join(', ')); s('crm-f-notes', r.notes);
        crmRenderCostRows(r.costs || {});
        const costs = r.costs || {};
        CRM_COST_ITEMS.forEach(item => {
            const c = costs[item.key] || {};
            const aEl = document.getElementById('crm-cost-amt-'+item.key);
            const rEl = document.getElementById('crm-cost-rate-'+item.key);
            const cEl = document.getElementById('crm-cost-cur-'+item.key);
            if (aEl) aEl.value = c.amt || '';
            if (cEl) cEl.value = c.cur || 'CNY';
            if (rEl) rEl.value = c.rate || (c.cur === 'CNY' || !c.cur ? 1 : '');
        });
        crmToggleShipMode();
        crmUpdateFeeTotal();
    }

    function crmSaveRecord() {
        const rec = crmFormToRecord();
        const validationErrors = crmValidateRecord(rec);
        if (validationErrors.length > 0) {
            showToast(validationErrors[0]);
            return;
        }
        const data = crmLoad();
        const editId = document.getElementById('crm-edit-id').value;
        const now = new Date().toISOString();
        const today = new Date().toISOString().split('T')[0];
        
        if (editId) {
            const idx = data.findIndex(r => String(r.id) === String(editId));
            if (idx >= 0) {
                const oldRecord = data[idx];
                rec.id = oldRecord.id;
                rec.createdAt = oldRecord.createdAt;
                
                if (rec.status !== oldRecord.status) {
                    if (!rec.statusHistory) {
                        rec.statusHistory = oldRecord.statusHistory || [];
                    }
                    rec.statusHistory.push({
                        status: rec.status,
                        timestamp: now,
                        previousStatus: oldRecord.status
                    });
                    
                    const shipMode = rec.shipMode || '';
                    const isAirOrExpress = shipMode === '空运' || shipMode === '快递';
                    
                    if (rec.status === '已下单' && !rec.bookedDate && !isAirOrExpress) {
                        rec.bookedDate = today;
                    }
                    if (rec.status === '已下单' && !rec.airBookedDate && isAirOrExpress) {
                        rec.airBookedDate = today;
                    }
                    if (rec.status === '已装柜' && !rec.loadedDate) {
                        rec.loadedDate = today;
                    }
                    if (rec.status === '已入库' && !rec.warehouse) {
                        rec.warehouse = today;
                    }
                    if (rec.status === '已开船' && !rec.etd && !isAirOrExpress) {
                        rec.etd = today;
                    }
                    if (rec.status === '已到港' && !rec.ata && !isAirOrExpress) {
                        rec.ata = today;
                    }
                    if (rec.status === '已到港' && !rec.airAta && isAirOrExpress) {
                        rec.airAta = today;
                    }
                    if (rec.status === '已清关' && !rec.clearedDate && !isAirOrExpress) {
                        rec.clearedDate = today;
                    }
                    if (rec.status === '已清关' && !rec.airClearedDate && isAirOrExpress) {
                        rec.airClearedDate = today;
                    }
                    if (rec.status === '已完结' && !rec.signed && !isAirOrExpress) {
                        rec.signed = today;
                    }
                    if (rec.status === '已完结' && !rec.airSigned && isAirOrExpress) {
                        rec.airSigned = today;
                    }
                } else {
                    rec.statusHistory = oldRecord.statusHistory || [];
                }
                
                data[idx] = rec;
            }
        } else {
            rec.id = crmNextId(data);
            rec.createdAt = now;
            rec.statusHistory = [{
                status: rec.status,
                timestamp: now,
                previousStatus: null
            }];
            data.unshift(rec);
        }
        crmSave(data);
        crmCloseModal();
        crmRender();
        reminderGenerateFromCRM();
        reconciliationGenerateFromCRM();
        showToast(editId ? '已更新' : '已保存');
    }

    function crmEditRecord(id) {
        const data = crmLoad();
        const r = data.find(x => String(x.id) === String(id));
        if (!r) return;
        crmRecordToForm(r);
        document.getElementById('crm-edit-id').value = id;
        document.getElementById('crm-modal-title').textContent = '编辑整柜';
        document.getElementById('crm-detail-modal').style.display = 'none';
        document.getElementById('crm-modal').style.display = 'block';
        crmBindFeeCalc();
    }

    function crmDeleteRecord(id) {
        if (!confirm('确认删除该条记录？')) return;
        const data = crmLoad().filter(x => String(x.id) !== String(id));
        crmSave(data);
        document.getElementById('crm-detail-modal').style.display = 'none';
        crmRender();
        reminderGenerateFromCRM();
        reconciliationGenerateFromCRM();
        showToast('已删除');
    }

    function crmCloneRecord(id) {
        const data = crmLoad();
        const r = data.find(x => String(x.id) === String(id));
        if (!r) return;
        const clone = JSON.parse(JSON.stringify(r));
        delete clone.id;
        delete clone.createdAt;
        delete clone.orderno;
        delete clone.mbl;
        delete clone.hbl;
        delete clone.statusHistory;
        clone.status = '待处理';
        clone.notes = (clone.notes || '') + '\n[复制自订单: ' + (r.orderno || r.id) + ']';
        crmRecordToForm(clone);
        document.getElementById('crm-edit-id').value = '';
        document.getElementById('crm-modal-title').textContent = '复制订单';
        document.getElementById('crm-detail-modal').style.display = 'none';
        document.getElementById('crm-modal').style.display = 'block';
        crmBindFeeCalc();
        showToast('已复制订单信息，请修改后保存');
    }

    function crmShowDetail(id) {
        const data = crmLoad();
        const r = data.find(x => String(x.id) === String(id));
        if (!r) return;
        const fmt = v => v || '—';
        const fmtMoney = v => v ? '¥' + Number(v).toLocaleString() : '—';
        const color = CRM_STATUS_COLOR[r.status] || '#7f8c8d';
        const section = (title, rows) => `
            <div style="margin-bottom:14px;">
                <div style="font-size:11px; font-weight:bold; color:#4a90e2; margin-bottom:8px; padding-bottom:4px; border-bottom:1px solid #e8f0f8;">${title}</div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px;">
                    ${rows.map(([l,v]) => `<div style="background:#f8fbff; border-radius:8px; padding:8px;">
                        <div style="font-size:10px; color:#888; margin-bottom:2px;">${l}</div>
                        <div style="font-size:13px; color:#2c3e50; font-weight:500; word-break:break-all;">${v}</div>
                    </div>`).join('')}
                </div>
            </div>`;
        
        const getTrackingUrl = (carrierType, trackingNo) => {
            if (!trackingNo || !carrierType) return null;
            const urls = {
                'sagawa': `https://k2k.sagawa-exp.co.jp/p/web/okurijosearch.do?okurijoNo=${trackingNo}`,
                'kuroneko': `https://toi.kuronekoyamato.co.jp/cgi-bin/tneko?dkino=${trackingNo}`,
                'japanpost': `https://trackings.post.japanpost.jp/services/srv/search/?requestNo1=${trackingNo}`,
                'fukutsu': `https://www.fukutsu.co.jp/cgi-bin/user/tntsearch.cgi?no=${trackingNo}`,
                'seino': `https://track.seino.co.jp/cgi-bin/tracking_e.cgi?number=${trackingNo}`,
                'daiichi': `http://www.daiichikamotsu.co.jp/track/track.php?number=${trackingNo}`,
            };
            return urls[carrierType] || null;
        };
        
        const getCarrierName = (carrierType) => {
            const names = {
                'sagawa': '佐川急便',
                'kuroneko': '黑猫宅急便',
                'japanpost': '日本邮政',
                'fukutsu': '福山通运',
                'seino': '西浓运输',
                'daiichi': '第一货物',
                'other': '其他'
            };
            return names[carrierType] || '—';
        };
        
        const fees = r.fees || {};
        const feeFx = fees.fx || {};
        const isLcl = (r.bizType || 'fcl') === 'lcl';
        const fmtFeeFx = (key, fallbackVal) => {
            const line = feeFx[key];
            if (line && line.amt) {
                return line.cur !== 'CNY'
                    ? `${line.amt} ${line.cur} × ${line.rate} = ¥${Number(line.cny).toLocaleString()}`
                    : `¥${Number(line.cny).toLocaleString()}`;
            }
            return fmtMoney(fallbackVal);
        };
        
        const trackingUrl = getTrackingUrl(r.carrierType, r.tracking);
        const trackingLink = r.tracking 
            ? (trackingUrl 
                ? `<a href="${trackingUrl}" target="_blank" style="color:#4a90e2; text-decoration:none; border-bottom:1px dashed #4a90e2;">${r.tracking} 🔗</a>`
                : r.tracking)
            : '—';
        
        document.getElementById('crm-detail-body').innerHTML = `
            <div style="display:flex; align-items:center; gap:10px; margin-bottom:14px; flex-wrap:wrap;">
                <div style="font-size:18px; font-weight:bold; color:#2c3e50;">${fmt(r.client)}</div>
                <span style="background:${isLcl?'#16a08522':'#4a90e222'}; color:${isLcl?'#16a085':'#4a90e2'}; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:bold;">${isLcl?'散货':'整柜'}</span>
                <span style="background:${color}22; color:${color}; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:bold;">${r.status}</span>
                <span style="background:${(r.settlementStatus === '已结算') ? '#27ae6022' : ((r.settlementStatus === '部分结算') ? '#f39c1222' : '#e74c3c22')}; color:${(r.settlementStatus === '已结算') ? '#27ae60' : ((r.settlementStatus === '部分结算') ? '#f39c12' : '#e74c3c')}; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:bold;">${r.settlementStatus || '未结算'}</span>
                ${(r.tags && r.tags.length) ? r.tags.map(t => `<span style="background:#9b59b622; color:#9b59b6; padding:4px 10px; border-radius:999px; font-size:11px; font-weight:bold;">${t}</span>`).join('') : ''}
                ${r.orderno ? `<span style="background:#f0f4fa; color:#607d8b; padding:4px 10px; border-radius:999px; font-size:11px; display:inline-flex; align-items:center; gap:4px;">${r.orderno}<button onclick="event.stopPropagation(); navigator.clipboard.writeText('${r.orderno}').then(() => alert('订单号已复制：${r.orderno}'));" style="background:none; border:none; cursor:pointer; padding:0; font-size:12px; color:#4a90e2; margin-left:2px;" title="复制订单号">📋</button></span>` : ''}
            </div>
            ${section(isLcl ? '运单 & 单号' : '提单 & 单号', [[isLcl ? '运单号' : '主单号 MBL', fmt(r.mbl)], [isLcl ? '参考单号' : '分单号 HBL', fmt(r.hbl)]])}
            ${r.tracking ? section('📦 快递信息', [
                ['快递单号', trackingLink],
                ['快递公司', getCarrierName(r.carrierType)],
            ]) : ''}
            ${section('航线 & 船务', [
                ['起运港', fmt(r.pol)], ['目的港', fmt(r.pod)],
                ['发货地址', fmt(r.shipaddr)], ['收货地址', fmt(r.recvaddr)],
                [isLcl ? '运输方式' : '柜型/数量', isLcl ? fmt(r.shipMode) : (r.ctype ? `${r.ctype} × ${r.cqty||1}` : '—')],
                ['船公司', fmt(r.carrier)],
                ['船名/航次', fmt(r.vessel)],
                ['贸易术语', fmt(r.incoterm)],
            ])}
            ${section('货物', [
                ['品名', fmt(r.goods)],
                ['毛重', r.weight ? r.weight + ' kg' : '—'],
                ['件数', r.pkgs ? r.pkgs + ' 件' : '—'],
                ['体积', r.cbm ? r.cbm + ' CBM' : '—'],
                ['计费重', r.billWeight ? r.billWeight + ' kg' : '—'],
                ['报价单价', r.unitPrice ? `¥${Number(r.unitPrice).toLocaleString()}/kg` : '—'],
            ])}
            ${section('关键日期', isLcl && (r.shipMode === '空运' || r.shipMode === '快递') ? [
                ['入仓日期', fmt(r.warehouse)],
                ['空运航班日期', fmt(r.flight)],
                ['签收时间', fmt(r.airSigned)],
            ] : [
                ['截关日', fmt(r.cutoff)], ['开船 ETD', fmt(r.etd)],
                ['预计到港 ETA', fmt(r.eta)], ['实际到港 ATA', fmt(r.ata)],
                ['提柜日', fmt(r.pickup)], ['免柜期截止', fmt(r.freetime)],
                ['签收时间', fmt(r.signed)],
            ])}
            ${isLcl
                ? section('💰 散货应收', [
                    ['计费重', fees.billWeight ? `${fees.billWeight} kg` : '—'],
                    ['应收单价', fees.unitPrice ? `¥${Number(fees.unitPrice).toLocaleString()}/kg` : '—'],
                    ['附加费 / 杂费', fmtMoney(fees.extra)],
                    ['税金', fmtMoney(fees.tax)],
                    ['商检费', fmtMoney(fees.commodity)],
                    ['熏蒸费', fmtMoney(fees.fumigation)],
                    ['尾端派送费', fmtMoney(fees.delivery)],
                    ['应收合计', `<b style="color:#2c7be5;">${fmtMoney(fees.total)}</b>`],
                ])
                : section('💰 客户应收', [
                    ['海运费', fmtMoney(fees.ocean)], ['拖车费', fmtMoney(fees.truck)],
                    ['报关费', fmtMoney(fees.customs)], ['税金', fmtMoney(fees.tax)],
                    ['查验费', fmtMoney(fees.inspection)],
                    ['商检费', fmtMoney(fees.commodity)],
                    ['熏蒸费', fmtMoney(fees.fumigation)],
                    ['ARRIVAL NOTICE費用', fmtFeeFx('arrival_notice', fees.arrival_notice)],
                    ['清关费', fmtFeeFx('clearance', fees.clearance)],
                    ['尾程派送费', fmtFeeFx('delivery', fees.delivery)],
                    ['其他', fmtMoney(fees.other)], ['应收合计', `<b style="color:#2c7be5;">${fmtMoney(fees.total)}</b>`],
                ])}
            ${(() => {
                const costs = r.costs || {};
                const costTotal = costs._total || 0;
                const profit = r.profit !== undefined ? r.profit : (fees.total - costTotal);
                const margin = r.margin !== undefined ? r.margin : (fees.total > 0 ? profit/fees.total : 0);
                const pc = profit >= 0 ? '#1f7a5c' : '#e74c3c';
                const hasCosts = isLcl ? (costTotal > 0 || costs.unitPrice || costs.extra) : CRM_COST_ITEMS.some(item => costs[item.key]);
                if (!hasCosts) return '<div style="background:#f8fbff;border-radius:8px;padding:10px;font-size:12px;color:#aaa;margin-bottom:14px;text-align:center;">暂未录入供应商应付</div>';
                const costRows = isLcl
                    ? [
                        `<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #f0e8dc;font-size:12px;"><span style="color:#c0762a;">计费重</span><span style="color:#444;">${costs.billWeight ? costs.billWeight + ' kg' : '—'}</span></div>`,
                        `<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #f0e8dc;font-size:12px;"><span style="color:#c0762a;">应付单价</span><span style="color:#444;">${costs.unitPrice ? `¥${Number(costs.unitPrice).toLocaleString()}/kg` : '—'}</span></div>`,
                        `<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #f0e8dc;font-size:12px;"><span style="color:#c0762a;">应付附加费</span><span style="color:#444;">${fmtMoney(costs.extra)}</span></div>`,
                        `<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #f0e8dc;font-size:12px;"><span style="color:#c0762a;">税金</span><span style="color:#444;">${fmtMoney(costs.tax)}</span></div>`,
                        `<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #f0e8dc;font-size:12px;"><span style="color:#c0762a;">尾端派送费</span><span style="color:#444;">${fmtMoney(costs.delivery)}</span></div>`
                    ].join('')
                    : CRM_COST_ITEMS.filter(item => costs[item.key]).map(item => {
                    const c = costs[item.key];
                    const detail = c.cur !== 'CNY' ? `${c.amt} ${c.cur} × ${c.rate} = ¥${Number(c.cny).toLocaleString()}` : `¥${Number(c.cny).toLocaleString()}`;
                    return `<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #f0e8dc;font-size:12px;"><span style="color:#c0762a;">${item.label}</span><span style="color:#444;">${detail}</span></div>`;
                }).join('');
                const bar = Math.min(Math.max(margin*100,0),100);
                return `<div style="margin-bottom:14px;">
                    <div style="font-size:11px;font-weight:bold;color:#e67e22;margin-bottom:8px;padding-bottom:4px;border-bottom:1px solid #f5dfc0;">🏭 ${isLcl ? '散货应付' : '供应商应付'}</div>
                    <div style="background:#fff9f2;border-radius:8px;padding:10px 12px;">${costRows}
                        <div style="display:flex;justify-content:space-between;padding-top:6px;margin-top:4px;font-size:13px;font-weight:bold;"><span style="color:#e67e22;">应付合计</span><span style="color:#e67e22;">¥${Number(costTotal).toLocaleString()}</span></div>
                    </div></div>
                <div style="background:${profit>=0?'linear-gradient(135deg,#f0fff4,#e8f8f0)':'linear-gradient(135deg,#fff4f4,#fde8e8)'};border:1px solid ${profit>=0?'#a8dfc0':'#f5b8b8'};border-radius:12px;padding:14px 16px;margin-bottom:14px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                        <span style="font-size:13px;font-weight:bold;color:${pc};">毛利</span>
                        <span style="font-size:18px;font-weight:bold;color:${pc};">${profit>=0?'':'-'}¥${Math.abs(profit).toLocaleString()}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;align-items:center;">
                        <span style="font-size:12px;color:#888;">毛利率</span>
                        <span style="font-size:14px;font-weight:bold;color:${pc};background:${profit>=0?'#d4f1e4':'#fde0e0'};padding:2px 12px;border-radius:999px;">${(margin*100).toFixed(1)}%</span>
                    </div>
                    <div style="margin-top:8px;background:rgba(255,255,255,0.6);border-radius:8px;overflow:hidden;height:6px;">
                        <div style="height:100%;background:${pc};width:${bar}%;transition:width 0.5s;"></div>
                    </div>
                </div>`;
            })()}
            ${r.notes ? `<div style="margin-bottom:14px;"><div style="font-size:11px; font-weight:bold; color:#4a90e2; margin-bottom:8px; padding-bottom:4px; border-bottom:1px solid #e8f0f8;">备注 / 日志</div>
                <div style="background:#f8fbff; border-radius:8px; padding:10px; font-size:13px; color:#2c3e50; white-space:pre-wrap; line-height:1.6;">${r.notes}</div></div>` : ''}
            <div style="font-size:10px; color:#aaa; margin-bottom:12px;">
                创建：${r.createdAt ? r.createdAt.slice(0,10) : '—'} &nbsp;|&nbsp; 更新：${r.updatedAt ? r.updatedAt.slice(0,10) : '—'}
            </div>
            <div style="display:flex; gap:10px; flex-wrap:wrap;">
                <button class="btn-main" style="background:#4a90e2; flex:1; padding:11px; min-width:100px;" onclick="crmEditRecord('${r.id}')">✏️ 编辑</button>
                <button class="btn-main" style="background:#9b59b6; flex:1; padding:11px; min-width:100px;" onclick="crmCloneRecord('${r.id}')">📋 复制</button>
                <button class="btn-main" style="background:#27ae60; flex:1; padding:11px; min-width:100px;" onclick="crmShareClientPdf('${r.id}')">📤 客户版PDF</button>
                <button class="btn-main" style="background:#e74c3c; flex:1; padding:11px; min-width:100px;" onclick="crmDeleteRecord('${r.id}')">🗑 删除</button>
            </div>`;
        document.getElementById('crm-detail-modal').style.display = 'block';
    }

    // CRM 勾选状态
    let crmSelectMode = false;
    let crmSelectedIds = new Set();

    function crmToggleSelectMode() {
        crmSelectMode = !crmSelectMode;
        crmSelectedIds.clear();
        const btn = document.getElementById('crm-select-toggle');
        const bar = document.getElementById('crm-bulk-bar');
        if (crmSelectMode) {
            if (btn) { btn.textContent = '退出勾选'; btn.style.background = '#95a5a6'; }
            if (bar) bar.style.display = 'flex';
        } else {
            if (btn) { btn.textContent = '☑ 勾选'; btn.style.background = '#f39c12'; }
            if (bar) bar.style.display = 'none';
        }
        crmRender();
    }

    function crmSelectAll() {
        const data = crmLoad();
        const q = (document.getElementById('crm-search').value || '').toLowerCase();
        const sf = document.getElementById('crm-filter-status').value;
        data.filter(r => {
            const matchQ = !q || [r.client,r.orderno,r.mbl,r.hbl,r.pol,r.pod,r.goods,r.carrier,r.vessel,r.shipMode,r.bizType].join(' ').toLowerCase().includes(q);
            const matchS = !sf || r.status === sf;
            return matchQ && matchS;
        }).forEach(r => crmSelectedIds.add(String(r.id)));
        crmUpdateBulkBar();
        crmRender();
    }

    function crmSelectNone() {
        crmSelectedIds.clear();
        crmUpdateBulkBar();
        crmRender();
    }

    function crmBulkChangeStatus(newStatus) {
        if (!newStatus || crmSelectedIds.size === 0) return;
        if (!confirm(`确认将选中的 ${crmSelectedIds.size} 条订单状态改为「${newStatus}」？`)) {
            document.getElementById('crm-bulk-status').value = '';
            return;
        }
        const data = crmLoad();
        const now = new Date().toISOString();
        const today = new Date().toISOString().split('T')[0];
        let updated = 0;
        data.forEach(r => {
            if (crmSelectedIds.has(String(r.id))) {
                r.status = newStatus;
                r.updatedAt = now;
                if (!r.statusHistory) r.statusHistory = [];
                r.statusHistory.push({
                    status: newStatus,
                    timestamp: now,
                    previousStatus: r.status
                });
                const shipMode = r.shipMode || '';
                const isAirOrExpress = shipMode === '空运' || shipMode === '快递';
                if (newStatus === '已下单' && !r.bookedDate && !isAirOrExpress) r.bookedDate = today;
                if (newStatus === '已下单' && !r.airBookedDate && isAirOrExpress) r.airBookedDate = today;
                if (newStatus === '已装柜' && !r.loadedDate) r.loadedDate = today;
                if (newStatus === '已入库' && !r.warehouse) r.warehouse = today;
                if (newStatus === '已开船' && !r.etd && !isAirOrExpress) r.etd = today;
                if (newStatus === '已到港' && !r.ata && !isAirOrExpress) r.ata = today;
                if (newStatus === '已到港' && !r.airAta && isAirOrExpress) r.airAta = today;
                if (newStatus === '已清关' && !r.clearedDate && !isAirOrExpress) r.clearedDate = today;
                if (newStatus === '已清关' && !r.airClearedDate && isAirOrExpress) r.airClearedDate = today;
                if (newStatus === '已完结' && !r.signed && !isAirOrExpress) r.signed = today;
                if (newStatus === '已完结' && !r.airSigned && isAirOrExpress) r.airSigned = today;
                updated++;
            }
        });
        crmSave(data);
        document.getElementById('crm-bulk-status').value = '';
        crmRender();
        showToast(`已更新 ${updated} 条订单状态`);
    }

    function crmToggleSelect(id, e) {
        e.stopPropagation();
        const strId = String(id);
        if (crmSelectedIds.has(strId)) crmSelectedIds.delete(strId);
        else crmSelectedIds.add(strId);
        crmUpdateBulkBar();
        const card = document.getElementById('crm-card-' + id);
        if (card) {
            const checked = crmSelectedIds.has(strId);
            card.style.background = checked ? 'rgba(74,144,226,0.08)' : '';
            card.style.boxShadow = checked ? '0 0 0 2px #4a90e2 inset, 0 12px 28px rgba(31,58,93,0.08)' : '';
            const cb = document.getElementById('crm-cb-' + id);
            if (cb) cb.checked = checked;
        }
    }

    function crmUpdateBulkBar() {
        const n = crmSelectedIds.size;
        const el = document.getElementById('crm-bulk-count');
        if (el) el.textContent = '已选 ' + n + ' 条';
        
        const statsEl = document.getElementById('crm-bulk-stats');
        if (statsEl) {
            if (n === 0) {
                statsEl.innerHTML = '';
            } else {
                const data = crmLoad();
                const selectedOrders = data.filter(r => crmSelectedIds.has(String(r.id)));
                const stats = crmCalculateStats(selectedOrders);
                statsEl.innerHTML = crmRenderStatsHtml(stats);
            }
        }
        
        crmUpdateSummaryStats();
    }

    function crmCalculateStats(orders) {
        let totalPkgs = 0, totalWeight = 0, totalCbm = 0, totalBillWeight = 0;
        let totalReceivable = 0, totalPayable = 0, totalProfit = 0;
        
        orders.forEach(r => {
            totalPkgs += Number(r.pkgs) || 0;
            totalWeight += Number(r.weight) || 0;
            totalCbm += Number(r.cbm) || 0;
            totalBillWeight += Number(r.billWeight) || 0;
            totalReceivable += Number((r.fees || {}).total) || 0;
            totalPayable += Number((r.costs || {})._total) || 0;
            totalProfit += Number(r.profit) || 0;
        });
        
        return [
            { label: '订单', value: orders.length, unit: '单', color: '#667eea' },
            { label: '件数', value: totalPkgs, unit: '件', color: '#3498db' },
            { label: '毛重', value: totalWeight, unit: 'kg', color: '#9b59b6' },
            { label: '体积', value: totalCbm, unit: 'CBM', color: '#1abc9c' },
            { label: '计费重', value: totalBillWeight, unit: 'kg', color: '#e67e22' },
            { label: '应收', value: '¥' + totalReceivable.toLocaleString(), unit: '', color: '#2c7be5' },
            { label: '应付', value: '¥' + totalPayable.toLocaleString(), unit: '', color: '#e74c3c' },
            { label: '毛利', value: (totalProfit >= 0 ? '' : '-') + '¥' + Math.abs(totalProfit).toLocaleString(), unit: '', color: totalProfit >= 0 ? '#27ae60' : '#e74c3c' }
        ];
    }

    function crmRenderStatsHtml(stats) {
        return stats.map(s => 
            `<span style="background:${s.color}22; color:${s.color}; padding:3px 8px; border-radius:6px; border:1px solid ${s.color}44; font-size:11px;">
                ${s.label}: ${typeof s.value === 'number' ? s.value.toLocaleString() : s.value}${s.unit}
            </span>`
        ).join('');
    }

    function crmUpdateSummaryStats() {
        const summaryEl = document.getElementById('crm-summary-stats');
        const modeEl = document.getElementById('crm-stats-mode');
        if (!summaryEl) return;
        
        const data = crmLoad();
        let orders = [];
        let modeText = '';
        
        if (crmSelectedIds.size > 0) {
            orders = data.filter(r => crmSelectedIds.has(String(r.id)));
            modeText = '已选 ' + orders.length + ' 单';
        } else {
            const container = document.getElementById('crm-list');
            const visibleIds = new Set();
            container.querySelectorAll('[data-order-id]').forEach(el => {
                visibleIds.add(el.getAttribute('data-order-id'));
            });
            orders = data.filter(r => visibleIds.has(String(r.id)));
            modeText = '当前筛选 ' + orders.length + ' 单';
        }
        
        if (modeEl) modeEl.textContent = modeText;
        
        if (orders.length === 0) {
            summaryEl.innerHTML = '<span style="color:#888; font-size:12px;">暂无订单数据</span>';
            return;
        }
        
        const stats = crmCalculateStats(orders);
        summaryEl.innerHTML = crmRenderStatsHtml(stats);
    }

    let crmCurrentPage = 1;
    let crmPageSize = 20;
    let crmFilteredTotal = 0;

    function crmPrevPage() {
        if (crmCurrentPage > 1) {
            crmCurrentPage--;
            crmRender();
        }
    }

    function crmNextPage() {
        const totalPages = Math.ceil(crmFilteredTotal / crmPageSize);
        if (crmCurrentPage < totalPages) {
            crmCurrentPage++;
            crmRender();
        }
    }

    function crmGoToPage(page) {
        const totalPages = Math.ceil(crmFilteredTotal / crmPageSize);
        if (page >= 1 && page <= totalPages) {
            crmCurrentPage = page;
            crmRender();
        }
    }

    function crmChangePageSize(size) {
        crmPageSize = parseInt(size);
        crmCurrentPage = 1;
        crmRender();
    }

    function crmUpdatePagination() {
        const totalPages = Math.ceil(crmFilteredTotal / crmPageSize);
        const pagination = document.getElementById('crm-pagination');
        const prevBtn = document.getElementById('crm-prev-page');
        const nextBtn = document.getElementById('crm-next-page');
        const pageInfo = document.getElementById('crm-page-info');
        const pageButtons = document.getElementById('crm-page-buttons');
        
        if (crmFilteredTotal <= crmPageSize) {
            pagination.style.display = 'none';
            return;
        }
        
        pagination.style.display = 'flex';
        prevBtn.style.display = crmCurrentPage > 1 ? 'inline-block' : 'none';
        nextBtn.style.display = crmCurrentPage < totalPages ? 'inline-block' : 'none';
        
        pageInfo.textContent = `第 ${crmCurrentPage}/${totalPages} 页 · 共 ${crmFilteredTotal} 条`;
        
        let btnHtml = '';
        const startPage = Math.max(1, crmCurrentPage - 2);
        const endPage = Math.min(totalPages, crmCurrentPage + 2);
        
        if (startPage > 1) {
            btnHtml += `<button onclick="crmGoToPage(1)" style="background:#f0f4fa; border:1px solid #ddd; color:#4a90e2; border-radius:4px; padding:4px 10px; font-size:12px; cursor:pointer;">1</button>`;
            if (startPage > 2) btnHtml += `<span style="color:#aaa;">...</span>`;
        }
        
        for (let i = startPage; i <= endPage; i++) {
            const isActive = i === crmCurrentPage;
            btnHtml += `<button onclick="crmGoToPage(${i})" style="background:${isActive?'#4a90e2':'#f0f4fa'}; border:1px solid ${isActive?'#4a90e2':'#ddd'}; color:${isActive?'#fff':'#4a90e2'}; border-radius:4px; padding:4px 10px; font-size:12px; cursor:pointer;">${i}</button>`;
        }
        
        if (endPage < totalPages) {
            if (endPage < totalPages - 1) btnHtml += `<span style="color:#aaa;">...</span>`;
            btnHtml += `<button onclick="crmGoToPage(${totalPages})" style="background:#f0f4fa; border:1px solid #ddd; color:#4a90e2; border-radius:4px; padding:4px 10px; font-size:12px; cursor:pointer;">${totalPages}</button>`;
        }
        
        pageButtons.innerHTML = btnHtml;
    }

    function crmRender() {
        const data = crmLoad();
        const q = (document.getElementById('crm-search').value || '').toLowerCase();
        const sf = document.getElementById('crm-filter-status').value;

        // stats
        const statusCounts = {};
        data.forEach(r => { statusCounts[r.status] = (statusCounts[r.status] || 0) + 1; });
        const statsBar = document.getElementById('crm-stats-bar');
        statsBar.innerHTML = `<span style="font-size:11px; color:#888; align-self:center;">共 ${data.length} 票</span>` +
            Object.entries(statusCounts).map(([s, c]) => {
                const col = CRM_STATUS_COLOR[s] || '#888';
                return `<span style="background:${col}18; color:${col}; border:1px solid ${col}44; padding:3px 9px; border-radius:999px; font-size:11px; font-weight:bold;">${s} ${c}</span>`;
            }).join('');

        // filter
        let list = data.filter(r => {
            const matchQ = !q || [r.client, r.orderno, r.mbl, r.hbl, r.pol, r.pod, r.goods, r.carrier, r.vessel, r.shipMode, r.bizType].join(' ').toLowerCase().includes(q);
            const matchS = !sf || r.status === sf;
            return matchQ && matchS;
        });

        // sort: 已结算排到后面
        list.sort((a, b) => {
            const aSettled = a.settlementStatus === '已结算' ? 1 : 0;
            const bSettled = b.settlementStatus === '已结算' ? 1 : 0;
            return aSettled - bSettled;
        });

        crmFilteredTotal = list.length;
        const totalPages = Math.ceil(crmFilteredTotal / crmPageSize);
        if (crmCurrentPage > totalPages && totalPages > 0) crmCurrentPage = totalPages;
        
        const startIndex = (crmCurrentPage - 1) * crmPageSize;
        const endIndex = startIndex + crmPageSize;
        const pageList = list.slice(startIndex, endIndex);

        const container = document.getElementById('crm-list');
        const empty = document.getElementById('crm-empty');
        if (list.length === 0) {
            container.innerHTML = '';
            empty.style.display = 'block';
            document.getElementById('crm-pagination').style.display = 'none';
            return;
        }
        empty.style.display = 'none';

        container.innerHTML = pageList.map((r, idx) => {
            const col = CRM_STATUS_COLOR[r.status] || '#888';
            const fees = r.fees || {};
            const isLcl = (r.bizType || 'fcl') === 'lcl';
            const etdStr = r.etd ? `ETD ${r.etd}` : '';
            const etaStr = r.eta ? `ETA ${r.eta}` : '';
            const route = [r.pol, r.pod].filter(Boolean).join(' → ') || '—';
            const cinfo = isLcl
                ? [r.shipMode, r.billWeight ? `计费重${Number(r.billWeight).toLocaleString()}kg` : ''].filter(Boolean).join('　')
                : [r.ctype, r.cqty > 1 ? `×${r.cqty}` : ''].filter(Boolean).join('');
            const selected = crmSelectedIds.has(String(r.id));
            const selStyle = selected ? 'background:rgba(74,144,226,0.08); box-shadow:0 0 0 2px #4a90e2 inset, 0 12px 28px rgba(31,58,93,0.08);' : '';
            const cbHtml = crmSelectMode
                ? `<div style="flex-shrink:0; display:flex; align-items:center; padding-right:4px;">
                    <input type="checkbox" id="crm-cb-${r.id}" ${selected?'checked':''} style="width:18px; height:18px; cursor:pointer; accent-color:#4a90e2;">
                </div>`
                : '';
            const globalIdx = startIndex + idx + 1;
            const indexHtml = `<div style="flex-shrink:0; min-width:28px; height:28px; background:linear-gradient(135deg,#667eea,#764ba2); color:#fff; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:12px; font-weight:bold; margin-right:8px;">${globalIdx}</div>`;
            return `<div id="crm-card-${r.id}" class="module-card" style="margin-bottom:10px; cursor:pointer; border-left:4px solid ${col}; ${selStyle}" data-order-id="${r.id}">
                <div style="display:flex; align-items:flex-start; gap:8px;">
                    ${indexHtml}
                    ${cbHtml}
                    <div style="flex:1; min-width:0; display:flex; align-items:flex-start; justify-content:space-between; gap:8px; flex-wrap:wrap;">
                        <div style="min-width:0;">
                            <div style="font-size:14px; font-weight:bold; color:#2c3e50; margin-bottom:4px;">${r.client || '（无客户名）'}${isLcl ? ' · 散货' : ''}</div>
                            <div style="font-size:12px; color:#607d8b;">${route}${cinfo ? '　' + cinfo : ''}</div>
                            ${r.orderno || r.mbl ? `<div style="font-size:11px; color:#aaa; margin-top:3px;">${[r.orderno, r.mbl].filter(Boolean).join(' | ')}</div>` : ''}
                        </div>
                        <div style="display:flex; flex-direction:column; align-items:flex-end; gap:4px; flex-shrink:0;">
                            <div style="display:flex; gap:4px; align-items:center;">
                                <span style="background:${col}22; color:${col}; padding:3px 10px; border-radius:999px; font-size:11px; font-weight:bold;">${r.status}</span>
                                <span style="background:${(r.settlementStatus === '已结算') ? '#27ae6022' : ((r.settlementStatus === '部分结算') ? '#f39c1222' : '#e74c3c22')}; color:${(r.settlementStatus === '已结算') ? '#27ae60' : ((r.settlementStatus === '部分结算') ? '#f39c12' : '#e74c3c')}; padding:2px 6px; border-radius:4px; font-size:10px; font-weight:bold;">${r.settlementStatus || '未结算'}</span>
                            </div>
                            ${fees.total ? `<span style="font-size:12px; font-weight:bold; color:#2c7be5;">应收 ¥${Number(fees.total).toLocaleString()}</span>` : ''}
                        ${(r.profit !== undefined && (r.costs||{})._total) ? `<span style="font-size:11px; font-weight:bold; color:${r.profit>=0?'#1f7a5c':'#e74c3c'};">利 ${r.profit>=0?'':'-'}¥${Math.abs(r.profit).toLocaleString()}${r.margin?` (${(r.margin*100).toFixed(0)}%)`:''}</span>` : ''}
                        </div>
                    </div>
                </div>
                ${etdStr || etaStr ? `<div style="margin-top:8px; font-size:11px; color:#888; padding-left:${crmSelectMode?'62px':'36px'}">${[etdStr, etaStr].filter(Boolean).join('　')}</div>` : ''}
                ${r.goods ? `<div style="margin-top:4px; font-size:11px; color:#95a5a6; padding-left:${crmSelectMode?'62px':'36px'}">货：${r.goods}</div>` : ''}
                ${(r.tags && r.tags.length) ? `<div style="margin-top:4px; padding-left:${crmSelectMode?'62px':'36px'}; display:flex; flex-wrap:wrap; gap:4px;">${r.tags.map(t => `<span style="background:#9b59b622; color:#9b59b6; padding:2px 8px; border-radius:999px; font-size:10px; font-weight:bold;">${t}</span>`).join('')}</div>` : ''}
            </div>`;
        }).join('');
        
        setTimeout(() => {
            document.querySelectorAll('[data-order-id]').forEach(card => {
                card.onclick = function(e) {
                    if (e.target.tagName === 'INPUT') return;
                    const orderId = this.getAttribute('data-order-id');
                    if (crmSelectMode) {
                        crmToggleSelect(orderId, e);
                    } else {
                        crmShowDetail(orderId);
                    }
                };
            });
        }, 0);
        
        setTimeout(() => crmUpdateSummaryStats(), 10);
        crmUpdatePagination();
    }


    // ─── CRM 视图切换 ───
    let crmCurrentView = 'list';
    function crmSwitchView(v) {
        crmCurrentView = v;
        document.getElementById('crm-view-list').style.display = v === 'list' ? 'block' : 'none';
        document.getElementById('crm-view-stats').style.display = v === 'stats' ? 'block' : 'none';
        const btnL = document.getElementById('crm-view-btn-list');
        const btnS = document.getElementById('crm-view-btn-stats');
        if (btnL) { btnL.style.background = v==='list'?'#4a90e2':'transparent'; btnL.style.color = v==='list'?'#fff':'#7a90a8'; }
        if (btnS) { btnS.style.background = v==='stats'?'#1f7a5c':'transparent'; btnS.style.color = v==='stats'?'#fff':'#7a90a8'; }
        if (v === 'stats') crmRenderStats();
    }

    // ─── CRM 利润统计 ───
    function crmRenderStats() {
        let data = crmLoad();
        const fmtM = v => v !== undefined ? (v>=0?'':'-')+'¥'+Math.abs(v).toLocaleString('zh-CN',{maximumFractionDigits:0}) : '—';
        const fmtP = v => v !== undefined ? (v*100).toFixed(1)+'%' : '—';

        const periodEl = document.getElementById('crm-stats-period');
        const filterEl = document.getElementById('crm-stats-filter');
        const period = periodEl ? periodEl.value : 'all';
        const filter = filterEl ? filterEl.value : 'all';

        const now = new Date();
        const thisMonth = now.toISOString().slice(0,7);
        const thisYear = now.getFullYear();
        const thisQuarter = Math.floor(now.getMonth() / 3) + 1;
        const quarterStart = new Date(thisYear, (thisQuarter-1)*3, 1).toISOString().slice(0,10);

        if(period === 'month'){
            data = data.filter(r => (r.etd||r.createdAt||'').slice(0,7) === thisMonth);
        }else if(period === 'quarter'){
            data = data.filter(r => (r.etd||r.createdAt||'') >= quarterStart);
        }else if(period === 'year'){
            data = data.filter(r => (r.etd||r.createdAt||'').slice(0,4) === String(thisYear));
        }

        if(filter === 'profit'){
            data = data.filter(r => r.profit !== undefined && r.profit > 0);
        }else if(filter === 'loss'){
            data = data.filter(r => r.profit !== undefined && r.profit < 0);
        }else if(filter === 'completed'){
            data = data.filter(r => r.status === '已完结');
        }

        const withCosts = data.filter(r => r.costs && r.costs._total);
        const totalRev  = data.reduce((s,r) => s + ((r.fees||{}).total||0), 0);
        const totalCost = withCosts.reduce((s,r) => s + (r.costs._total||0), 0);
        const totalProfit = withCosts.reduce((s,r) => s + (r.profit||0), 0);
        const avgMargin  = totalRev > 0 ? (withCosts.reduce((s,r)=>s+(r.profit||0),0)) / withCosts.reduce((s,r)=>s+((r.fees||{}).total||0),0) : 0;
        const profitColor = totalProfit >= 0 ? '#1f7a5c' : '#e74c3c';

        const overview = document.getElementById('crm-stat-overview');
        if (overview) overview.innerHTML = [
            {label:'总票数', val: data.length+'票', sub:'含'+withCosts.length+'票有应付数据', color:'#4a90e2'},
            {label:'总应收', val:'¥'+totalRev.toLocaleString(), sub:'客户应收合计', color:'#2980b9'},
            {label:'总应付', val:'¥'+totalCost.toLocaleString(), sub:'供应商应付合计', color:'#e67e22'},
            {label:'毛利 / 毛利率', val: fmtM(totalProfit), sub: fmtP(avgMargin)+' 综合毛利率', color: profitColor},
        ].map(c=>`<div class="stat-card" style="border-top:3px solid ${c.color};">
            <div class="stat-label">${c.label}</div>
            <div class="stat-value" style="color:${c.color};font-size:16px;">${c.val}</div>
            <div class="stat-sub">${c.sub}</div>
        </div>`).join('');

        const byMonth = {};
        withCosts.forEach(r => {
            const month = (r.etd||r.createdAt||'').slice(0,7);
            if (!month) return;
            if (!byMonth[month]) byMonth[month] = { rev:0, cost:0, profit:0 };
            byMonth[month].rev    += (r.fees||{}).total||0;
            byMonth[month].cost   += r.costs._total||0;
            byMonth[month].profit += r.profit||0;
        });
        const months = Object.keys(byMonth).sort();
        const canvas = document.getElementById('crm-profit-chart');
        const emptyEl = document.getElementById('crm-profit-chart-empty');
        if (months.length < 2) {
            if (canvas) canvas.style.display = 'none';
            if (emptyEl) emptyEl.style.display = 'block';
        } else {
            if (canvas) canvas.style.display = 'block';
            if (emptyEl) emptyEl.style.display = 'none';
            const ctx = canvas.getContext('2d');
            canvas.width = canvas.offsetWidth * window.devicePixelRatio || 600;
            canvas.height = 200 * window.devicePixelRatio;
            ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
            const W = canvas.offsetWidth || 600, H = 200;
            const profits = months.map(m => byMonth[m].profit);
            const revs    = months.map(m => byMonth[m].rev);
            const maxVal  = Math.max(...profits, ...revs, 1);
            const minVal  = Math.min(...profits, 0);
            const range   = maxVal - minVal || 1;
            const pad = { l:50, r:16, t:16, b:36 };
            const chartW = W - pad.l - pad.r;
            const chartH = H - pad.t - pad.b;
            const xStep  = chartW / (months.length - 1 || 1);
            const yScale = v => pad.t + chartH - ((v - minVal) / range) * chartH;
            ctx.clearRect(0, 0, W, H);
            ctx.strokeStyle = '#eee'; ctx.lineWidth = 1;
            [0, 0.25, 0.5, 0.75, 1].forEach(t => {
                const y = pad.t + chartH * t;
                ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(W - pad.r, y); ctx.stroke();
                const v = maxVal - t * range;
                ctx.fillStyle = '#aaa'; ctx.font = '10px sans-serif'; ctx.textAlign = 'right';
                ctx.fillText('¥'+Math.round(v/1000)+'k', pad.l - 4, y + 3);
            });
            if (minVal < 0) {
                const zy = yScale(0);
                ctx.strokeStyle = '#ccc'; ctx.setLineDash([4,3]); ctx.lineWidth = 1;
                ctx.beginPath(); ctx.moveTo(pad.l, zy); ctx.lineTo(W-pad.r, zy); ctx.stroke();
                ctx.setLineDash([]);
            }
            const barW = Math.max(4, xStep * 0.4);
            months.forEach((m, i) => {
                const x = pad.l + i * xStep;
                const v = byMonth[m].rev;
                const y0 = yScale(0), y1 = yScale(v);
                ctx.fillStyle = 'rgba(74,144,226,0.2)';
                ctx.fillRect(x - barW/2, Math.min(y0,y1), barW, Math.abs(y0-y1));
            });
            ctx.strokeStyle = '#1f7a5c'; ctx.lineWidth = 2.5; ctx.setLineDash([]);
            ctx.beginPath();
            months.forEach((m, i) => {
                const x = pad.l + i * xStep, y = yScale(byMonth[m].profit);
                i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
            });
            ctx.stroke();
            months.forEach((m, i) => {
                const x = pad.l + i * xStep, y = yScale(byMonth[m].profit);
                const p = byMonth[m].profit;
                ctx.beginPath(); ctx.arc(x, y, 4, 0, Math.PI*2);
                ctx.fillStyle = p >= 0 ? '#1f7a5c' : '#e74c3c'; ctx.fill();
            });
            ctx.fillStyle = '#888'; ctx.font = '10px sans-serif'; ctx.textAlign = 'center';
            months.forEach((m, i) => {
                const x = pad.l + i * xStep;
                ctx.fillText(m.slice(5), x, H - 8);
            });
        }

        const byRoute = {};
        withCosts.forEach(r => {
            const route = r.route || '未知航线';
            if (!byRoute[route]) byRoute[route] = { rev:0, cost:0, profit:0, count:0 };
            byRoute[route].rev    += (r.fees||{}).total||0;
            byRoute[route].cost   += r.costs._total||0;
            byRoute[route].profit += r.profit||0;
            byRoute[route].count  ++;
        });
        const routeList = Object.entries(byRoute).sort((a,b) => b[1].profit - a[1].profit);
        const routeEl = document.getElementById('crm-stat-routes');
        if (routeEl) {
            if (!routeList.length) { routeEl.innerHTML = '<div style="color:#bbb;font-size:12px;text-align:center;padding:16px;">暂无数据</div>'; }
            else routeEl.innerHTML = routeList.map(([name, d], i) => {
                const margin = d.rev > 0 ? d.profit/d.rev : 0;
                const pc = d.profit >= 0 ? '#1f7a5c' : '#e74c3c';
                const barPct = Math.min(Math.max(margin*100, 0), 100);
                return `<div style="padding:10px 0;border-bottom:1px solid #f0f4fa;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                        <div style="display:flex;align-items:center;gap:8px;">
                            <span style="background:#e8f4fd;color:#2980b9;border-radius:999px;padding:1px 8px;font-size:10px;font-weight:bold;">#${i+1}</span>
                            <span style="font-size:13px;font-weight:bold;color:#2c3e50;">${name}</span>
                            <span style="font-size:10px;color:#aaa;">${d.count}票</span>
                        </div>
                        <span style="font-size:13px;font-weight:bold;color:${pc};">${fmtM(d.profit)}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;font-size:11px;color:#888;margin-bottom:4px;">
                        <span>应收 ¥${d.rev.toLocaleString()}</span>
                        <span>应付 ¥${d.cost.toLocaleString()}</span>
                        <span style="color:${pc};font-weight:bold;">${fmtP(margin)}</span>
                    </div>
                    <div style="background:#eee;border-radius:999px;height:4px;overflow:hidden;">
                        <div style="height:100%;background:${pc};width:${barPct}%;"></div>
                    </div>
                </div>`;
            }).join('');
        }

        const byCarrier = {};
        withCosts.forEach(r => {
            const carrier = r.carrier || '未知船司';
            if (!byCarrier[carrier]) byCarrier[carrier] = { rev:0, cost:0, profit:0, count:0 };
            byCarrier[carrier].rev    += (r.fees||{}).total||0;
            byCarrier[carrier].cost   += r.costs._total||0;
            byCarrier[carrier].profit += r.profit||0;
            byCarrier[carrier].count  ++;
        });
        const carrierList = Object.entries(byCarrier).sort((a,b) => b[1].profit - a[1].profit);
        const carrierEl = document.getElementById('crm-stat-carriers');
        if (carrierEl) {
            if (!carrierList.length) { carrierEl.innerHTML = '<div style="color:#bbb;font-size:12px;text-align:center;padding:16px;">暂无数据</div>'; }
            else carrierEl.innerHTML = carrierList.slice(0,10).map(([name, d], i) => {
                const margin = d.rev > 0 ? d.profit/d.rev : 0;
                const pc = d.profit >= 0 ? '#1f7a5c' : '#e74c3c';
                return `<div style="padding:8px 0;border-bottom:1px solid #f0f4fa;display:flex;justify-content:space-between;align-items:center;">
                    <div style="display:flex;align-items:center;gap:8px;">
                        <span style="background:#fef5e7;color:#e67e22;border-radius:999px;padding:1px 8px;font-size:10px;font-weight:bold;">#${i+1}</span>
                        <span style="font-size:12px;color:#2c3e50;">${name}</span>
                        <span style="font-size:10px;color:#aaa;">${d.count}票</span>
                    </div>
                    <div style="text-align:right;">
                        <span style="font-size:12px;font-weight:bold;color:${pc};">${fmtM(d.profit)}</span>
                        <span style="font-size:10px;color:#888;margin-left:8px;">${fmtP(margin)}</span>
                    </div>
                </div>`;
            }).join('');
        }

        const byClient = {};
        withCosts.forEach(r => {
            const c = r.client || '未知';
            if (!byClient[c]) byClient[c] = { rev:0, cost:0, profit:0, count:0 };
            byClient[c].rev    += (r.fees||{}).total||0;
            byClient[c].cost   += r.costs._total||0;
            byClient[c].profit += r.profit||0;
            byClient[c].count  ++;
        });
        const clientList = Object.entries(byClient).sort((a,b) => b[1].profit - a[1].profit);
        const clEl = document.getElementById('crm-stat-clients');
        if (clEl) {
            if (!clientList.length) { clEl.innerHTML = '<div style="color:#bbb;font-size:12px;text-align:center;padding:16px;">暂无数据</div>'; }
            else clEl.innerHTML = clientList.map(([name, d], i) => {
                const margin = d.rev > 0 ? d.profit/d.rev : 0;
                const pc = d.profit >= 0 ? '#1f7a5c' : '#e74c3c';
                const barPct = Math.min(Math.max(margin*100, 0), 100);
                return `<div style="padding:10px 0;border-bottom:1px solid #f0f4fa;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                        <div style="display:flex;align-items:center;gap:8px;">
                            <span style="background:#4a90e222;color:#4a90e2;border-radius:999px;padding:1px 8px;font-size:10px;font-weight:bold;">#${i+1}</span>
                            <span style="font-size:13px;font-weight:bold;color:#2c3e50;">${name}</span>
                            <span style="font-size:10px;color:#aaa;">${d.count}票</span>
                        </div>
                        <span style="font-size:13px;font-weight:bold;color:${pc};">${fmtM(d.profit)}</span>
                    </div>
                    <div style="display:flex;justify-content:space-between;font-size:11px;color:#888;margin-bottom:4px;">
                        <span>应收 ¥${d.rev.toLocaleString()}</span>
                        <span>应付 ¥${d.cost.toLocaleString()}</span>
                        <span style="color:${pc};font-weight:bold;">${fmtP(margin)}</span>
                    </div>
                    <div style="background:#eee;border-radius:999px;height:4px;overflow:hidden;">
                        <div style="height:100%;background:${pc};width:${barPct}%;"></div>
                    </div>
                </div>`;
            }).join('');
        }

        const detailEl = document.getElementById('crm-stat-detail');
        if (detailEl) {
            const rows = data.filter(r => (r.fees||{}).total || (r.costs||{})._total).sort((a,b)=>(b.etd||'').localeCompare(a.etd||''));
            if (!rows.length) { detailEl.innerHTML = '<div style="color:#bbb;font-size:12px;text-align:center;padding:16px;">暂无数据</div>'; return; }
            detailEl.innerHTML = `<table style="width:100%;border-collapse:collapse;font-size:11px;">
                <thead><tr style="background:var(--bg-tertiary);">
                    <th style="padding:7px 6px;text-align:left;border-bottom:2px solid var(--border-color);color:#4a90e2;min-width:100px;">客户</th>
                    <th style="padding:7px 6px;text-align:center;border-bottom:2px solid var(--border-color);color:#4a90e2;">ETD</th>
                    <th style="padding:7px 6px;text-align:right;border-bottom:2px solid var(--border-color);color:#27ae60;">应收</th>
                    <th style="padding:7px 6px;text-align:right;border-bottom:2px solid var(--border-color);color:#e67e22;">应付</th>
                    <th style="padding:7px 6px;text-align:right;border-bottom:2px solid var(--border-color);color:#1f7a5c;">毛利</th>
                    <th style="padding:7px 6px;text-align:center;border-bottom:2px solid var(--border-color);color:#1f7a5c;">利润率</th>
                </tr></thead>
                <tbody>${rows.map((r,i)=>{
                    const rev  = (r.fees||{}).total||0;
                    const cost = (r.costs||{})._total||0;
                    const pft  = r.profit !== undefined ? r.profit : rev - cost;
                    const mgn  = rev > 0 ? pft/rev : 0;
                    const pc   = pft >= 0 ? '#1f7a5c' : '#e74c3c';
                    const hasCost = (r.costs||{})._total;
                    return `<tr style="background:${i%2?'var(--bg-tertiary)':'var(--bg-primary)'};">
                        <td style="padding:7px 6px;font-weight:600;color:var(--text-primary);">${r.client||'—'}</td>
                        <td style="padding:7px 6px;text-align:center;color:var(--text-secondary);">${r.etd||'—'}</td>
                        <td style="padding:7px 6px;text-align:right;color:#2980b9;">¥${rev.toLocaleString()}</td>
                        <td style="padding:7px 6px;text-align:right;color:#e67e22;">${hasCost?'¥'+cost.toLocaleString():'—'}</td>
                        <td style="padding:7px 6px;text-align:right;font-weight:bold;color:${pc};">${hasCost?fmtM(pft):'—'}</td>
                        <td style="padding:7px 6px;text-align:center;"><span style="background:${hasCost?(pft>=0?'#d4f1e4':'#fde0e0'):'#f5f5f5'};color:${hasCost?pc:'#bbb'};padding:2px 8px;border-radius:999px;font-weight:bold;">${hasCost?fmtP(mgn):'—'}</span></td>
                    </tr>`;
                }).join('')}</tbody>
            </table>`;
        }
    }

    function crmExportCSV(selectionOnly = false) {
        let data = crmLoad();
        if (selectionOnly && crmSelectedIds.size > 0) {
            data = data.filter(r => crmSelectedIds.has(String(r.id)));
        }
        if (!data.length) { showToast('暂无数据'); return; }
        const headers = ['业务类型','客户','订单号','MBL','HBL','运输方式','起运港','目的港','发货地址','收货地址','柜型','柜数','船公司','船名航次',
            '品名','毛重(kg)','件数','体积(CBM)','计费重(kg)','单价(¥/kg)','截关日','ETD','ETA','ATA','提柜日','免柜期',
            '海运费','国内拖车费','报关费','税金','ARRIVAL NOTICE費用','清关费','尾程派送费','其他费','应收合计','状态','贸易术语','备注','创建日期'];
        const rows = data.map(r => {
            const f = r.fees || {};
            return [r.bizType === 'lcl' ? '散货' : '整柜', r.client,r.orderno,r.mbl,r.hbl,r.shipMode,r.pol,r.pod,r.shipaddr,r.recvaddr,r.ctype,r.cqty,r.carrier,r.vessel,
                r.goods,r.weight,r.pkgs,r.cbm,r.billWeight,r.unitPrice,r.cutoff,r.etd,r.eta,r.ata,r.pickup,r.freetime,
                f.ocean,f.truck,f.customs,f.tax,f.arrival_notice,f.clearance,f.delivery,f.other,f.total,r.status,r.incoterm,
                (r.notes||'').replace(/\n/g,' '),(r.createdAt||'').slice(0,10)]
                .map(v => `"${v||''}"`).join(',');
        });
        const csv = '\uFEFF' + [headers.map(h=>`"${h}"`).join(','), ...rows].join('\n');
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([csv], {type:'text/csv;charset=utf-8;'}));
        a.download = 'HGCD_CRM_' + new Date().toISOString().slice(0,10) + '.csv';
        a.click();
        showToast('CSV已导出');
    }

    const DEFAULT_API_URL = 'http://107.173.7.180:3000';
    const DEFAULT_API_KEY_ENCRYPTED = 'Y3JtMjAyNHNlY3JldGtleTEyMw==';
    const CLOUDFLARE_API_URL = 'https://crm-tracking-api.wubairan.workers.dev';
    const CLOUDFLARE_API_KEY_ENCRYPTED = 'Y3JtMjAyNHNlY3JldGtleTEyMw==';
    let editingApiIndex = -1;

    function decryptApiKey(encrypted) {
        try {
            return atob(encrypted);
        } catch(e) {
            return '';
        }
    }

    function encryptApiKey(key) {
        try {
            return btoa(key);
        } catch(e) {
            return '';
        }
    }

    function getApiConfigs() {
        const stored = localStorage.getItem('crm_api_configs');
        if (stored) {
            try {
                return JSON.parse(stored);
            } catch(e) {}
        }
        return [
            {
                id: 'default',
                name: 'VPS服务器',
                url: DEFAULT_API_URL,
                key: DEFAULT_API_KEY_ENCRYPTED,
                isDefault: true
            },
            {
                id: 'cloudflare',
                name: 'Cloudflare备用',
                url: CLOUDFLARE_API_URL,
                key: CLOUDFLARE_API_KEY_ENCRYPTED,
                isDefault: false
            }
        ];
    }

    function saveApiConfigs(configs) {
        localStorage.setItem('crm_api_configs', JSON.stringify(configs));
    }

    function getCurrentApiConfig() {
        const configs = getApiConfigs();
        const currentId = localStorage.getItem('crm_current_api_id') || 'default';
        return configs.find(c => c.id === currentId) || configs[0];
    }

    function getDecryptedKey(config) {
        if (config.isDefault) {
            return decryptApiKey(DEFAULT_API_KEY_ENCRYPTED);
        }
        return decryptApiKey(config.key);
    }

    // 获取有效的API密钥，依次尝试多个来源
    function getEffectiveApiKey() {
        // 1. 尝试当前配置中心的key
        const config = getCurrentApiConfig();
        if (config) {
            const apiKey = getDecryptedKey(config);
            if (apiKey) return apiKey;
        }
        
        // 2. 尝试旧版localStorage里的cloudflare_api_key
        const legacyKey = localStorage.getItem('cloudflare_api_key');
        if (legacyKey) return legacyKey;
        
        // 3. 使用默认密钥（与DEFAULT_API_KEY_ENCRYPTED解密后一致）
        return decryptApiKey(DEFAULT_API_KEY_ENCRYPTED);
    }

    // 获取有效的API URL，依次尝试多个来源
    function getEffectiveApiUrl() {
        // 1. 尝试当前配置中心的URL
        const config = getCurrentApiConfig();
        if (config && config.url) {
            return config.url;
        }
        
        // 2. 尝试旧版localStorage里的cloudflare_api_url
        const legacyUrl = localStorage.getItem('cloudflare_api_url');
        if (legacyUrl) return legacyUrl;
        
        // 3. 使用默认VPS URL（与DEFAULT_API_URL一致）
        return DEFAULT_API_URL;
    }

    function showApiConfig() {
        const modal = document.getElementById('api-config-modal');
        modal.style.display = 'flex';
        
        let autoSyncValue = localStorage.getItem('crm_auto_sync');
        if (autoSyncValue === null) {
            localStorage.setItem('crm_auto_sync', 'true');
            autoSyncValue = 'true';
        }
        const autoSync = autoSyncValue === 'true';
        document.getElementById('config-auto-sync').checked = autoSync;
        updateAutoSyncSlider();
        
        document.getElementById('api-config-status').style.display = 'none';
        document.getElementById('api-edit-section').style.display = 'none';
        editingApiIndex = -1;
        
        renderApiConfigList();
        
        const slider = document.getElementById('auto-sync-slider');
        slider.onclick = function() {
            const checkbox = document.getElementById('config-auto-sync');
            checkbox.checked = !checkbox.checked;
            updateAutoSyncSlider();
        };
    }

    function renderApiConfigList() {
        const configs = getApiConfigs();
        const currentId = localStorage.getItem('crm_current_api_id') || 'default';
        const listEl = document.getElementById('api-config-list');
        
        if (configs.length === 0) {
            listEl.innerHTML = '<div style="text-align:center; color:var(--text-secondary); padding:20px;">暂无API配置，请添加</div>';
            return;
        }
        
        listEl.innerHTML = configs.map((config, index) => {
            const isCurrent = config.id === currentId;
            const maskedKey = config.isDefault ? '••••••••••••' : '••••••••••••';
            return `
                <div style="padding:12px; margin-bottom:8px; background:var(--bg-primary); border:1px solid ${isCurrent ? '#9b59b6' : 'var(--border-color)'}; border-radius:8px; ${isCurrent ? 'box-shadow:0 0 0 2px rgba(155,89,182,0.2);' : ''}">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                        <div style="display:flex; align-items:center; gap:8px;">
                            <span style="font-weight:bold; color:var(--text-primary);">${config.name}</span>
                            ${isCurrent ? '<span style="background:#9b59b6; color:#fff; padding:2px 8px; border-radius:4px; font-size:10px;">当前使用</span>' : ''}
                            ${config.isDefault ? '<span style="background:#27ae60; color:#fff; padding:2px 8px; border-radius:4px; font-size:10px;">系统默认</span>' : ''}
                        </div>
                        <div style="display:flex; gap:4px;">
                            ${!isCurrent ? `<button onclick="selectApiConfig('${config.id}')" style="background:#3498db; color:#fff; border:none; border-radius:4px; padding:4px 8px; cursor:pointer; font-size:11px;">选用</button>` : ''}
                            ${!config.isDefault ? `<button onclick="editApiConfig(${index})" style="background:#f39c12; color:#fff; border:none; border-radius:4px; padding:4px 8px; cursor:pointer; font-size:11px;">编辑</button>` : ''}
                            ${!config.isDefault ? `<button onclick="deleteApiConfig('${config.id}')" style="background:#e74c3c; color:#fff; border:none; border-radius:4px; padding:4px 8px; cursor:pointer; font-size:11px;">删除</button>` : ''}
                        </div>
                    </div>
                    <div style="font-size:11px; color:var(--text-secondary);">
                        <div style="margin-bottom:2px;">URL: ${config.url}</div>
                        <div>Key: ${maskedKey}</div>
                    </div>
                </div>
            `;
        }).join('');
    }

    function addNewApiConfig() {
        editingApiIndex = -1;
        document.getElementById('api-edit-title').textContent = '添加新配置';
        document.getElementById('config-name').value = '';
        document.getElementById('config-api-url').value = '';
        document.getElementById('config-api-key').value = '';
        document.getElementById('api-edit-section').style.display = 'block';
    }

    function editApiConfig(index) {
        const configs = getApiConfigs();
        const config = configs[index];
        if (!config) return;
        
        editingApiIndex = index;
        document.getElementById('api-edit-title').textContent = '编辑配置';
        document.getElementById('config-name').value = config.name;
        document.getElementById('config-api-url').value = config.url;
        document.getElementById('config-api-key').value = '';
        document.getElementById('config-api-key').placeholder = '留空则保持原密钥不变';
        document.getElementById('api-edit-section').style.display = 'block';
    }

    function saveCurrentApiConfig() {
        const name = document.getElementById('config-name').value.trim();
        const url = document.getElementById('config-api-url').value.trim();
        const key = document.getElementById('config-api-key').value.trim();
        
        if (!name || !url) {
            showApiStatus('请填写配置名称和API URL', true);
            return;
        }
        
        const configs = getApiConfigs();
        
        if (editingApiIndex === -1) {
            if (!key) {
                showApiStatus('请填写API Key', true);
                return;
            }
            configs.push({
                id: 'api_' + Date.now(),
                name: name,
                url: url,
                key: encryptApiKey(key),
                isDefault: false
            });
            showApiStatus('✅ 配置已添加');
        } else {
            configs[editingApiIndex].name = name;
            configs[editingApiIndex].url = url;
            if (key) {
                configs[editingApiIndex].key = encryptApiKey(key);
            }
            showApiStatus('✅ 配置已更新');
        }
        
        saveApiConfigs(configs);
        document.getElementById('api-edit-section').style.display = 'none';
        renderApiConfigList();
    }

    function cancelEditApiConfig() {
        document.getElementById('api-edit-section').style.display = 'none';
        editingApiIndex = -1;
    }

    function selectApiConfig(id) {
        localStorage.setItem('crm_current_api_id', id);
        renderApiConfigList();
        showApiStatus('✅ 已切换到此配置');
    }

    function deleteApiConfig(id) {
        if (!confirm('确定要删除此API配置吗？')) return;
        
        const configs = getApiConfigs();
        const newConfigs = configs.filter(c => c.id !== id);
        saveApiConfigs(newConfigs);
        
        const currentId = localStorage.getItem('crm_current_api_id');
        if (currentId === id) {
            localStorage.setItem('crm_current_api_id', 'default');
        }
        
        renderApiConfigList();
        showApiStatus('✅ 配置已删除');
    }

    function showApiStatus(msg, isError = false) {
        const status = document.getElementById('api-config-status');
        status.style.display = 'block';
        status.style.color = isError ? '#e74c3c' : '#27ae60';
        status.textContent = msg;
        setTimeout(() => {
            status.style.display = 'none';
        }, 2000);
    }

    function updateAutoSyncSlider() {
        const checkbox = document.getElementById('config-auto-sync');
        const slider = document.getElementById('auto-sync-slider');
        const dot = document.getElementById('auto-sync-dot');
        if (checkbox.checked) {
            slider.style.backgroundColor = '#9b59b6';
            dot.style.left = '27px';
            localStorage.setItem('crm_auto_sync', 'true');
        } else {
            slider.style.backgroundColor = '#ccc';
            dot.style.left = '3px';
            localStorage.setItem('crm_auto_sync', 'false');
        }
    }

    function hideApiConfig() {
        document.getElementById('api-config-modal').style.display = 'none';
    }

    function crmExportTracking() {
        const config = getCurrentApiConfig();
        const apiUrl = config.url;
        const apiKey = getDecryptedKey(config);
        
        const allData = {
            orders: [],
            clients: [],
            suppliers: [],
            airQuotes: [],
            fclQuotes: [],
            todos: [],
            calendarMemos: [],
            shipmentNotes: null,
            appState: null,
            apiConfigs: getApiConfigs(),
            currentApiId: localStorage.getItem('crm_current_api_id') || 'default'
        };
        
        const ordersData = crmLoad();
        if (ordersData.length) {
            allData.orders = ordersData.map(r => ({
                id: r.id || crypto.randomUUID(),
                bizType: r.bizType || 'fcl',
                client: r.client || '',
                orderno: r.orderno || '',
                clientOrderNo: r.clientOrderNo || '',
                mbl: r.mbl || '',
                hbl: r.hbl || '',
                shipMode: r.shipMode || '',
                pol: r.pol || '',
                pod: r.pod || '',
                shipaddr: r.shipaddr || '',
                recvaddr: r.recvaddr || '',
                ctype: r.ctype || '',
                cqty: r.cqty || 1,
                carrier: r.carrier || '',
                vessel: r.vessel || '',
                goods: r.goods || '',
                weight: r.weight || 0,
                pkgs: r.pkgs || 0,
                cbm: r.cbm || 0,
                billWeight: r.billWeight || 0,
                unitPrice: r.unitPrice || 0,
                bookedDate: r.bookedDate || '',
                loadedDate: r.loadedDate || '',
                cutoff: r.cutoff || '',
                etd: r.etd || '',
                eta: r.eta || '',
                ata: r.ata || '',
                clearedDate: r.clearedDate || '',
                pickup: r.pickup || '',
                deliveryDate: r.deliveryDate || '',
                freetime: r.freetime || '',
                signed: r.signed || '',
                warehouse: r.warehouse || '',
                flight: r.flight || '',
                airSigned: r.airSigned || '',
                airBookedDate: r.airBookedDate || '',
                airAta: r.airAta || '',
                airClearedDate: r.airClearedDate || '',
                tracking: r.tracking || '',
                carrierType: r.carrierType || '',
                status: r.status || '',
                settlementStatus: r.settlementStatus || '未结算',
                incoterm: r.incoterm || '',
                tags: r.tags || [],
                notes: r.notes || '',
                fees: r.fees || null,
                costs: r.costs || null,
                receivable: r.receivable || 0,
                payable: r.payable || 0,
                profit: r.profit || 0,
                margin: r.margin || 0,
                statusHistory: r.statusHistory || [],
                createdAt: r.createdAt || new Date().toISOString(),
                updatedAt: r.updatedAt || new Date().toISOString()
            }));
        }
        
        try {
            const clientsData = localStorage.getItem('logistics_client_data');
            if (clientsData) allData.clients = JSON.parse(clientsData);
        } catch(e) {}
        
        try {
            const suppliersData = localStorage.getItem('logistics_supplier_data');
            if (suppliersData) allData.suppliers = JSON.parse(suppliersData);
        } catch(e) {}
        
        try {
            const airQuotesData = localStorage.getItem('freight_air_cache_v1');
            if (airQuotesData) allData.airQuotes = [{ id: '1', data: JSON.parse(airQuotesData) }];
        } catch(e) {}
        
        try {
            const fclQuotesData = localStorage.getItem('freight_fcl_cache_v1');
            if (fclQuotesData) allData.fclQuotes = [{ id: '1', data: JSON.parse(fclQuotesData) }];
        } catch(e) {}
        
        try {
            const todosData = localStorage.getItem('dashboard_todos_v1');
            if (todosData) allData.todos = JSON.parse(todosData);
        } catch(e) {}
        
        try {
            const memosData = localStorage.getItem('hcn_calendar_memos');
            if (memosData) {
                const memos = JSON.parse(memosData);
                allData.calendarMemos = Object.entries(memos).map(([date, content]) => ({
                    id: crypto.randomUUID(),
                    date: date,
                    content: content
                }));
            }
        } catch(e) {}
        
        try {
            const shipmentNotes = localStorage.getItem('shipment_notes_v1');
            if (shipmentNotes) allData.shipmentNotes = shipmentNotes;
        } catch(e) {}
        
        try {
            const appState = localStorage.getItem('logistics_workbench_state_v1');
            if (appState) allData.appState = JSON.parse(appState);
        } catch(e) {}
        
        showToast('正在同步数据到云端...');
        
        fetch(apiUrl + '/api/sync-all', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify(allData)
        })
        .then(response => response.json())
        .then(result => {
            if (result.success) {
                showToast('✅ 数据已同步到云端');
            } else {
                showToast('同步失败：' + (result.error || '未知错误'));
            }
        })
        .catch(error => {
            showToast('❌ 同步失败：' + error.message);
        });
    }

    function crmRestoreFromCloud() {
        // 使用兼容逻辑获取API配置
        const apiUrl = getEffectiveApiUrl();
        const apiKey = getEffectiveApiKey();
        
        // 调试日志
        console.log('[云端恢复] API URL:', apiUrl);
        console.log('[云端恢复] API Key:', apiKey ? `${apiKey.substring(0, 8)}...` : '未设置');
        console.log('[云端恢复] 当前配置:', getCurrentApiConfig());
        console.log('[云端恢复] 旧版cloudflare_api_key:', localStorage.getItem('cloudflare_api_key'));
        console.log('[云端恢复] 旧版cloudflare_api_url:', localStorage.getItem('cloudflare_api_url'));
        
        if (!apiUrl || !apiKey) {
            showToast('请先配置API或检查网络连接');
            console.error('[云端恢复] 缺少API配置');
            return;
        }
        
        if (!confirm('确定要从云端恢复数据吗？这将覆盖本地数据。')) {
            return;
        }
        
        showToast('正在从云端恢复数据...');
        
        fetch(apiUrl + '/api/backup', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${apiKey}`
            }
        })
        .then(response => response.json())
        .then(result => {
            if (result.success && result.data) {
                const data = result.data;
                let restoreCount = 0;
                
                if (data.orders && data.orders.length) {
                    crmSave(data.orders);
                    restoreCount += data.orders.length;
                }
                
                if (data.clients && data.clients.length) {
                    const clients = data.clients.map(c => ({
                        id: c.id || Date.now().toString(),
                        name: c.name || '',
                        level: c.level || 'B',
                        contact: c.contact || '',
                        phone: c.phone || '',
                        email: c.email || '',
                        route: c.route || '',
                        address: c.address || '',
                        notes: c.notes || '',
                        createdAt: c.createdAt || new Date().toISOString(),
                        updatedAt: c.updatedAt || new Date().toISOString()
                    }));
                    localStorage.setItem('logistics_client_data', JSON.stringify(clients));
                    restoreCount += clients.length;
                }
                
                if (data.suppliers && data.suppliers.length) {
                    const suppliers = data.suppliers.map(s => ({
                        id: s.id || Date.now().toString(),
                        name: s.name || '',
                        type: s.type || '船代理',
                        contact: s.contact || '',
                        phone: s.phone || '',
                        email: s.email || '',
                        region: s.region || '',
                        address: s.address || '',
                        bank: s.bank || '',
                        notes: s.notes || '',
                        createdAt: s.createdAt || new Date().toISOString(),
                        updatedAt: s.updatedAt || new Date().toISOString()
                    }));
                    localStorage.setItem('logistics_supplier_data', JSON.stringify(suppliers));
                    restoreCount += suppliers.length;
                }
                
                if (data.airQuotes && data.airQuotes.length) {
                    const airData = data.airQuotes[0];
                    if (airData && airData.data) {
                        localStorage.setItem('freight_air_cache_v1', JSON.stringify(airData.data));
                        restoreCount++;
                    }
                }
                
                if (data.fclQuotes && data.fclQuotes.length) {
                    const fclData = data.fclQuotes[0];
                    if (fclData && fclData.data) {
                        localStorage.setItem('freight_fcl_cache_v1', JSON.stringify(fclData.data));
                        restoreCount++;
                    }
                }
                
                if (data.todos && data.todos.length) {
                    localStorage.setItem('dashboard_todos_v1', JSON.stringify(data.todos));
                    restoreCount += data.todos.length;
                }
                
                if (data.calendarMemos && data.calendarMemos.length) {
                    const memos = {};
                    data.calendarMemos.forEach(m => {
                        memos[m.date] = m.content;
                    });
                    localStorage.setItem('hcn_calendar_memos', JSON.stringify(memos));
                    restoreCount += data.calendarMemos.length;
                }
                
                if (data.shipmentNotes && data.shipmentNotes.length) {
                    localStorage.setItem('shipment_notes_v1', data.shipmentNotes[0].content || '');
                    restoreCount++;
                }
                
                if (data.appState && data.appState.length) {
                    const state = data.appState[0];
                    if (state && state.state) {
                        localStorage.setItem('logistics_workbench_state_v1', JSON.stringify(state.state));
                        restoreCount++;
                    }
                }
                
                if (data.apiConfigs && data.apiConfigs.length) {
                    saveApiConfigs(data.apiConfigs);
                    restoreCount++;
                }
                
                if (data.currentApiId) {
                    localStorage.setItem('crm_current_api_id', data.currentApiId);
                    restoreCount++;
                }
                
                showToast('✅ 已从云端恢复 ' + restoreCount + ' 条数据！');
                crmRender();
                if (typeof supplierLoadData === 'function') supplierLoadData();
                if (typeof clientLoadData === 'function') clientLoadData();
                if (typeof supplierRender === 'function') supplierRender();
                if (typeof clientRender === 'function') clientRender();
                reminderLoadData();
                reminderGenerateFromCRM();
                reminderRender();
                reconciliationLoadData();
                reconciliationGenerateFromCRM();
                reconciliationRender();
                freightLoadData();
                freightRender();
            } else {
                showToast('❌ 恢复失败：' + (result.error || '未知错误'));
            }
        })
        .catch(error => {
            showToast('❌ 恢复失败：' + error.message);
        });
    }

    // ─── PDF 导出选项弹窗 ───
    let _crmPdfList = null;

    function crmExportPDF(selectionOnly = false) {
        const data = crmLoad();
        let list;
        const shouldUseSelection = crmSelectedIds.size > 0 && (selectionOnly || crmSelectMode);
        if (shouldUseSelection) {
            list = data.filter(r => crmSelectedIds.has(String(r.id)));
        } else {
            const q = (document.getElementById('crm-search').value || '').toLowerCase();
            const sf = document.getElementById('crm-filter-status').value;
            list = data.filter(r => {
                const mQ = !q || [r.client,r.orderno,r.mbl,r.hbl,r.pol,r.pod,r.goods,r.carrier,r.vessel,r.shipMode,r.bizType].join(' ').toLowerCase().includes(q);
                return mQ && (!sf || r.status === sf);
            });
        }
        if (!list.length) { showToast('暂无数据'); return; }
        _crmPdfList = list;
        document.getElementById('crm-pdf-modal').style.display = 'flex';
    }

    function crmClosePdfModal() {
        document.getElementById('crm-pdf-modal').style.display = 'none';
        _crmPdfList = null;
    }

    function crmBuildPdfHtml(list, mode, opts = {}) {
        const STATUS_COLOR = {
            '询价':'#8e44ad','已下单':'#2980b9','已入库':'#3498db','已审单':'#9b59b6','已装柜':'#e67e22','已开船':'#16a085',
            '已到港':'#27ae60','已清关':'#1f7a5c','已完结':'#7f8c8d','取消':'#c0392b'
        };
        const fmt = v => v || '—';
        const today = new Date().toLocaleDateString('zh-CN');
        const isClient = mode === 'client';
        const includeActions = opts.includeActions !== false;

        const statusSummary = {};
        list.forEach(r => { statusSummary[r.status] = (statusSummary[r.status]||0)+1; });
        const summaryTags = Object.entries(statusSummary).map(([s,c]) => {
            const col = STATUS_COLOR[s]||'#888';
            return `<span style="background:${col}18;color:${col};border:1px solid ${col}44;padding:3px 10px;border-radius:999px;font-size:11px;font-weight:bold;margin-right:6px;">${s} ${c}票</span>`;
        }).join('');

        const totalRev  = list.reduce((s,r) => s + ((r.fees||{}).total||0), 0);
        const totalCost = isClient ? 0 : list.reduce((s,r) => s + ((r.costs||{})._total||0), 0);
        const totalProfit = isClient ? 0 : list.reduce((s,r) => s + (r.profit||0), 0);
        const bizTypes = [...new Set(list.map(r => r.bizType || 'fcl'))];
        const bizLabel = bizTypes.length === 1
            ? (bizTypes[0] === 'lcl' ? '散货费用单' : '整柜费用单')
            : '业务费用单';

        const thS = 'padding:10px 6px;color:#fff;font-size:11px;border:1px solid #3d7fcf;';
        const feeDetailItems = [
            ['海运费', 'ocean'],
            ['拖车费', 'truck'],
            ['报关费', 'customs'],
            ['查验费', 'inspection'],
            ['商检费', 'commodity'],
            ['熏蒸费', 'fumigation'],
            ['税金', 'tax'],
            ['ARRIVAL NOTICE費用', 'arrival_notice'],
            ['清关费', 'clearance'],
            ['尾程派送费', 'delivery'],
            ['其他', 'other']
        ];
        const buildFeeDetailHtml = (fees) => {
            const rows = feeDetailItems
                .filter(([, key]) => Number(fees?.[key]) > 0)
                .map(([label, key]) =>
                    `<div style="display:flex;justify-content:space-between;gap:8px;white-space:nowrap;">
                        <span style="color:#7f8c8d;">${label}</span>
                        <span style="font-weight:600;color:#2c3e50;">¥${Number(fees[key]).toLocaleString()}</span>
                    </div>`
                );
            return rows.length
                ? `<div style="display:flex;flex-direction:column;gap:3px;">${rows.join('')}</div>`
                : '<span style="color:#bbb;">—</span>';
        };

        const headRow = isClient
            ? `<tr style="background:linear-gradient(135deg,#4a90e2,#5ba3f5);">
                <th style="${thS}text-align:center;min-width:56px;">类型</th>
                <th style="${thS}text-align:left;min-width:80px;">客户</th>
                <th style="${thS}text-align:left;min-width:90px;">内部单号</th>
                <th style="${thS}text-align:left;min-width:100px;">MBL</th>
                <th style="${thS}text-align:center;min-width:100px;">航线</th>
                <th style="${thS}text-align:center;">柜型/方式</th>
                <th style="${thS}text-align:left;min-width:80px;">品名</th>
                <th style="${thS}text-align:center;min-width:68px;">ETD</th>
                <th style="${thS}text-align:center;min-width:68px;">ETA</th>
                <th style="${thS}text-align:center;min-width:68px;">签收</th>
                <th style="${thS}text-align:left;min-width:170px;">明细金额</th>
                <th style="${thS}text-align:center;min-width:80px;">应收合计</th>
                <th style="${thS}text-align:center;min-width:64px;">状态</th>
            </tr>`
            : `<tr style="background:linear-gradient(135deg,#2c3e50,#34495e);">
                <th style="${thS}text-align:center;min-width:56px;">类型</th>
                <th style="${thS}text-align:left;min-width:80px;">客户</th>
                <th style="${thS}text-align:left;min-width:90px;">内部单号</th>
                <th style="${thS}text-align:left;min-width:100px;">MBL</th>
                <th style="${thS}text-align:center;min-width:90px;">航线</th>
                <th style="${thS}text-align:center;">柜型/方式</th>
                <th style="${thS}text-align:center;min-width:64px;">ETD</th>
                <th style="${thS}text-align:right;min-width:72px;">应收</th>
                <th style="${thS}text-align:right;min-width:72px;">应付</th>
                <th style="${thS}text-align:right;min-width:72px;">毛利</th>
                <th style="${thS}text-align:center;min-width:52px;">利润率</th>
                <th style="${thS}text-align:center;min-width:56px;">状态</th>
            </tr>`;

        const rowsHtml = list.map((r, i) => {
            const f = r.fees || {};
            const isLcl = (r.bizType || 'fcl') === 'lcl';
            const col = STATUS_COLOR[r.status] || '#888';
            const bg = i%2===0 ? '#fff' : '#f8fbff';
            const tdS = `padding:7px 6px;border:1px solid #e0e8f0;font-size:11px;`;
            const statusBadge = `<span style="background:${col}22;color:${col};padding:2px 8px;border-radius:999px;font-size:10px;font-weight:bold;white-space:nowrap;">${r.status}</span>`;
            if (isClient) {
                const signedDate = r.signed || r.airSigned || '';
                return `<tr style="background:${bg};">
                    <td style="${tdS}text-align:center;color:${isLcl?'#16a085':'#4a90e2'};font-weight:bold;">${isLcl?'散货':'整柜'}</td>
                    <td style="${tdS}font-weight:600;color:#2c3e50;">${r.client||'—'}</td>
                    <td style="${tdS}color:#555;">${r.orderno||'—'}</td>
                    <td style="${tdS}color:#555;">${r.mbl||'—'}</td>
                    <td style="${tdS}text-align:center;">${fmt(r.pol)} → ${fmt(r.pod)}</td>
                    <td style="${tdS}text-align:center;color:#444;">${isLcl ? (r.shipMode||'—') : `${r.ctype||'—'}${r.cqty>1?' ×'+r.cqty:''}`}</td>
                    <td style="${tdS}color:#555;">${fmt(r.goods)}</td>
                    <td style="${tdS}text-align:center;color:#555;">${fmt(r.etd)}</td>
                    <td style="${tdS}text-align:center;color:#555;">${fmt(r.eta)}</td>
                    <td style="${tdS}text-align:center;color:#555;">${fmt(signedDate)}</td>
                    <td style="${tdS}line-height:1.45;min-width:170px;">${buildFeeDetailHtml(f)}</td>
                    <td style="${tdS}text-align:center;font-weight:bold;color:#2c7be5;">${f.total ? '¥'+Number(f.total).toLocaleString() : '—'}</td>
                    <td style="${tdS}text-align:center;">${statusBadge}</td>
                </tr>`;
            } else {
                const cost = (r.costs||{})._total || 0;
                const pft  = r.profit !== undefined ? r.profit : ((f.total||0) - cost);
                const mgn  = (f.total||0) > 0 ? pft/(f.total||0) : 0;
                const pc   = pft >= 0 ? '#1f7a5c' : '#e74c3c';
                const hasCost = (r.costs||{})._total;
                return `<tr style="background:${bg};">
                    <td style="${tdS}text-align:center;color:${isLcl?'#16a085':'#4a90e2'};font-weight:bold;">${isLcl?'散货':'整柜'}</td>
                    <td style="${tdS}font-weight:600;color:#2c3e50;">${r.client||'—'}</td>
                    <td style="${tdS}color:#555;">${r.orderno||'—'}</td>
                    <td style="${tdS}color:#555;">${r.mbl||'—'}</td>
                    <td style="${tdS}text-align:center;">${fmt(r.pol)} → ${fmt(r.pod)}</td>
                    <td style="${tdS}text-align:center;">${isLcl ? (r.shipMode||'—') : `${r.ctype||'—'}${r.cqty>1?' ×'+r.cqty:''}`}</td>
                    <td style="${tdS}text-align:center;color:#555;">${fmt(r.etd)}</td>
                    <td style="${tdS}text-align:right;color:#2980b9;font-weight:bold;">${f.total ? '¥'+Number(f.total).toLocaleString() : '—'}</td>
                    <td style="${tdS}text-align:right;color:#e67e22;">${hasCost ? '¥'+Number(cost).toLocaleString() : '—'}</td>
                    <td style="${tdS}text-align:right;font-weight:bold;color:${pc};">${hasCost ? (pft>=0?'':'- ')+'¥'+Math.abs(pft).toLocaleString() : '—'}</td>
                    <td style="${tdS}text-align:center;"><span style="background:${hasCost?(pft>=0?'#d4f1e4':'#fde0e0'):'#f5f5f5'};color:${hasCost?pc:'#bbb'};padding:2px 6px;border-radius:999px;font-size:10px;font-weight:bold;">${hasCost?(mgn*100).toFixed(1)+'%':'—'}</span></td>
                    <td style="${tdS}text-align:center;">${statusBadge}</td>
                </tr>`;
            }
        }).join('');

        const footerRow = isClient
            ? `<tr style="background:#f0f6ff;">
                <td colspan="11" style="padding:8px 6px;border:1px solid #e0e8f0;font-size:11px;font-weight:bold;color:#2c3e50;text-align:right;">应收合计</td>
                <td style="padding:8px 6px;border:1px solid #e0e8f0;font-size:12px;font-weight:bold;color:#2c7be5;text-align:center;">¥${totalRev.toLocaleString()}</td>
                <td style="border:1px solid #e0e8f0;"></td>
            </tr>`
            : `<tr style="background:#f0f6ff;">
                <td colspan="7" style="padding:8px 6px;border:1px solid #e0e8f0;font-size:11px;font-weight:bold;color:#2c3e50;text-align:right;">合计</td>
                <td style="padding:8px 6px;border:1px solid #e0e8f0;font-size:12px;font-weight:bold;color:#2980b9;text-align:right;">¥${totalRev.toLocaleString()}</td>
                <td style="padding:8px 6px;border:1px solid #e0e8f0;font-size:12px;font-weight:bold;color:#e67e22;text-align:right;">¥${totalCost.toLocaleString()}</td>
                <td style="padding:8px 6px;border:1px solid #e0e8f0;font-size:12px;font-weight:bold;color:${totalProfit>=0?'#1f7a5c':'#e74c3c'};text-align:right;">${totalProfit>=0?'':'- '}¥${Math.abs(totalProfit).toLocaleString()}</td>
                <td colspan="2" style="border:1px solid #e0e8f0;"></td>
            </tr>`;

        const headerColor = isClient ? '#4a90e2' : '#2c3e50';
        const titleLabel  = isClient ? `📦 ${bizLabel}（客户版）` : `📊 ${bizLabel}（内部完整版）`;
        const watermark   = isClient ? '' : '<div style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%) rotate(-30deg);font-size:48px;color:rgba(0,0,0,0.04);font-weight:bold;pointer-events:none;white-space:nowrap;z-index:0;">内部保密</div>';
        const actionHtml = includeActions ? `
    <div class="no-print" style="margin-top:20px;display:flex;gap:12px;justify-content:center;">
        <button onclick="window.print()" style="padding:12px 32px;background:${headerColor};color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:bold;cursor:pointer;">🖨️ 打印 / 保存为PDF</button>
        <button onclick="window.close()" style="padding:12px 24px;background:#95a5a6;color:#fff;border:none;border-radius:8px;font-size:14px;cursor:pointer;">关闭</button>
    </div>` : '';

        return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">
    <title>${titleLabel}</title>
    <style>
    *{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:"PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;background:#fff;padding:20px;position:relative;}
    @media print{
    body{padding:0;}
    .no-print{display:none!important;}
    @page{margin:10mm 8mm;size:A4 landscape;}
    }
    </style></head><body>
    ${watermark}
    <div style="max-width:1100px;margin:0 auto;position:relative;z-index:1;">
    <div style="display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:14px;padding-bottom:12px;border-bottom:3px solid ${headerColor};">
        <div>
        <div style="font-size:20px;font-weight:bold;color:#2c3e50;letter-spacing:1px;">${titleLabel}</div>
        <div style="font-size:11px;color:#888;margin-top:4px;">导出日期：${today}　共 ${list.length} 条记录</div>
        </div>
        <div style="text-align:right;font-size:12px;color:${headerColor};font-weight:bold;">应收合计：¥${totalRev.toLocaleString()}${!isClient ? `<br><span style="color:#1f7a5c;">毛利：${totalProfit>=0?'':'- '}¥${Math.abs(totalProfit).toLocaleString()}</span>` : ''}</div>
    </div>
    <div style="margin-bottom:12px;display:flex;flex-wrap:wrap;gap:4px;align-items:center;">
        <span style="font-size:11px;color:#aaa;margin-right:4px;">状态汇总</span>${summaryTags}
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:11px;">${headRow}<tbody>${rowsHtml}</tbody><tfoot>${footerRow}</tfoot></table>
    <div style="margin-top:12px;font-size:9px;color:#ccc;text-align:right;">由 HGCD CRM系统生成 · ${today}${isClient ? '' : ' · 内部资料，请勿外传'}</div>
    ${actionHtml}
    </div>
    </body></html>`;
    }

    function crmBuildAndDownloadPDF(mode) {
        // mode: 'client' = 只含客户应收，'full' = 含供应商应付+毛利
        const list = _crmPdfList;
        if (!list || !list.length) return;
        crmClosePdfModal();

        if (typeof html2canvas === 'undefined' || typeof window.jspdf === 'undefined') {
            showToast('PDF生成库未加载，正在加载...');
            const script1 = document.createElement('script');
            script1.src = 'https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js';
            script1.onload = () => {
                const script2 = document.createElement('script');
                script2.src = 'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js';
                script2.onload = () => crmBuildAndDownloadPDFActual(list, mode);
                document.head.appendChild(script2);
            };
            document.head.appendChild(script1);
            return;
        }
        
        crmBuildAndDownloadPDFActual(list, mode);
    }

    async function crmBuildAndDownloadPDFActual(list, mode) {
        const isClient = mode === 'client';
        const bizTypes = [...new Set(list.map(r => r.bizType || 'fcl'))];
        const bizLabel = bizTypes.length === 1
            ? (bizTypes[0] === 'lcl' ? '散货费用单' : '整柜费用单')
            : '业务费用单';
        
        const firstRecord = list[0];
        const safeOrder = String(firstRecord.orderno || firstRecord.mbl || firstRecord.id || 'record').replace(/[\/:*?"<>|]+/g, '-').trim();
        const safeGoods = String(firstRecord.goods || '').replace(/[\/:*?"<>|]+/g, '-').trim().substring(0, 20);
        const totalPieces = list.reduce((sum, r) => sum + (parseInt(r.pieces) || parseInt(r.cqty) || 1), 0);
        
        const fileNameParts = [safeOrder];
        if (safeGoods) fileNameParts.push(safeGoods);
        fileNameParts.push(`${totalPieces}件`);
        const fileName = `${fileNameParts.join('_')}.pdf`;

        showToast('正在生成PDF...');

        const html = crmBuildPdfHtml(list, mode, { includeActions: false });
        const wrap = document.createElement('div');
        wrap.style.cssText = 'position:fixed;left:-9999px;top:0;width:1120px;background:#fff;z-index:-9999;';
        wrap.innerHTML = html;
        document.body.appendChild(wrap);

        try {
            await new Promise(resolve => setTimeout(resolve, 200));
            
            const canvas = await html2canvas(wrap, {
                scale: 2,
                backgroundColor: '#ffffff',
                useCORS: true,
                logging: false,
                width: wrap.scrollWidth,
                height: wrap.scrollHeight
            });
            
            const imgData = canvas.toDataURL('image/png');
            const { jsPDF } = window.jspdf;
            const pdf = new jsPDF('l', 'mm', 'a4');
            
            const pageWidth = 297;
            const pageHeight = 210;
            const margin = 5;
            const imgWidth = pageWidth - margin * 2;
            const imgHeight = (canvas.height * imgWidth) / canvas.width;
            
            let heightLeft = imgHeight;
            let position = margin;
            
            pdf.addImage(imgData, 'PNG', margin, position, imgWidth, imgHeight);
            heightLeft -= (pageHeight - margin * 2);
            
            while (heightLeft > 0) {
                position = heightLeft - imgHeight + margin;
                pdf.addPage();
                pdf.addImage(imgData, 'PNG', margin, position, imgWidth, imgHeight);
                heightLeft -= (pageHeight - margin * 2);
            }
            
            const pdfBlob = pdf.output('blob');
            const pdfFile = new File([pdfBlob], fileName, { type: 'application/pdf' });
            
            if (navigator.share && navigator.canShare && navigator.canShare({ files: [pdfFile] })) {
                try {
                    await navigator.share({
                        title: fileName,
                        files: [pdfFile]
                    });
                    wrap.remove();
                    return;
                } catch (err) {
                    if (err && err.name === 'AbortError') {
                        wrap.remove();
                        return;
                    }
                }
            }
            
            const url = URL.createObjectURL(pdfBlob);
            const a = document.createElement('a');
            a.href = url;
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 3000);
            
            showToast('PDF已下载');
        } catch (err) {
            console.error(err);
            showToast('PDF生成失败：' + (err.message || '未知错误'), true);
        } finally {
            wrap.remove();
        }
    }

    async function crmShareClientPdf(id) {
        const data = crmLoad();
        const record = data.find(x => String(x.id) === String(id));
        if (!record) { showToast('未找到订单', true); return; }

        if (typeof html2canvas === 'undefined' || typeof window.jspdf === 'undefined') {
            showToast('PDF生成库未加载，请刷新页面重试');
            const html = crmBuildPdfHtml([record], 'client', { includeActions: false });
            const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.target = '_blank';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 3000);
            return;
        }

        const html = crmBuildPdfHtml([record], 'client', { includeActions: false });
        const wrap = document.createElement('div');
        wrap.style.cssText = 'position:fixed;left:-9999px;top:0;width:1120px;background:#fff;z-index:-9999;';
        wrap.innerHTML = html;
        document.body.appendChild(wrap);

        const safeClient = String(record.client || '客户').replace(/[\/:*?"<>|]+/g, '-').trim();
        const safeOrder = String(record.orderno || record.mbl || record.id || 'record').replace(/[\/:*?"<>|]+/g, '-').trim();
        const bizLabel = (record.bizType || 'fcl') === 'lcl' ? '散货费用单' : '整柜费用单';
        const fileName = `客户版${bizLabel}_${safeClient}_${safeOrder}.pdf`;

        showToast('正在生成客户版PDF...');

        try {
            await new Promise(resolve => setTimeout(resolve, 200));
            
            const canvas = await html2canvas(wrap, {
                scale: 2,
                backgroundColor: '#ffffff',
                useCORS: true,
                logging: false,
                width: wrap.scrollWidth,
                height: wrap.scrollHeight
            });
            
            const imgData = canvas.toDataURL('image/png');
            const { jsPDF } = window.jspdf;
            const pdf = new jsPDF('l', 'mm', 'a4');
            
            const pageWidth = 297;
            const pageHeight = 210;
            const margin = 5;
            const imgWidth = pageWidth - margin * 2;
            const imgHeight = (canvas.height * imgWidth) / canvas.width;
            
            let heightLeft = imgHeight;
            let position = margin;
            
            pdf.addImage(imgData, 'PNG', margin, position, imgWidth, imgHeight);
            heightLeft -= (pageHeight - margin * 2);
            
            while (heightLeft > 0) {
                position = heightLeft - imgHeight + margin;
                pdf.addPage();
                pdf.addImage(imgData, 'PNG', margin, position, imgWidth, imgHeight);
                heightLeft -= (pageHeight - margin * 2);
            }
            
            const pdfBlob = pdf.output('blob');
            const pdfFile = new File([pdfBlob], fileName, { type: 'application/pdf' });
            
            let shared = false;
            if (navigator.share && navigator.canShare && navigator.canShare({ files: [pdfFile] })) {
                try {
                    await navigator.share({
                        title: fileName,
                        files: [pdfFile]
                    });
                    shared = true;
                    showToast('客户版PDF已分享');
                } catch (shareErr) {
                    console.log('分享取消或失败:', shareErr);
                }
            }
            
            if (!shared) {
                const link = document.createElement('a');
                link.href = URL.createObjectURL(pdfBlob);
                link.download = fileName;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                showToast('客户版PDF已下载');
            }
        } catch (err) {
            console.error('PDF生成失败:', err);
            showToast('PDF生成失败: ' + (err.message || '未知错误'));
            const html = crmBuildPdfHtml([record], 'client', { includeActions: false });
            const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.target = '_blank';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 3000);
        } finally {
            wrap.remove();
        }
    }

    // ===================== 客户档案管理 =====================
    let clientData = [];
    const CLIENT_STORAGE_KEY = 'logistics_client_data';

    function clientLoadData(){
        try{
            const saved = localStorage.getItem(CLIENT_STORAGE_KEY);
            const loaded = saved ? JSON.parse(saved) : [];
            clientData = loaded.map(c => ({
                id: c.id || Date.now().toString(),
                name: c.name || '',
                level: c.level || 'B',
                contact: c.contact || '',
                phone: c.phone || '',
                email: c.email || '',
                route: c.route || '',
                address: c.address || '',
                notes: c.notes || '',
                createdAt: c.createdAt || new Date().toISOString(),
                updatedAt: c.updatedAt || new Date().toISOString()
            }));
            localStorage.setItem(CLIENT_STORAGE_KEY, JSON.stringify(clientData));
        }catch{
            clientData = [];
        }
    }

    function clientSaveData(){
        try {
            localStorage.setItem(CLIENT_STORAGE_KEY, JSON.stringify(clientData));
            return true;
        } catch(e) {
            console.error('客户档案保存失败:', e);
            showToast('保存失败，请检查浏览器存储权限', true);
            return false;
        }
    }

    function clientShowAddModal(){
        document.getElementById('client-modal-title').textContent = '新增客户';
        document.getElementById('client-edit-id').value = '';
        document.getElementById('client-f-name').value = '';
        document.getElementById('client-f-level').value = 'B';
        document.getElementById('client-f-contact').value = '';
        document.getElementById('client-f-phone').value = '';
        document.getElementById('client-f-email').value = '';
        document.getElementById('client-f-route').value = '';
        document.getElementById('client-f-address').value = '';
        document.getElementById('client-f-notes').value = '';
        document.getElementById('client-modal').style.display = 'block';
    }

    function clientShowEditModal(id){
        const item = clientData.find(c => c.id === id);
        if(!item) return;
        document.getElementById('client-modal-title').textContent = '编辑客户';
        document.getElementById('client-edit-id').value = id;
        document.getElementById('client-f-name').value = item.name || '';
        document.getElementById('client-f-level').value = item.level || 'B';
        document.getElementById('client-f-contact').value = item.contact || '';
        document.getElementById('client-f-phone').value = item.phone || '';
        document.getElementById('client-f-email').value = item.email || '';
        document.getElementById('client-f-route').value = item.route || '';
        document.getElementById('client-f-address').value = item.address || '';
        document.getElementById('client-f-notes').value = item.notes || '';
        document.getElementById('client-modal').style.display = 'block';
    }

    function clientCloseModal(){
        document.getElementById('client-modal').style.display = 'none';
    }

    function clientSaveRecord(){
        const editId = document.getElementById('client-edit-id').value;
        const name = document.getElementById('client-f-name').value.trim();
        if(!name){
            alert('请输入客户名称');
            return;
        }
        const record = {
            id: editId || Date.now().toString(),
            name,
            level: document.getElementById('client-f-level').value,
            contact: document.getElementById('client-f-contact').value.trim(),
            phone: document.getElementById('client-f-phone').value.trim(),
            email: document.getElementById('client-f-email').value.trim(),
            route: document.getElementById('client-f-route').value.trim(),
            address: document.getElementById('client-f-address').value.trim(),
            notes: document.getElementById('client-f-notes').value.trim(),
            createdAt: editId ? (clientData.find(c => c.id === editId)?.createdAt || new Date().toISOString()) : new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        if(editId){
            const idx = clientData.findIndex(c => c.id === editId);
            if(idx !== -1) clientData[idx] = record;
        }else{
            clientData.unshift(record);
        }
        if(clientSaveData()){
            showToast(editId ? '客户已更新' : '客户已添加');
        }
        clientCloseModal();
        clientRender();
    }

    function clientDeleteRecord(id){
        if(!confirm('确定删除该客户？此操作不可恢复。')) return;
        clientData = clientData.filter(c => c.id !== id);
        clientSaveData();
        clientRender();
    }

    function clientRender(){
        const statsBar = document.getElementById('client-stats-bar');
        const listEl = document.getElementById('client-list');
        const emptyEl = document.getElementById('client-empty');
        const searchEl = document.getElementById('client-search');
        const levelFilterEl = document.getElementById('client-filter-level');
        if(!statsBar || !listEl || !emptyEl) return;
        const search = searchEl ? searchEl.value.toLowerCase() : '';
        const levelFilter = levelFilterEl ? levelFilterEl.value : '';
        let filtered = clientData.filter(c => {
            const matchSearch = !search || 
                (c.name && c.name.toLowerCase().includes(search)) ||
                (c.contact && c.contact.toLowerCase().includes(search)) ||
                (c.phone && c.phone.includes(search));
            const matchLevel = !levelFilter || c.level === levelFilter;
            return matchSearch && matchLevel;
        });
        const totalA = clientData.filter(c => c.level === 'A').length;
        const totalB = clientData.filter(c => c.level === 'B').length;
        const totalC = clientData.filter(c => c.level === 'C').length;
        statsBar.innerHTML = `
            <span style="background:var(--bg-urgent, #e8f4fd); color:#2980b9; padding:4px 10px; border-radius:12px; font-size:11px;">A级: ${totalA}</span>
            <span style="background:var(--bg-normal, #e8f8f0); color:#27ae60; padding:4px 10px; border-radius:12px; font-size:11px;">B级: ${totalB}</span>
            <span style="background:var(--bg-warning, #fef5e7); color:#f39c12; padding:4px 10px; border-radius:12px; font-size:11px;">C级: ${totalC}</span>
            <span style="background:var(--bg-secondary); color:var(--text-secondary); padding:4px 10px; border-radius:12px; font-size:11px;">共 ${clientData.length} 条</span>
        `;
        if(filtered.length === 0){
            listEl.innerHTML = '';
            emptyEl.style.display = 'block';
            return;
        }
        emptyEl.style.display = 'none';
        listEl.innerHTML = filtered.map(c => {
            const levelColor = c.level === 'A' ? '#e74c3c' : (c.level === 'B' ? '#27ae60' : '#f39c12');
            const levelBg = c.level === 'A' ? '#fdeaea' : (c.level === 'B' ? '#e8f8f0' : '#fef5e7');
            const clientJson = JSON.stringify(c).replace(/"/g, '&quot;');
            return `
            <div class="module-card" style="padding:12px 14px; margin-bottom:8px; background:var(--bg-primary);">
                <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:10px;">
                    <div style="flex:1;">
                        <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
                            <span style="font-size:15px; font-weight:bold; color:var(--text-primary);">${c.name}</span>
                            <span style="background:${levelBg}; color:${levelColor}; padding:2px 8px; border-radius:10px; font-size:10px; font-weight:bold;">${c.level}级</span>
                        </div>
                        <div style="display:flex; flex-wrap:wrap; gap:12px; font-size:12px; color:var(--text-secondary);">
                            ${c.contact ? `<span>👤 ${c.contact}</span>` : ''}
                            ${c.phone ? `<span>📞 ${c.phone}</span>` : ''}
                            ${c.email ? `<span>📧 ${c.email}</span>` : ''}
                            ${c.route ? `<span>🚢 ${c.route}</span>` : ''}
                        </div>
                        ${c.address ? `<div style="font-size:12px; color:var(--text-secondary); margin-top:4px;">📍 ${c.address}</div>` : ''}
                        ${c.notes ? `<div style="font-size:11px; color:var(--text-secondary); margin-top:4px; padding:6px; background:var(--bg-secondary); border-radius:6px;">${c.notes}</div>` : ''}
                    </div>
                    <div style="display:flex; gap:6px; flex-shrink:0;">
                        <button onclick="clientShowEditModal('${c.id}')" style="background:#3498db; color:#fff; border:none; border-radius:6px; padding:6px 10px; font-size:11px; cursor:pointer;">编辑</button>
                        <button onclick="clientDeleteRecord('${c.id}')" style="background:#e74c3c; color:#fff; border:none; border-radius:6px; padding:6px 10px; font-size:11px; cursor:pointer;">删除</button>
                    </div>
                </div>
            </div>`;
        }).join('');
    }

    function clientExportCSV(){
        if(clientData.length === 0){
            alert('暂无数据可导出');
            return;
        }
        const headers = ['客户名称', '等级', '联系人', '电话', '邮箱', '常用航线', '地址', '备注', '创建时间'];
        const rows = clientData.map(c => [
            c.name, c.level, c.contact, c.phone, c.email, c.route, c.address, c.notes, c.createdAt
        ]);
        let csv = '\uFEFF' + headers.join(',') + '\n' + rows.map(r => r.map(v => `"${(v||'').toString().replace(/"/g,'""')}"`).join(',')).join('\n');
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `客户档案_${new Date().toISOString().slice(0,10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
    }

    // ===================== 供应商管理 =====================
    let supplierData = [];
    const SUPPLIER_STORAGE_KEY = 'logistics_supplier_data';

    function supplierLoadData(){
        try{
            const saved = localStorage.getItem(SUPPLIER_STORAGE_KEY);
            const loaded = saved ? JSON.parse(saved) : [];
            supplierData = loaded.map(s => ({
                id: s.id || Date.now().toString(),
                name: s.name || '',
                type: s.type || '船代理',
                contact: s.contact || '',
                phone: s.phone || '',
                email: s.email || '',
                region: s.region || '',
                address: s.address || '',
                bank: s.bank || '',
                notes: s.notes || '',
                createdAt: s.createdAt || new Date().toISOString(),
                updatedAt: s.updatedAt || new Date().toISOString()
            }));
            localStorage.setItem(SUPPLIER_STORAGE_KEY, JSON.stringify(supplierData));
        }catch{
            supplierData = [];
        }
    }

    function supplierSaveData(){
        try {
            localStorage.setItem(SUPPLIER_STORAGE_KEY, JSON.stringify(supplierData));
            return true;
        } catch(e) {
            console.error('供应商保存失败:', e);
            showToast('保存失败，请检查浏览器存储权限', true);
            return false;
        }
    }

    function supplierShowAddModal(){
        document.getElementById('supplier-modal-title').textContent = '新增供应商';
        document.getElementById('supplier-edit-id').value = '';
        document.getElementById('supplier-f-name').value = '';
        document.getElementById('supplier-f-type').value = '船代理';
        document.getElementById('supplier-f-contact').value = '';
        document.getElementById('supplier-f-phone').value = '';
        document.getElementById('supplier-f-email').value = '';
        document.getElementById('supplier-f-region').value = '';
        document.getElementById('supplier-f-address').value = '';
        document.getElementById('supplier-f-bank').value = '';
        document.getElementById('supplier-f-notes').value = '';
        document.getElementById('supplier-modal').style.display = 'block';
    }

    function supplierShowEditModal(id){
        const item = supplierData.find(s => s.id === id);
        if(!item) return;
        document.getElementById('supplier-modal-title').textContent = '编辑供应商';
        document.getElementById('supplier-edit-id').value = id;
        document.getElementById('supplier-f-name').value = item.name || '';
        document.getElementById('supplier-f-type').value = item.type || '船代理';
        document.getElementById('supplier-f-contact').value = item.contact || '';
        document.getElementById('supplier-f-phone').value = item.phone || '';
        document.getElementById('supplier-f-email').value = item.email || '';
        document.getElementById('supplier-f-region').value = item.region || '';
        document.getElementById('supplier-f-address').value = item.address || '';
        document.getElementById('supplier-f-bank').value = item.bank || '';
        document.getElementById('supplier-f-notes').value = item.notes || '';
        document.getElementById('supplier-modal').style.display = 'block';
    }

    function supplierCloseModal(){
        document.getElementById('supplier-modal').style.display = 'none';
    }

    function supplierSaveRecord(){
        const editId = document.getElementById('supplier-edit-id').value;
        const name = document.getElementById('supplier-f-name').value.trim();
        if(!name){
            alert('请输入供应商名称');
            return;
        }
        const record = {
            id: editId || Date.now().toString(),
            name,
            type: document.getElementById('supplier-f-type').value,
            contact: document.getElementById('supplier-f-contact').value.trim(),
            phone: document.getElementById('supplier-f-phone').value.trim(),
            email: document.getElementById('supplier-f-email').value.trim(),
            region: document.getElementById('supplier-f-region').value.trim(),
            address: document.getElementById('supplier-f-address').value.trim(),
            bank: document.getElementById('supplier-f-bank').value.trim(),
            notes: document.getElementById('supplier-f-notes').value.trim(),
            createdAt: editId ? (supplierData.find(s => s.id === editId)?.createdAt || new Date().toISOString()) : new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        if(editId){
            const idx = supplierData.findIndex(s => s.id === editId);
            if(idx !== -1) supplierData[idx] = record;
        }else{
            supplierData.unshift(record);
        }
        if(supplierSaveData()){
            showToast(editId ? '供应商已更新' : '供应商已添加');
        }
        supplierCloseModal();
        supplierRender();
    }

    function supplierDeleteRecord(id){
        if(!confirm('确定删除该供应商？此操作不可恢复。')) return;
        supplierData = supplierData.filter(s => s.id !== id);
        supplierSaveData();
        supplierRender();
    }

    function supplierRender(){
        const statsBar = document.getElementById('supplier-stats-bar');
        const listEl = document.getElementById('supplier-list');
        const emptyEl = document.getElementById('supplier-empty');
        const searchEl = document.getElementById('supplier-search');
        const typeFilterEl = document.getElementById('supplier-filter-type');
        if(!statsBar || !listEl || !emptyEl) return;
        const search = searchEl ? searchEl.value.toLowerCase() : '';
        const typeFilter = typeFilterEl ? typeFilterEl.value : '';
        let filtered = supplierData.filter(s => {
            const matchSearch = !search || 
                (s.name && s.name.toLowerCase().includes(search)) ||
                (s.contact && s.contact.toLowerCase().includes(search)) ||
                (s.phone && s.phone.includes(search));
            const matchType = !typeFilter || s.type === typeFilter;
            return matchSearch && matchType;
        });
        const typeCounts = {};
        supplierData.forEach(s => { typeCounts[s.type] = (typeCounts[s.type] || 0) + 1; });
        let statsHtml = `<span style="background:var(--bg-secondary); color:var(--text-secondary); padding:4px 10px; border-radius:12px; font-size:11px;">共 ${supplierData.length} 条</span>`;
        Object.entries(typeCounts).forEach(([type, count]) => {
            statsHtml += `<span style="background:var(--bg-warning, #fef5e7); color:#e67e22; padding:4px 10px; border-radius:12px; font-size:11px;">${type}: ${count}</span>`;
        });
        statsBar.innerHTML = statsHtml;
        if(filtered.length === 0){
            listEl.innerHTML = '';
            emptyEl.style.display = 'block';
            return;
        }
        emptyEl.style.display = 'none';
        listEl.innerHTML = filtered.map(s => {
            const typeColor = s.type === '船代理' ? '#3498db' : (s.type === '拖车行' ? '#9b59b6' : (s.type === '报关行' ? '#1abc9c' : '#e67e22'));
            return `
            <div class="module-card" style="padding:12px 14px; margin-bottom:8px; background:var(--bg-primary);">
                <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:10px;">
                    <div style="flex:1;">
                        <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
                            <span style="font-size:15px; font-weight:bold; color:var(--text-primary);">${s.name}</span>
                            <span style="background:var(--bg-warning, #fef5e7); color:${typeColor}; padding:2px 8px; border-radius:10px; font-size:10px; font-weight:bold;">${s.type}</span>
                        </div>
                        <div style="display:flex; flex-wrap:wrap; gap:12px; font-size:12px; color:var(--text-secondary);">
                            ${s.contact ? `<span>👤 ${s.contact}</span>` : ''}
                            ${s.phone ? `<span>📞 ${s.phone}</span>` : ''}
                            ${s.email ? `<span>📧 ${s.email}</span>` : ''}
                            ${s.region ? `<span>🌍 ${s.region}</span>` : ''}
                        </div>
                        ${s.address ? `<div style="font-size:12px; color:var(--text-secondary); margin-top:4px;">📍 ${s.address}</div>` : ''}
                        ${s.bank ? `<div style="font-size:11px; color:var(--text-secondary); margin-top:4px; padding:6px; background:var(--bg-secondary); border-radius:6px;">🏦 ${s.bank}</div>` : ''}
                        ${s.notes ? `<div style="font-size:11px; color:var(--text-secondary); margin-top:4px; padding:6px; background:var(--bg-secondary); border-radius:6px;">${s.notes}</div>` : ''}
                    </div>
                    <div style="display:flex; gap:6px; flex-shrink:0;">
                        <button onclick="supplierShowEditModal('${s.id}')" style="background:#e67e22; color:#fff; border:none; border-radius:6px; padding:6px 10px; font-size:11px; cursor:pointer;">编辑</button>
                        <button onclick="supplierDeleteRecord('${s.id}')" style="background:#e74c3c; color:#fff; border:none; border-radius:6px; padding:6px 10px; font-size:11px; cursor:pointer;">删除</button>
                    </div>
                </div>
            </div>`;
        }).join('');
    }

    function supplierExportCSV(){
        if(supplierData.length === 0){
            alert('暂无数据可导出');
            return;
        }
        const headers = ['供应商名称', '类型', '联系人', '电话', '邮箱', '服务区域', '地址', '银行账户', '备注', '创建时间'];
        const rows = supplierData.map(s => [
            s.name, s.type, s.contact, s.phone, s.email, s.region, s.address, s.bank, s.notes, s.createdAt
        ]);
        let csv = '\uFEFF' + headers.join(',') + '\n' + rows.map(r => r.map(v => `"${(v||'').toString().replace(/"/g,'""')}"`).join(',')).join('\n');
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `供应商档案_${new Date().toISOString().slice(0,10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
    }

    // ===================== 提醒通知系统 =====================
    let reminderData = [];
    const REMINDER_STORAGE_KEY = 'logistics_reminder_data';

    function reminderLoadData(){
        try{
            const saved = localStorage.getItem(REMINDER_STORAGE_KEY);
            reminderData = saved ? JSON.parse(saved) : [];
        }catch{
            reminderData = [];
        }
    }

    function reminderSaveData(){
        try {
            localStorage.setItem(REMINDER_STORAGE_KEY, JSON.stringify(reminderData));
            return true;
        } catch(e) {
            console.error('提醒保存失败:', e);
            showToast('保存失败，请检查浏览器存储权限', true);
            return false;
        }
    }

    function reminderRefresh(){
        reminderGenerateFromCRM();
        reminderRender();
        updateDashboard();
    }

    function reminderGenerateFromCRM(){
        const today = new Date();
        today.setHours(0,0,0,0);
        const newReminders = [];
        const crmData = crmLoad();
        crmData.forEach(r => {
            if(r.etd){
                const etdDate = new Date(r.etd);
                const daysDiff = Math.ceil((etdDate - today) / (1000*60*60*24));
                if(daysDiff >= 0 && daysDiff <= 30){
                    newReminders.push({
                        id: `etd-${r.id}`,
                        type: 'etd',
                        title: `ETD提醒: ${r.client || r.orderno || r.id}`,
                        date: r.etd,
                        daysLeft: daysDiff,
                        orderId: r.id,
                        status: daysDiff <= 3 ? 'urgent' : (daysDiff <= 7 ? 'warning' : 'normal')
                    });
                }
            }
            if(r.eta){
                const etaDate = new Date(r.eta);
                const daysDiff = Math.ceil((etaDate - today) / (1000*60*60*24));
                if(daysDiff >= 0 && daysDiff <= 30){
                    newReminders.push({
                        id: `eta-${r.id}`,
                        type: 'eta',
                        title: `ETA提醒: ${r.client || r.orderno || r.id}`,
                        date: r.eta,
                        daysLeft: daysDiff,
                        orderId: r.id,
                        status: daysDiff <= 3 ? 'urgent' : (daysDiff <= 7 ? 'warning' : 'normal')
                    });
                }
            }
            if(r.freetime){
                const ftDate = new Date(r.freetime);
                const daysDiff = Math.ceil((ftDate - today) / (1000*60*60*24));
                if(daysDiff >= 0 && daysDiff <= 30){
                    newReminders.push({
                        id: `ft-${r.id}`,
                        type: 'freetime',
                        title: `免柜期到期: ${r.client || r.orderno || r.id}`,
                        date: r.freetime,
                        daysLeft: daysDiff,
                        orderId: r.id,
                        status: daysDiff <= 3 ? 'urgent' : (daysDiff <= 7 ? 'warning' : 'normal')
                    });
                }
            }
        });
        reminderData = newReminders;
        reminderSaveData();
        updateDashboard();
    }

    function reminderRender(){
        const statsBar = document.getElementById('reminder-stats-bar');
        const listEl = document.getElementById('reminder-list');
        const emptyEl = document.getElementById('reminder-empty');
        const typeFilterEl = document.getElementById('reminder-filter-type');
        const daysFilterEl = document.getElementById('reminder-filter-days');
        if(!statsBar || !listEl || !emptyEl) return;
        const typeFilter = typeFilterEl ? typeFilterEl.value : '';
        const daysFilter = daysFilterEl ? daysFilterEl.value : 'all';
        let filtered = reminderData.filter(r => {
            const matchType = !typeFilter || r.type === typeFilter;
            let matchDays = true;
            if(daysFilter !== 'all'){
                const maxDays = parseInt(daysFilter);
                matchDays = r.daysLeft <= maxDays;
            }
            return matchType && matchDays;
        });
        filtered.sort((a,b) => a.daysLeft - b.daysLeft);
        const urgentCount = filtered.filter(r => r.status === 'urgent').length;
        const warningCount = filtered.filter(r => r.status === 'warning').length;
        const normalCount = filtered.filter(r => r.status === 'normal').length;
        statsBar.innerHTML = `
            <span style="background:var(--bg-urgent, #fdeaea); color:#e74c3c; padding:4px 10px; border-radius:12px; font-size:11px;">紧急: ${urgentCount}</span>
            <span style="background:var(--bg-warning, #fef5e7); color:#f39c12; padding:4px 10px; border-radius:12px; font-size:11px;">注意: ${warningCount}</span>
            <span style="background:var(--bg-normal, #e8f8f0); color:#27ae60; padding:4px 10px; border-radius:12px; font-size:11px;">正常: ${normalCount}</span>
            <span style="background:var(--bg-secondary); color:var(--text-secondary); padding:4px 10px; border-radius:12px; font-size:11px;">共 ${filtered.length} 条</span>
        `;
        if(filtered.length === 0){
            listEl.innerHTML = '';
            emptyEl.style.display = 'block';
            return;
        }
        emptyEl.style.display = 'none';
        const typeLabels = { etd: 'ETD提醒', eta: 'ETA提醒', freetime: '免柜期', receivable: '应收', payable: '应付' };
        const typeIcons = { etd: '🚢', eta: '📦', freetime: '⏰', receivable: '💰', payable: '💸' };
        listEl.innerHTML = filtered.map(r => {
            const bgColor = r.status === 'urgent' ? '#fdeaea' : (r.status === 'warning' ? '#fef5e7' : '#e8f8f0');
            const borderColor = r.status === 'urgent' ? '#e74c3c' : (r.status === 'warning' ? '#f39c12' : '#27ae60');
            const textColor = r.status === 'urgent' ? '#c0392b' : (r.status === 'warning' ? '#d68910' : '#1e8449');
            const reminderJson = JSON.stringify(r).replace(/"/g, '&quot;');
            return `
            <div class="module-card" style="padding:12px 14px; margin-bottom:8px; border-left:4px solid ${borderColor}; background:var(--bg-primary);">
                <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
                    <div style="flex:1;">
                        <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                            <span style="font-size:16px;">${typeIcons[r.type] || '🔔'}</span>
                            <span style="font-size:14px; font-weight:bold; color:${textColor};">${r.title}</span>
                        </div>
                        <div style="font-size:12px; color:var(--text-secondary);">
                            <span>📅 ${r.date}</span>
                            <span style="margin-left:12px; font-weight:bold; color:${textColor};">${r.daysLeft === 0 ? '今天到期！' : `还有 ${r.daysLeft} 天`}</span>
                        </div>
                    </div>
                    <div style="display:flex; gap:6px;">
                        <button onclick="reminderGoToOrder('${r.orderId}')" style="background:#3498db; color:#fff; border:none; border-radius:6px; padding:6px 10px; font-size:11px; cursor:pointer;">查看订单</button>
                    </div>
                </div>
            </div>`;
        }).join('');
    }

    function reminderGoToOrder(orderId){
        switchTab(15);
        setTimeout(() => {
            const order = crmLoad().find(r => String(r.id) === String(orderId));
            if(order) crmShowDetail(order.id);
        }, 300);
    }

    // ===================== 应收应付对账 =====================
    let reconciliationData = { receivable: [], payable: [] };
    const RECON_STORAGE_KEY = 'logistics_reconciliation_data';

    function reconciliationLoadData(){
        try{
            const saved = localStorage.getItem(RECON_STORAGE_KEY);
            reconciliationData = saved ? JSON.parse(saved) : { receivable: [], payable: [] };
        }catch{
            reconciliationData = { receivable: [], payable: [] };
        }
    }

    function reconciliationSaveData(){
        try {
            localStorage.setItem(RECON_STORAGE_KEY, JSON.stringify(reconciliationData));
            return true;
        } catch(e) {
            console.error('对账保存失败:', e);
            showToast('保存失败，请检查浏览器存储权限', true);
            return false;
        }
    }

    function reconciliationGenerateFromCRM(){
        const receivableMap = {};
        const payableMap = {};
        const crmData = crmLoad();
        
        function isFullySettled(status) {
            return status === '已结算' || status === '已收款' || status === '已付款' || status === 'paid';
        }
        
        crmData.forEach(r => {
            const settlementStatus = r.settlementStatus || '未结算';
            
            // ── 应收：按客户名汇总（只包含未完全结算的订单） ──
            const clientName = r.client;
            const receivableAmt = (r.fees||{}).total || 0;
            if(clientName && receivableAmt > 0 && !isFullySettled(settlementStatus)){
                if(!receivableMap[clientName]) receivableMap[clientName] = { customer: clientName, orders: [], totalAmount: 0, paidAmount: 0 };
                const paidAmount = getSettlementPaidAmount(receivableAmt, settlementStatus);
                receivableMap[clientName].orders.push({
                    orderId: r.id,
                    orderno: r.orderno || r.id,
                    date: r.etd || r.createdAt,
                    amount: receivableAmt,
                    status: settlementStatus
                });
                receivableMap[clientName].totalAmount += receivableAmt;
                receivableMap[clientName].paidAmount += paidAmount;
            }
            // ── 应付：按船公司/承运人汇总（只包含未完全结算的订单） ──
            const payableAmt = (r.costs||{})._total || 0;
            const carrierName = r.carrier;
            if(carrierName && payableAmt > 0 && !isFullySettled(settlementStatus)){
                if(!payableMap[carrierName]) payableMap[carrierName] = { supplier: carrierName, orders: [], totalAmount: 0, paidAmount: 0 };
                const paidAmount = getSettlementPaidAmount(payableAmt, settlementStatus);
                payableMap[carrierName].orders.push({
                    orderId: r.id,
                    orderno: r.orderno || r.id,
                    date: r.etd || r.createdAt,
                    amount: payableAmt,
                    status: settlementStatus
                });
                payableMap[carrierName].totalAmount += payableAmt;
                payableMap[carrierName].paidAmount += paidAmount;
            }
        });
        reconciliationData.receivable = Object.values(receivableMap);
        reconciliationData.payable = Object.values(payableMap);
        reconciliationSaveData();
    }

    function reconciliationRender(){
        const statsBar = document.getElementById('recon-stats-bar');
        const listEl = document.getElementById('recon-list');
        const emptyEl = document.getElementById('recon-empty');
        const typeFilterEl = document.getElementById('recon-filter-type');
        const statusFilterEl = document.getElementById('recon-filter-status');
        const searchEl = document.getElementById('recon-search');
        if(!statsBar || !listEl || !emptyEl) return;
        const typeFilter = typeFilterEl ? typeFilterEl.value : 'receivable';
        const statusFilter = statusFilterEl ? statusFilterEl.value : '';
        const search = searchEl ? searchEl.value.toLowerCase() : '';
        let data = typeFilter === 'receivable' ? reconciliationData.receivable : reconciliationData.payable;
        let filtered = data.filter(item => {
            const name = item.customer || item.supplier || '';
            const matchSearch = !search || name.toLowerCase().includes(search);
            const unpaid = item.totalAmount - item.paidAmount;
            let status = 'paid';
            if(unpaid > 0 && item.paidAmount > 0) status = 'partial';
            else if(unpaid > 0) status = 'unpaid';
            const matchStatus = !statusFilter || status === statusFilter;
            return matchSearch && matchStatus;
        });
        const totalReceivable = reconciliationData.receivable.reduce((sum, r) => sum + r.totalAmount, 0);
        const totalReceivablePaid = reconciliationData.receivable.reduce((sum, r) => sum + r.paidAmount, 0);
        const totalPayable = reconciliationData.payable.reduce((sum, r) => sum + r.totalAmount, 0);
        const totalPayablePaid = reconciliationData.payable.reduce((sum, r) => sum + r.paidAmount, 0);
        statsBar.innerHTML = `
            <span style="background:#e8f4fd; color:#2980b9; padding:4px 10px; border-radius:12px; font-size:11px;">应收: ¥${Math.round(totalReceivable)}</span>
            <span style="background:#e8f8f0; color:#27ae60; padding:4px 10px; border-radius:12px; font-size:11px;">已收: ¥${Math.round(totalReceivablePaid)}</span>
            <span style="background:#fef5e7; color:#e67e22; padding:4px 10px; border-radius:12px; font-size:11px;">应付: ¥${Math.round(totalPayable)}</span>
            <span style="background:#fdeaea; color:#e74c3c; padding:4px 10px; border-radius:12px; font-size:11px;">已付: ¥${Math.round(totalPayablePaid)}</span>
        `;
        if(filtered.length === 0){
            listEl.innerHTML = '';
            emptyEl.style.display = 'block';
            return;
        }
        emptyEl.style.display = 'none';
        const isReceivable = typeFilter === 'receivable';
        listEl.innerHTML = filtered.map(item => {
            const name = item.customer || item.supplier || '未知';
            const unpaid = item.totalAmount - item.paidAmount;
            let status = 'paid';
            let statusLabel = '已结算';
            let statusColor = '#27ae60';
            let statusBg = '#e8f8f0';
            if(unpaid > 0 && item.paidAmount > 0){
                status = 'partial';
                statusLabel = '部分结算';
                statusColor = '#f39c12';
                statusBg = '#fef5e7';
            }else if(unpaid > 0){
                status = 'unpaid';
                statusLabel = '未结算';
                statusColor = '#e74c3c';
                statusBg = '#fdeaea';
            }
            return `
            <div class="module-card" style="padding:12px 14px; margin-bottom:8px;">
                <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
                    <div style="flex:1;">
                        <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
                            <span style="font-size:15px; font-weight:bold; color:#2c3e50;">${name}</span>
                            <span style="background:${statusBg}; color:${statusColor}; padding:2px 8px; border-radius:10px; font-size:10px; font-weight:bold;">${statusLabel}</span>
                        </div>
                        <div style="display:flex; flex-wrap:wrap; gap:16px; font-size:12px; color:#666;">
                            <span>总金额: <strong style="color:#2c3e50;">¥${Math.round(item.totalAmount)}</strong></span>
                            <span>已${isReceivable ? '收' : '付'}: <strong style="color:#27ae60;">¥${Math.round(item.paidAmount)}</strong></span>
                            <span>未${isReceivable ? '收' : '付'}: <strong style="color:#e74c3c;">¥${Math.round(unpaid)}</strong></span>
                            <span>订单数: ${item.orders.length}</span>
                        </div>
                    </div>
                    <div style="display:flex; gap:6px; flex-shrink:0;">
                        <button onclick="reconciliationShowDetail('${name}', '${typeFilter}')" style="background:#9b59b6; color:#fff; border:none; border-radius:6px; padding:6px 10px; font-size:11px; cursor:pointer;">详情</button>
                    </div>
                </div>
            </div>`;
        }).join('');
    }

    function reconciliationShowDetail(name, type){
        const data = type === 'receivable' ? reconciliationData.receivable : reconciliationData.payable;
        const item = data.find(d => (d.customer || d.supplier) === name);
        if(!item) return;
        const isReceivable = type === 'receivable';
        const unpaid = item.totalAmount - item.paidAmount;
        document.getElementById('recon-modal-title').textContent = `${name} - ${isReceivable ? '应收' : '应付'}对账详情`;
        const bodyEl = document.getElementById('recon-modal-body');
        bodyEl.innerHTML = `
            <div style="margin-bottom:16px; padding:12px; background:#f8f9fa; border-radius:10px;">
                <div style="display:flex; justify-content:space-between; margin-bottom:8px;">
                    <span style="color:#666;">总金额</span>
                    <span style="font-weight:bold; font-size:16px;">¥${Math.round(item.totalAmount)}</span>
                </div>
                <div style="display:flex; justify-content:space-between; margin-bottom:8px;">
                    <span style="color:#666;">已${isReceivable ? '收' : '付'}</span>
                    <span style="font-weight:bold; color:#27ae60;">¥${Math.round(item.paidAmount)}</span>
                </div>
                <div style="display:flex; justify-content:space-between;">
                    <span style="color:#666;">未${isReceivable ? '收' : '付'}</span>
                    <span style="font-weight:bold; color:#e74c3c;">¥${Math.round(unpaid)}</span>
                </div>
            </div>
            <div style="font-size:13px; font-weight:bold; margin-bottom:10px; color:#2c3e50;">关联订单</div>
            <div style="max-height:300px; overflow-y:auto;">
                ${item.orders.map(o => `
                    <div style="padding:10px; margin-bottom:8px; background:#f8f9fa; border-radius:8px; display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <div style="font-size:12px; color:#666;">订单: ${o.orderno || o.orderId}</div>
                            <div style="font-size:11px; color:#999;">${o.date || ''}</div>
                        </div>
                        <div style="text-align:right;">
                            <div style="font-weight:bold;">¥${Math.round(o.amount)}</div>
                            <div style="font-size:10px; color:${o.status === 'paid' ? '#27ae60' : '#e74c3c'};">${o.status === 'paid' ? '已结算' : '未结算'}</div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
        document.getElementById('recon-modal').style.display = 'block';
    }

    function reconciliationCloseModal(){
        document.getElementById('recon-modal').style.display = 'none';
    }

    function reconciliationExport(){
        const typeFilter = document.getElementById('recon-filter-type').value;
        const data = typeFilter === 'receivable' ? reconciliationData.receivable : reconciliationData.payable;
        const isReceivable = typeFilter === 'receivable';
        if(data.length === 0){
            alert('暂无数据可导出');
            return;
        }
        const headers = [isReceivable ? '客户名称' : '供应商名称', '总金额', '已' + (isReceivable ? '收' : '付'), '未' + (isReceivable ? '收' : '付'), '订单数'];
        const rows = data.map(item => {
            const name = item.customer || item.supplier || '';
            const unpaid = item.totalAmount - item.paidAmount;
            return [name, Math.round(item.totalAmount), Math.round(item.paidAmount), Math.round(unpaid), item.orders.length];
        });
        let csv = '\uFEFF' + headers.join(',') + '\n' + rows.map(r => r.map(v => `"${v}"`).join(',')).join('\n');
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${isReceivable ? '应收' : '应付'}对账单_${new Date().toISOString().slice(0,10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
    }

    // ===================== 运价管理 =====================
    let freightData = [];
    const FREIGHT_STORAGE_KEY = 'logistics_freight_data';

    function freightLoadData(){
        try{
            const saved = localStorage.getItem(FREIGHT_STORAGE_KEY);
            freightData = saved ? JSON.parse(saved) : [];
            console.log('运价数据加载完成，共', freightData.length, '条');
        }catch(e){
            console.error('运价数据加载失败:', e);
            freightData = [];
        }
    }

    function freightSaveData(){
        try {
            const dataStr = JSON.stringify(freightData);
            localStorage.setItem(FREIGHT_STORAGE_KEY, dataStr);
            console.log('运价数据保存成功，共', freightData.length, '条');
            const verify = localStorage.getItem(FREIGHT_STORAGE_KEY);
            if(verify !== dataStr){
                console.error('运价数据保存验证失败');
                return false;
            }
            return true;
        } catch(e) {
            console.error('运价保存失败:', e);
            showToast('保存失败，请检查浏览器存储权限', true);
            return false;
        }
    }

    function freightShowAddModal(){
        document.getElementById('freight-modal-title').textContent = '新增运价';
        document.getElementById('freight-edit-id').value = '';
        document.getElementById('freight-f-route').value = '中日';
        document.getElementById('freight-f-type').value = '整柜';
        document.getElementById('freight-f-pol').value = '';
        document.getElementById('freight-f-pod').value = '';
        document.getElementById('freight-f-carrier').value = '';
        document.getElementById('freight-f-containertype').value = '';
        document.getElementById('freight-f-price').value = '';
        document.getElementById('freight-f-validto').value = '';
        document.getElementById('freight-f-notes').value = '';
        document.getElementById('freight-modal').style.display = 'block';
    }

    function freightShowEditModal(id){
        const item = freightData.find(f => f.id === id);
        if(!item) return;
        document.getElementById('freight-modal-title').textContent = '编辑运价';
        document.getElementById('freight-edit-id').value = id;
        document.getElementById('freight-f-route').value = item.route || '中日';
        document.getElementById('freight-f-type').value = item.type || '整柜';
        const polSelect = document.getElementById('freight-f-pol');
        const podSelect = document.getElementById('freight-f-pod');
        if(item.pol && ![...polSelect.options].some(o => o.value === item.pol)){
            polSelect.value = '其他';
        } else {
            polSelect.value = item.pol || '';
        }
        if(item.pod && ![...podSelect.options].some(o => o.value === item.pod)){
            podSelect.value = '其他';
        } else {
            podSelect.value = item.pod || '';
        }
        document.getElementById('freight-f-carrier').value = item.carrier || '';
        document.getElementById('freight-f-containertype').value = item.containerType || '';
        document.getElementById('freight-f-price').value = item.price || '';
        document.getElementById('freight-f-validto').value = item.validTo || '';
        document.getElementById('freight-f-notes').value = item.notes || '';
        document.getElementById('freight-modal').style.display = 'block';
    }

    function freightCloseModal(){
        document.getElementById('freight-modal').style.display = 'none';
    }

    function freightSaveRecord(){
        const editId = document.getElementById('freight-edit-id').value;
        const route = document.getElementById('freight-f-route').value;
        const record = {
            id: editId || Date.now().toString(),
            route,
            type: document.getElementById('freight-f-type').value,
            pol: document.getElementById('freight-f-pol').value.trim(),
            pod: document.getElementById('freight-f-pod').value.trim(),
            carrier: document.getElementById('freight-f-carrier').value.trim(),
            containerType: document.getElementById('freight-f-containertype').value.trim(),
            price: parseFloat(document.getElementById('freight-f-price').value) || 0,
            validTo: document.getElementById('freight-f-validto').value,
            notes: document.getElementById('freight-f-notes').value.trim(),
            createdAt: editId ? (freightData.find(f => f.id === editId)?.createdAt || new Date().toISOString()) : new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        if(editId){
            const idx = freightData.findIndex(f => f.id === editId);
            if(idx !== -1){
                freightData[idx] = record;
            } else {
                freightData.unshift(record);
            }
        }else{
            freightData.unshift(record);
        }
        const saved = freightSaveData();
        if(saved){
            showToast(editId ? '运价已更新' : '运价已添加');
        }
        freightCloseModal();
        freightRender();
    }

    function freightDeleteRecord(id){
        if(!confirm('确定删除该运价记录？')) return;
        freightData = freightData.filter(f => f.id !== id);
        freightSaveData();
        freightRender();
    }

    function freightRender(){
        const statsBar = document.getElementById('freight-stats-bar');
        const listEl = document.getElementById('freight-list');
        const emptyEl = document.getElementById('freight-empty');
        const searchEl = document.getElementById('freight-search');
        const typeFilterEl = document.getElementById('freight-filter-type');
        const routeFilterEl = document.getElementById('freight-filter-route');
        if(!statsBar || !listEl || !emptyEl) return;
        const search = searchEl ? searchEl.value.toLowerCase() : '';
        const typeFilter = typeFilterEl ? typeFilterEl.value : '';
        const routeFilter = routeFilterEl ? routeFilterEl.value : '';
        let filtered = freightData.filter(f => {
            const matchSearch = !search || 
                (f.route && f.route.toLowerCase().includes(search)) ||
                (f.pol && f.pol.toLowerCase().includes(search)) ||
                (f.pod && f.pod.toLowerCase().includes(search)) ||
                (f.carrier && f.carrier.toLowerCase().includes(search));
            const matchType = !typeFilter || f.type === typeFilter;
            const matchRoute = !routeFilter || f.route === routeFilter;
            return matchSearch && matchType && matchRoute;
        });
        const routeCounts = {};
        freightData.forEach(f => { routeCounts[f.route] = (routeCounts[f.route] || 0) + 1; });
        let statsHtml = `<span style="background:var(--bg-secondary); color:var(--text-secondary); padding:4px 10px; border-radius:12px; font-size:11px;">共 ${freightData.length} 条</span>`;
        Object.entries(routeCounts).forEach(([route, count]) => {
            statsHtml += `<span style="background:var(--bg-normal, #e8f8f0); color:#16a085; padding:4px 10px; border-radius:12px; font-size:11px;">${route}: ${count}</span>`;
        });
        statsBar.innerHTML = statsHtml;
        if(filtered.length === 0){
            listEl.innerHTML = '';
            emptyEl.style.display = 'block';
            return;
        }
        emptyEl.style.display = 'none';
        const today = new Date().toISOString().slice(0,10);
        listEl.innerHTML = filtered.map(f => {
            const isExpired = f.validTo && f.validTo < today;
            const expireColor = isExpired ? '#e74c3c' : (f.validTo ? '#27ae60' : '#666');
            return `
            <div class="module-card" style="padding:12px 14px; margin-bottom:8px; ${isExpired ? 'opacity:0.6;' : ''} background:var(--bg-primary);">
                <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:10px;">
                    <div style="flex:1;">
                        <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
                            <span style="font-size:15px; font-weight:bold; color:var(--text-primary);">${f.pol || '?'} → ${f.pod || '?'}</span>
                            <span style="background:var(--bg-normal, #e8f8f0); color:#16a085; padding:2px 8px; border-radius:10px; font-size:10px; font-weight:bold;">${f.route}</span>
                            <span style="background:var(--bg-secondary); color:#e67e22; padding:2px 8px; border-radius:10px; font-size:10px;">${f.type}</span>
                            ${isExpired ? '<span style="background:#fdeaea; color:#e74c3c; padding:2px 8px; border-radius:10px; font-size:10px;">已过期</span>' : ''}
                        </div>
                        <div style="display:flex; flex-wrap:wrap; gap:12px; font-size:12px; color:var(--text-secondary);">
                            ${f.carrier ? `<span>🚢 ${f.carrier}</span>` : ''}
                            ${f.containerType ? `<span>📦 ${f.containerType}</span>` : ''}
                            <span style="color:#16a085; font-weight:bold;">¥${Math.round(f.price)}</span>
                            ${f.validTo ? `<span style="color:${expireColor};">有效期: ${f.validTo}</span>` : ''}
                        </div>
                        ${f.notes ? `<div style="font-size:11px; color:var(--text-secondary); margin-top:4px; padding:6px; background:var(--bg-secondary); border-radius:6px;">${f.notes}</div>` : ''}
                    </div>
                    <div style="display:flex; gap:6px; flex-shrink:0;">
                        <button onclick="freightShowEditModal('${f.id}')" style="background:#16a085; color:#fff; border:none; border-radius:6px; padding:6px 10px; font-size:11px; cursor:pointer;">编辑</button>
                        <button onclick="freightDeleteRecord('${f.id}')" style="background:#e74c3c; color:#fff; border:none; border-radius:6px; padding:6px 10px; font-size:11px; cursor:pointer;">删除</button>
                    </div>
                </div>
            </div>`;
        }).join('');
    }

    function freightExportCSV(){
        if(freightData.length === 0){
            alert('暂无数据可导出');
            return;
        }
        const headers = ['航线', '类型', '起运港', '目的港', '船公司', '柜型', '运费(人民币)', '有效期', '备注', '创建时间'];
        const rows = freightData.map(f => [
            f.route, f.type, f.pol, f.pod, f.carrier, f.containerType, f.price, f.validTo, f.notes, f.createdAt
        ]);
        let csv = '\uFEFF' + headers.join(',') + '\n' + rows.map(r => r.map(v => `"${(v||'').toString().replace(/"/g,'""')}"`).join(',')).join('\n');
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `运价表_${new Date().toISOString().slice(0,10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
    }

    const FREIGHT_TREND_COLORS = [
        '#16a085', '#e74c3c', '#3498db', '#9b59b6', '#f39c12', 
        '#1abc9c', '#e67e22', '#2ecc71', '#34495e', '#d35400',
        '#27ae60', '#8e44ad', '#2980b9', '#c0392b', '#f1c40f'
    ];
    let freightTrendAllPoints = [];
    const FREIGHT_TREND_DAYS = 45;

    function isWithinDays(dateStr, days){
        if(!dateStr) return false;
        const date = new Date(dateStr);
        const now = new Date();
        const diffTime = now.getTime() - date.getTime();
        const diffDays = diffTime / (1000 * 60 * 60 * 24);
        return diffDays <= days;
    }

    function freightInitTrendRoutes(){
        drawFreightTrendChart();
        initGlobalIndexChart();
        loadGlobalFreightIndex();
    }

    function getAllFreightTrendData(ctype){
        const crmData = crmLoad();
        const routeMap = new Map();
        crmData.filter(r => {
            const matchCtype = !ctype || r.ctype === ctype;
            const hasOcean = r.fees && (r.fees.ocean > 0 || r.fees.fx?.ocean?.cny > 0);
            const date = r.etd || r.createdAt?.slice(0, 10) || '';
            const withinDays = isWithinDays(date, FREIGHT_TREND_DAYS);
            return matchCtype && hasOcean && r.bizType !== 'lcl' && r.pol && r.pod && withinDays;
        }).forEach(r => {
            const route = `${r.pol} → ${r.pod}`;
            const ocean = r.fees?.fx?.ocean?.cny || r.fees?.ocean || 0;
            const cqty = r.cqty || 1;
            const pricePerContainer = ocean / cqty;
            const date = r.etd || r.createdAt?.slice(0, 10) || '';
            if(date && pricePerContainer > 0){
                if(!routeMap.has(route)) routeMap.set(route, []);
                routeMap.get(route).push({
                    date, value: pricePerContainer, route, pol: r.pol, pod: r.pod,
                    source: 'CRM订单', ctype: r.ctype, mbl: r.mbl, client: r.client
                });
            }
        });
        freightData.filter(f => {
            const matchCtype = !ctype || f.containerType === ctype;
            const date = f.validTo || f.createdAt?.slice(0, 10) || '';
            const withinDays = isWithinDays(date, FREIGHT_TREND_DAYS);
            return matchCtype && f.price > 0 && f.pol && f.pod && withinDays;
        }).forEach(f => {
            const route = `${f.pol} → ${f.pod}`;
            const date = f.validTo || f.createdAt?.slice(0, 10) || '';
            if(date && f.price > 0){
                if(!routeMap.has(route)) routeMap.set(route, []);
                routeMap.get(route).push({
                    date, value: f.price, route, pol: f.pol, pod: f.pod,
                    source: '运价管理', ctype: f.containerType, carrier: f.carrier
                });
            }
        });
        routeMap.forEach(points => points.sort((a, b) => a.date.localeCompare(b.date)));
        return routeMap;
    }

    function drawFreightTrendChart(){
        const ctype = document.getElementById('freight-trend-ctype')?.value;
        const statusEl = document.getElementById('freight-trend-status');
        const summaryEl = document.getElementById('freight-trend-summary');
        const legendEl = document.getElementById('freight-trend-legend');
        const canvas = document.getElementById('freight-trend-canvas');
        if(!canvas) return;
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const cssWidth = canvas.clientWidth || 600;
        const cssHeight = 280;
        canvas.width = cssWidth * dpr;
        canvas.height = cssHeight * dpr;
        ctx.setTransform(1, 0, 0, 1, 0, 0);
        ctx.scale(dpr, dpr);
        ctx.clearRect(0, 0, cssWidth, cssHeight);

        const routeMap = getAllFreightTrendData(ctype);
        if(routeMap.size === 0){
            if(statusEl) statusEl.textContent = '暂无海运费数据';
            if(summaryEl) summaryEl.textContent = '请在CRM或运价管理中录入数据';
            if(legendEl) legendEl.innerHTML = '';
            freightTrendAllPoints = [];
            return;
        }

        const padding = { top: 20, right: 50, bottom: 35, left: 60 };
        const width = cssWidth - padding.left - padding.right;
        const height = cssHeight - padding.top - padding.bottom;

        freightTrendAllPoints = [];
        routeMap.forEach(points => freightTrendAllPoints.push(...points));
        const allValues = freightTrendAllPoints.map(p => p.value);
        const min = Math.min(...allValues);
        const max = Math.max(...allValues);
        const range = max - min || 1;
        const allDates = [...new Set(freightTrendAllPoints.map(p => p.date))].sort();

        ctx.fillStyle = '#7a8a99';
        ctx.font = '10px sans-serif';
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        for(let i = 0; i <= 4; i++){
            const y = padding.top + (height / 4) * i;
            const val = max - (range / 4) * i;
            ctx.fillText('¥' + val.toFixed(0), padding.left - 6, y);
        }

        ctx.strokeStyle = '#e6edf5';
        ctx.lineWidth = 1;
        for(let i = 0; i <= 4; i++){
            const y = padding.top + (height / 4) * i;
            ctx.beginPath();
            ctx.moveTo(padding.left, y);
            ctx.lineTo(padding.left + width, y);
            ctx.stroke();
        }

        const routes = [...routeMap.keys()].sort();
        routes.forEach((route, routeIndex) => {
            const points = routeMap.get(route);
            const color = FREIGHT_TREND_COLORS[routeIndex % FREIGHT_TREND_COLORS.length];
            ctx.beginPath();
            points.forEach((point, index) => {
                const x = padding.left + (width * allDates.indexOf(point.date)) / Math.max(allDates.length - 1, 1);
                const y = padding.top + height - ((point.value - min) / range) * height;
                if(index === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
            });
            ctx.strokeStyle = color;
            ctx.lineWidth = 2;
            ctx.stroke();

            points.forEach((point) => {
                const x = padding.left + (width * allDates.indexOf(point.date)) / Math.max(allDates.length - 1, 1);
                const y = padding.top + height - ((point.value - min) / range) * height;
                ctx.fillStyle = color;
                ctx.beginPath();
                ctx.arc(x, y, 4, 0, Math.PI * 2);
                ctx.fill();
            });
        });

        if(allDates.length > 0){
            ctx.fillStyle = '#7a8a99';
            ctx.font = '10px sans-serif';
            ctx.textAlign = 'left';
            ctx.textBaseline = 'alphabetic';
            ctx.fillText(allDates[0], padding.left, cssHeight - 10);
            ctx.textAlign = 'right';
            ctx.fillText(allDates[allDates.length - 1], padding.left + width, cssHeight - 10);
        }

        const totalPoints = freightTrendAllPoints.length;
        const crmCount = freightTrendAllPoints.filter(p => p.source === 'CRM订单').length;
        const freightCount = freightTrendAllPoints.filter(p => p.source === '运价管理').length;
        if(statusEl) statusEl.textContent = `近 ${FREIGHT_TREND_DAYS} 天 · ${routes.length} 条航线 · ${totalPoints} 个数据点 (CRM ${crmCount} + 运价管理 ${freightCount})`;
        const avg = allValues.reduce((a, b) => a + b, 0) / allValues.length;
        if(summaryEl) summaryEl.textContent = `均价 ¥${avg.toFixed(0)} | 区间 ¥${min.toFixed(0)}-¥${max.toFixed(0)}`;

        if(legendEl){
            legendEl.innerHTML = routes.map((route, i) => {
                const color = FREIGHT_TREND_COLORS[i % FREIGHT_TREND_COLORS.length];
                const count = routeMap.get(route).length;
                return `<span style="display:inline-flex;align-items:center;gap:4px;background:${color}15;color:${color};padding:4px 10px;border-radius:12px;font-size:11px;border:1px solid ${color}33;">
                    <span style="width:10px;height:10px;background:${color};border-radius:50%;"></span>
                    ${route} (${count})
                </span>`;
            }).join('');
        }
    }

    function freightTrendCanvasMouseMove(e){
        const canvas = document.getElementById('freight-trend-canvas');
        const tooltip = document.getElementById('freight-trend-tooltip');
        if(!canvas || !tooltip || freightTrendAllPoints.length === 0) return;
        const rect = canvas.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const padding = { top: 20, right: 50, bottom: 35, left: 60 };
        const cssWidth = canvas.clientWidth || 600;
        const cssHeight = 280;
        const width = cssWidth - padding.left - padding.right;
        const height = cssHeight - padding.top - padding.bottom;
        const allValues = freightTrendAllPoints.map(p => p.value);
        const min = Math.min(...allValues);
        const max = Math.max(...allValues);
        const range = max - min || 1;
        const allDates = [...new Set(freightTrendAllPoints.map(p => p.date))].sort();

        let nearestPoint = null;
        let minDist = 20;
        freightTrendAllPoints.forEach(point => {
            const px = padding.left + (width * allDates.indexOf(point.date)) / Math.max(allDates.length - 1, 1);
            const py = padding.top + height - ((point.value - min) / range) * height;
            const dist = Math.sqrt((x - px) ** 2 + (y - py) ** 2);
            if(dist < minDist){
                minDist = dist;
                nearestPoint = { ...point, px, py };
            }
        });

        if(nearestPoint){
            tooltip.style.display = 'block';
            tooltip.innerHTML = `
                <div style="font-weight:bold;margin-bottom:4px;">${nearestPoint.route}</div>
                <div>日期: ${nearestPoint.date}</div>
                <div>运费: <b style="color:#2ecc71;">¥${nearestPoint.value.toFixed(0)}</b></div>
                <div>柜型: ${nearestPoint.ctype || '—'}</div>
                <div>来源: ${nearestPoint.source}</div>
                ${nearestPoint.client ? `<div>客户: ${nearestPoint.client}</div>` : ''}
                ${nearestPoint.carrier ? `<div>船司: ${nearestPoint.carrier}</div>` : ''}
            `;
            let tx = nearestPoint.px + 10;
            let ty = nearestPoint.py - 10;
            if(tx + 180 > cssWidth) tx = nearestPoint.px - 190;
            if(ty < 10) ty = 10;
            tooltip.style.left = tx + 'px';
            tooltip.style.top = ty + 'px';
        } else {
            tooltip.style.display = 'none';
        }
    }

    function freightTrendCanvasMouseLeave(){
        const tooltip = document.getElementById('freight-trend-tooltip');
        if(tooltip) tooltip.style.display = 'none';
    }

    // ===================== 国际运价指数功能 =====================
    let globalIndexAllPoints = {};
    let globalIndexMultiData = {};
    const GLOBAL_INDEX_COLORS = {
        bdi: '#e74c3c',
        scfi: '#3498db',
        fbx: '#27ae60'
    };
    const FRED_API_KEY = 'fred';

    const GLOBAL_INDEX_CONFIG = {
        bdi: {
            name: 'BDI (波罗的海干散货指数)',
            fredId: 'BRIT1M',
            description: '反映全球干散货运价',
            unit: '点',
            baseValue: 2000,
            volatility: 500
        },
        scfi: {
            name: 'SCFI (上海集装箱运价指数)',
            fredId: 'NASDAQOMXB10',
            description: '反映上海出口集装箱运价',
            unit: '点',
            baseValue: 1800,
            volatility: 300
        },
        fbx: {
            name: 'FBX (Freightos集装箱指数)',
            fredId: 'NASDAQOMXBGI',
            description: '全球集装箱运价指数',
            unit: '点',
            baseValue: 2100,
            volatility: 300
        }
    };

    let globalIndexCache = {
        data: null,
        timestamp: 0,
        period: ''
    };

    async function loadGlobalFreightIndex(){
        const period = parseInt(document.getElementById('global-index-period')?.value || '90');
        const statusEl = document.getElementById('global-index-status');
        const summaryEl = document.getElementById('global-index-summary');
        const legendEl = document.getElementById('global-index-legend');
        const canvas = document.getElementById('global-freight-index-canvas');
        
        if(!canvas) return;
        
        if(statusEl) statusEl.textContent = '正在加载数据...';
        if(summaryEl) summaryEl.textContent = '';
        if(legendEl) legendEl.innerHTML = '';
        
        const now = Date.now();
        if(globalIndexCache.period === String(period) && globalIndexCache.data && (now - globalIndexCache.timestamp) < 3600000){
            drawMultiGlobalIndexChart(globalIndexCache.data);
            return;
        }
        
        const allData = {};
        const types = ['bdi', 'scfi', 'fbx'];
        
        for(const type of types){
            allData[type] = generateMockIndexData(type, period);
        }
        
        globalIndexCache = {
            data: allData,
            timestamp: now,
            period: String(period)
        };
        
        globalIndexMultiData = allData;
        drawMultiGlobalIndexChart(allData);
    }

    function generateMockIndexData(type, period){
        const config = GLOBAL_INDEX_CONFIG[type];
        const points = [];
        const today = new Date();
        const baseValue = config.baseValue;
        const volatility = config.volatility;
        
        for(let i = period; i >= 0; i--){
            const date = new Date(today);
            date.setDate(date.getDate() - i);
            const dateStr = date.toISOString().split('T')[0];
            
            const trend = Math.sin(i / 15) * volatility * 0.5;
            const noise = (Math.random() - 0.5) * volatility * 0.3;
            const value = Math.max(500, baseValue + trend + noise);
            
            points.push({
                date: dateStr,
                value: Math.round(value)
            });
        }
        
        return points;
    }

    function drawMultiGlobalIndexChart(allData){
        const canvas = document.getElementById('global-freight-index-canvas');
        const statusEl = document.getElementById('global-index-status');
        const summaryEl = document.getElementById('global-index-summary');
        const legendEl = document.getElementById('global-index-legend');
        
        if(!canvas) return;
        
        const types = Object.keys(allData);
        if(types.length === 0) return;
        
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const parent = canvas.parentElement;
        const cssWidth = parent ? parent.clientWidth : (canvas.clientWidth || 800);
        const cssHeight = 350;
        canvas.width = cssWidth * dpr;
        canvas.height = cssHeight * dpr;
        canvas.style.width = '100%';
        canvas.style.height = cssHeight + 'px';
        ctx.setTransform(1, 0, 0, 1, 0, 0);
        ctx.scale(dpr, dpr);
        ctx.clearRect(0, 0, cssWidth, cssHeight);
        
        globalIndexAllPoints = allData;
        
        const padding = { top: 25, right: 60, bottom: 40, left: 55 };
        const width = cssWidth - padding.left - padding.right;
        const height = cssHeight - padding.top - padding.bottom;
        
        let allValues = [];
        let maxPoints = 0;
        types.forEach(type => {
            if(allData[type] && allData[type].length > 0){
                allValues = allValues.concat(allData[type].map(p => p.value));
                maxPoints = Math.max(maxPoints, allData[type].length);
            }
        });
        
        if(allValues.length === 0) return;
        
        const min = Math.min(...allValues);
        const max = Math.max(...allValues);
        const range = max - min || 1;
        
        ctx.fillStyle = '#7a8a99';
        ctx.font = '10px sans-serif';
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        for(let i = 0; i <= 4; i++){
            const y = padding.top + (height / 4) * i;
            const val = max - (range / 4) * i;
            ctx.fillText(val.toFixed(0), padding.left - 6, y);
        }
        
        ctx.strokeStyle = '#e6edf5';
        ctx.lineWidth = 1;
        for(let i = 0; i <= 4; i++){
            const y = padding.top + (height / 4) * i;
            ctx.beginPath();
            ctx.moveTo(padding.left, y);
            ctx.lineTo(padding.left + width, y);
            ctx.stroke();
        }
        
        types.forEach(type => {
            const points = allData[type];
            if(!points || points.length === 0) return;
            
            const color = GLOBAL_INDEX_COLORS[type];
            
            ctx.beginPath();
            points.forEach((point, index) => {
                const x = padding.left + (width * index) / Math.max(points.length - 1, 1);
                const y = padding.top + height - ((point.value - min) / range) * height;
                if(index === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
            });
            ctx.strokeStyle = color;
            ctx.lineWidth = 2;
            ctx.stroke();
        });
        
        const firstType = types[0];
        const firstPoints = allData[firstType];
        if(firstPoints && firstPoints.length > 0){
            ctx.fillStyle = '#7a8a99';
            ctx.font = '10px sans-serif';
            ctx.textBaseline = 'alphabetic';
            
            const totalPoints = firstPoints.length;
            const datePositions = [
                { index: 0, align: 'left' },
                { index: totalPoints - 1, align: 'right' }
            ];
            
            datePositions.forEach(pos => {
                const point = firstPoints[pos.index];
                if(!point) return;
                const x = padding.left + (width * pos.index) / Math.max(totalPoints - 1, 1);
                ctx.textAlign = pos.align;
                ctx.fillText(point.date, x, cssHeight - 10);
            });
        }
        
        let summaryParts = [];
        types.forEach(type => {
            const points = allData[type];
            if(points && points.length > 0){
                const latest = points[points.length - 1].value;
                const prev = points.length > 1 ? points[points.length - 2].value : latest;
                const change = ((latest - prev) / prev * 100).toFixed(1);
                const changeStr = change >= 0 ? `+${change}%` : `${change}%`;
                const color = GLOBAL_INDEX_COLORS[type];
                summaryParts.push(`<span style="color:${color}">${type.toUpperCase()}: ${latest.toFixed(0)} (${changeStr})</span>`);
            }
        });
        
        if(statusEl) statusEl.textContent = `三大运价指数对比 · ${maxPoints} 个数据点`;
        if(summaryEl) summaryEl.innerHTML = summaryParts.join(' | ');
        
        if(legendEl){
            let legendHtml = '';
            types.forEach(type => {
                const config = GLOBAL_INDEX_CONFIG[type];
                const color = GLOBAL_INDEX_COLORS[type];
                legendHtml += `<span style="display:inline-flex;align-items:center;gap:4px;background:${color}15;color:${color};padding:4px 10px;border-radius:12px;font-size:11px;border:1px solid ${color}33;margin:2px;">
                    <span style="width:10px;height:10px;background:${color};border-radius:50%;"></span>
                    ${config.name}
                </span>`;
            });
            legendEl.innerHTML = legendHtml;
        }
    }

    function globalIndexCanvasMouseMove(e){
        const canvas = document.getElementById('global-freight-index-canvas');
        const tooltip = document.getElementById('global-index-tooltip');
        if(!canvas || !tooltip || Object.keys(globalIndexAllPoints).length === 0) return;
        
        const rect = canvas.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const padding = { top: 25, right: 60, bottom: 40, left: 55 };
        const cssWidth = rect.width;
        const cssHeight = 350;
        const width = cssWidth - padding.left - padding.right;
        const height = cssHeight - padding.top - padding.bottom;
        
        let allValues = [];
        Object.keys(globalIndexAllPoints).forEach(type => {
            if(globalIndexAllPoints[type]){
                allValues = allValues.concat(globalIndexAllPoints[type].map(p => p.value));
            }
        });
        
        if(allValues.length === 0) return;
        
        const min = Math.min(...allValues);
        const max = Math.max(...allValues);
        const range = max - min || 1;
        
        let tooltipContent = '';
        let foundAny = false;
        
        Object.keys(globalIndexAllPoints).forEach(type => {
            const points = globalIndexAllPoints[type];
            if(!points || points.length === 0) return;
            
            let nearestPoint = null;
            let minDist = 30;
            
            points.forEach((point, index) => {
                const px = padding.left + (width * index) / Math.max(points.length - 1, 1);
                const py = padding.top + height - ((point.value - min) / range) * height;
                const dist = Math.sqrt((x - px) ** 2 + (y - py) ** 2);
                if(dist < minDist){
                    minDist = dist;
                    nearestPoint = { ...point, px, py };
                }
            });
            
            if(nearestPoint){
                foundAny = true;
                const color = GLOBAL_INDEX_COLORS[type];
                const config = GLOBAL_INDEX_CONFIG[type];
                tooltipContent += `<div style="margin-bottom:4px;"><span style="color:${color};font-weight:bold;">${type.toUpperCase()}</span>: ${nearestPoint.value.toFixed(0)} ${config.unit}</div>`;
                if(!tooltipContent.includes('日期:')){
                    tooltipContent = `<div style="font-weight:bold;margin-bottom:6px;">${nearestPoint.date}</div>` + tooltipContent;
                }
            }
        });
        
        if(foundAny){
            tooltip.style.display = 'block';
            tooltip.innerHTML = tooltipContent;
            let tx = x + 15;
            let ty = y - 10;
            if(tx + 180 > cssWidth) tx = x - 190;
            if(ty < 10) ty = 10;
            tooltip.style.left = tx + 'px';
            tooltip.style.top = ty + 'px';
        } else {
            tooltip.style.display = 'none';
        }
    }

    function globalIndexCanvasMouseLeave(){
        const tooltip = document.getElementById('global-index-tooltip');
        if(tooltip) tooltip.style.display = 'none';
    }

    function initGlobalIndexChart(){
        const canvas = document.getElementById('global-freight-index-canvas');
        if(canvas){
            canvas.addEventListener('mousemove', globalIndexCanvasMouseMove);
            canvas.addEventListener('mouseleave', globalIndexCanvasMouseLeave);
        }
    }

    // ===================== 全局预览功能 =====================
    let previewTimeout = null;
    let previewCard = null;
    let previewAutoHideTimer = null;

    function initPreviewCard(){
        previewCard = document.getElementById('global-preview-card');
        if(previewCard){
            previewCard.addEventListener('click', function(e){
                if(e.target.classList.contains('preview-card-close') || e.target === previewCard){
                    hidePreview();
                }
            });
        }
    }

    function showPreview(html, event){
        if(!previewCard) initPreviewCard();
        clearTimeout(previewTimeout);
        clearTimeout(previewAutoHideTimer);
        previewTimeout = setTimeout(() => {
            previewCard.innerHTML = '<button class="preview-card-close" onclick="hidePreview()">×</button>' + html;
            previewCard.classList.add('show');
            positionPreview(event);
            previewAutoHideTimer = setTimeout(() => {
                hidePreview();
            }, 4000);
        }, 300);
    }

    function hidePreview(){
        if(!previewCard) initPreviewCard();
        clearTimeout(previewTimeout);
        clearTimeout(previewAutoHideTimer);
        previewCard.classList.remove('show');
    }

    function positionPreview(event){
        if(!previewCard) return;
        const rect = previewCard.getBoundingClientRect();
        let x = event.clientX + 15;
        let y = event.clientY + 15;
        if(x + rect.width > window.innerWidth - 20){
            x = event.clientX - rect.width - 15;
        }
        if(y + rect.height > window.innerHeight - 20){
            y = event.clientY - rect.height - 15;
        }
        previewCard.style.left = Math.max(10, x) + 'px';
        previewCard.style.top = Math.max(10, y) + 'px';
    }

    function getPreviewHtml_CRMOrder(order){
        const statusColor = order.status === '已完结' ? '#27ae60' : (order.status === '进行中' ? '#3498db' : '#e67e22');
        const statusBg = order.status === '已完结' ? '#e8f8f0' : (order.status === '进行中' ? '#e8f4fd' : '#fef5e7');
        const profit = order.profit || 0;
        const profitColor = profit >= 0 ? '#27ae60' : '#e74c3c';
        return `
            <div class="preview-card-header">
                <div class="preview-card-icon" style="background: linear-gradient(135deg, #1f7a5c, #27ae60);">📦</div>
                <div>
                    <div class="preview-card-title">${order.customer || order.id}</div>
                    <div class="preview-card-subtitle">${order.route || '未知航线'} · ${order.containerType || ''}</div>
                </div>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">状态</span>
                <span class="preview-card-tag" style="background:${statusBg};color:${statusColor};">${order.status || '待处理'}</span>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">ETD / ETA</span>
                <span class="preview-card-value">${order.etd || '-'} / ${order.eta || '-'}</span>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">船公司</span>
                <span class="preview-card-value">${order.carrier || '-'}</span>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">柜号</span>
                <span class="preview-card-value">${order.containerNo || '-'}</span>
            </div>
            <div class="preview-card-stats">
                <div class="preview-stat-item">
                    <div class="preview-stat-value">¥${((order.fees||{}).total||0).toLocaleString()}</div>
                    <div class="preview-stat-label">应收</div>
                </div>
                <div class="preview-stat-item">
                    <div class="preview-stat-value">¥${((order.costs||{})._total||0).toLocaleString()}</div>
                    <div class="preview-stat-label">应付</div>
                </div>
                <div class="preview-stat-item">
                    <div class="preview-stat-value" style="color:${profitColor};">¥${profit.toLocaleString()}</div>
                    <div class="preview-stat-label">毛利</div>
                </div>
            </div>
        `;
    }

    function getPreviewHtml_Client(client){
        const levelColors = {
            'A': { bg: '#fdeaea', color: '#e74c3c' },
            'B': { bg: '#e8f8f0', color: '#27ae60' },
            'C': { bg: '#fef5e7', color: '#f39c12' }
        };
        const lc = levelColors[client.level] || levelColors['B'];
        const crmData = crmLoad();
        const orders = crmData.filter(r => r.client === client.name);
        const totalRevenue = orders.reduce((sum, r) => sum + ((r.fees||{}).total||0), 0);
        const totalProfit = orders.reduce((sum, r) => sum + (r.profit||0), 0);
        return `
            <div class="preview-card-header">
                <div class="preview-card-icon" style="background: linear-gradient(135deg, #4a90e2, #5ba3f5);">👥</div>
                <div>
                    <div class="preview-card-title">${client.name}</div>
                    <div class="preview-card-subtitle">${client.route || '未设置航线'}</div>
                </div>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">等级</span>
                <span class="preview-card-tag" style="background:${lc.bg};color:${lc.color};">${client.level}级客户</span>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">联系人</span>
                <span class="preview-card-value">${client.contact || '-'}</span>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">电话</span>
                <span class="preview-card-value">${client.phone || '-'}</span>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">邮箱</span>
                <span class="preview-card-value">${client.email || '-'}</span>
            </div>
            ${client.address ? `<div class="preview-card-row"><span class="preview-card-label">地址</span><span class="preview-card-value">${client.address}</span></div>` : ''}
            <div class="preview-card-stats">
                <div class="preview-stat-item">
                    <div class="preview-stat-value">${orders.length}</div>
                    <div class="preview-stat-label">订单数</div>
                </div>
                <div class="preview-stat-item">
                    <div class="preview-stat-value">¥${totalRevenue.toLocaleString()}</div>
                    <div class="preview-stat-label">累计应收</div>
                </div>
                <div class="preview-stat-item">
                    <div class="preview-stat-value">¥${totalProfit.toLocaleString()}</div>
                    <div class="preview-stat-label">累计毛利</div>
                </div>
            </div>
        `;
    }

    function getPreviewHtml_Supplier(supplier){
        const typeColors = {
            '船代理': { bg: '#e8f4fd', color: '#3498db' },
            '拖车行': { bg: '#f5eef8', color: '#9b59b6' },
            '报关行': { bg: '#e8f8f5', color: '#1abc9c' },
            '仓库': { bg: '#fef5e7', color: '#e67e22' },
            '清关行': { bg: '#fdeaea', color: '#e74c3c' }
        };
        const tc = typeColors[supplier.type] || { bg: '#f5f5f5', color: '#666' };
        const crmData = crmLoad();
        const orders = crmData.filter(r => r.carrier === supplier.name);
        const totalCost = orders.reduce((sum, r) => sum + ((r.costs||{})._total||0), 0);
        return `
            <div class="preview-card-header">
                <div class="preview-card-icon" style="background: linear-gradient(135deg, #e67e22, #f39c12);">🏭</div>
                <div>
                    <div class="preview-card-title">${supplier.name}</div>
                    <div class="preview-card-subtitle">${supplier.region || '未设置区域'}</div>
                </div>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">类型</span>
                <span class="preview-card-tag" style="background:${tc.bg};color:${tc.color};">${supplier.type}</span>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">联系人</span>
                <span class="preview-card-value">${supplier.contact || '-'}</span>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">电话</span>
                <span class="preview-card-value">${supplier.phone || '-'}</span>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">邮箱</span>
                <span class="preview-card-value">${supplier.email || '-'}</span>
            </div>
            ${supplier.bank ? `<div class="preview-card-row"><span class="preview-card-label">银行</span><span class="preview-card-value" style="font-size:11px;">${supplier.bank}</span></div>` : ''}
            <div class="preview-card-stats">
                <div class="preview-stat-item">
                    <div class="preview-stat-value">${orders.length}</div>
                    <div class="preview-stat-label">订单数</div>
                </div>
                <div class="preview-stat-item">
                    <div class="preview-stat-value">¥${totalCost.toLocaleString()}</div>
                    <div class="preview-stat-label">累计应付</div>
                </div>
                <div class="preview-stat-item">
                    <div class="preview-stat-value">${supplier.region || '-'}</div>
                    <div class="preview-stat-label">服务区域</div>
                </div>
            </div>
        `;
    }

    function getPreviewHtml_Freight(freight){
        const today = new Date().toISOString().slice(0,10);
        const isExpired = freight.validTo && freight.validTo < today;
        const expireColor = isExpired ? '#e74c3c' : '#27ae60';
        return `
            <div class="preview-card-header">
                <div class="preview-card-icon" style="background: linear-gradient(135deg, #16a085, #1abc9c);">💰</div>
                <div>
                    <div class="preview-card-title">${freight.pol || '?'} → ${freight.pod || '?'}</div>
                    <div class="preview-card-subtitle">${freight.route} · ${freight.type}</div>
                </div>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">船公司</span>
                <span class="preview-card-value">${freight.carrier || '-'}</span>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">柜型</span>
                <span class="preview-card-value">${freight.containerType || '-'}</span>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">运费</span>
                <span class="preview-card-value" style="color:#16a085;font-size:15px;">¥${Math.round(freight.price||0)}</span>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">有效期</span>
                <span class="preview-card-value" style="color:${expireColor};">${freight.validTo || '长期有效'}${isExpired ? ' (已过期)' : ''}</span>
            </div>
            ${freight.notes ? `<div style="margin-top:10px;padding:8px;background:#f8f9fa;border-radius:8px;font-size:11px;color:#666;">${freight.notes}</div>` : ''}
        `;
    }

    function getPreviewHtml_Reminder(reminder){
        const statusColors = {
            'urgent': { bg: '#fdeaea', color: '#c0392b', border: '#e74c3c' },
            'warning': { bg: '#fef5e7', color: '#d68910', border: '#f39c12' },
            'normal': { bg: '#e8f8f0', color: '#1e8449', border: '#27ae60' }
        };
        const sc = statusColors[reminder.status] || statusColors['normal'];
        const crmData = crmLoad();
        const order = crmData.find(r => String(r.id) === String(reminder.orderId));
        return `
            <div class="preview-card-header">
                <div class="preview-card-icon" style="background: ${sc.bg}; border: 2px solid ${sc.border};">🔔</div>
                <div>
                    <div class="preview-card-title">${reminder.title}</div>
                    <div class="preview-card-subtitle" style="color:${sc.color};">${reminder.daysLeft === 0 ? '今天到期！' : `还有 ${reminder.daysLeft} 天`}</div>
                </div>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">日期</span>
                <span class="preview-card-value">${reminder.date}</span>
            </div>
            <div class="preview-card-row">
                <span class="preview-card-label">类型</span>
                <span class="preview-card-tag" style="background:${sc.bg};color:${sc.color};">${reminder.type === 'etd' ? 'ETD提醒' : reminder.type === 'eta' ? 'ETA提醒' : '免柜期'}</span>
            </div>
            ${order ? `
            <div style="margin-top:10px;padding:10px;background:#f8f9fa;border-radius:8px;">
                <div style="font-size:11px;color:#666;margin-bottom:6px;">关联订单</div>
                <div style="font-size:12px;"><strong>${order.customer || order.id}</strong></div>
                <div style="font-size:11px;color:#888;">${order.route || ''} · ${order.containerType || ''}</div>
            </div>
            ` : ''}
        `;
    }

    let ocrExtractedData = null;

    function toggleOcrSection(){
        const section = document.getElementById('ocr-section');
        const btn = document.getElementById('ocr-toggle-btn');
        if(section.style.display === 'none'){
            section.style.display = 'block';
            btn.textContent = '收起';
        } else {
            section.style.display = 'none';
            btn.textContent = '展开';
        }
    }

    function handleOcrFileSelect(event){
        const file = event.target.files[0];
        if(!file) return;
        const isPdf = file.type === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf');
        const isImage = file.type.startsWith('image/');
        if(!isPdf && !isImage){
            showToast('请选择PDF或图片文件', true);
            return;
        }
        if(isPdf){
            handlePdfFile(file);
        } else {
            handleImageFile(file);
        }
    }

    function handleImageFile(file){
        const reader = new FileReader();
        reader.onload = function(e){
            const preview = document.getElementById('ocr-preview');
            const previewImg = document.getElementById('ocr-preview-img');
            previewImg.src = e.target.result;
            preview.style.display = 'block';
            performOcr(e.target.result);
        };
        reader.readAsDataURL(file);
    }

    async function handlePdfFile(file){
        const progressDiv = document.getElementById('ocr-progress');
        const progressBar = document.getElementById('ocr-progress-bar');
        const statusDiv = document.getElementById('ocr-status');
        const preview = document.getElementById('ocr-preview');
        const previewImg = document.getElementById('ocr-preview-img');
        const resultDiv = document.getElementById('ocr-result');
        const actionArea = document.getElementById('ocr-action-area');
        const clearBtn = document.getElementById('ocr-clear-btn');

        progressDiv.style.display = 'block';
        resultDiv.style.display = 'none';
        actionArea.style.display = 'none';
        clearBtn.style.display = 'none';
        preview.style.display = 'none';
        progressBar.style.width = '0%';
        statusDiv.textContent = '正在加载PDF.js...';

        try {
            if(typeof pdfjsLib === 'undefined'){
                await loadPdfJsScript();
            }
            progressBar.style.width = '10%';
            statusDiv.textContent = '正在读取PDF文件...';

            const arrayBuffer = await file.arrayBuffer();
            const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
            const numPages = pdf.numPages;
            
            let allText = '';
            let imageDataList = [];
            
            for(let i = 1; i <= numPages; i++){
                statusDiv.textContent = `正在处理第 ${i}/${numPages} 页...`;
                progressBar.style.width = (10 + (i / numPages) * 30) + '%';
                
                const page = await pdf.getPage(i);
                const scale = 2;
                const viewport = page.getViewport({ scale });
                
                const canvas = document.createElement('canvas');
                const context = canvas.getContext('2d');
                canvas.width = viewport.width;
                canvas.height = viewport.height;
                
                await page.render({
                    canvasContext: context,
                    viewport: viewport
                }).promise;
                
                const imageData = canvas.toDataURL('image/png');
                imageDataList.push(imageData);
                
                if(i === 1){
                    previewImg.src = imageData;
                    preview.style.display = 'block';
                }
            }
            
            progressBar.style.width = '40%';
            statusDiv.textContent = '正在OCR识别...';
            
            let combinedText = '';
            for(let i = 0; i < imageDataList.length; i++){
                statusDiv.textContent = `正在识别第 ${i + 1}/${numPages} 页...`;
                const pageText = await performOcrOnImage(imageDataList[i], (progress) => {
                    const totalProgress = 40 + (i / numPages) * 50 + (progress / numPages) * 50;
                    progressBar.style.width = totalProgress + '%';
                });
                combinedText += pageText + '\n\n';
            }
            
            progressBar.style.width = '100%';
            statusDiv.textContent = '识别完成，正在提取关键字段...';
            
            ocrExtractedData = extractBillFields(combinedText);
            
            const resultContent = document.getElementById('ocr-result-content');
            resultContent.innerHTML = formatOcrResult(ocrExtractedData, combinedText);
            progressDiv.style.display = 'none';
            resultDiv.style.display = 'block';
            actionArea.style.display = 'block';
            clearBtn.style.display = 'inline-block';
            populateOcrOrderSelect();
            
            showToast(`PDF识别完成，共 ${numPages} 页`);
        } catch(e){
            console.error('PDF处理错误:', e);
            statusDiv.textContent = 'PDF处理失败: ' + e.message;
            progressBar.style.background = '#e74c3c';
            showToast('PDF处理失败', true);
        }
    }

    function loadPdfJsScript(){
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.min.js';
            script.onload = () => {
                pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.worker.min.js';
                resolve();
            };
            script.onerror = reject;
            document.head.appendChild(script);
        });
    }

    async function performOcrOnImage(imageData, onProgress){
        if(typeof Tesseract === 'undefined'){
            await loadTesseractScript();
        }
        
        const result = await Tesseract.recognize(imageData, 'eng+chi_sim', {
            logger: m => {
                if(m.status === 'recognizing text' && onProgress){
                    onProgress(m.progress);
                }
            }
        });
        
        return result.data.text;
    }

    async function performOcr(imageData){
        const progressDiv = document.getElementById('ocr-progress');
        const progressBar = document.getElementById('ocr-progress-bar');
        const statusDiv = document.getElementById('ocr-status');
        const resultDiv = document.getElementById('ocr-result');
        const resultContent = document.getElementById('ocr-result-content');
        const actionArea = document.getElementById('ocr-action-area');
        const clearBtn = document.getElementById('ocr-clear-btn');

        progressDiv.style.display = 'block';
        resultDiv.style.display = 'none';
        actionArea.style.display = 'none';
        clearBtn.style.display = 'none';
        progressBar.style.width = '0%';
        statusDiv.textContent = '正在加载OCR引擎...';

        try {
            if(typeof Tesseract === 'undefined'){
                statusDiv.textContent = '正在加载Tesseract.js...';
                await loadTesseractScript();
            }

            progressBar.style.width = '20%';
            statusDiv.textContent = '正在识别提单内容...';

            const result = await Tesseract.recognize(imageData, 'eng+chi_sim', {
                logger: m => {
                    if(m.status === 'recognizing text'){
                        const percent = 20 + m.progress * 80;
                        progressBar.style.width = percent + '%';
                        statusDiv.textContent = `识别中... ${Math.round(m.progress * 100)}%`;
                    }
                }
            });

            progressBar.style.width = '100%';
            statusDiv.textContent = '识别完成，正在提取关键字段...';

            const text = result.data.text;
            ocrExtractedData = extractBillFields(text);

            resultContent.innerHTML = formatOcrResult(ocrExtractedData, text);
            progressDiv.style.display = 'none';
            resultDiv.style.display = 'block';
            actionArea.style.display = 'block';
            clearBtn.style.display = 'inline-block';
            populateOcrOrderSelect();

            showToast('OCR识别完成');
        } catch(e){
            console.error('OCR Error:', e);
            statusDiv.textContent = '识别失败: ' + e.message;
            progressBar.style.background = '#e74c3c';
            showToast('OCR识别失败', true);
        }
    }

    function loadTesseractScript(){
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js';
            script.onload = resolve;
            script.onerror = reject;
            document.head.appendChild(script);
        });
    }

    function extractBillFields(text){
        const data = {
            mbl: '',
            hbl: '',
            pol: '',
            pod: '',
            vessel: '',
            carrier: '',
            etd: '',
            eta: '',
            containerNo: '',
            containerType: '',
            weight: '',
            pkgs: '',
            goods: '',
            shipper: '',
            consignee: ''
        };

        const lines = text.split('\n').map(l => l.trim()).filter(l => l);

        const mblMatch = text.match(/(?:MBL|Master\s*Bill|B\/L\s*No\.?|Bill\s*of\s*Lading\s*No\.?)[:\s]*([A-Z0-9]{8,15})/i);
        if(mblMatch) data.mbl = mblMatch[1];

        const hblMatch = text.match(/(?:HBL|House\s*Bill|H\/B\s*L)[:\s]*([A-Z0-9]{8,15})/i);
        if(hblMatch) data.hbl = hblMatch[1];

        const polMatch = text.match(/(?:POL|Port\s*of\s*Loading|起运港|装货港)[:\s]*([A-Za-z\u4e00-\u9fa5]{2,20})/i);
        if(polMatch) data.pol = polMatch[1];

        const podMatch = text.match(/(?:POD|Port\s*of\s*Discharge|目的港|卸货港)[:\s]*([A-Za-z\u4e00-\u9fa5]{2,20})/i);
        if(podMatch) data.pod = podMatch[1];

        const vesselMatch = text.match(/(?:Vessel|Vessel\s*Name|船名|VSL)[:\s]*([A-Za-z0-9\u4e00-\u9fa5\s]{2,30})/i);
        if(vesselMatch) data.vessel = vesselMatch[1].trim();

        const carrierMatch = text.match(/(?:Carrier|Shipping\s*Line|船公司|承运人)[:\s]*([A-Za-z\u4e00-\u9fa5]{2,20})/i);
        if(carrierMatch) data.carrier = carrierMatch[1];

        const etdMatch = text.match(/(?:ETD|Estimated\s*Time\s*of\s*Departure|预计开船|开船日期)[:\s]*(\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})/i);
        if(etdMatch) data.etd = normalizeDate(etdMatch[1]);

        const etaMatch = text.match(/(?:ETA|Estimated\s*Time\s*of\s*Arrival|预计到港|到港日期)[:\s]*(\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})/i);
        if(etaMatch) data.eta = normalizeDate(etaMatch[1]);

        const containerMatch = text.match(/(?:Container\s*No\.?|柜号|箱号)[:\s]*([A-Z]{3,4}[A-Z0-9]{6,10})/i);
        if(containerMatch) data.containerNo = containerMatch[1];

        const ctypeMatch = text.match(/(?:Container\s*Type|柜型|箱型)[:\s]*([24]0\s*(?:GP|HQ)|45\s*HQ)/i);
        if(ctypeMatch) data.containerType = ctypeMatch[1].replace(/\s/g, '');

        const weightMatch = text.match(/(?:Gross\s*Weight|毛重|G\.W\.)[:\s]*([\d,.]+)\s*(?:KG|kg|KGS)/i);
        if(weightMatch) data.weight = weightMatch[1].replace(/,/g, '');

        const pkgsMatch = text.match(/(?:No\.?\s*of\s*Pkgs|Packages|件数|Package)[:\s]*([\d,]+)/i);
        if(pkgsMatch) data.pkgs = pkgsMatch[1].replace(/,/g, '');

        const goodsMatch = text.match(/(?:Description\s*of\s*Goods|货名|品名|Description)[:\s]*([A-Za-z\u4e00-\u9fa5\s]{2,50})/i);
        if(goodsMatch) data.goods = goodsMatch[1].trim();

        return data;
    }

    function normalizeDate(dateStr){
        const parts = dateStr.split(/[-/]/);
        if(parts.length === 3){
            let [y, m, d] = parts;
            if(y.length === 2){
                y = '20' + y;
            }
            if(m.length === 1) m = '0' + m;
            if(d.length === 1) d = '0' + d;
            if(parts[0].length <= 2){
                [m, d, y] = parts;
                if(y.length === 2) y = '20' + y;
                if(m.length === 1) m = '0' + m;
                if(d.length === 1) d = '0' + d;
            }
            return `${y}-${m}-${d}`;
        }
        return dateStr;
    }

    function formatOcrResult(data, rawText){
        let html = '<div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">';
        const fields = [
            ['主提单号 MBL', data.mbl],
            ['分提单号 HBL', data.hbl],
            ['起运港 POL', data.pol],
            ['目的港 POD', data.pod],
            ['船名/航次', data.vessel],
            ['船公司', data.carrier],
            ['ETD', data.etd],
            ['ETA', data.eta],
            ['柜号', data.containerNo],
            ['柜型', data.containerType],
            ['毛重 (KG)', data.weight],
            ['件数', data.pkgs],
            ['品名', data.goods]
        ];
        fields.forEach(([label, value]) => {
            const hasValue = value && value.trim();
            html += `<div style="padding:6px 8px; background:${hasValue ? '#e8f8f0' : '#f5f5f5'}; border-radius:6px;">
                <div style="font-size:10px; color:#888;">${label}</div>
                <div style="font-size:12px; color:${hasValue ? '#2c3e50' : '#aaa'}; font-weight:${hasValue ? '500' : 'normal'};">${hasValue ? value : '—'}</div>
            </div>`;
        });
        html += '</div>';
        html += `<details style="margin-top:10px;"><summary style="cursor:pointer; font-size:11px; color:#888;">查看原始识别文本</summary>
            <pre style="margin-top:8px; padding:10px; background:#fff; border:1px solid #e0e6ed; border-radius:6px; font-size:10px; white-space:pre-wrap; word-break:break-all; max-height:150px; overflow-y:auto;">${rawText.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
        </details>`;
        return html;
    }

    function populateOcrOrderSelect(){
        const select = document.getElementById('ocr-target-order');
        if(!select) return;
        const crmData = crmLoad();
        select.innerHTML = '<option value="">选择现有订单更新...</option>';
        crmData.forEach(r => {
            const label = `${r.client || '未知客户'} - ${r.mbl || r.orderno || r.id}`;
            select.innerHTML += `<option value="${r.id}">${label}</option>`;
        });
    }

    function fillCrmFromOcr(mode){
        if(!ocrExtractedData){
            showToast('没有识别数据', true);
            return;
        }
        if(mode === 'update'){
            const select = document.getElementById('ocr-target-order');
            const orderId = select?.value;
            if(!orderId){
                showToast('请选择要更新的订单', true);
                return;
            }
            crmEditRecord(parseInt(orderId));
            setTimeout(() => {
                fillOcrDataToForm();
                showToast('已填充识别数据，请确认后保存');
            }, 300);
        } else {
            crmShowAddModal();
            setTimeout(() => {
                fillOcrDataToForm();
                showToast('已填充识别数据，请确认后保存');
            }, 300);
        }
    }

    function fillOcrDataToForm(){
        if(!ocrExtractedData) return;
        const mapping = {
            'crm-f-mbl': ocrExtractedData.mbl,
            'crm-f-hbl': ocrExtractedData.hbl,
            'crm-f-pol': ocrExtractedData.pol,
            'crm-f-pod': ocrExtractedData.pod,
            'crm-f-vessel': ocrExtractedData.vessel,
            'crm-f-carrier': ocrExtractedData.carrier,
            'crm-f-etd': ocrExtractedData.etd,
            'crm-f-eta': ocrExtractedData.eta,
            'crm-f-ctype': ocrExtractedData.containerType,
            'crm-f-weight': ocrExtractedData.weight,
            'crm-f-pkgs': ocrExtractedData.pkgs,
            'crm-f-goods': ocrExtractedData.goods
        };
        Object.entries(mapping).forEach(([id, value]) => {
            if(value){
                const el = document.getElementById(id);
                if(el) el.value = value;
            }
        });
    }

    function clearOcrResult(){
        const preview = document.getElementById('ocr-preview');
        const progressDiv = document.getElementById('ocr-progress');
        const resultDiv = document.getElementById('ocr-result');
        const actionArea = document.getElementById('ocr-action-area');
        const clearBtn = document.getElementById('ocr-clear-btn');
        const fileInput = document.getElementById('ocr-file-input');

        preview.style.display = 'none';
        progressDiv.style.display = 'none';
        resultDiv.style.display = 'none';
        actionArea.style.display = 'none';
        clearBtn.style.display = 'none';
        fileInput.value = '';
        ocrExtractedData = null;
    }

    function initNewModules(){
        clientLoadData();
        clientRender();
        supplierLoadData();
        supplierRender();
        reminderLoadData();
        reminderRefresh();
        reconciliationLoadData();
        reconciliationGenerateFromCRM();
        reconciliationRender();
        freightLoadData();
        loadQuickQuotes();
        freightRender();
        freightInitTrendRoutes();
        const trendCanvas = document.getElementById('freight-trend-canvas');
        if(trendCanvas){
            trendCanvas.addEventListener('mousemove', freightTrendCanvasMouseMove);
            trendCanvas.addEventListener('mouseleave', freightTrendCanvasMouseLeave);
        }
        initShippingLabel();
    }

    function initShippingLabel(){
        const select = document.getElementById('label-order-select');
        if(!select) return;
        
        const orders = crmLoad();
        select.innerHTML = '<option value="">-- 选择订单或手动填写 --</option>';
        
        orders.forEach(order => {
            const opt = document.createElement('option');
            opt.value = order.id;
            const clientName = order.client || order.shipper || '未知客户';
            const route = order.route || (order.pol && order.pod ? order.pol + '-' + order.pod : '');
            opt.textContent = `${order.orderNo || order.id} - ${clientName} (${route})`;
            select.appendChild(opt);
        });
        
        document.getElementById('label-date').value = new Date().toISOString().split('T')[0];
    }

    function autoMatchOrder(){
        const searchText = document.getElementById('label-auto-search').value.trim().toLowerCase();
        const resultDiv = document.getElementById('label-match-result');
        
        if(!searchText){
            resultDiv.style.display = 'none';
            return;
        }
        
        const orders = crmLoad();
        
        if(orders.length === 0){
            resultDiv.innerHTML = '✗ CRM中没有订单数据';
            resultDiv.style.color = '#e74c3c';
            resultDiv.style.display = 'block';
            return;
        }
        
        const matchedOrder = orders.find(order => {
            const orderNo = (order.orderNo || '').toLowerCase();
            const tracking = (order.tracking || '').toLowerCase();
            const mbl = (order.mbl || '').toLowerCase();
            const hbl = (order.hbl || '').toLowerCase();
            const client = (order.client || '').toLowerCase();
            const shipper = (order.shipper || '').toLowerCase();
            const consignee = (order.consignee || '').toLowerCase();
            
            return orderNo.includes(searchText) || 
                   tracking.includes(searchText) || 
                   mbl.includes(searchText) || 
                   hbl.includes(searchText) ||
                   client.includes(searchText) ||
                   shipper.includes(searchText) ||
                   consignee.includes(searchText);
        });
        
        if(matchedOrder){
            document.getElementById('label-order-select').value = matchedOrder.id;
            loadOrderToLabel();
            
            const clientName = matchedOrder.client || matchedOrder.shipper || '未知客户';
            const route = matchedOrder.route || (matchedOrder.pol && matchedOrder.pod ? matchedOrder.pol + '-' + matchedOrder.pod : '');
            resultDiv.innerHTML = `✓ 已匹配: ${matchedOrder.orderNo || matchedOrder.id} - ${clientName} (${route})`;
            resultDiv.style.color = '#27ae60';
            resultDiv.style.display = 'block';
        } else {
            resultDiv.innerHTML = '✗ 未找到匹配的订单';
            resultDiv.style.color = '#e74c3c';
            resultDiv.style.display = 'block';
        }
    }

    function loadOrderToLabel(){
        const select = document.getElementById('label-order-select');
        const orderId = select.value;
        
        if(!orderId){
            clearLabelForm();
            return;
        }
        
        const orders = crmLoad();
        const order = orders.find(o => o.id === orderId);
        
        if(!order) return;
        
        document.getElementById('label-sender-name').value = order.shipper || order.client || '';
        document.getElementById('label-sender-address').value = order.shipaddr || '';
        document.getElementById('label-sender-phone').value = order.shipperphone || '';
        document.getElementById('label-sender-email').value = order.shipperemail || '';
        
        document.getElementById('label-receiver-name').value = order.consignee || '';
        document.getElementById('label-receiver-address').value = order.recvaddr || '';
        document.getElementById('label-receiver-phone').value = order.consigneephone || '';
        document.getElementById('label-receiver-email').value = order.consigneeemail || '';
        
        document.getElementById('label-tracking').value = order.orderNo || order.tracking || order.mbl || order.hbl || '';
        document.getElementById('label-goods').value = order.goods || order.cargoname || '';
        document.getElementById('label-weight').value = order.weight || order.grossweight || '';
        document.getElementById('label-pieces').value = order.pieces || order.pkgs || '1';
        
        if(order.etd){
            document.getElementById('label-date').value = order.etd;
        }
    }

    function clearLabelForm(){
        document.getElementById('label-sender-name').value = '';
        document.getElementById('label-sender-address').value = '';
        document.getElementById('label-sender-phone').value = '';
        document.getElementById('label-sender-email').value = '';
        document.getElementById('label-receiver-name').value = '';
        document.getElementById('label-receiver-address').value = '';
        document.getElementById('label-receiver-phone').value = '';
        document.getElementById('label-receiver-email').value = '';
        document.getElementById('label-tracking').value = '';
        document.getElementById('label-goods').value = '';
        document.getElementById('label-weight').value = '';
        document.getElementById('label-pieces').value = '1';
        document.getElementById('label-date').value = new Date().toISOString().split('T')[0];
    }

    function generateLabelPreview(){
        const lang = document.getElementById('label-language').value;
        
        const texts = {
            zh: {
                title: '跨境物流面单',
                sender: '发件人',
                senderAddr: '发件人地址',
                receiver: '收件人',
                receiverAddr: '收件人地址',
                tracking: '运单号',
                date: '日期',
                service: '服务',
                payment: '付款',
                pieces: '件数',
                package: '包裹信息',
                weight: '重量',
                dimensions: '尺寸',
                goods: '货物',
                value: '价值',
                hscode: 'HS编码',
                customs: '海关信息',
                origin: '原产国',
                vat: 'VAT/税号',
                declaration: '申报'
            },
            en: {
                title: 'SHIPPING LABEL',
                sender: 'SENDER',
                senderAddr: 'Sender Address',
                receiver: 'RECEIVER',
                receiverAddr: 'Receiver Address',
                tracking: 'Tracking No.',
                date: 'Date',
                service: 'Service',
                payment: 'Payment',
                pieces: 'Pieces',
                package: 'PACKAGE INFO',
                weight: 'Weight',
                dimensions: 'Dimensions',
                goods: 'Goods',
                value: 'Value',
                hscode: 'HS Code',
                customs: 'CUSTOMS INFO',
                origin: 'Origin',
                vat: 'VAT/Tax ID',
                declaration: 'Declaration'
            },
            ja: {
                title: '配送伝票',
                sender: '差出人',
                senderAddr: '差出人住所',
                receiver: '受取人',
                receiverAddr: '受取人住所',
                tracking: '追跡番号',
                date: '日付',
                service: 'サービス',
                payment: '支払',
                pieces: '個数',
                package: '荷物情報',
                weight: '重量',
                dimensions: 'サイズ',
                goods: '貨物',
                value: '価値',
                hscode: 'HSコード',
                customs: '税関情報',
                origin: '原産国',
                vat: 'VAT/税番号',
                declaration: '申告'
            }
        };
        
        const t = texts[lang];
        
        const senderName = document.getElementById('label-sender-name').value || t.sender;
        const senderAddress = document.getElementById('label-sender-address').value || t.senderAddr;
        const senderPhone = document.getElementById('label-sender-phone').value || '';
        const senderEmail = document.getElementById('label-sender-email').value || '';
        
        const receiverName = document.getElementById('label-receiver-name').value || t.receiver;
        const receiverAddress = document.getElementById('label-receiver-address').value || t.receiverAddr;
        const receiverPhone = document.getElementById('label-receiver-phone').value || '';
        const receiverEmail = document.getElementById('label-receiver-email').value || '';
        
        const tracking = document.getElementById('label-tracking').value || t.tracking;
        const date = document.getElementById('label-date').value || '';
        const service = document.getElementById('label-service').value || '';
        const payment = document.getElementById('label-payment').value || '';
        
        const weight = document.getElementById('label-weight').value || '';
        const pieces = document.getElementById('label-pieces').value || '1';
        const dimensions = document.getElementById('label-dimensions').value || '';
        const goods = document.getElementById('label-goods').value || '';
        const value = document.getElementById('label-value').value || '';
        const hscode = document.getElementById('label-hscode').value || '';
        
        const origin = document.getElementById('label-origin').value || '';
        const vat = document.getElementById('label-vat').value || '';
        const declaration = document.getElementById('label-declaration').value || '';
        
        const preview = document.getElementById('shipping-label-preview');
        
        let barcodeHTML = '';
        if(tracking && tracking !== t.tracking){
            barcodeHTML = `
                <div style="text-align:center; margin:15px 0; padding:10px; background:#f5f5f5; border-radius:5px;">
                    <div style="font-family:'Courier New', monospace; font-size:18px; font-weight:bold; letter-spacing:3px; color:#000;">${tracking}</div>
                    <div style="font-size:10px; color:#666; margin-top:5px;">TRACKING NUMBER</div>
                </div>`;
        }
        
        const qrTracking = tracking !== t.tracking ? tracking : '';
        const qrUrl = qrTracking ? 
            `https://tracking-ruby-seven.vercel.app/?no=${encodeURIComponent(qrTracking)}` : 
            'https://tracking-ruby-seven.vercel.app/';
        
        preview.innerHTML = `
            <div style="font-family:Arial, sans-serif; font-size:11px; line-height:1.5;">
                <div style="text-align:center; border-bottom:3px solid #000; padding-bottom:10px; margin-bottom:15px;">
                    <div style="font-size:16px; font-weight:bold; color:#000;">SHIPPING LABEL</div>
                    <div style="font-size:10px; color:#666; margin-top:3px;">${t.title}</div>
                    ${tracking && tracking !== t.tracking ? `<div style="font-size:14px; font-weight:bold; color:#2c7be5; margin-top:8px; padding:6px 12px; background:#e8f4f8; border-radius:4px; display:inline-block;">📦 ${tracking}</div>` : ''}
                </div>
                
                ${barcodeHTML}
                
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:15px; margin-bottom:15px;">
                    <div style="background:#e8f4f8; padding:10px; border-radius:5px; border-left:4px solid #2c7be5;">
                        <div style="font-size:10px; font-weight:bold; color:#2c7be5; margin-bottom:5px;">📤 ${t.sender}</div>
                        <div style="font-weight:bold; color:#000; margin-bottom:3px;">${senderName}</div>
                        <div style="color:#333; font-size:10px;">${senderAddress}</div>
                        ${senderPhone ? `<div style="color:#666; font-size:10px; margin-top:3px;">📞 ${senderPhone}</div>` : ''}
                        ${senderEmail ? `<div style="color:#666; font-size:10px;">📧 ${senderEmail}</div>` : ''}
                    </div>
                    
                    <div style="background:#fff8f0; padding:10px; border-radius:5px; border-left:4px solid #e67e22;">
                        <div style="font-size:10px; font-weight:bold; color:#e67e22; margin-bottom:5px;">📥 ${t.receiver}</div>
                        <div style="font-weight:bold; color:#000; margin-bottom:3px;">${receiverName}</div>
                        <div style="color:#333; font-size:10px;">${receiverAddress}</div>
                        ${receiverPhone ? `<div style="color:#666; font-size:10px; margin-top:3px;">📞 ${receiverPhone}</div>` : ''}
                        ${receiverEmail ? `<div style="color:#666; font-size:10px;">📧 ${receiverEmail}</div>` : ''}
                    </div>
                </div>
                
                <div style="background:#f5f5f5; padding:10px; border-radius:5px; margin-bottom:15px;">
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                        ${date ? `<div><span style="color:#666; font-size:9px;">${t.date}:</span> <span style="font-weight:bold;">${date}</span></div>` : ''}
                        ${service ? `<div><span style="color:#666; font-size:9px;">${t.service}:</span> <span style="font-weight:bold;">${service}</span></div>` : ''}
                        ${payment ? `<div><span style="color:#666; font-size:9px;">${t.payment}:</span> <span style="font-weight:bold;">${payment}</span></div>` : ''}
                        ${pieces ? `<div><span style="color:#666; font-size:9px;">${t.pieces}:</span> <span style="font-weight:bold;">${pieces}</span></div>` : ''}
                    </div>
                </div>
                
                <div style="border:1px solid #ddd; border-radius:5px; padding:10px; margin-bottom:15px;">
                    <div style="font-size:10px; font-weight:bold; color:#2c3e50; margin-bottom:8px;">📦 ${t.package}</div>
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; font-size:10px;">
                        ${weight ? `<div><span style="color:#666;">${t.weight}:</span> <span style="font-weight:bold;">${weight} kg</span></div>` : ''}
                        ${dimensions ? `<div><span style="color:#666;">${t.dimensions}:</span> <span style="font-weight:bold;">${dimensions}</span></div>` : ''}
                        ${goods ? `<div style="grid-column:1/-1;"><span style="color:#666;">${t.goods}:</span> <span style="font-weight:bold;">${goods}</span></div>` : ''}
                        ${value ? `<div><span style="color:#666;">${t.value}:</span> <span style="font-weight:bold;">USD ${value}</span></div>` : ''}
                        ${hscode ? `<div><span style="color:#666;">${t.hscode}:</span> <span style="font-weight:bold;">${hscode}</span></div>` : ''}
                    </div>
                </div>
                
                ${(origin || vat || declaration) ? `
                <div style="background:#fff4f4; border:1px solid #f0d0d0; border-radius:5px; padding:10px; margin-bottom:15px;">
                    <div style="font-size:10px; font-weight:bold; color:#c0392b; margin-bottom:8px;">🛃 ${t.customs}</div>
                    <div style="font-size:10px;">
                        ${origin ? `<div style="margin-bottom:3px;"><span style="color:#666;">${t.origin}:</span> <span style="font-weight:bold;">${origin}</span></div>` : ''}
                        ${vat ? `<div style="margin-bottom:3px;"><span style="color:#666;">${t.vat}:</span> <span style="font-weight:bold;">${vat}</span></div>` : ''}
                        ${declaration ? `<div style="margin-top:5px; padding-top:5px; border-top:1px dashed #ddd;"><span style="color:#666;">${t.declaration}:</span> ${declaration}</div>` : ''}
                    </div>
                </div>` : ''}
                
                <div style="text-align:center; margin-top:15px; padding-top:10px; border-top:1px dashed #ddd;">
                    <div id="label-qrcode" style="display:inline-block; margin-bottom:5px;"></div>
                    <div style="font-size:9px; color:#999;">扫描二维码查询货物轨迹</div>
                </div>
            </div>`;
        
        setTimeout(() => {
            generateQRCode(qrUrl);
        }, 100);
    }

    function generateQRCode(text){
        const qrContainer = document.getElementById('label-qrcode');
        if(!qrContainer) return;
        
        qrContainer.innerHTML = '';
        
        try {
            if(typeof QRCode === 'undefined'){
                qrContainer.innerHTML = '<div style="color:red;font-size:10px;">QRCode库未加载</div>';
                return;
            }
            
            const qrDiv = document.createElement('div');
            new QRCode(qrDiv, {
                text: text,
                width: 80,
                height: 80,
                correctLevel: QRCode.CorrectLevel.M
            });
            
            setTimeout(() => {
                const qrImg = qrDiv.querySelector('img');
                const qrCanvas = qrDiv.querySelector('canvas');
                
                if(qrImg){
                    qrContainer.appendChild(qrImg);
                } else if(qrCanvas){
                    qrContainer.appendChild(qrCanvas);
                } else {
                    qrContainer.innerHTML = '<div style="color:red;font-size:10px;">二维码生成失败</div>';
                }
            }, 100);
        } catch(e) {
            qrContainer.innerHTML = '<div style="color:red;font-size:10px;">二维码生成失败: ' + e.message + '</div>';
        }
    }

    function printShippingLabel(){
        const preview = document.getElementById('shipping-label-preview');
        if(!preview) return;
        
        const printWindow = window.open('', '_blank');
        printWindow.document.write(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>打印面单</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; background: #fff; }
                    @media print {
                        body { margin: 0; }
                        @page { size: A4; margin: 10mm; }
                    }
                </style>
            </head>
            <body>
                ${preview.innerHTML}
            </body>
            </html>
        `);
        printWindow.document.close();
        printWindow.focus();
        setTimeout(() => {
            printWindow.print();
            printWindow.close();
        }, 250);
    }

    function exportLabelToPDF(){
        const preview = document.getElementById('shipping-label-preview');
        if(!preview) return;
        if(!preview.innerHTML.trim()) {
            generateLabelPreview();
        }
        
        const tracking = document.getElementById('label-tracking').value || 'label';
        
        if(typeof html2canvas === 'undefined'){
            const script1 = document.createElement('script');
            script1.src = 'https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js';
            script1.onload = () => {
                const script2 = document.createElement('script');
                script2.src = 'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js';
                script2.onload = () => exportLabelToPDFActual(preview, tracking);
                document.head.appendChild(script2);
            };
            document.head.appendChild(script1);
        } else {
            exportLabelToPDFActual(preview, tracking);
        }
    }

    function exportLabelToPDFActual(preview, tracking){
        const goods = document.getElementById('label-goods').value || '';
        const pieces = document.getElementById('label-pieces').value || '1';
        
        html2canvas(preview, { scale: 2, backgroundColor: '#fff', useCORS: true }).then(async canvas => {
            if (!window.jspdf || !window.jspdf.jsPDF) {
                throw new Error('jsPDF 未加载');
            }
            const imgData = canvas.toDataURL('image/jpeg', 0.95);
            const { jsPDF } = window.jspdf;
            const pdf = new jsPDF('p', 'mm', 'a4');
            const pW = pdf.internal.pageSize.getWidth();
            const pH = pdf.internal.pageSize.getHeight();
            
            const imgW = canvas.width;
            const imgH = canvas.height;
            const ratio = Math.min(pW / imgW * 0.9, pH / imgH * 0.9);
            const finalW = imgW * ratio;
            const finalH = imgH * ratio;
            const x = (pW - finalW) / 2;
            const y = (pH - finalH) / 2;
            
            pdf.addImage(imgData, 'JPEG', x, y, finalW, finalH);

            const fileNameParts = [tracking];
            if (goods) fileNameParts.push(goods);
            fileNameParts.push(`${pieces}件`);
            const fileName = `${fileNameParts.join('_')}.pdf`;
            const blob = pdf.output('blob');
            const file = new File([blob], fileName, { type: 'application/pdf' });
            if (navigator.share && navigator.canShare && navigator.canShare({ files: [file] })) {
                try {
                    await navigator.share({ files: [file], title: fileName });
                    return;
                } catch (err) {
                    if (err && err.name === 'AbortError') return;
                }
            }
            downloadBlob(blob, fileName);
        }).catch(err => {
            console.error(err);
            showToast(`PDF 导出失败: ${err.message || '未知错误'}`, true);
        });
    }

    function shareLabelAsImage(){
        const preview = document.getElementById('shipping-label-preview');
        if(!preview) return;
        if(!preview.innerHTML.trim()) {
            generateLabelPreview();
        }
        
        if(typeof html2canvas === 'undefined'){
            const script = document.createElement('script');
            script.src = 'https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js';
            script.onload = () => shareLabelAsImageActual(preview);
            document.head.appendChild(script);
        } else {
            shareLabelAsImageActual(preview);
        }
    }

    function shareLabelAsImageActual(preview){
        html2canvas(preview, { scale: 2, backgroundColor: '#fff', useCORS: true }).then(canvas => {
            canvas.toBlob(blob => {
                if (!blob) {
                    throw new Error('图片生成失败');
                }
                const file = new File([blob], 'shipping_label.png', { type: 'image/png' });
                if(navigator.share && navigator.canShare && navigator.canShare({ files: [file] })){
                    navigator.share({
                        files: [file],
                        title: 'Shipping Label',
                        text: 'Shipping Label Image'
                    }).catch(err => {
                        if (!err || err.name !== 'AbortError') downloadImage(canvas);
                    });
                } else {
                    downloadImage(canvas);
                }
            }, 'image/png');
        }).catch(err => {
            console.error(err);
            showToast(`图片分享失败: ${err.message || '未知错误'}`, true);
        });
    }

    function downloadImage(canvas){
        const link = document.createElement('a');
        link.download = 'shipping_label.png';
        link.href = canvas.toDataURL('image/png');
        link.click();
    }

    function downloadBlob(blob, fileName){
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        link.href = url;
        link.download = fileName;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function copyLabelInfo(){
        const tracking = document.getElementById('label-tracking').value || '';
        const sender = document.getElementById('label-sender-name').value || '';
        const receiver = document.getElementById('label-receiver-name').value || '';
        const goods = document.getElementById('label-goods').value || '';
        const weight = document.getElementById('label-weight').value || '';
        const pieces = document.getElementById('label-pieces').value || '1';
        
        const info = `运单号: ${tracking}
发件人: ${sender}
收件人: ${receiver}
货物: ${goods}
重量: ${weight} kg
件数: ${pieces}件`;
        
        navigator.clipboard.writeText(info).then(() => {
            showToast('面单信息已复制');
        }).catch(() => {
            alert('复制失败，请手动复制：\n' + info);
        });
    }

    function toggleTheme() {
        const body = document.body;
        const btn = document.getElementById('theme-toggle');
        body.classList.toggle('dark-mode');
        const isDark = body.classList.contains('dark-mode');
        btn.textContent = isDark ? '☀️' : '🌙';
        localStorage.setItem('hgcd_theme', isDark ? 'dark' : 'light');
        
        document.querySelectorAll('iframe').forEach(iframe => {
            try {
                iframe.contentWindow.postMessage({ type: 'theme-change', isDark: isDark }, '*');
            } catch(e) {}
        });
    }

    function initTheme() {
        const saved = localStorage.getItem('hgcd_theme');
        const btn = document.getElementById('theme-toggle');
        if (saved === 'dark') {
            document.body.classList.add('dark-mode');
            if (btn) btn.textContent = '☀️';
        }
    }

    window.onload = async function(){
        initTheme();
        initLanguage();
        await initAuth();
        checkAndAutoSyncFromCloud();
    };

    function checkAndAutoSyncFromCloud() {
        const config = getCurrentApiConfig();
        const apiUrl = config.url;
        const apiKey = getDecryptedKey(config);
        
        if (!apiUrl || !apiKey) {
            return;
        }
        
        const autoSync = localStorage.getItem('crm_auto_sync');
        if (autoSync === 'false') {
            return;
        }
        
        const localData = crmLoad();
        const lastSyncTime = localStorage.getItem('crm_last_cloud_sync_time');
        const now = Date.now();
        
        const SYNC_INTERVAL = 60 * 60 * 1000;
        
        if (localData.length === 0) {
            silentSyncFromCloud(apiUrl, apiKey);
            return;
        }
        
        if (lastSyncTime) {
            const timeSinceLastSync = now - parseInt(lastSyncTime);
            if (timeSinceLastSync < SYNC_INTERVAL) {
                return;
            }
        }
        
        silentSyncFromCloud(apiUrl, apiKey);
    }

    function silentSyncFromCloud(apiUrl, apiKey) {
        fetch(apiUrl + '/api/backup', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${apiKey}`
            }
        })
        .then(response => response.json())
        .then(result => {
            if (result.success && result.data) {
                const data = result.data;
                let restoreCount = 0;
                
                if (data.orders && data.orders.length) {
                    const localOrders = crmLoad();
                    const localOrderMap = new Map(localOrders.map(o => [String(o.id), o]));
                    let hasChanges = false;
                    
                    data.orders.forEach(serverOrder => {
                        // 修复serverOrder的tags字段
                        if (!serverOrder.tags) {
                            serverOrder.tags = [];
                        } else if (typeof serverOrder.tags === 'string') {
                            serverOrder.tags = serverOrder.tags.split(',').map(t => t.trim()).filter(t => t);
                        } else if (!Array.isArray(serverOrder.tags)) {
                            serverOrder.tags = [];
                        }
                        
                        const localOrder = localOrderMap.get(String(serverOrder.id));
                        if (!localOrder) {
                            localOrders.push(serverOrder);
                            restoreCount++;
                            hasChanges = true;
                        } else {
                            const serverUpdated = new Date(serverOrder.updatedAt || serverOrder.createdAt).getTime();
                            const localUpdated = new Date(localOrder.updatedAt || localOrder.createdAt).getTime();
                            if (serverUpdated > localUpdated) {
                                const idx = localOrders.findIndex(o => String(o.id) === String(serverOrder.id));
                                if (idx >= 0) {
                                    localOrders[idx] = serverOrder;
                                    restoreCount++;
                                    hasChanges = true;
                                }
                            }
                        }
                    });
                    
                    if (hasChanges) {
                        localStorage.setItem(CRM_KEY, JSON.stringify(localOrders));
                    }
                }
                
                if (data.clients && data.clients.length) {
                    localStorage.setItem('logistics_client_data', JSON.stringify(data.clients));
                    restoreCount += data.clients.length;
                }
                
                if (data.suppliers && data.suppliers.length) {
                    localStorage.setItem('logistics_supplier_data', JSON.stringify(data.suppliers));
                    restoreCount += data.suppliers.length;
                }
                
                localStorage.setItem('crm_last_cloud_sync_time', Date.now().toString());
                
                if (restoreCount > 0) {
                    showToast(`✅ 已从云端同步 ${restoreCount} 条数据`);
                    crmRender();
                    if (typeof supplierLoadData === 'function') supplierLoadData();
                    if (typeof clientLoadData === 'function') clientLoadData();
                    if (typeof supplierRender === 'function') supplierRender();
                    if (typeof clientRender === 'function') clientRender();
                    reminderLoadData();
                    reminderGenerateFromCRM();
                    reminderRender();
                    reconciliationLoadData();
                    reconciliationGenerateFromCRM();
                    reconciliationRender();
                    freightLoadData();
                    freightRender();
                }
            }
        })
        .catch(error => {
            console.log('自动同步失败:', error);
        });
    }
