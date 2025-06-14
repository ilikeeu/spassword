// ==UserScript==
// @name          智能密码管理助手 Pro - Material-UI完全修复版
// @namespace     https://www.deno.dev/
// @version       3.1.5
// @description   自动检测和填充密码，支持多账户切换、密码变更检测和历史记录管理。完全修复Material-UI受控组件填充问题。
// @author        Password Manager Pro
// @match         *://*/*
// @grant         GM_xmlhttpRequest
// @grant         GM_setValue
// @grant         GM_getValue
// @grant         GM_addStyle
// @grant         GM_registerMenuCommand
// @grant         GM_setClipboard
// @run-at        document-end
// @icon         data:image/x-icon;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAACdUlEQVR4nF2TPWtcVxCGnzn3Siuhj0iOVMgLLiT8A+yg1HaXbZIqaVIIUijgLsHg36DG6QRhsQuXSWEMwYka24XTCNJZARGIYuGNEkVeRbY+9u45Z14X98oYD0wzzDsf58xjAAIzEMB/sAysDuHaANoJcOhleHIG3WXYfFdjAgP4DcpFWANuGLSOgQEQ62QCcArVANafwa2vIQkwQQGE/+HBjFmnV4tyMgtJsigRQ1ACT1IxLbEPv3wAn/4JHgxyH9ZmoPO3NMySXCqSu2UJD4Hsbsm9yJL2YTgNn/wLa19AtkO4arA5BOL4eMjj41YdHWGLiwz29zk7OqJot9HkJK+2t4kgmXmUrIJlXsLdQVlqF9LhzZvK/b5SrydJqp4/1+unT3VuBw8faqPV0k9macNMP8Ld4HD9tH7pwNgYYXaWwzt3eLG6yuilS7QuX+b3lRUO7t/nw06HqStXqKQwCIEM14PDQlUXMJdA4mB9nb1ul9zvc7q1xV/37tHrdpE7IxcvksGiGRkWQq7F5Oa7AGxuDsoS5UyYmKAoSzQ6ipmhWog3HjLsGZBAAjDDcyanBCEgiZQSrvp0mmaiLrAXMjwu66Cfr5CbiXAH6W03JNTkhjr2yP6Aq4XZZiXhFy4E5uftZGeH4XBIubREjJFXu7vY5CRlu83rXk+D42PPZiTpYwPYgttz8M0LGEYYcbAEVPVq5OakK1CCOA2jB/DdV/Ct/QDF5xCewYMps84/ZkT3HCHkECwC0V3JzJNZMSHxUvp5AJ/NgltDFd9D+RGsCW4ArZNmgnOYAM6girB+/C5M7+P8Kyx7g3PV4JwbnCvofvkezm8AGhhzCI1do8sAAAAASUVORK5CYII=

// ==/UserScript==

(function() {
    'use strict';

    // 配置
    const CONFIG = {
        API_BASE: 'https://www.deno.dev',
        STORAGE_KEY: 'password_manager_token',
        AUTO_SAVE: true,
        AUTO_FILL: true,
        SHOW_NOTIFICATIONS: true,
        DETECT_PASSWORD_CHANGE: true,
        DEBUG_MODE: false // 添加调试模式控制
    };

    // 全局变量
    let authToken = GM_getValue(CONFIG.STORAGE_KEY, '');
    let currentUser = null;
    let isAuthenticated = false;
    let detectedForms = [];
    let passwordManagerUI = null;
    let isPasswordManagerSite = false;
    let cachedMatches = [];
    let lastSubmittedData = null;
    let floatingButton = null;
    let authVerified = false;

    // 密码更新检测相关变量
    let passwordFieldWatchers = new Map();
    let lastDetectedCredentials = new Map();
    let pendingUpdates = new Map();
    let updateRetryCount = new Map();
    let pageUnloadHandler = null;

    // 登录状态检测相关变量
    let loginAttempts = new Map();
    let loginStatusWatcher = null;
    let initialPageState = null;
    let loginSuccessPatterns = [];
    let loginFailurePatterns = [];
    let isMonitoringLogin = false;

    // 快速更新相关变量
    let preCheckedCredentials = new Map();
    let fastUpdateQueue = [];
    let isProcessingFastUpdate = false;

    // 添加监听器状态控制
    let isPasswordWatchingActive = false;
    let lastFieldDetectionTime = 0;
    let fieldDetectionCooldown = 2000; // 2秒冷却时间

    // 调试日志函数
    function debugLog(message, ...args) {
        if (CONFIG.DEBUG_MODE) {
            console.log(message, ...args);
        }
    }

    // 重要日志函数（总是显示）
    function importantLog(message, ...args) {
        console.log(message, ...args);
    }

    // ========== 修复的快速密码更新系统 ==========

    // 预检查登录凭据
    async function preCheckLoginCredentials(username, password) {
        const credentialKey = `${window.location.hostname}_${username}`;

        debugLog('🚀 预检查登录凭据:', username.substring(0, 3) + '***');

        try {
            // 异步预检查，不阻塞登录流程
            const checkPromise = makeRequest('/api/detect-login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + authToken
                },
                body: JSON.stringify({
                    url: window.location.href,
                    username: username,
                    password: password
                })
            });

            // 将预检查结果缓存
            preCheckedCredentials.set(credentialKey, {
                username: username,
                password: password,
                url: window.location.href,
                checkPromise: checkPromise,
                timestamp: Date.now()
            });

            debugLog('✅ 预检查已启动:', credentialKey);

        } catch (error) {
            console.error('预检查失败:', error);
        }
    }

    // 快速执行密码更新 - 修复版本
    async function executeFastPasswordUpdate(username) {
        if (isProcessingFastUpdate) {
            debugLog('⚠️ 快速更新正在进行中，跳过重复执行');
            return;
        }

        isProcessingFastUpdate = true;
        const credentialKey = `${window.location.hostname}_${username}`;

        debugLog('⚡ 开始快速密码更新:', username.substring(0, 3) + '***');

        try {
            const preChecked = preCheckedCredentials.get(credentialKey);

            if (preChecked) {
                debugLog('⚡ 使用预检查数据执行更新');

                try {
                    // 等待预检查结果
                    const response = await preChecked.checkPromise;
                    debugLog('⚡ 预检查结果:', response);

                    if (response.exists && response.passwordChanged) {
                        debugLog('⚡ 确认密码变更，执行快速更新');
                        await updateExistingPasswordFast(response.existing.id, preChecked.password);
                        showNotification('⚡ 密码已快速更新', 'success');

                    } else if (response.saved) {
                        debugLog('⚡ 新账户已快速保存');
                        showNotification('⚡ 新账户已快速保存', 'success');
                        cachedMatches = [];

                    } else if (response.exists && response.identical) {
                        debugLog('ℹ️ 密码未变化');
                        showNotification('ℹ️ 密码未变化，无需更新', 'info');
                    } else {
                        debugLog('⚠️ 未知响应状态，执行直接检查:', response);
                        await executeDirectPasswordUpdate(username, credentialKey);
                    }
                } catch (error) {
                    console.error('预检查结果处理失败:', error);
                    await executeDirectPasswordUpdate(username, credentialKey);
                }
            } else {
                debugLog('❌ 未找到预检查数据，执行直接检查');
                await executeDirectPasswordUpdate(username, credentialKey);
            }

        } catch (error) {
            console.error('快速密码更新失败:', error);
            // 失败时加入重试队列
            fastUpdateQueue.push({
                username: username,
                timestamp: Date.now()
            });
        } finally {
            isProcessingFastUpdate = false;
            // 清理预检查数据
            preCheckedCredentials.delete(credentialKey);
        }
    }

    // 直接执行密码更新检查 - 修复版本
    async function executeDirectPasswordUpdate(username, credentialKey) {
        debugLog('🔄 执行直接密码更新检查:', username.substring(0, 3) + '***');

        // 从登录尝试中获取密码
        let password = null;
        for (const [key, attempt] of loginAttempts.entries()) {
            if (attempt.username === username && (attempt.status === 'success' || attempt.status === 'pending')) {
                password = attempt.password;
                break;
            }
        }

        if (!password) {
            console.error('❌ 未找到对应的密码');
            return;
        }

        try {
            const response = await makeRequest('/api/detect-login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + authToken
                },
                body: JSON.stringify({
                    url: window.location.href,
                    username: username,
                    password: password
                })
            });

            debugLog('🔄 直接检查结果:', response);

            if (response.exists && response.passwordChanged) {
                debugLog('🔄 确认密码变更，执行更新');
                await updateExistingPasswordFast(response.existing.id, password);
                showNotification('✅ 密码已更新', 'success');

            } else if (response.saved) {
                debugLog('✅ 新账户已保存');
                showNotification('✅ 新账户已保存', 'success');
                cachedMatches = [];

            } else if (response.exists && response.identical) {
                debugLog('ℹ️ 密码未变化');
                showNotification('ℹ️ 密码未变化，无需更新', 'info');
            } else {
                debugLog('⚠️ 未知响应状态:', response);
            }
        } catch (error) {
            console.error('直接检查失败:', error);
            throw error;
        }
    }

    // 快速更新密码（不等待响应）- 修复版本
    async function updateExistingPasswordFast(passwordId, newPassword) {
        debugLog('⚡ 快速更新密码:', passwordId);

        try {
            const response = await makeRequest(`/api/update-existing-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + authToken
                },
                body: JSON.stringify({
                    passwordId: passwordId,
                    newPassword: newPassword
                })
            });

            debugLog('✅ 快速密码更新成功:', passwordId, response);
            cachedMatches = [];
            return response;

        } catch (error) {
            console.error('快速密码更新失败:', error);
            // 失败时重试
            setTimeout(() => {
                debugLog('🔄 重试密码更新:', passwordId);
                updateExistingPasswordFast(passwordId, newPassword);
            }, 2000);
            throw error;
        }
    }

    // 处理快速更新队列
    async function processFastUpdateQueue() {
        if (fastUpdateQueue.length === 0) return;

        debugLog('🔄 处理快速更新队列，待处理:', fastUpdateQueue.length);

        const queueCopy = [...fastUpdateQueue];
        fastUpdateQueue = [];

        for (const item of queueCopy) {
            try {
                await executeFastPasswordUpdate(item.username);
            } catch (error) {
                console.error('处理快速更新队列失败:', error);
            }
        }
    }

    // ========== 修复的登录状态检测系统 ==========

    // 初始化登录状态检测
    function initLoginStatusDetection() {
        if (isMonitoringLogin) {
            debugLog('🔍 登录状态检测已在运行中');
            return;
        }

        debugLog('🔍 初始化快速登录状态检测系统');
        isMonitoringLogin = true;

        // 记录初始页面状态
        captureInitialPageState();

        // 设置登录成功/失败检测模式
        setupLoginPatterns();

        // 启动快速登录状态监听
        startFastLoginStatusWatching();
    }

    // 捕获初始页面状态
    function captureInitialPageState() {
        initialPageState = {
            url: window.location.href,
            pathname: window.location.pathname,
            title: document.title,
            timestamp: Date.now(),
            hasLoginForm: detectedForms.length > 0,
            bodyText: document.body.textContent.toLowerCase(),
            errorElements: document.querySelectorAll('.error, .alert-danger, .alert-error, [class*="error"], [class*="fail"], .invalid-feedback').length,
            hasUserMenu: !!document.querySelector('.user-menu, .profile-menu, [href*="logout"], [href*="signout"], .logout'),
            hasWelcomeText: /welcome|欢迎|dashboard|控制台/.test(document.body.textContent.toLowerCase())
        };

        debugLog('📸 已捕获初始页面状态:', initialPageState);
    }

    // 设置登录检测模式
    function setupLoginPatterns() {
        // 登录成功的常见模式
        loginSuccessPatterns = [
            // URL变化模式
            {
                type: 'url_change',
                patterns: [
                    /\/dashboard/i,
                    /\/home/i,
                    /\/profile/i,
                    /\/account/i,
                    /\/welcome/i,
                    /\/main/i,
                    /\/index(?!\.html?$)/i,
                    /\/user/i,
                    /\/member/i,
                    /\/admin/i,
                    /\/console/i,
                    /\/panel/i
                ]
            },
            // 页面内容模式
            {
                type: 'content',
                patterns: [
                    /welcome\s+back/i,
                    /successfully\s+logged/i,
                    /login\s+successful/i,
                    /dashboard/i,
                    /logout/i,
                    /sign\s+out/i,
                    /退出登录/i,
                    /注销/i,
                    /欢迎回来/i,
                    /登录成功/i,
                    /控制台/i,
                    /个人中心/i,
                    /我的账户/i,
                    /用户中心/i,
                    /管理面板/i
                ]
            },
            // DOM元素模式
            {
                type: 'elements',
                selectors: [
                    '.user-menu',
                    '.profile-menu',
                    '.logout-btn',
                    '.signout-btn',
                    '[href*="logout"]',
                    '[href*="signout"]',
                    '[href*="sign-out"]',
                    '.dashboard',
                    '.user-info',
                    '.user-profile',
                    '.avatar',
                    '.user-avatar',
                    '.account-menu',
                    '.header-user',
                    '.nav-user',
                    '.user-dropdown',
                    '.profile-dropdown'
                ]
            }
        ];

        // 登录失败的常见模式
        loginFailurePatterns = [
            // 错误消息模式
            {
                type: 'error_content',
                patterns: [
                    /invalid.*password/i,
                    /incorrect.*password/i,
                    /wrong.*password/i,
                    /invalid.*credentials/i,
                    /authentication.*failed/i,
                    /login.*failed/i,
                    /access.*denied/i,
                    /unauthorized/i,
                    /用户名.*密码.*错误/i,
                    /密码.*错误/i,
                    /密码.*不正确/i,
                    /登录.*失败/i,
                    /认证.*失败/i,
                    /账号.*密码.*不正确/i,
                    /用户名.*不存在/i,
                    /账户.*不存在/i,
                    /验证.*失败/i
                ]
            },
            // 错误元素模式
            {
                type: 'error_elements',
                selectors: [
                    '.error',
                    '.alert-danger',
                    '.alert-error',
                    '.login-error',
                    '.auth-error',
                    '.form-error',
                    '[class*="error"]',
                    '[class*="fail"]',
                    '[class*="invalid"]',
                    '.invalid-feedback',
                    '.field-error',
                    '.input-error',
                    '.message-error',
                    '.notification-error',
                    '.toast-error'
                ]
            }
        ];

        debugLog('🎯 已设置登录检测模式');
    }

    // 启动快速登录状态监听
    function startFastLoginStatusWatching() {
        debugLog('⚡ 启动快速登录状态监听器');

        // 清理旧的监听器
        if (loginStatusWatcher) {
            loginStatusWatcher.cleanup();
        }

        // 超高频URL监听 - 100ms检查一次
        let lastUrl = window.location.href;
        let lastPathname = window.location.pathname;

        const urlWatcher = setInterval(() => {
            const currentUrl = window.location.href;
            const currentPathname = window.location.pathname;

            if (currentUrl !== lastUrl || currentPathname !== lastPathname) {
                debugLog('⚡ 检测到URL快速变化:', {
                    from: lastUrl,
                    to: currentUrl,
                    pathChanged: lastPathname !== currentPathname
                });

                lastUrl = currentUrl;
                lastPathname = currentPathname;

                // URL变化立即检查登录状态
                checkLoginStatusFast('url_change');

                // 如果是明显的成功跳转，立即执行快速更新
                if (isObviousSuccessRedirect(currentUrl, currentPathname)) {
                    handleLoginSuccessFast('obvious_redirect');
                }
            }
        }, 100);

        // 实时DOM监听
        const domWatcher = new MutationObserver((mutations) => {
            let shouldCheckFast = false;
            let hasSuccessIndicator = false;
            let hasErrorIndicator = false;

            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            const element = node;

                            // 检查成功指示器
                            if (element.classList && (
                                element.classList.contains('user-menu') ||
                                element.classList.contains('logout') ||
                                element.classList.contains('dashboard') ||
                                element.classList.contains('welcome') ||
                                element.querySelector && element.querySelector('.user-menu, [href*="logout"], .dashboard, .welcome')
                            )) {
                                hasSuccessIndicator = true;
                                shouldCheckFast = true;
                            }

                            // 检查错误指示器
                            if (element.classList && (
                                element.classList.contains('error') ||
                                element.classList.contains('alert-danger') ||
                                element.classList.contains('login-error') ||
                                element.querySelector && element.querySelector('.error, .alert-danger, .login-error')
                            )) {
                                hasErrorIndicator = true;
                                shouldCheckFast = true;
                            }

                            // 检查文本内容
                            if (element.textContent) {
                                const text = element.textContent.toLowerCase();
                                if (text.includes('welcome') || text.includes('dashboard') ||
                                    text.includes('logout') || text.includes('欢迎') ||
                                    text.includes('控制台')) {
                                    hasSuccessIndicator = true;
                                    shouldCheckFast = true;
                                }

                                if (text.includes('error') || text.includes('failed') ||
                                    text.includes('错误') || text.includes('失败')) {
                                    hasErrorIndicator = true;
                                    shouldCheckFast = true;
                                }
                            }
                        }
                    });
                }
            });

            if (shouldCheckFast) {
                debugLog('⚡ DOM变化触发快速检查', { hasSuccessIndicator, hasErrorIndicator });

                if (hasSuccessIndicator) {
                    handleLoginSuccessFast('success_indicator');
                } else if (hasErrorIndicator) {
                    handleLoginFailureFast('error_indicator');
                } else {
                    setTimeout(() => checkLoginStatusFast('dom_change'), 50);
                }
            }
        });

        domWatcher.observe(document.body, {
            childList: true,
            subtree: true,
            characterData: true
        });

        // 页面卸载前的最后检查
        const beforeUnloadHandler = () => {
            debugLog('⚡ 页面即将卸载，执行最后的快速检查');
            handleLoginSuccessFast('page_unload');
        };

        window.addEventListener('beforeunload', beforeUnloadHandler);
        window.addEventListener('pagehide', beforeUnloadHandler);

        loginStatusWatcher = {
            urlWatcher,
            domWatcher,
            beforeUnloadHandler,
            cleanup: () => {
                clearInterval(urlWatcher);
                domWatcher.disconnect();
                window.removeEventListener('beforeunload', beforeUnloadHandler);
                window.removeEventListener('pagehide', beforeUnloadHandler);
            }
        };

        // 立即进行初始检查
        setTimeout(() => checkLoginStatusFast('initial'), 50);

        debugLog('⚡ 快速登录状态监听器已启动');
    }

    // 检查是否是明显的成功重定向
    function isObviousSuccessRedirect(currentUrl, currentPathname) {
        const successPatterns = [
            /\/dashboard/i,
            /\/home/i,
            /\/profile/i,
            /\/account/i,
            /\/welcome/i,
            /\/main/i,
            /\/admin/i,
            /\/console/i,
            /\/panel/i
        ];

        for (const pattern of successPatterns) {
            if (pattern.test(currentUrl) || pattern.test(currentPathname)) {
                return true;
            }
        }

        if (initialPageState &&
            initialPageState.url.match(/login|signin|auth/i) &&
            !currentUrl.match(/login|signin|auth|register|signup/i)) {
            return true;
        }

        return false;
    }

    // 快速检查登录状态
    function checkLoginStatusFast(trigger = 'unknown') {
        if (!isMonitoringLogin || loginAttempts.size === 0) {
            return;
        }

        debugLog(`⚡ 快速检查登录状态 (触发: ${trigger})`);

        const currentState = {
            url: window.location.href,
            pathname: window.location.pathname,
            title: document.title,
            bodyText: document.body.textContent.toLowerCase(),
            timestamp: Date.now(),
            hasUserMenu: !!document.querySelector('.user-menu, .profile-menu, [href*="logout"], [href*="signout"], .logout'),
            hasWelcomeText: /welcome|欢迎|dashboard|控制台/.test(document.body.textContent.toLowerCase())
        };

        const loginSuccess = detectLoginSuccessFast(currentState, trigger);
        const loginFailure = detectLoginFailureFast(currentState, trigger);

        debugLog('⚡ 快速登录状态检查结果:', {
            success: loginSuccess,
            failure: loginFailure,
            trigger: trigger,
            pendingAttempts: loginAttempts.size
        });

        if (loginSuccess) {
            handleLoginSuccessFast(trigger);
        } else if (loginFailure) {
            handleLoginFailureFast(trigger);
        }
    }

    // 快速检测登录成功
    function detectLoginSuccessFast(currentState, trigger) {
        debugLog('⚡ 快速检测登录成功');

        // 1. URL明显变化检测
        if (currentState.pathname !== initialPageState.pathname) {
            for (const pattern of loginSuccessPatterns[0].patterns) {
                if (pattern.test(currentState.url) || pattern.test(currentState.pathname)) {
                    debugLog('⚡ 通过URL快速检测到登录成功:', pattern);
                    return true;
                }
            }

            // 离开登录页面
            if (!currentState.pathname.match(/login|signin|auth|register|signup/i) &&
                initialPageState.url.match(/login|signin|auth/i)) {
                debugLog('⚡ 通过离开登录页快速检测到登录成功');
                return true;
            }
        }

        // 2. 用户菜单出现
        if (currentState.hasUserMenu && !initialPageState.hasUserMenu) {
            debugLog('⚡ 通过用户菜单快速检测到登录成功');
            return true;
        }

        // 3. 欢迎文本出现
        if (currentState.hasWelcomeText && !initialPageState.hasWelcomeText) {
            debugLog('⚡ 通过欢迎文本快速检测到登录成功');
            return true;
        }

        // 4. DOM元素检测
        for (const selector of loginSuccessPatterns[2].selectors) {
            if (document.querySelector(selector)) {
                debugLog('⚡ 通过DOM元素快速检测到登录成功:', selector);
                return true;
            }
        }

        // 5. 页面标题变化
        if (currentState.title !== initialPageState.title) {
            const titleLower = currentState.title.toLowerCase();
            if (titleLower.includes('dashboard') || titleLower.includes('welcome') ||
                titleLower.includes('home') || titleLower.includes('控制台') ||
                titleLower.includes('欢迎')) {
                debugLog('⚡ 通过标题变化快速检测到登录成功');
                return true;
            }
        }

        return false;
    }

    // 快速检测登录失败
    function detectLoginFailureFast(currentState, trigger) {
        debugLog('⚡ 快速检测登录失败');

        // 1. 错误消息检测
        for (const pattern of loginFailurePatterns[0].patterns) {
            if (pattern.test(currentState.bodyText)) {
                debugLog('⚡ 通过错误消息快速检测到登录失败:', pattern);
                return true;
            }
        }

        // 2. 错误元素检测
        for (const selector of loginFailurePatterns[1].selectors) {
            const errorElements = document.querySelectorAll(selector);
            if (errorElements.length > 0) {
                for (const element of errorElements) {
                    if (element.offsetParent !== null && element.textContent.trim()) {
                        debugLog('⚡ 通过错误元素快速检测到登录失败:', selector);
                        return true;
                    }
                }
            }
        }

        return false;
    }

    // 快速处理登录成功 - 修复版本（关键修复：避免显示多余通知）
    async function handleLoginSuccessFast(trigger = 'unknown') {
        importantLog(`✅ 快速处理登录成功！(触发: ${trigger})`);

        let updatedCount = 0;
        const updatePromises = [];
        let hasPendingAttempts = false;

        // 检查是否有待处理的登录尝试
        for (const [key, attempt] of loginAttempts.entries()) {
            if (attempt.status === 'pending') {
                hasPendingAttempts = true;
                break;
            }
        }

        // 只有在有待处理的登录尝试时才显示通知和执行更新
        if (!hasPendingAttempts) {
            debugLog('ℹ️ 没有待处理的登录尝试，跳过密码更新');
            cleanupLoginStatusWatcher();
            return;
        }

        showNotification('🎉 检测到登录成功，正在更新密码...', 'success');

        // 立即执行所有待处理的快速更新
        for (const [key, attempt] of loginAttempts.entries()) {
            if (attempt.status === 'pending') {
                debugLog('⚡ 登录成功，执行快速密码更新:', attempt.username.substring(0, 3) + '***');
                attempt.status = 'success';

                // 创建更新Promise
                const updatePromise = (async () => {
                    try {
                        await executeFastPasswordUpdate(attempt.username);
                        updatedCount++;
                        debugLog(`✅ 密码更新完成 ${updatedCount}`);
                    } catch (error) {
                        console.error('密码更新失败:', error);
                        // 即使失败也要显示通知
                        showNotification(`❌ 密码更新失败: ${attempt.username.substring(0, 3)}***`, 'error');
                    }
                })();

                updatePromises.push(updatePromise);
            }
        }

        // 等待所有更新完成
        if (updatePromises.length > 0) {
            try {
                debugLog(`⚡ 等待 ${updatePromises.length} 个密码更新完成...`);
                const results = await Promise.allSettled(updatePromises);

                // 统计成功和失败的数量
                const successCount = results.filter(r => r.status === 'fulfilled').length;
                const failureCount = results.filter(r => r.status === 'rejected').length;

                debugLog(`⚡ 密码更新完成统计: 成功 ${successCount}, 失败 ${failureCount}`);

                if (successCount > 0) {
                    showNotification(`✅ 已成功更新 ${successCount} 个密码`, 'success');
                }

                if (failureCount > 0) {
                    showNotification(`⚠️ ${failureCount} 个密码更新失败`, 'warning');
                }

            } catch (error) {
                console.error('批量更新失败:', error);
                showNotification('⚠️ 密码更新过程中发生错误', 'warning');
            }
        }

        // 清理监听器
        cleanupLoginStatusWatcher();
    }

    // 快速处理登录失败 - 修复版本
    function handleLoginFailureFast(trigger = 'unknown') {
        debugLog(`❌ 快速处理登录失败！(触发: ${trigger})`);

        let hasFailedAttempts = false;

        // 检查是否有待处理的登录尝试
        for (const [key, attempt] of loginAttempts.entries()) {
            if (attempt.status === 'pending') {
                hasFailedAttempts = true;
                break;
            }
        }

        // 只有在有待处理的登录尝试时才显示通知
        if (hasFailedAttempts) {
            showNotification('❌ 检测到登录失败，不会更新密码', 'warning');

            // 标记所有待更新的密码为失败
            loginAttempts.forEach((attempt, key) => {
                if (attempt.status === 'pending') {
                    debugLog('❌ 登录失败，取消密码更新:', attempt.username.substring(0, 3) + '***');
                    attempt.status = 'failed';
                }
            });
        } else {
            debugLog('ℹ️ 没有待处理的登录尝试，跳过失败处理');
        }

        // 清理监听器
        cleanupLoginStatusWatcher();
    }

    // 清理登录状态监听器
    function cleanupLoginStatusWatcher() {
        debugLog('🧹 清理登录状态监听器');

        if (loginStatusWatcher) {
            loginStatusWatcher.cleanup();
            loginStatusWatcher = null;
        }

        isMonitoringLogin = false;

        // 处理剩余的快速更新队列
        setTimeout(() => {
            processFastUpdateQueue();
        }, 1000);

        // 清理过期的登录尝试记录
        setTimeout(() => {
            loginAttempts.clear();
            preCheckedCredentials.clear();
            debugLog('🧹 已清理登录尝试记录');
        }, 5000);
    }

    // ========== 其余代码保持不变 ==========

    // 全局函数定义
    function fillPasswordFromElement(buttonElement) {
        debugLog('🔐 fillPasswordFromElement 被调用', buttonElement);
        try {
            const passwordItem = buttonElement.closest('.pm-password-item');
            if (!passwordItem) {
                console.error('❌ 找不到 .pm-password-item 元素');
                showNotification('❌ 填充失败：找不到密码项', 'error');
                return;
            }

            const matchDataStr = passwordItem.getAttribute('data-match');
            if (!matchDataStr) {
                console.error('❌ 找不到 data-match 属性');
                showNotification('❌ 填充失败：找不到密码数据', 'error');
                return;
            }

            const matchData = JSON.parse(matchDataStr);
            debugLog('🔐 解析密码数据成功:', matchData);

            fillPassword(matchData);
        } catch (error) {
            console.error('❌ fillPasswordFromElement 执行失败:', error);
            showNotification('❌ 填充失败', 'error');
        }
    }

    // 更新现有密码 - 增强版本，支持重试
    async function updateExistingPassword(passwordId, newPassword, retryCount = 0) {
        debugLog('🔄 自动更新密码', passwordId, '重试次数:', retryCount);

        try {
            const response = await makeRequest(`/api/update-existing-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + authToken
                },
                body: JSON.stringify({
                    passwordId: passwordId,
                    newPassword: newPassword
                })
            });

            showNotification('✅ 密码已自动更新，历史记录已保存', 'success');

            // 清除缓存和重试记录
            cachedMatches = [];
            updateRetryCount.delete(passwordId);
            pendingUpdates.delete(passwordId);

            debugLog('✅ 密码更新成功:', passwordId);

        } catch (error) {
            console.error('更新密码失败:', error);

            // 重试逻辑
            if (retryCount < 3) {
                debugLog(`🔄 密码更新失败，准备重试 ${retryCount + 1}/3`);
                updateRetryCount.set(passwordId, retryCount + 1);

                // 延迟重试
                setTimeout(() => {
                    updateExistingPassword(passwordId, newPassword, retryCount + 1);
                }, (retryCount + 1) * 2000);
            } else {
                showNotification('❌ 密码更新失败，已达到最大重试次数', 'error');
                updateRetryCount.delete(passwordId);
                pendingUpdates.delete(passwordId);
            }
        }
    }

    // 查看密码历史
    async function viewPasswordHistory(passwordId) {
        try {
            const response = await makeRequest(`/api/passwords/${passwordId}/history`, {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer ' + authToken
                }
            });

            showPasswordHistoryModal(response.history, passwordId);
        } catch (error) {
            console.error('获取密码历史失败:', error);
            showNotification('❌ 获取密码历史失败', 'error');
        }
    }

    // 删除历史密码记录
    async function deleteHistoryEntry(passwordId, historyId) {
        if (!confirm('确定要删除这条历史记录吗？')) {
            return;
        }

        try {
            const response = await makeRequest('/api/passwords/delete-history', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + authToken
                },
                body: JSON.stringify({
                    passwordId: passwordId,
                    historyId: historyId
                })
            });

            if (response.success) {
                showNotification('🗑️ 历史记录已删除', 'success');
                // 重新加载历史记录
                viewPasswordHistory(passwordId);
            } else {
                throw new Error(response.error || '删除失败');
            }
        } catch (error) {
            console.error('删除历史记录失败:', error);
            showNotification('❌ 删除历史记录失败: ' + error.message, 'error');
        }
    }

    // 删除所有历史记录
    async function deleteAllHistory(passwordId) {
        if (!confirm('确定要删除所有历史记录吗？此操作无法撤销。')) {
            return;
        }

        try {
            const response = await makeRequest('/api/passwords/delete-history', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + authToken
                },
                body: JSON.stringify({
                    passwordId: passwordId,
                    historyId: 'all'
                })
            });

            if (response.success) {
                showNotification('🗑️ ' + response.message, 'success');
                // 重新加载历史记录
                viewPasswordHistory(passwordId);
            } else {
                throw new Error(response.error || '删除失败');
            }
        } catch (error) {
            console.error('删除所有历史记录失败:', error);
            showNotification('❌ 删除所有历史记录失败: ' + error.message, 'error');
        }
    }

    // 显示密码历史模态框
    function showPasswordHistoryModal(history, passwordId) {
        const modal = document.createElement('div');
        modal.className = 'pm-password-history-modal';
        modal.innerHTML = `
            <div class="pm-modal-overlay">
                <div class="pm-modal-content">
                    <div class="pm-modal-header">
                        <h3>📜 密码历史记录</h3>
                        <div class="pm-modal-header-actions">
                            ${history.length > 0 ? `
                                <button type="button" class="pm-btn pm-btn-danger pm-btn-sm pm-btn-delete-all" data-password-id="${passwordId}" title="删除所有历史记录">
                                    🗑️ 清空历史
                                </button>
                            ` : ''}
                            <button type="button" class="pm-close-btn">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                    </div>
                    <div class="pm-modal-body">
                        ${history.length === 0 ?
                            '<p class="pm-text-center">暂无历史记录</p>' :
                            history.map((entry, index) => `
                                <div class="pm-history-item">
                                    <div class="pm-history-header">
                                        <span class="pm-history-date">${new Date(entry.changedAt).toLocaleString()}</span>
                                        <div class="pm-history-actions">
                                            <button type="button" class="pm-btn pm-btn-success pm-btn-sm pm-btn-restore" data-password-id="${entry.passwordId || passwordId}" data-history-id="${entry.id}" title="恢复此密码">
                                                🔄 恢复此密码
                                            </button>
                                            <button type="button" class="pm-btn pm-btn-danger pm-btn-sm pm-btn-delete-history" data-password-id="${entry.passwordId || passwordId}" data-history-id="${entry.id}" title="删除此历史记录">
                                                🗑️ 删除
                                            </button>
                                        </div>
                                    </div>
                                    <div class="pm-history-password">
                                        <label>密码：</label>
                                        <span class="pm-password-value" id="historyPwd${index}">••••••••</span>
                                        <button type="button" class="pm-btn pm-btn-sm pm-btn-secondary pm-btn-toggle-history-pwd" data-element-id="historyPwd${index}" data-password="${escapeHtml(entry.oldPassword)}">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                    </div>
                                </div>
                            `).join('')
                        }
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // 事件委托监听
        modal.addEventListener('click', (e) => {
            const target = e.target;

            if (target.matches('.pm-modal-overlay') || target.closest('.pm-close-btn')) {
                if (!target.closest('.pm-modal-content') || target.closest('.pm-close-btn')) {
                    modal.remove();
                    return;
                }
            }

            const toggleButton = target.closest('.pm-btn-toggle-history-pwd');
            if (toggleButton) {
                const elementId = toggleButton.dataset.elementId;
                const password = toggleButton.dataset.password;
                const element = document.getElementById(elementId);
                const icon = toggleButton.querySelector('i');

                if (element && icon) {
                    if (element.textContent === '••••••••') {
                        element.textContent = password;
                        icon.className = 'fas fa-eye-slash';
                    } else {
                        element.textContent = '••••••••';
                        icon.className = 'fas fa-eye';
                    }
                }
                return;
            }

            const restoreButton = target.closest('.pm-btn-restore');
            if (restoreButton) {
                const passwordIdToRestore = restoreButton.dataset.passwordId;
                const historyIdToRestore = restoreButton.dataset.historyId;

                if (!confirm('确定要恢复到这个历史密码吗？当前密码将被保存到历史记录中。')) {
                    return;
                }

                makeRequest('/api/passwords/restore', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify({ passwordId: passwordIdToRestore, historyId: historyIdToRestore })
                }).then(() => {
                    showNotification('✅ 密码已恢复到历史版本', 'success');
                    modal.remove();
                    cachedMatches = []; // 清除缓存
                }).catch(error => {
                    showNotification('❌ 恢复密码失败', 'error');
                    console.error('恢复密码失败:', error);
                });
                return;
            }

            const deleteButton = target.closest('.pm-btn-delete-history');
            if (deleteButton) {
                const passwordIdToDelete = deleteButton.dataset.passwordId;
                const historyIdToDelete = deleteButton.dataset.historyId;
                deleteHistoryEntry(passwordIdToDelete, historyIdToDelete);
                return;
            }

            const deleteAllButton = target.closest('.pm-btn-delete-all');
            if (deleteAllButton) {
                const passwordIdToDelete = deleteAllButton.dataset.passwordId;
                deleteAllHistory(passwordIdToDelete);
                return;
            }
        });
    }

    // 主要填充函数 - 修复async问题
    async function fillPassword(passwordData) {
        debugLog('🔐 开始填充密码流程:', passwordData);

        try {
            let username, password;

            if (typeof passwordData === 'object') {
                username = passwordData.username;
                password = passwordData.password;
            } else {
                username = arguments[1];
                password = arguments[2];
            }

            if (!username || !password) {
                console.error('❌ 用户名或密码为空');
                showNotification('❌ 用户名或密码为空', 'error');
                return;
            }

            debugLog('🔐 准备填充:', {
                username: username?.substring(0, 3) + '***',
                hasPassword: !!password
            });

            // 使用更精确的字段查找
            const usernameFields = findUsernameFieldsAdvanced();
            const passwordFields = findPasswordFieldsAdvanced();

            debugLog('🔍 找到字段:', {
                usernameFields: usernameFields.length,
                passwordFields: passwordFields.length,
                usernameFieldsDetails: usernameFields.map(f => ({
                    tag: f.tagName,
                    type: f.type,
                    name: f.name,
                    id: f.id,
                    className: f.className,
                    placeholder: f.placeholder
                })),
                passwordFieldsDetails: passwordFields.map(f => ({
                    tag: f.tagName,
                    type: f.type,
                    name: f.name,
                    id: f.id,
                    className: f.className
                }))
            });

            if (usernameFields.length === 0 && passwordFields.length === 0) {
                console.warn('⚠️ 未找到任何可填充的字段');
                showNotification('⚠️ 未找到可填充的字段', 'warning');
                return;
            }

            let filledFields = 0;

            // 填充用户名字段
            if (usernameFields.length > 0 && username) {
                debugLog('🔐 开始填充用户名字段...');
                for (let i = 0; i < usernameFields.length; i++) {
                    const field = usernameFields[i];
                    debugLog(`🔐 尝试填充用户名字段 ${i + 1}:`, field);

                    const success = await fillInputFieldAdvanced(field, username, '用户名');
                    if (success) {
                        filledFields++;
                        debugLog(`✅ 用户名字段 ${i + 1} 填充成功`);
                    } else {
                        debugLog(`❌ 用户名字段 ${i + 1} 填充失败`);
                    }
                }
            }

            // 填充密码字段
            if (passwordFields.length > 0 && password) {
                debugLog('🔐 开始填充密码字段...');
                for (let i = 0; i < passwordFields.length; i++) {
                    const field = passwordFields[i];
                    debugLog(`🔐 尝试填充密码字段 ${i + 1}:`, field);

                    const success = await fillInputFieldAdvanced(field, password, '密码');
                    if (success) {
                        filledFields++;
                        debugLog(`✅ 密码字段 ${i + 1} 填充成功`);
                    } else {
                        debugLog(`❌ 密码字段 ${i + 1} 填充失败`);
                    }
                }
            }

            // 显示结果
            if (filledFields > 0) {
                showNotification(`🔐 已填充 ${filledFields} 个字段`, 'success');
                importantLog(`✅ 填充完成，共填充 ${filledFields} 个字段`);
            } else {
                showNotification('⚠️ 填充失败，请检查页面字段', 'warning');
                console.warn('⚠️ 所有字段填充都失败了');
            }

            // 关闭弹窗
            if (passwordManagerUI) {
                passwordManagerUI.remove();
                passwordManagerUI = null;
            }

        } catch (error) {
            console.error('❌ 填充密码时发生错误:', error);
            showNotification('❌ 填充密码失败', 'error');
        }
    }

    // ========== 增强的密码更新检测系统 ==========

    // 启动密码字段监听 - 优化版本，避免重复调用
    function startPasswordFieldWatching() {
        // 检查冷却时间，避免频繁重复调用
        const now = Date.now();
        if (isPasswordWatchingActive && (now - lastFieldDetectionTime) < fieldDetectionCooldown) {
            debugLog('⚠️ 密码字段监听系统正在冷却中，跳过重复启动');
            return;
        }

        if (isPasswordWatchingActive) {
            debugLog('⚠️ 密码字段监听系统已在运行中，先清理再重启');
            cleanupPasswordFieldWatchers();
        }

        lastFieldDetectionTime = now;
        isPasswordWatchingActive = true;

        debugLog('🔍 启动密码字段监听系统');

        // 清理旧的监听器
        passwordFieldWatchers.clear();

        // 监听所有密码字段
        const passwordFields = findPasswordFieldsAdvanced();
        const usernameFields = findUsernameFieldsAdvanced();

        if (passwordFields.length === 0 && usernameFields.length === 0) {
            debugLog('ℹ️ 未找到任何字段，跳过监听器设置');
            isPasswordWatchingActive = false;
            return;
        }

        passwordFields.forEach((passwordField, index) => {
            watchPasswordField(passwordField, usernameFields, index);
        });

        // 设置页面卸载监听
        setupPageUnloadHandler();

        debugLog(`🔍 已设置 ${passwordFields.length} 个密码字段监听器`);
    }

    // 监听单个密码字段
    function watchPasswordField(passwordField, usernameFields, index) {
        const fieldId = `pwd_${index}_${Date.now()}`;

        // 创建监听器对象
        const watcher = {
            field: passwordField,
            usernameFields: usernameFields,
            lastValue: '',
            lastUsername: '',
            changeTimer: null,
            submitTimer: null
        };

        // 输入事件监听
        const inputHandler = (e) => {
            clearTimeout(watcher.changeTimer);
            watcher.changeTimer = setTimeout(() => {
                handlePasswordFieldChange(watcher);
            }, 300);
        };

        // 失焦事件监听
        const blurHandler = (e) => {
            setTimeout(() => {
                handlePasswordFieldChange(watcher);
            }, 50);
        };

        // 键盘事件监听（回车键）
        const keyHandler = (e) => {
            if (e.key === 'Enter') {
                setTimeout(() => {
                    handlePasswordFieldSubmit(watcher);
                }, 50);
            }
        };

        // 绑定事件
        passwordField.addEventListener('input', inputHandler);
        passwordField.addEventListener('blur', blurHandler);
        passwordField.addEventListener('keydown', keyHandler);

        // 保存监听器
        passwordFieldWatchers.set(fieldId, {
            ...watcher,
            inputHandler,
            blurHandler,
            keyHandler,
            cleanup: () => {
                passwordField.removeEventListener('input', inputHandler);
                passwordField.removeEventListener('blur', blurHandler);
                passwordField.removeEventListener('keydown', keyHandler);
                clearTimeout(watcher.changeTimer);
                clearTimeout(watcher.submitTimer);
            }
        });

        debugLog(`🔍 已设置密码字段监听器: ${fieldId}`);
    }

    // 处理密码字段变化
    function handlePasswordFieldChange(watcher) {
        if (!isAuthenticated || isPasswordManagerSite) return;

        const currentPassword = watcher.field.value;
        const currentUsername = getCurrentUsername(watcher.usernameFields);

        // 检查是否有有效的凭据
        if (!currentUsername || !currentPassword || currentPassword.length < 3) {
            return;
        }

        // 检查是否与上次记录的值相同
        if (currentPassword === watcher.lastValue && currentUsername === watcher.lastUsername) {
            return;
        }

        debugLog('🔍 检测到密码字段变化:', {
            username: currentUsername.substring(0, 3) + '***',
            passwordLength: currentPassword.length,
            hasChanged: currentPassword !== watcher.lastValue
        });

        // 更新记录
        watcher.lastValue = currentPassword;
        watcher.lastUsername = currentUsername;

        // 记录当前凭据
        const credentialKey = `${window.location.hostname}_${currentUsername}`;
        lastDetectedCredentials.set(credentialKey, {
            username: currentUsername,
            password: currentPassword,
            timestamp: Date.now(),
            url: window.location.href
        });

        // 预检查凭据（不阻塞用户操作）
        preCheckLoginCredentials(currentUsername, currentPassword);
    }

    // 处理密码字段提交
    function handlePasswordFieldSubmit(watcher) {
        if (!isAuthenticated || isPasswordManagerSite) return;

        const currentPassword = watcher.field.value;
        const currentUsername = getCurrentUsername(watcher.usernameFields);

        if (!currentUsername || !currentPassword) return;

        debugLog('🔍 检测到密码字段提交事件');

        // 记录登录尝试并启动快速状态检测
        recordLoginAttemptFast(currentUsername, currentPassword);
    }

    // 快速记录登录尝试
    function recordLoginAttemptFast(username, password) {
        const attemptKey = `${window.location.hostname}_${username}_${Date.now()}`;

        const attempt = {
            username: username,
            password: password,
            url: window.location.href,
            timestamp: Date.now(),
            status: 'pending' // pending, success, failed
        };

        loginAttempts.set(attemptKey, attempt);

        debugLog('⚡ 快速记录登录尝试:', {
            username: username.substring(0, 3) + '***',
            url: attempt.url,
            key: attemptKey
        });

        // 立即启动快速登录状态检测
        initLoginStatusDetection();

        // 设置快速超时处理（5秒后假设成功）
        setTimeout(() => {
            const currentAttempt = loginAttempts.get(attemptKey);
            if (currentAttempt && currentAttempt.status === 'pending') {
                debugLog('⚡ 快速超时，假设登录成功');
                handleLoginSuccessFast('fast_timeout');
            }
        }, 5000);
    }

    // 获取当前用户名
    function getCurrentUsername(usernameFields) {
        for (const field of usernameFields) {
            if (field.value && field.value.trim()) {
                return field.value.trim();
            }
        }
        return '';
    }

    // 设置页面卸载处理器
    function setupPageUnloadHandler() {
        // 清理旧的处理器
        if (pageUnloadHandler) {
            window.removeEventListener('beforeunload', pageUnloadHandler);
            window.removeEventListener('pagehide', pageUnloadHandler);
        }

        // 创建新的处理器
        pageUnloadHandler = () => {
            debugLog('⚡ 页面即将卸载，执行快速密码更新');

            // 检查是否有待处理的登录尝试
            loginAttempts.forEach((attempt, key) => {
                if (attempt.status === 'pending') {
                    debugLog('⚡ 页面卸载时发现待处理的登录尝试，立即执行快速更新');
                    // 页面跳转通常意味着登录成功，立即执行快速更新
                    attempt.status = 'success';
                    executeFastPasswordUpdate(attempt.username);
                }
            });
        };

        // 绑定事件
        window.addEventListener('beforeunload', pageUnloadHandler);
        window.addEventListener('pagehide', pageUnloadHandler);
    }

    // 清理密码字段监听器 - 优化版本
    function cleanupPasswordFieldWatchers() {
        debugLog('🧹 清理密码字段监听器');

        passwordFieldWatchers.forEach((watcher, id) => {
            watcher.cleanup();
        });

        passwordFieldWatchers.clear();
        isPasswordWatchingActive = false;

        if (pageUnloadHandler) {
            window.removeEventListener('beforeunload', pageUnloadHandler);
            window.removeEventListener('pagehide', pageUnloadHandler);
            pageUnloadHandler = null;
        }

        // 清理登录状态监听器
        cleanupLoginStatusWatcher();
    }

    // 扩展对象
    window.pmExtension = {
        fillPassword: fillPassword,

        setToken: function() {
            const token = document.getElementById('tokenInput').value.trim();
            if (token) {
                authToken = token;
                GM_setValue(CONFIG.STORAGE_KEY, token);
                authVerified = false;
                verifyAuth().then(() => {
                    if (passwordManagerUI) {
                        passwordManagerUI.remove();
                        passwordManagerUI = null;
                    }
                    createPasswordManagerUI();
                });
            }
        },

        copyToken: function(token) {
            try {
                if (typeof GM_setClipboard !== 'undefined') {
                    GM_setClipboard(token);
                    showCopySuccess();
                    showNotification('📋 令牌已复制到剪贴板', 'success');
                    return;
                }

                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(token).then(() => {
                        showCopySuccess();
                        showNotification('📋 令牌已复制到剪贴板', 'success');
                    }).catch(() => {
                        fallbackCopy(token);
                    });
                } else {
                    fallbackCopy(token);
                }
            } catch (error) {
                fallbackCopy(token);
            }
        },

        refreshAuth: async function() {
            authVerified = false;
            await verifyAuth();
            showNotification('🔄 连接状态已刷新', 'info');
            if (passwordManagerUI) {
                passwordManagerUI.remove();
                passwordManagerUI = null;
            }
            createPasswordManagerUI();
        },

        highlightForms: function() {
            detectedForms.forEach(form => {
                const overlay = document.createElement('div');
                overlay.className = 'pm-form-overlay';

                const rect = form.getBoundingClientRect();
                overlay.style.top = (rect.top + window.scrollY) + 'px';
                overlay.style.left = (rect.left + window.scrollX) + 'px';
                overlay.style.width = rect.width + 'px';
                overlay.style.height = rect.height + 'px';

                document.body.appendChild(overlay);

                setTimeout(() => overlay.remove(), 3000);
            });

            showNotification('📍 登录表单已高亮显示', 'info');
        },

        // 手动获取密码匹配（用户主动操作）
        getPasswordMatches: async function() {
            if (!isAuthenticated || isPasswordManagerSite) {
                showNotification('❌ 未连接到密码管理器', 'error');
                return [];
            }

            try {
                const matches = await getPasswordMatches();
                cachedMatches = matches;
                updateFloatingButton(matches);
                return matches;
            } catch (error) {
                console.error('获取密码匹配失败:', error);
                showNotification('❌ 获取密码匹配失败', 'error');
                return [];
            }
        },

        // 切换调试模式
        toggleDebugMode: function() {
            CONFIG.DEBUG_MODE = !CONFIG.DEBUG_MODE;
            showNotification(`🔧 调试模式已${CONFIG.DEBUG_MODE ? '开启' : '关闭'}`, 'info');
            importantLog(`🔧 调试模式已${CONFIG.DEBUG_MODE ? '开启' : '关闭'}`);
        }
    };

    // ========== 工具函数 ==========

    // 检查是否是密码管理器网站
    function checkPasswordManagerSite() {
        isPasswordManagerSite = window.location.hostname.includes('www.deno.dev') ||
                                 window.location.hostname.includes('localhost') ||
                                 window.location.hostname.includes('127.0.0.1');
        return isPasswordManagerSite;
    }

    // 高级用户名字段查找 - 完全重写
    function findUsernameFieldsAdvanced() {
        const fields = new Set();

        // 1. 直接查找所有可能的input元素
        const allInputs = document.querySelectorAll('input');

        allInputs.forEach(input => {
            // 跳过不可见、禁用或只读的字段
            if (!isElementVisible(input) || input.disabled || input.readOnly) {
                return;
            }

            // 跳过明确的密码字段
            if (input.type === 'password') {
                return;
            }

            // 跳过不合适的input类型
            if (['hidden', 'submit', 'button', 'reset', 'file', 'image', 'checkbox', 'radio'].includes(input.type)) {
                return;
            }

            // 检查是否是用户名字段的各种条件
            const name = (input.name || '').toLowerCase();
            const id = (input.id || '').toLowerCase();
            const placeholder = (input.placeholder || '').toLowerCase();
            const autocomplete = (input.autocomplete || '').toLowerCase();
            const className = (input.className || '').toLowerCase();

            // 通过name属性判断
            if (name.includes('email') || name.includes('user') || name.includes('login') ||
                name.includes('account') || name.includes('username')) {
                fields.add(input);
                debugLog('✅ 通过name属性识别用户名字段:', input);
                return;
            }

            // 通过id属性判断
            if (id.includes('email') || id.includes('user') || id.includes('login') ||
                id.includes('account') || id.includes('username')) {
                fields.add(input);
                debugLog('✅ 通过id属性识别用户名字段:', input);
                return;
            }

            // 通过placeholder判断
            if (placeholder.includes('email') || placeholder.includes('user') || placeholder.includes('邮箱') ||
                placeholder.includes('用户') || placeholder.includes('账号') || placeholder.includes('手机')) {
                fields.add(input);
                debugLog('✅ 通过placeholder识别用户名字段:', input);
                return;
            }

            // 通过autocomplete判断
            if (autocomplete.includes('email') || autocomplete.includes('username') || autocomplete.includes('tel')) {
                fields.add(input);
                debugLog('✅ 通过autocomplete识别用户名字段:', input);
                return;
            }

            // 通过input类型判断
            if (input.type === 'email' || input.type === 'tel') {
                fields.add(input);
                debugLog('✅ 通过type属性识别用户名字段:', input);
                return;
            }

            // Material-UI特殊处理
            if (className.includes('muiinputbase-input') || className.includes('MuiInputBase-input')) {
                // 查找关联的label
                const formControl = input.closest('.MuiFormControl-root');
                if (formControl) {
                    const label = formControl.querySelector('.MuiFormLabel-root, .MuiInputLabel-root');
                    if (label) {
                        const labelText = label.textContent.toLowerCase();
                        if (labelText.includes('email') || labelText.includes('user') || labelText.includes('邮箱') ||
                            labelText.includes('用户') || labelText.includes('账号')) {
                            fields.add(input);
                            debugLog('✅ 通过Material-UI label识别用户名字段:', input);
                            return;
                        }
                    }
                }
            }
        });

        // 2. 如果没有找到明确的用户名字段，查找第一个text类型的input（在密码字段之前）
        if (fields.size === 0) {
            const passwordField = document.querySelector('input[type="password"]');
            if (passwordField) {
                const allTextInputs = Array.from(document.querySelectorAll('input[type="text"], input:not([type]), input[type=""]'))
                    .filter(input => isElementVisible(input) && !input.disabled && !input.readOnly);

                for (const textInput of allTextInputs) {
                    // 检查这个text input是否在密码字段之前（在DOM中的位置）
                    const comparison = textInput.compareDocumentPosition(passwordField);
                    if (comparison & Node.DOCUMENT_POSITION_FOLLOWING) {
                        fields.add(textInput);
                        debugLog('✅ 通过位置推断识别用户名字段:', textInput);
                        break; // 只取第一个
                    }
                }
            }
        }

        debugLog('🔍 最终找到的用户名字段:', Array.from(fields));
        return Array.from(fields);
    }

    // 高级密码字段查找 - 完全重写
    function findPasswordFieldsAdvanced() {
        const fields = [];

        // 查找所有密码字段
        const passwordInputs = document.querySelectorAll('input[type="password"]');

        passwordInputs.forEach(input => {
            if (isElementVisible(input) && !input.disabled && !input.readOnly) {
                fields.push(input);
                debugLog('✅ 找到密码字段:', input);
            }
        });

        debugLog('🔍 最终找到的密码字段:', fields);
        return fields;
    }

    // 高级字段填充函数 - 完全重写，专门针对Material-UI
    function fillInputFieldAdvanced(field, value, fieldType) {
        return new Promise(async (resolve) => {
            if (!field || !value) {
                debugLog(`❌ ${fieldType}字段或值为空`);
                resolve(false);
                return;
            }

            try {
                debugLog(`🔐 开始填充${fieldType}字段:`, field, '值:', value.substring(0, 3) + '***');

                // 检查字段状态
                if (!isElementVisible(field)) {
                    debugLog(`❌ ${fieldType}字段不可见`);
                    resolve(false);
                    return;
                }

                if (field.disabled || field.readOnly) {
                    debugLog(`❌ ${fieldType}字段被禁用或只读`);
                    resolve(false);
                    return;
                }

                // 记录原始值
                const originalValue = field.value;
                debugLog(`📝 ${fieldType}字段原始值:`, originalValue);

                // 第一步：聚焦并准备字段
                field.focus();
                debugLog(`👆 ${fieldType}字段已聚焦`);

                // 等待聚焦生效
                await new Promise(resolve => setTimeout(resolve, 50));

                // 第二步：React特殊处理 - 在设置值之前
                let reactProps = null;
                try {
                    // 查找React实例
                    const reactKeys = Object.keys(field).find(key =>
                        key.startsWith('__reactInternalInstance') ||
                        key.startsWith('_reactInternalInstance') ||
                        key.startsWith('__reactInternalFiber') ||
                        key.startsWith('_reactInternalFiber')
                    );

                    if (reactKeys) {
                        const reactInstance = field[reactKeys];
                        if (reactInstance) {
                            reactProps = reactInstance.memoizedProps ||
                                        (reactInstance._currentElement && reactInstance._currentElement.props) ||
                                        reactInstance.return?.memoizedProps;
                            debugLog('🔍 找到React实例和props:', reactProps);
                        }
                    }
                } catch (e) {
                    debugLog('⚠️ React实例查找失败:', e);
                }

                // 第三步：清空字段
                field.value = '';

                // 触发清空事件
                triggerEventAdvanced(field, 'input', '');

                // 等待清空生效
                await new Promise(resolve => setTimeout(resolve, 50));

                // 第四步：设置新值 - 多种方式同时进行

                // 方式1: 直接设置value
                field.value = value;
                debugLog(`📝 方式1完成，当前值:`, field.value);

                // 方式2: 使用原生setter
                try {
                    const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
                    if (descriptor && descriptor.set) {
                        descriptor.set.call(field, value);
                        debugLog(`📝 方式2完成，当前值:`, field.value);
                    }
                } catch (e) {
                    debugLog(`⚠️ 方式2失败:`, e);
                }

                // 方式3: React特殊处理
                if (reactProps) {
                    try {
                        // 清除React的_valueTracker
                        if (field._valueTracker) {
                            field._valueTracker.setValue('');
                        }

                        // 直接修改React的内部状态
                        const lastValue = field.value;
                        field.value = value;

                        // 创建合成事件
                        const event = {
                            target: field,
                            currentTarget: field,
                            type: 'change',
                            bubbles: true,
                            cancelable: true,
                            nativeEvent: new Event('change', { bubbles: true })
                        };

                        // 触发React的onChange
                        if (reactProps.onChange) {
                            reactProps.onChange(event);
                            debugLog('✅ React onChange已触发');
                        }

                        // 触发React的onInput
                        if (reactProps.onInput) {
                            reactProps.onInput(event);
                            debugLog('✅ React onInput已触发');
                        }

                        debugLog(`📝 React方式完成，当前值:`, field.value);
                    } catch (e) {
                        debugLog('⚠️ React特殊处理失败:', e);
                    }
                }

                // 等待React处理
                await new Promise(resolve => setTimeout(resolve, 100));

                // 第五步：Material-UI特殊处理
                try {
                    const formControl = field.closest('.MuiFormControl-root');
                    if (formControl) {
                        debugLog('🔍 检测到Material-UI表单控件');

                        const label = formControl.querySelector('.MuiInputLabel-root, .MuiFormLabel-root');
                        if (label) {
                            // 激活label的shrink状态
                            label.setAttribute('data-shrink', 'true');
                            label.classList.add('MuiInputLabel-shrink');
                            label.classList.remove('MuiInputLabel-outlined');
                            debugLog('✅ Material-UI label状态已更新');
                        }

                        // 更新输入框的状态
                        const inputBase = formControl.querySelector('.MuiInputBase-root');
                        if (inputBase) {
                            inputBase.classList.add('Mui-focused');
                            debugLog('✅ Material-UI输入框focused状态已更新');
                        }
                    }
                } catch (e) {
                    debugLog('⚠️ Material-UI特殊处理失败:', e);
                }

                // 第六步：触发所有相关事件
                triggerEventAdvanced(field, 'input', value);
                triggerEventAdvanced(field, 'change', value);

                // 等待事件处理
                await new Promise(resolve => setTimeout(resolve, 100));

                // 第七步：强制保持值
                const checkAndMaintainValue = () => {
                    if (field.value !== value) {
                        debugLog(`🔧 检测到值被清空，重新设置: ${field.value} -> ${value}`);
                        field.value = value;

                        // 重新触发React事件
                        if (reactProps && reactProps.onChange) {
                            const event = {
                                target: field,
                                currentTarget: field,
                                type: 'change'
                            };
                            reactProps.onChange(event);
                        }
                    }
                };

                // 多次检查和维护值
                setTimeout(checkAndMaintainValue, 50);
                setTimeout(checkAndMaintainValue, 150);
                setTimeout(checkAndMaintainValue, 300);

                // 等待最终稳定
                await new Promise(resolve => setTimeout(resolve, 400));

                // 第八步：验证填充结果
                const finalValue = field.value;
                debugLog(`🔍 ${fieldType}字段最终值:`, finalValue);

                if (finalValue === value) {
                    // 添加视觉反馈
                    field.style.backgroundColor = '#dcfce7';
                    field.style.borderColor = '#10b981';
                    field.style.transition = 'all 0.3s ease';

                    setTimeout(() => {
                        field.style.backgroundColor = '';
                        field.style.borderColor = '';
                        field.style.transition = '';
                    }, 2000);

                    debugLog(`✅ ${fieldType}字段填充成功！`);
                    resolve(true);
                } else {
                    debugLog(`❌ ${fieldType}字段填充失败，期望值: ${value}，实际值: ${finalValue}`);

                    // 最后一次尝试
                    debugLog('🔧 进行最后一次填充尝试...');
                    field.value = value;

                    setTimeout(() => {
                        const retryValue = field.value;
                        debugLog(`🔍 重试后${fieldType}字段值:`, retryValue);
                        resolve(retryValue === value);
                    }, 100);
                }

            } catch (error) {
                console.error(`❌ 填充${fieldType}字段时发生异常:`, error);
                resolve(false);
            }
        });
    }

    // 高级事件触发函数
    function triggerEventAdvanced(element, eventType, value) {
        try {
            let event;

            switch (eventType) {
                case 'input':
                    event = new InputEvent('input', {
                        bubbles: true,
                        cancelable: true,
                        data: value,
                        inputType: 'insertText'
                    });
                    break;

                case 'change':
                    event = new Event('change', {
                        bubbles: true,
                        cancelable: true
                    });
                    break;

                case 'focus':
                    event = new FocusEvent('focus', {
                        bubbles: true,
                        cancelable: true
                    });
                    break;

                case 'blur':
                    event = new FocusEvent('blur', {
                        bubbles: true,
                        cancelable: true
                    });
                    break;

                case 'keydown':
                case 'keyup':
                    event = new KeyboardEvent(eventType, {
                        bubbles: true,
                        cancelable: true,
                        key: 'Tab'
                    });
                    break;

                default:
                    event = new Event(eventType, {
                        bubbles: true,
                        cancelable: true
                    });
            }

            element.dispatchEvent(event);
            debugLog(`✅ ${eventType}事件已触发`);

        } catch (e) {
            debugLog(`❌ 触发${eventType}事件失败:`, e);
        }
    }

    // 检查元素是否可见
    function isElementVisible(element) {
        if (!element) return false;

        try {
            const rect = element.getBoundingClientRect();
            const style = window.getComputedStyle(element);

            return rect.width > 0 &&
                   rect.height > 0 &&
                   style.display !== 'none' &&
                   style.visibility !== 'hidden' &&
                   style.opacity !== '0' &&
                   element.offsetParent !== null;
        } catch (e) {
            return false;
        }
    }

    // ========== 浮动按钮显示/隐藏控制 ==========

    // 显示浮动按钮
    function showFloatingButton() {
        if (!floatingButton) {
            floatingButton = createFloatingButton();
        } else if (!document.body.contains(floatingButton)) {
            document.body.appendChild(floatingButton);
        }
        floatingButton.style.display = 'flex';
    }

    // 隐藏浮动按钮
    function hideFloatingButton() {
        if (floatingButton && document.body.contains(floatingButton)) {
            floatingButton.style.display = 'none';
        }
    }

    // 更新按钮显示状态
    function updateButtonVisibility() {
        if (isPasswordManagerSite) {
            showFloatingButton();
            return;
        }

        // 只有检测到登录表单时才显示按钮
        if (detectedForms.length > 0) {
            showFloatingButton();
        } else {
            hideFloatingButton();
        }
    }

    // ========== 样式 ==========

    GM_addStyle(`
        .pm-notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, #10b981, #059669);
            color: white;
            padding: 12px 20px;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            z-index: 10000;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 14px;
            font-weight: 600;
            max-width: 350px;
            transform: translateX(400px);
            transition: transform 0.3s ease;
            cursor: pointer;
        }

        .pm-notification.show {
            transform: translateX(0);
        }

        .pm-notification.error {
            background: linear-gradient(135deg, #ef4444, #dc2626);
        }

        .pm-notification.warning {
            background: linear-gradient(135deg, #f59e0b, #d97706);
        }

        .pm-notification.info {
            background: linear-gradient(135deg, #3b82f6, #2563eb);
        }

        .pm-floating-btn {
            position: fixed;
            bottom: 20px;
            right: 20px;
            min-width: 48px;
            min-height: 48px;
            background: transparent;
            border: none;
            cursor: pointer;
            z-index: 9999;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            user-select: none;
            animation: breathe 4s ease-in-out infinite;
            touch-action: none;
            padding: 0;
            margin: 0;
            border-radius: 50%;
        }

        .pm-floating-btn:hover {
            animation-play-state: paused;
            transform: scale(1.1);
            filter: brightness(1.2) drop-shadow(0 8px 16px rgba(0,0,0,0.3));
        }

        .pm-floating-btn.dragging {
            animation-play-state: paused;
            transform: scale(1.1);
            cursor: grabbing;
            filter: brightness(1.3) drop-shadow(0 12px 24px rgba(0,0,0,0.4));
        }

        .pm-floating-btn.has-matches {
            animation: breatheMatched 3.5s ease-in-out infinite;
        }

        .pm-floating-btn.multiple-matches {
            animation: breatheMultiple 3s ease-in-out infinite;
        }

        .pm-floating-btn .match-count {
            position: absolute;
            top: -8px;
            right: -8px;
            background: #ef4444;
            color: white;
            border-radius: 50%;
            width: 22px;
            height: 22px;
            font-size: 12px;
            font-weight: bold;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 2px solid white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
            animation: pulse 2s ease-in-out infinite;
        }

        .pm-floating-btn-icon {
            width: 48px;
            height: 48px;
            object-fit: contain;
            pointer-events: none;
            display: block;
            image-rendering: -webkit-optimize-contrast;
            image-rendering: crisp-edges;
            border-radius: 50%;
        }

        .pm-floating-btn.fallback-icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, #6366f1, #4f46e5);
            color: white;
            font-size: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        @keyframes breathe {
            0%, 100% {
                transform: scale(1);
                filter: brightness(1) drop-shadow(0 4px 8px rgba(0,0,0,0.2));
            }
            25% {
                transform: scale(1.03);
                filter: brightness(1.05) drop-shadow(0 6px 12px rgba(0,0,0,0.25));
            }
            50% {
                transform: scale(1.08);
                filter: brightness(1.1) drop-shadow(0 8px 16px rgba(0,0,0,0.3));
            }
            75% {
                transform: scale(1.05);
                filter: brightness(1.07) drop-shadow(0 7px 14px rgba(0,0,0,0.27));
            }
        }

        @keyframes breatheMatched {
            0%, 100% {
                transform: scale(1);
                filter: brightness(1) hue-rotate(0deg) drop-shadow(0 4px 8px rgba(16, 185, 129, 0.3));
            }
            25% {
                transform: scale(1.04);
                filter: brightness(1.05) hue-rotate(5deg) drop-shadow(0 6px 12px rgba(16, 185, 129, 0.4));
            }
            50% {
                transform: scale(1.1);
                filter: brightness(1.15) hue-rotate(10deg) drop-shadow(0 8px 16px rgba(16, 185, 129, 0.5));
            }
            75% {
                transform: scale(1.06);
                filter: brightness(1.08) hue-rotate(7deg) drop-shadow(0 7px 14px rgba(16, 185, 129, 0.45));
            }
        }

        @keyframes breatheMultiple {
            0%, 100% {
                transform: scale(1);
                filter: brightness(1) hue-rotate(0deg) drop-shadow(0 4px 8px rgba(245, 158, 11, 0.3));
            }
            20% {
                transform: scale(1.05);
                filter: brightness(1.1) hue-rotate(-5deg) drop-shadow(0 6px 12px rgba(245, 158, 11, 0.4));
            }
            40% {
                transform: scale(1.12);
                filter: brightness(1.2) hue-rotate(-10deg) drop-shadow(0 8px 16px rgba(245, 158, 11, 0.5));
            }
            60% {
                transform: scale(1.08);
                filter: brightness(1.15) hue-rotate(-7deg) drop-shadow(0 7px 14px rgba(245, 158, 11, 0.45));
            }
            80% {
                transform: scale(1.03);
                filter: brightness(1.05) hue-rotate(-3deg) drop-shadow(0 5px 10px rgba(245, 158, 11, 0.35));
            }
        }

        @keyframes pulse {
            0%, 100% {
                transform: scale(1);
                opacity: 1;
            }
            50% {
                transform: scale(1.1);
                opacity: 0.8;
            }
        }

        .pm-popup {
            position: fixed;
            bottom: 90px;
            right: 20px;
            width: 420px;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.15);
            z-index: 10000;
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.3s ease;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            border: 1px solid rgba(0,0,0,0.1);
            max-height: 600px;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }

        .pm-popup.show {
            opacity: 1;
            transform: translateY(0);
        }

        .pm-popup-header {
            padding: 16px 20px;
            border-bottom: 1px solid #e5e7eb;
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            color: white;
            border-radius: 16px 16px 0 0;
            font-weight: 600;
            flex-shrink: 0;
        }

        .pm-popup-title {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .pm-match-stats {
            font-size: 12px;
            opacity: 0.9;
            display: flex;
            gap: 8px;
        }

        .pm-match-stat {
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .pm-match-stat .count {
            background: rgba(255,255,255,0.2);
            padding: 2px 6px;
            border-radius: 10px;
            font-weight: bold;
        }

        .pm-popup-content {
            padding: 16px 20px;
            overflow-y: auto;
            flex: 1;
        }

        .pm-password-item {
            padding: 16px;
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            margin-bottom: 12px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            background: white;
        }

        .pm-password-item:hover {
            background: #f8fafc;
            border-color: #6366f1;
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(99, 102, 241, 0.15);
        }

        .pm-password-item.exact-match {
            border-color: #10b981;
            background: linear-gradient(135deg, #f0fdf4, #dcfce7);
        }

        .pm-password-item.subdomain-match {
            border-color: #3b82f6;
            background: linear-gradient(135deg, #eff6ff, #dbeafe);
        }

        .pm-password-item.sitename-match {
            border-color: #f59e0b;
            background: linear-gradient(135deg, #fffbeb, #fef3c7);
        }

        .pm-password-item-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
        }

        .pm-password-item-title {
            font-weight: 700;
            color: #1f2937;
            margin-bottom: 6px;
            font-size: 16px;
        }

        .pm-password-item-username {
            color: #6b7280;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 6px;
            font-weight: 500;
        }

        .pm-password-item-url {
            color: #3b82f6;
            font-size: 12px;
            margin-top: 6px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-weight: 500;
        }

        .pm-match-badge {
            font-size: 11px;
            padding: 4px 8px;
            border-radius: 12px;
            font-weight: 700;
            white-space: nowrap;
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .pm-match-badge.exact {
            background: #10b981;
            color: white;
        }

        .pm-match-badge.subdomain {
            background: #3b82f6;
            color: white;
        }

        .pm-match-badge.sitename {
            background: #f59e0b;
            color: white;
        }

        .pm-password-item-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 12px;
            font-size: 11px;
            color: #9ca3af;
            font-weight: 500;
        }

        .pm-password-item-actions {
            display: flex;
            gap: 8px;
            margin-top: 12px;
        }

        .pm-btn-fill {
            background: linear-gradient(135deg, #10b981, #059669);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            transition: all 0.2s ease;
        }

        .pm-btn-fill:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
        }

        .pm-btn-history {
            background: linear-gradient(135deg, #3b82f6, #2563eb);
            color: white;
            border: none;
            padding: 10px 12px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
        }

        .pm-btn-history:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }

        .pm-login-prompt {
            text-align: center;
            color: #6b7280;
        }

        .pm-login-btn {
            background: linear-gradient(135deg, #6366f1, #4f46e5);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            margin-top: 8px;
        }

        .pm-input {
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            margin-bottom: 8px;
            font-size: 14px;
        }

        .pm-btn {
            background: linear-gradient(135deg, #10b981, #059669);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            width: 100%;
        }

        .pm-btn-sm {
            padding: 6px 12px;
            font-size: 11px;
        }

        .pm-btn-secondary {
            background: #6b7280;
        }

        .pm-btn-success {
            background: linear-gradient(135deg, #10b981, #059669);
        }

        .pm-btn-danger {
            background: linear-gradient(135deg, #ef4444, #dc2626);
        }

        .pm-token-display {
            background: #f8fafc;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 12px;
            margin: 12px 0;
            font-family: monospace;
            font-size: 12px;
            word-break: break-all;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .pm-token-display:hover {
            background: #f1f5f9;
            border-color: #6366f1;
        }

        .pm-no-matches {
            text-align: center;
            color: #6b7280;
            padding: 20px;
        }

        .pm-save-form {
            border-top: 1px solid #e5e7eb;
            padding-top: 16px;
            margin-top: 16px;
        }

        .pm-match-summary {
            background: linear-gradient(135deg, #f8fafc, #f1f5f9);
            border: 1px solid #e5e7eb;
            border-radius: 10px;
            padding: 12px;
            margin-bottom: 16px;
            font-size: 13px;
            color: #4b5563;
        }

        .pm-match-summary-title {
            font-weight: 600;
            margin-bottom: 8px;
            color: #1f2937;
        }

        .pm-match-types {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }

        .pm-match-type {
            display: flex;
            align-items: center;
            gap: 4px;
            font-size: 12px;
        }

        .pm-match-type-icon {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }

        .pm-match-type-icon.exact {
            background: #10b981;
        }

        .pm-match-type-icon.subdomain {
            background: #3b82f6;
        }

        .pm-match-type-icon.sitename {
            background: #f59e0b;
        }

        .pm-password-history-modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 10002;
        }

        .pm-modal-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(5px);
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .pm-modal-content {
            position: relative;
            background: white;
            border-radius: 16px;
            padding: 24px;
            max-width: 500px;
            width: 90%;
            box-shadow: 0 20px 40px rgba(0,0,0,0.2);
            max-height: 80vh;
            overflow-y: auto;
        }

        .pm-modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid #e5e7eb;
        }

        .pm-modal-header h3 {
            margin: 0;
            color: #1f2937;
            font-size: 18px;
            font-weight: 700;
        }

        .pm-modal-header-actions {
            display: flex;
            gap: 8px;
            align-items: center;
        }

        .pm-close-btn {
            background: none;
            border: none;
            font-size: 20px;
            color: #6b7280;
            cursor: pointer;
            padding: 8px;
            border-radius: 50%;
            transition: all 0.2s ease;
        }

        .pm-close-btn:hover {
            background: #f3f4f6;
            color: #374151;
        }

        .pm-modal-body {
            margin: 0;
        }

        .pm-history-item {
            background: #f8fafc;
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 12px;
        }

        .pm-history-item:last-child {
            margin-bottom: 0;
        }

        .pm-history-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            flex-wrap: wrap;
            gap: 8px;
        }

        .pm-history-date {
            font-size: 14px;
            color: #6b7280;
            font-weight: 600;
        }

        .pm-history-actions {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .pm-history-password {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .pm-history-password label {
            font-weight: 600;
            font-size: 14px;
            color: #374151;
            min-width: 60px;
        }

        .pm-password-value {
            flex: 1;
            padding: 8px 12px;
            background: white;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            font-family: monospace;
            font-size: 14px;
        }

        .pm-text-center {
            text-align: center;
            color: #6b7280;
            padding: 40px 20px;
            font-style: italic;
        }

        .pm-form-overlay {
            position: absolute;
            border: 3px solid #10b981;
            background: rgba(16, 185, 129, 0.1);
            pointer-events: none;
            z-index: 9998;
            border-radius: 8px;
            animation: highlightForm 3s ease-in-out;
        }

        @keyframes highlightForm {
            0%, 100% { opacity: 0; }
            50% { opacity: 1; }
        }

        @media (max-width: 768px) {
            .pm-popup {
                width: 95%;
                right: 2.5%;
                bottom: 80px;
            }

            .pm-modal-content {
                margin: 16px;
                max-height: 90vh;
            }

            .pm-modal-header-actions {
                flex-direction: column;
                gap: 4px;
            }

            .pm-history-header {
                flex-direction: column;
                align-items: stretch;
                gap: 12px;
            }

            .pm-history-actions {
                justify-content: center;
            }

            .pm-floating-btn {
                bottom: 15px;
                right: 15px;
            }
        }
    `);

    // ========== 主要功能函数 ==========

    // 初始化
    async function init() {
        importantLog('🔐 密码管理助手 Pro 已启动（Material-UI完全修复版）');

        checkPasswordManagerSite();

        // 只在有令牌且未验证时进行验证
        if (authToken && !authVerified) {
            await verifyAuth();
        }

        // 初始检测
        detectLoginForms();
        updateButtonVisibility();

        observeFormChanges();
        registerMenuCommands();

        if (isPasswordManagerSite) {
            monitorPasswordManagerAuth();
        } else if (isAuthenticated) {
            // 启动密码字段监听系统
            startPasswordFieldWatching();
        }
    }

    // 验证登录状态 - 优化版本
    async function verifyAuth() {
        if (!authToken || authVerified) {
            return;
        }

        try {
            const response = await makeRequest('/api/auth/verify', {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer ' + authToken
                }
            });

            if (response.authenticated) {
                isAuthenticated = true;
                currentUser = response.user;
                authVerified = true; // 标记已验证

                // 只在密码管理器网站上显示连接成功消息
                if (isPasswordManagerSite) {
                    showNotification('🔐 密码管理助手已连接', 'success');
                } else {
                    // 启动密码字段监听系统
                    startPasswordFieldWatching();
                }
            } else {
                authToken = '';
                GM_setValue(CONFIG.STORAGE_KEY, '');
                isAuthenticated = false;
                authVerified = false;
            }
        } catch (error) {
            console.error('验证失败:', error);
            isAuthenticated = false;
            authVerified = false;
        }
    }

    // 创建浮动按钮
    function createFloatingButton() {
        const btn = document.createElement('button');
        btn.className = 'pm-floating-btn';
        btn.title = '密码管理助手 Pro';

        // 从存储中恢复位置
        const savedPosition = GM_getValue('pm_button_position', { bottom: 20, right: 20 });
        btn.style.bottom = savedPosition.bottom + 'px';
        btn.style.right = savedPosition.right + 'px';

        // 尝试加载图片
        const icon = document.createElement('img');
        icon.src = 'https://cdn.mevrik.com/uploads/image6848833820236.png';
        icon.className = 'pm-floating-btn-icon';
        icon.alt = 'Password Manager';

        // 图片加载成功
        icon.onload = function() {
            btn.appendChild(icon);
        };

        // 图片加载失败，使用备用图标
        icon.onerror = function() {
            btn.classList.add('fallback-icon');
            btn.innerHTML = '🔐';
        };

        try {
            btn.appendChild(icon);
        } catch (e) {
            btn.classList.add('fallback-icon');
            btn.innerHTML = '🔐';
        }

        // 添加拖拽功能
        let isDragging = false;
        let dragOffset = { x: 0, y: 0 };
        let startTime = 0;

        btn.addEventListener('mousedown', handleDragStart);
        document.addEventListener('mousemove', handleDragMove);
        document.addEventListener('mouseup', handleDragEnd);

        btn.addEventListener('touchstart', handleTouchStart, { passive: false });
        document.addEventListener('touchmove', handleTouchMove, { passive: false });
        document.addEventListener('touchend', handleTouchEnd);

        function handleDragStart(e) {
            e.preventDefault();
            startDrag(e.clientX, e.clientY);
        }

        function handleTouchStart(e) {
            e.preventDefault();
            const touch = e.touches[0];
            startDrag(touch.clientX, touch.clientY);
        }

        function startDrag(clientX, clientY) {
            isDragging = true;
            startTime = Date.now();
            btn.classList.add('dragging');

            const rect = btn.getBoundingClientRect();
            dragOffset.x = clientX - rect.left;
            dragOffset.y = clientY - rect.top;

            btn.style.pointerEvents = 'none';
        }

        function handleDragMove(e) {
            if (!isDragging) return;
            e.preventDefault();
            updatePosition(e.clientX, e.clientY);
        }

        function handleTouchMove(e) {
            if (!isDragging) return;
            e.preventDefault();
            const touch = e.touches[0];
            updatePosition(touch.clientX, touch.clientY);
        }

        function updatePosition(clientX, clientY) {
            const newX = clientX - dragOffset.x;
            const newY = clientY - dragOffset.y;

            const windowWidth = window.innerWidth;
            const windowHeight = window.innerHeight;
            const btnWidth = btn.offsetWidth;
            const btnHeight = btn.offsetHeight;

            const left = Math.max(0, Math.min(newX, windowWidth - btnWidth));
            const top = Math.max(0, Math.min(newY, windowHeight - btnHeight));

            const bottom = windowHeight - top - btnHeight;
            const right = windowWidth - left - btnWidth;

            btn.style.bottom = bottom + 'px';
            btn.style.right = right + 'px';
            btn.style.left = 'auto';
            btn.style.top = 'auto';
        }

        function handleDragEnd(e) {
            if (!isDragging) return;
            endDrag();
        }

        function handleTouchEnd(e) {
            if (!isDragging) return;
            endDrag();
        }

        function endDrag() {
            const dragDuration = Date.now() - startTime;

            isDragging = false;
            btn.classList.remove('dragging');

            const bottom = parseInt(btn.style.bottom);
            const right = parseInt(btn.style.right);
            GM_setValue('pm_button_position', { bottom, right });

            setTimeout(() => {
                btn.style.pointerEvents = 'auto';

                if (dragDuration < 200) {
                    togglePasswordManager();
                }
            }, 100);
        }

        btn.addEventListener('click', (e) => {
            if (!isDragging) {
                e.stopPropagation();
                togglePasswordManager();
            }
        });

        return btn;
    }

    // 切换密码管理器界面
    function togglePasswordManager() {
        if (passwordManagerUI) {
            passwordManagerUI.remove();
            passwordManagerUI = null;
            return;
        }

        createPasswordManagerUI();
    }

    // 创建密码管理器界面
    async function createPasswordManagerUI() {
        const popup = document.createElement('div');
        popup.className = 'pm-popup';

        if (!isAuthenticated) {
            popup.innerHTML = `
                <div class="pm-popup-header">
                    <div class="pm-popup-title">
                        <span>🔐</span>
                        <span>密码管理助手 Pro</span>
                    </div>
                </div>
                <div class="pm-popup-content">
                    <div class="pm-login-prompt">
                        <p>请先登录密码管理器</p>
                        <button class="pm-login-btn">前往登录</button>
                        ${renderTokenInput()}
                    </div>
                </div>
            `;
        } else {
            if (isPasswordManagerSite) {
                popup.innerHTML = `
                    <div class="pm-popup-header">
                        <div class="pm-popup-title">
                            <span>🔐</span>
                            <span>密码管理助手 Pro</span>
                        </div>
                    </div>
                    <div class="pm-popup-content">
                        <div style="text-align: center; margin-bottom: 16px;">
                            <p style="color: #10b981; font-weight: 600;">✅ 已连接到密码管理器</p>
                        </div>
                        <div>
                            <p style="font-size: 12px; color: #6b7280; margin-bottom: 8px;">当前登录令牌：</p>
                            <div class="pm-token-display">
                                ${authToken.substring(0, 20)}...
                            </div>
                        </div>
                        <button class="pm-btn" data-action="refresh-auth" style="margin-top: 8px;">
                            🔄 刷新连接状态
                        </button>
                        <button class="pm-btn" data-action="toggle-debug" style="margin-top: 8px; background: #6b7280;">
                            🔧 ${CONFIG.DEBUG_MODE ? '关闭' : '开启'}调试模式
                        </button>
                    </div>
                `;
            } else {
                // 使用缓存的匹配，如果没有则提示用户点击获取
                const matches = cachedMatches;

                if (matches.length === 0) {
                    popup.innerHTML = `
                        <div class="pm-popup-header">
                            <div class="pm-popup-title">
                                <span>🔐</span>
                                <span>密码管理助手 Pro</span>
                            </div>
                        </div>
                        <div class="pm-popup-content">
                            <div class="pm-no-matches">
                                <p>🔍 点击下方按钮获取匹配的账户</p>
                                <button class="pm-btn" data-action="get-matches" style="margin-top: 12px;">
                                    🔍 获取匹配账户
                                </button>
                            </div>
                            ${renderDetectedForms()}
                        </div>
                    `;
                } else {
                    popup.innerHTML = `
                        <div class="pm-popup-header">
                            <div class="pm-popup-title">
                                <span>🔐</span>
                                <span>密码管理助手 Pro</span>
                            </div>
                            ${renderMatchStats(matches)}
                        </div>
                        <div class="pm-popup-content">
                            ${renderPasswordMatches(matches)}
                            ${renderDetectedForms()}
                        </div>
                    `;
                }
            }
        }

        document.body.appendChild(popup);
        passwordManagerUI = popup;

        // 使用事件委托来处理所有点击事件
        popup.addEventListener('click', async (e) => {
            const target = e.target;
            const fillButton = target.closest('.pm-btn-fill');
            const historyButton = target.closest('.pm-btn-history');
            const loginBtn = target.closest('.pm-login-btn');
            const tokenDisplay = target.closest('.pm-token-display');
            const actionButton = target.closest('.pm-btn');

            if (fillButton) {
                e.preventDefault();
                fillPasswordFromElement(fillButton);
            } else if (historyButton) {
                e.preventDefault();
                const passwordId = historyButton.getAttribute('data-password-id');
                if (passwordId) {
                    viewPasswordHistory(passwordId);
                }
            } else if (loginBtn) {
                window.open(CONFIG.API_BASE, '_blank');
            } else if (tokenDisplay) {
                window.pmExtension.copyToken(authToken);
            } else if (actionButton) {
                const action = actionButton.dataset.action;
                if(action === 'refresh-auth') {
                    window.pmExtension.refreshAuth();
                } else if(action === 'set-token') {
                    window.pmExtension.setToken();
                } else if(action === 'highlight-forms') {
                    window.pmExtension.highlightForms();
                } else if(action === 'get-matches') {
                    // 获取匹配账户
                    const matches = await window.pmExtension.getPasswordMatches();
                    if (matches.length > 0) {
                        // 重新创建UI显示匹配结果
                        popup.remove();
                        passwordManagerUI = null;
                        createPasswordManagerUI();
                    }
                } else if(action === 'toggle-debug') {
                    window.pmExtension.toggleDebugMode();
                    // 重新创建UI以更新按钮文本
                    popup.remove();
                    passwordManagerUI = null;
                    createPasswordManagerUI();
                }
            }
        });

        setTimeout(() => popup.classList.add('show'), 10);

        document.addEventListener('click', function closePopup(e) {
            if (passwordManagerUI && !passwordManagerUI.contains(e.target) && !e.target.closest('.pm-floating-btn')) {
                passwordManagerUI.remove();
                passwordManagerUI = null;
                document.removeEventListener('click', closePopup);
            }
        });
    }

    // 渲染匹配统计
    function renderMatchStats(matches) {
        const exactCount = matches.filter(m => m.matchType === 'exact').length;
        const subdomainCount = matches.filter(m => m.matchType === 'subdomain').length;
        const sitenameCount = matches.filter(m => m.matchType === 'sitename').length;

        return `
            <div class="pm-match-stats">
                <div class="pm-match-stat">
                    <div class="pm-match-type-icon exact"></div>
                    <span class="count">${exactCount}</span>
                    <span>精确</span>
                </div>
                <div class="pm-match-stat">
                    <div class="pm-match-type-icon subdomain"></div>
                    <span class="count">${subdomainCount}</span>
                    <span>子域</span>
                </div>
                <div class="pm-match-stat">
                    <div class="pm-match-type-icon sitename"></div>
                    <span class="count">${sitenameCount}</span>
                    <span>站名</span>
                </div>
            </div>
        `;
    }

    // 渲染令牌输入
    function renderTokenInput() {
        return `
            <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #e5e7eb;">
                <p style="font-size: 12px; color: #6b7280; margin-bottom: 8px;">或手动输入登录令牌：</p>
                <input type="text" id="tokenInput" class="pm-input" placeholder="粘贴登录令牌..." style="font-size: 11px;">
                <button class="pm-btn" data-action="set-token" style="margin-top: 4px;">
                    设置令牌
                </button>
            </div>
        `;
    }

    // 获取密码匹配 - 只在用户主动调用时执行
    async function getPasswordMatches() {
        if (!isAuthenticated || isPasswordManagerSite) return [];

        try {
            const response = await makeRequest('/api/auto-fill', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + authToken
                },
                body: JSON.stringify({
                    url: window.location.href
                })
            });

            return response.matches || [];
        } catch (error) {
            console.error('获取密码匹配失败:', error);
            return [];
        }
    }

    // 渲染密码匹配
    function renderPasswordMatches(matches) {
        let content = '';

        content += `
            <div class="pm-match-summary">
                <div class="pm-match-summary-title">🎯 匹配说明</div>
                <div class="pm-match-types">
                    <div class="pm-match-type">
                        <div class="pm-match-type-icon exact"></div>
                        <span>精确：域名完全相同</span>
                    </div>
                    <div class="pm-match-type">
                        <div class="pm-match-type-icon subdomain"></div>
                        <span>子域：子域名匹配</span>
                    </div>
                    <div class="pm-match-type">
                        <div class="pm-match-type-icon sitename"></div>
                        <span>站名：网站名称包含</span>
                    </div>
                </div>
            </div>
        `;

        content += `
            <div style="margin-bottom: 16px;">
                <h4 style="margin: 0 0 12px 0; color: #1f2937; font-size: 14px;">
                    🔐 选择要填充的账户 (${matches.length} 个)
                </h4>
            </div>
        `;

        content += renderPasswordList(matches);
        return content;
    }

    // 渲染密码列表
    function renderPasswordList(matches) {
        return matches.map((match, index) => {
            const matchTypeText = {
                'exact': '精确匹配',
                'subdomain': '子域匹配',
                'sitename': '站名匹配'
            };

            const matchTypeIcon = {
                'exact': '🎯',
                'subdomain': '🌐',
                'sitename': '🏷️'
            };

            const lastUsed = match.updatedAt ? new Date(match.updatedAt).toLocaleDateString() : '未知';
            const matchDataAttr = escapeHtml(JSON.stringify(match));

            return `
                <div class="pm-password-item ${match.matchType}-match" data-match='${matchDataAttr}'>
                    <div class="pm-password-item-header">
                        <div>
                            <div class="pm-password-item-title">${escapeHtml(match.siteName)}</div>
                            <div class="pm-password-item-username">
                                <span>👤</span>
                                <span>${escapeHtml(match.username)}</span>
                            </div>
                        </div>
                        <div class="pm-match-badge ${match.matchType}">
                            <span>${matchTypeIcon[match.matchType]}</span>
                            <span>${matchTypeText[match.matchType] || match.matchType}</span>
                        </div>
                    </div>

                    ${match.url ? `<div class="pm-password-item-url">🔗 ${escapeHtml(match.url)}</div>` : ''}

                    <div class="pm-password-item-actions">
                        <button class="pm-btn-fill">
                            ⚡ 立即填充
                        </button>
                        <button class="pm-btn-history" data-password-id="${match.id}" title="查看密码历史">
                            📜
                        </button>
                    </div>

                    <div class="pm-password-item-meta">
                        <span>最后使用: ${lastUsed}</span>
                        <span>匹配度: ${match.matchScore}%</span>
                    </div>
                </div>
            `;
        }).join('');
    }

    // HTML转义函数
    function escapeHtml(text) {
        if (typeof text !== 'string') {
            text = String(text);
        }
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // 渲染检测到的表单
    function renderDetectedForms() {
        if (detectedForms.length === 0 || isPasswordManagerSite) return '';

        return `
            <div class="pm-save-form">
                <h4 style="margin: 0 0 8px 0; color: #1f2937; font-size: 14px;">📝 检测到 ${detectedForms.length} 个登录表单</h4>
                <p style="color: #6b7280; font-size: 12px; margin-bottom: 8px;">登录后可自动保存账户信息</p>
                <button class="pm-btn" data-action="highlight-forms">高亮显示表单</button>
            </div>
        `;
    }

    // 增强的登录表单检测 - 支持Material-UI等现代框架
    function detectLoginForms() {
        detectedForms = [];

        // 策略1: 查找包含用户名和密码字段的 form
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            const usernameFields = findUsernameFieldsAdvanced().filter(field => form.contains(field));
            const passwordFields = findPasswordFieldsAdvanced().filter(field => form.contains(field));

            if (usernameFields.length > 0 && passwordFields.length > 0) {
                detectedForms.push(form);
                if (CONFIG.AUTO_SAVE && !isPasswordManagerSite) {
                    form.removeEventListener('submit', handleFormSubmit);
                    form.addEventListener('submit', handleFormSubmit);
                }
                debugLog('✅ 检测到登录表单 (Form-based):', form);
            }
        });

        // 策略2: 如果没有找到form，但找到了用户名和密码字段
        if (detectedForms.length === 0) {
            const usernameFields = findUsernameFieldsAdvanced();
            const passwordFields = findPasswordFieldsAdvanced();

            if (usernameFields.length > 0 && passwordFields.length > 0) {
                // 创建虚拟表单用于检测
                const virtualForm = document.body;
                detectedForms.push(virtualForm);
                debugLog('✅ 检测到登录字段（无form包裹）');
            }
        }

        debugLog(`🔍 最终检测到 ${detectedForms.length} 个登录表单。`);
        updateButtonVisibility();

        // 重新启动密码字段监听
        if (isAuthenticated && !isPasswordManagerSite) {
            cleanupPasswordFieldWatchers();
            startPasswordFieldWatching();
        }
    }

    // 处理表单提交 - 保留原有逻辑作为备用
    async function handleFormSubmit(e) {
        if (!isAuthenticated || isPasswordManagerSite) return;

        const form = e.target;

        // 查找所有密码字段
        const passwordFields = findPasswordFieldsAdvanced().filter(field => form.contains(field));
        const visiblePasswordFields = passwordFields.filter(field => isElementVisible(field));

        if (visiblePasswordFields.length > 1) {
            debugLog('📝 检测到注册/修改密码表单（存在多个密码框），本次提交将不自动保存密码。');
            return;
        }

        // 查找用户名字段
        const usernameFields = findUsernameFieldsAdvanced().filter(field => form.contains(field));
        const usernameField = usernameFields[0];
        const passwordField = visiblePasswordFields[0];

        if (usernameField && passwordField && usernameField.value && passwordField.value) {
            const submitData = {
                url: window.location.href,
                username: usernameField.value,
                password: passwordField.value
            };

            lastSubmittedData = submitData;

            // 记录登录尝试并启动快速状态检测
            recordLoginAttemptFast(submitData.username, submitData.password);
        }
    }

    // 更新浮动按钮
    function updateFloatingButton(matches) {
        if (!floatingButton) return;

        floatingButton.classList.remove('has-matches', 'multiple-matches');
        const existingCount = floatingButton.querySelector('.match-count');
        if (existingCount) existingCount.remove();

        if (matches.length > 0) {
            if (matches.length === 1) {
                floatingButton.classList.add('has-matches');
                floatingButton.title = `找到 1 个匹配的账户`;
            } else {
                floatingButton.classList.add('multiple-matches');
                floatingButton.title = `找到 ${matches.length} 个匹配的账户`;

                const countBadge = document.createElement('div');
                countBadge.className = 'match-count';
                countBadge.textContent = matches.length > 9 ? '9+' : matches.length;
                floatingButton.appendChild(countBadge);
            }
        } else {
            floatingButton.title = '密码管理助手 Pro';
        }
    }

    // 监听表单变化
    function observeFormChanges() {
        const observer = new MutationObserver((mutations) => {
            let shouldRedetect = false;

            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            if (node.tagName === 'FORM' ||
                                (node instanceof HTMLElement && (
                                    node.querySelector('input[type="password"]') ||
                                    node.querySelector('input[name*="user" i]') ||
                                    node.querySelector('input[id*="user" i]') ||
                                    node.querySelector('.MuiInputBase-input') ||
                                    node.classList.contains('MuiFormControl-root')
                                ))
                            ) {
                                shouldRedetect = true;
                            }
                        }
                    });
                }
            });

            if (shouldRedetect) {
                clearTimeout(window._pm_detection_timer);
                window._pm_detection_timer = setTimeout(() => {
                    detectLoginForms();
                }, 500);
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    // 监听密码管理器的登录状态
    function monitorPasswordManagerAuth() {
        const originalSetItem = localStorage.setItem;
        localStorage.setItem = function(key, value) {
            if (key === 'authToken') {
                if (value && value !== authToken) {
                    authToken = value;
                    GM_setValue(CONFIG.STORAGE_KEY, value);
                    isAuthenticated = true;
                    authVerified = true;
                    showNotification('🔐 已自动获取登录令牌', 'success');
                }
            }
            originalSetItem.apply(this, arguments);
        };

        setInterval(() => {
            const newToken = localStorage.getItem('authToken');
            if (newToken && newToken !== authToken) {
                authToken = newToken;
                GM_setValue(CONFIG.STORAGE_KEY, newToken);
                isAuthenticated = true;
                authVerified = true;
                showNotification('🔐 密码管理器登录状态已同步', 'success');
            }
        }, 2000);
    }

    // 注册菜单命令
    function registerMenuCommands() {
        GM_registerMenuCommand('🔐 打开密码管理器', () => {
            window.open(CONFIG.API_BASE, '_blank');
        });

        GM_registerMenuCommand('🔄 重新检测表单', () => {
            detectLoginForms();
            showNotification('🔍 重新检测完成', 'info');
        });

        GM_registerMenuCommand('📍 重置按钮位置', () => {
            GM_setValue('pm_button_position', { bottom: 20, right: 20 });
            if (floatingButton) {
                floatingButton.style.bottom = '20px';
                floatingButton.style.right = '20px';
                floatingButton.style.left = 'auto';
                floatingButton.style.top = 'auto';
            }
            showNotification('📍 按钮位置已重置', 'info');
        });

        GM_registerMenuCommand('⚙️ 设置令牌', () => {
            const token = prompt('请输入密码管理器的登录令牌（可在密码管理器中获取）:');
            if (token) {
                authToken = token;
                GM_setValue(CONFIG.STORAGE_KEY, token);
                authVerified = false;
                verifyAuth();
            }
        });

        GM_registerMenuCommand('🚪 退出登录', () => {
            authToken = '';
            GM_setValue(CONFIG.STORAGE_KEY, '');
            isAuthenticated = false;
            authVerified = false;
            cachedMatches = [];
            updateFloatingButton([]);
            cleanupPasswordFieldWatchers();
            showNotification('👋 已退出登录', 'info');
        });

        GM_registerMenuCommand('👁️ 强制显示/隐藏按钮', () => {
            if (floatingButton && floatingButton.style.display === 'none') {
                showFloatingButton();
                showNotification('👁️ 按钮已强制显示', 'info');
            } else {
                hideFloatingButton();
                showNotification('👁️ 按钮已隐藏', 'info');
            }
        });

        GM_registerMenuCommand('🧪 测试填充功能', () => {
            const testData = {
                id: 'test',
                username: 'test@example.com',
                password: 'testpassword123'
            };
            fillPassword(testData);
        });

        GM_registerMenuCommand('🔧 切换调试模式', () => {
            window.pmExtension.toggleDebugMode();
        });

        GM_registerMenuCommand('🔍 调试信息', () => {
            importantLog('=== 密码管理助手 Pro 调试信息（Material-UI完全修复版）===');
            importantLog('认证状态:', isAuthenticated);
            importantLog('认证已验证:', authVerified);
            importantLog('当前用户:', currentUser);
            importantLog('检测到的表单:', detectedForms);
            importantLog('缓存的匹配:', cachedMatches);
            importantLog('页面URL:', window.location.href);
            importantLog('最后提交数据:', lastSubmittedData);
            importantLog('配置信息:', CONFIG);
            importantLog('找到的用户名字段:', findUsernameFieldsAdvanced());
            importantLog('找到的密码字段:', findPasswordFieldsAdvanced());
            importantLog('密码字段监听器数量:', passwordFieldWatchers.size);
            importantLog('最后检测到的凭据:', lastDetectedCredentials);
            importantLog('待处理的更新:', pendingUpdates);
            importantLog('登录尝试记录:', loginAttempts);
            importantLog('初始页面状态:', initialPageState);
            importantLog('是否正在监控登录:', isMonitoringLogin);
            importantLog('预检查凭据:', preCheckedCredentials);
            importantLog('快速更新队列:', fastUpdateQueue);
            importantLog('密码监听状态:', isPasswordWatchingActive);
            importantLog('调试模式:', CONFIG.DEBUG_MODE);

            showNotification('🔍 调试信息已输出到控制台', 'info');
        });
    }

    // 显示复制成功状态
    function showCopySuccess() {
        const tokenDisplay = document.querySelector('.pm-token-display');
        if (tokenDisplay) {
            tokenDisplay.style.background = '#10b981';
            tokenDisplay.style.borderColor = '#10b981';
            tokenDisplay.style.color = 'white';
            setTimeout(() => {
                tokenDisplay.style.background = '';
                tokenDisplay.style.borderColor = '';
                tokenDisplay.style.color = '';
            }, 2000);
        }
    }

    // 降级复制方案
    function fallbackCopy(text) {
        try {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            textArea.style.top = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();

            const successful = document.execCommand('copy');
            document.body.removeChild(textArea);

            if (successful) {
                showCopySuccess();
                showNotification('📋 已复制到剪贴板', 'success');
            } else {
                throw new Error('Copy command failed');
            }
        } catch (error) {
            showNotification('📋 复制失败，请手动复制', 'warning');
        }
    }

    // 发送请求
    function makeRequest(url, options = {}) {
        return new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                method: options.method || 'GET',
                url: CONFIG.API_BASE + url,
                headers: options.headers || {},
                data: options.body,
                onload: function(response) {
                    try {
                        const data = JSON.parse(response.responseText);
                        if (response.status >= 200 && response.status < 300) {
                            resolve(data);
                        } else {
                            reject(new Error(data.error || '请求失败'));
                        }
                    } catch (error) {
                        reject(new Error('解析响应失败'));
                    }
                },
                onerror: function(error) {
                    reject(new Error('网络请求失败'));
                }
            });
        });
    }

    // 显示通知
    function showNotification(message, type = 'success') {
        if (!CONFIG.SHOW_NOTIFICATIONS) return;

        const notification = document.createElement('div');
        notification.className = `pm-notification ${type}`;
        notification.textContent = message;

        document.body.appendChild(notification);

        setTimeout(() => notification.classList.add('show'), 100);

        notification.onclick = () => {
            notification.classList.remove('show');
            setTimeout(() => notification.remove(), 300);
        };

        setTimeout(() => {
            if(document.body.contains(notification)) {
               notification.classList.remove('show');
               setTimeout(() => {
                   if (document.body.contains(notification)) {
                       notification.remove()
                   }
               }, 300);
            }
        }, 4000);
    }

    // 启动
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
