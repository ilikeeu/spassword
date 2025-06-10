// ==UserScript==
// @name         智能密码管理助手 Pro - 修正版
// @namespace    https://修改为你的密码管理系统地址/
// @version      2.1.2
// @description  自动检测和填充密码，支持多账户切换、密码变更检测和历史记录管理。修正相同账号不同密码的处理逻辑，不会保存为新账号，只提示是否更新现有账号。
// @author       Password Manager Pro
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_addStyle
// @grant        GM_registerMenuCommand
// @grant        GM_setClipboard
// @run-at       document-end
// @icon         data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🔐</text></svg>
// ==/UserScript==

(function() {
    'use strict';

    // 配置
    const CONFIG = {
        API_BASE: 'https://修改为你的密码管理系统地址',
        STORAGE_KEY: 'password_manager_token',
        AUTO_SAVE: true,
        AUTO_FILL: true,
        SHOW_NOTIFICATIONS: true,
        DETECT_PASSWORD_CHANGE: true
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

    // ========== 全局函数定义 ==========

    // 全局填充函数
    function fillPasswordFromElement(buttonElement) {
        console.log('🔐 fillPasswordFromElement 被调用', buttonElement);
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
            console.log('🔐 解析密码数据成功:', matchData);

            fillPassword(matchData);
        } catch (error) {
            console.error('❌ fillPasswordFromElement 执行失败:', error);
            showNotification('❌ 填充失败', 'error');
        }
    }

    // 更新现有密码
    async function updateExistingPassword(passwordId, newPassword) {
        console.log('🔄 updateExistingPassword 被调用', passwordId);
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

            showNotification('✅ 密码已更新，历史记录已保存', 'success');
            setTimeout(checkPasswordMatches, 1000);

            const prompt = document.querySelector('.pm-password-change-prompt');
            if (prompt) {
                prompt.remove();
            }
        } catch (error) {
            console.error('更新密码失败:', error);
            showNotification('❌ 更新密码失败', 'error');
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

    // 显示密码历史模态框
    function showPasswordHistoryModal(history, passwordId) {
        const modal = document.createElement('div');
        modal.className = 'pm-password-history-modal';
        modal.innerHTML = `
            <div class="pm-modal-overlay">
                <div class="pm-modal-content">
                    <div class="pm-modal-header">
                        <h3>📜 密码历史记录</h3>
                        <button type="button" class="pm-close-btn">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <div class="pm-modal-body">
                        ${history.length === 0 ?
                          '<p class="pm-text-center">暂无历史记录</p>' :
                          history.map((entry, index) => `
                            <div class="pm-history-item">
                                <div class="pm-history-header">
                                    <span class="pm-history-date">${new Date(entry.changedAt).toLocaleString()}</span>
                                    <button type="button" class="pm-btn pm-btn-success pm-btn-sm pm-btn-restore" data-password-id="${entry.passwordId || passwordId}" data-history-id="${entry.id}">
                                        🔄 恢复此密码
                                    </button>
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

        // -- 本地函数定义 --

        const closeModal = () => {
            modal.remove();
        };

        const toggleHistoryPassword = (button) => {
            const elementId = button.dataset.elementId;
            const password = button.dataset.password;
            const element = document.getElementById(elementId);
            const icon = button.querySelector('i');

            if (element && icon) {
                if (element.textContent === '••••••••') {
                    element.textContent = password;
                    icon.className = 'fas fa-eye-slash';
                } else {
                    element.textContent = '••••••••';
                    icon.className = 'fas fa-eye';
                }
            }
        };

        const restorePasswordHistory = async (button) => {
            const passwordIdToRestore = button.dataset.passwordId;
            const historyIdToRestore = button.dataset.historyId;

            if (!confirm('确定要恢复到这个历史密码吗？当前密码将被保存到历史记录中。')) {
                return;
            }

            try {
                await makeRequest('/api/passwords/restore', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify({ passwordId: passwordIdToRestore, historyId: historyIdToRestore })
                });

                showNotification('✅ 密码已恢复到历史版本', 'success');
                closeModal();
                setTimeout(checkPasswordMatches, 1000);
            } catch (error) {
                showNotification('❌ 恢复密码失败', 'error');
                console.error('恢复密码失败:', error);
            }
        };

        // -- 事件委托监听 --

        modal.addEventListener('click', (e) => {
            const target = e.target;

            // 检查是否点击了遮罩层或关闭按钮
            if (target.matches('.pm-modal-overlay') || target.closest('.pm-close-btn')) {
                // 确保点击的不是内容区域
                if (!target.closest('.pm-modal-content') || target.closest('.pm-close-btn')) {
                    closeModal();
                    return;
                }
            }

            // 检查是否点击了切换密码可见性按钮
            const toggleButton = target.closest('.pm-btn-toggle-history-pwd');
            if (toggleButton) {
                toggleHistoryPassword(toggleButton);
                return;
            }

            // 检查是否点击了恢复密码按钮
            const restoreButton = target.closest('.pm-btn-restore');
            if (restoreButton) {
                restorePasswordHistory(restoreButton);
                return;
            }
        });
    }

    // 主要填充函数
    function fillPassword(passwordData) {
        console.log('🔐 开始填充密码流程:', passwordData);

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

            console.log('🔐 准备填充:', {
                username: username?.substring(0, 3) + '***',
                hasPassword: !!password
            });

            // 查找字段
            const usernameFields = findAllUsernameFields();
            const passwordFields = findAllPasswordFields();

            console.log('🔍 找到字段:', {
                usernameFields: usernameFields.length,
                passwordFields: passwordFields.length
            });

            if (usernameFields.length === 0 && passwordFields.length === 0) {
                console.warn('⚠️ 未找到任何可填充的字段');
                showNotification('⚠️ 未找到可填充的字段', 'warning');

                // 显示调试信息
                const allInputs = document.querySelectorAll('input');
                console.log('🔍 页面所有输入字段:', Array.from(allInputs).map(input => ({
                    type: input.type,
                    name: input.name,
                    id: input.id,
                    className: input.className,
                    placeholder: input.placeholder,
                    visible: isElementVisible(input),
                    disabled: input.disabled,
                    readonly: input.readOnly
                })));
                return;
            }

            let filledFields = 0;

            // 填充用户名字段
            if (usernameFields.length > 0 && username) {
                console.log('🔄 开始填充用户名字段');
                usernameFields.forEach((field, index) => {
                    try {
                        console.log(`🔄 尝试填充用户名字段 ${index + 1}:`, {
                            tag: field.tagName,
                            type: field.type,
                            name: field.name,
                            id: field.id,
                            className: field.className
                        });

                        if (fillInputField(field, username, '用户名')) {
                            filledFields++;
                            console.log(`✅ 用户名字段 ${index + 1} 填充成功`);
                        } else {
                            console.log(`❌ 用户名字段 ${index + 1} 填充失败`);
                        }
                    } catch (error) {
                        console.error(`❌ 用户名字段 ${index + 1} 填充异常:`, error);
                    }
                });
            }

            // 填充密码字段
            if (passwordFields.length > 0 && password) {
                console.log('🔄 开始填充密码字段');
                passwordFields.forEach((field, index) => {
                    try {
                        console.log(`🔄 尝试填充密码字段 ${index + 1}:`, {
                            tag: field.tagName,
                            type: field.type,
                            name: field.name,
                            id: field.id,
                            className: field.className
                        });

                        if (fillInputField(field, password, '密码')) {
                            filledFields++;
                            console.log(`✅ 密码字段 ${index + 1} 填充成功`);
                        } else {
                            console.log(`❌ 密码字段 ${index + 1} 填充失败`);
                        }
                    } catch (error) {
                        console.error(`❌ 密码字段 ${index + 1} 填充异常:`, error);
                    }
                });
            }

            // 显示结果
            if (filledFields > 0) {
                showNotification(`🔐 已填充 ${filledFields} 个字段`, 'success');
                console.log(`✅ 填充完成，共填充 ${filledFields} 个字段`);
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

    // 扩展对象
    window.pmExtension = {
        fillPassword: fillPassword,

        setToken: function() {
            const token = document.getElementById('tokenInput').value.trim();
            if (token) {
                authToken = token;
                GM_setValue(CONFIG.STORAGE_KEY, token);
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
        }
    };

    // ========== 工具函数 ==========

    // 检查是否是密码管理器网站
    function checkPasswordManagerSite() {
        isPasswordManagerSite = window.location.hostname.includes('spassword.pages.dev') ||
                                 window.location.hostname.includes('localhost') ||
                                 window.location.hostname.includes('127.0.0.1');
        return isPasswordManagerSite;
    }

    // 改进的字段填充函数
    function fillInputField(field, value, fieldType) {
        if (!field || !value) {
            console.log(`❌ ${fieldType}字段或值为空`);
            return false;
        }

        try {
            // 检查字段是否可见和可编辑
            if (!isElementVisible(field)) {
                console.log(`❌ ${fieldType}字段不可见:`, field);
                return false;
            }

            if (field.disabled) {
                console.log(`❌ ${fieldType}字段被禁用:`, field);
                return false;
            }

            if (field.readOnly) {
                console.log(`❌ ${fieldType}字段为只读:`, field);
                return false;
            }

            console.log(`🔄 开始填充${fieldType}字段:`, field);

            const oldValue = field.value;

            // 聚焦字段
            field.focus();
            console.log(`📍 ${fieldType}字段已聚焦`);

            // 清空并设置值
            field.value = '';
            field.value = value;

            // 使用原生setter
            try {
                const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
                if (descriptor && descriptor.set) {
                    descriptor.set.call(field, value);
                    console.log(`🔧 ${fieldType}字段使用原生setter设置值`);
                }
            } catch (e) {
                console.log(`⚠️ ${fieldType}字段原生setter失败:`, e);
            }

            // 触发事件
            triggerInputEvents(field, value);

            // 验证值
            const finalValue = field.value;
            if (finalValue === value) {
                console.log(`✅ ${fieldType}字段值设置成功`);

                // 视觉反馈
                field.style.backgroundColor = '#dcfce7';
                field.style.borderColor = '#10b981';
                setTimeout(() => {
                    field.style.backgroundColor = '';
                    field.style.borderColor = '';
                }, 2000);

                return true;
            } else {
                console.log(`❌ ${fieldType}字段值设置失败，期望: ${value}, 实际: ${finalValue}`);
                return false;
            }

        } catch (error) {
            console.error(`❌ 填充${fieldType}字段时发生异常:`, error);
            return false;
        } finally {
            // 移除焦点
            setTimeout(() => {
                try {
                    field.blur();
                } catch (e) {
                    console.warn('移除焦点失败:', e);
                }
            }, 200);
        }
    }

    // 触发输入事件
    function triggerInputEvents(field, value) {
        console.log('🎭 触发输入事件');

        const events = [
            { type: 'focus', event: new FocusEvent('focus', { bubbles: true }) },
            { type: 'input', event: new InputEvent('input', { bubbles: true, data: value }) },
            { type: 'change', event: new Event('change', { bubbles: true }) },
            { type: 'keydown', event: new KeyboardEvent('keydown', { bubbles: true }) },
            { type: 'keyup', event: new KeyboardEvent('keyup', { bubbles: true }) }
        ];

        events.forEach(({ type, event }) => {
            try {
                field.dispatchEvent(event);
                console.log(`✅ 触发${type}事件成功`);
            } catch (e) {
                console.warn(`❌ 触发${type}事件失败:`, e);
            }
        });

        // React特殊处理
        try {
            if (field._valueTracker) {
                field._valueTracker.setValue('');
                console.log('🔧 React _valueTracker 已重置');
            }
        } catch (e) {
            console.warn('React特殊处理失败:', e);
        }
    }

    // 查找用户名字段
    function findAllUsernameFields() {
        console.log('🔍 开始查找用户名字段');

        const selectors = [
            'input[type="text"]',
            'input[type="email"]',
            'input[type="tel"]',
            'input:not([type])',
            'input[name*="user" i]',
            'input[name*="email" i]',
            'input[name*="login" i]',
            'input[name*="account" i]',
            'input[name*="username" i]',
            'input[id*="user" i]',
            'input[id*="email" i]',
            'input[id*="login" i]',
            'input[id*="account" i]',
            'input[id*="username" i]',
            'input[placeholder*="用户" i]',
            'input[placeholder*="邮箱" i]',
            'input[placeholder*="email" i]',
            'input[placeholder*="username" i]',
            'input[placeholder*="账号" i]',
            'input[placeholder*="手机" i]',
            'input[placeholder*="phone" i]',
            'input[autocomplete="username"]',
            'input[autocomplete="email"]'
        ];

        const fields = new Set();

        selectors.forEach(selector => {
            try {
                document.querySelectorAll(selector).forEach(field => {
                    if (field.type !== 'password' &&
                        field.type !== 'hidden' &&
                        field.type !== 'submit' &&
                        field.type !== 'button' &&
                        isElementVisible(field)) {
                        fields.add(field);
                    }
                });
            } catch (e) {
                console.warn(`选择器 ${selector} 失败:`, e);
            }
        });

        const fieldsArray = Array.from(fields);
        console.log(`🔍 找到 ${fieldsArray.length} 个用户名字段`);
        return fieldsArray;
    }

    // 查找密码字段
    function findAllPasswordFields() {
        console.log('🔍 开始查找密码字段');

        const fields = Array.from(document.querySelectorAll('input[type="password"]'))
            .filter(field => isElementVisible(field));

        console.log(`🔍 找到 ${fields.length} 个密码字段`);
        return fields;
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
                   !element.hidden;
        } catch (e) {
            return false;
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
            width: 56px;
            height: 56px;
            background: linear-gradient(135deg, #6366f1, #4f46e5);
            border: none;
            border-radius: 50%;
            color: white;
            font-size: 20px;
            cursor: pointer;
            box-shadow: 0 8px 20px rgba(99, 102, 241, 0.3);
            z-index: 9999;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .pm-floating-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 25px rgba(99, 102, 241, 0.4);
        }

        .pm-floating-btn.has-matches {
            background: linear-gradient(135deg, #10b981, #059669);
            animation: pulse 2s infinite;
        }

        .pm-floating-btn.multiple-matches {
            background: linear-gradient(135deg, #f59e0b, #d97706);
        }

        .pm-floating-btn .match-count {
            position: absolute;
            top: -5px;
            right: -5px;
            background: #ef4444;
            color: white;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            font-size: 12px;
            font-weight: bold;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 2px solid white;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
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

        .pm-quick-fill {
            background: linear-gradient(135deg, #10b981, #059669);
            color: white;
            border: none;
            padding: 12px 16px;
            border-radius: 10px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            width: 100%;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s ease;
        }

        .pm-quick-fill:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(16, 185, 129, 0.3);
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

        .pm-password-change-prompt {
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            z-index: 10001;
            max-width: 400px;
            width: 90%;
            background: linear-gradient(135deg, #fef3c7, #fde68a);
            border: 2px solid #f59e0b;
            border-radius: 12px;
            padding: 16px;
            color: #92400e;
        }

        .pm-password-change-prompt h4 {
            margin: 0 0 8px 0;
            color: #92400e;
            font-size: 14px;
            font-weight: 700;
        }

        .pm-password-change-prompt p {
            margin: 0 0 12px 0;
            font-size: 12px;
        }

        .pm-password-change-actions {
            display: flex;
            gap: 8px;
        }

        .pm-btn-update {
            background: #f59e0b;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 11px;
            font-weight: 600;
            flex: 1;
        }

        .pm-btn-ignore {
            background: #6b7280;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 11px;
            font-weight: 600;
            flex: 1;
        }

        .pm-btn-history-view {
            background: #3b82f6;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 11px;
            font-weight: 600;
            flex: 1;
        }

        /* 密码历史模态框样式 */
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
            /* [修正] 使用 Flexbox 将内容居中 */
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
        }

        .pm-history-date {
            font-size: 14px;
            color: #6b7280;
            font-weight: 600;
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
    `);

    // ========== 主要功能函数 ==========

    // 初始化
    async function init() {
        console.log('🔐 密码管理助手 Pro 已启动');

        checkPasswordManagerSite();

        if (authToken) {
            await verifyAuth();
        }

        createFloatingButton();
        detectLoginForms();
        observeFormChanges();
        registerMenuCommands();

        if (isPasswordManagerSite) {
            monitorPasswordManagerAuth();
        } else if (isAuthenticated) {
            checkPasswordMatches();
        }
    }

    // 检查密码匹配
    async function checkPasswordMatches() {
        try {
            const matches = await getPasswordMatches();
            cachedMatches = matches;
            updateFloatingButton(matches);
        } catch (error) {
            console.error('检查密码匹配失败:', error);
        }
    }

    // 更新浮动按钮
    function updateFloatingButton(matches) {
        const floatingBtn = document.querySelector('.pm-floating-btn');
        if (!floatingBtn) return;

        floatingBtn.classList.remove('has-matches', 'multiple-matches');
        const existingCount = floatingBtn.querySelector('.match-count');
        if (existingCount) existingCount.remove();

        if (matches.length > 0) {
            if (matches.length === 1) {
                floatingBtn.classList.add('has-matches');
                floatingBtn.title = `找到 1 个匹配的账户`;
            } else {
                floatingBtn.classList.add('multiple-matches');
                floatingBtn.title = `找到 ${matches.length} 个匹配的账户`;

                const countBadge = document.createElement('div');
                countBadge.className = 'match-count';
                countBadge.textContent = matches.length > 9 ? '9+' : matches.length;
                floatingBtn.appendChild(countBadge);
            }
        } else {
            floatingBtn.title = '密码管理助手 Pro';
        }
    }

    // 验证登录状态
    async function verifyAuth() {
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
                if (!isPasswordManagerSite) {
                    showNotification('🔐 密码管理助手已连接', 'success');
                    setTimeout(checkPasswordMatches, 1000);
                }
            } else {
                authToken = '';
                GM_setValue(CONFIG.STORAGE_KEY, '');
                isAuthenticated = false;
            }
        } catch (error) {
            console.error('验证失败:', error);
            isAuthenticated = false;
        }
    }

    // 创建浮动按钮
    function createFloatingButton() {
        const btn = document.createElement('button');
        btn.className = 'pm-floating-btn';
        btn.innerHTML = '🔐';
        btn.title = '密码管理助手 Pro';
        btn.onclick = togglePasswordManager;
        document.body.appendChild(btn);
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
                    </div>
                `;
            } else {
                const matches = cachedMatches.length > 0 ? cachedMatches : await getPasswordMatches();

                popup.innerHTML = `
                    <div class="pm-popup-header">
                        <div class="pm-popup-title">
                            <span>🔐</span>
                            <span>密码管理助手 Pro</span>
                        </div>
                        ${matches.length > 0 ? renderMatchStats(matches) : ''}
                    </div>
                    <div class="pm-popup-content">
                        ${matches.length > 0 ? renderPasswordMatches(matches) : renderNoMatches()}
                        ${renderDetectedForms()}
                    </div>
                `;
            }
        }

        document.body.appendChild(popup);
        passwordManagerUI = popup;

        // 使用事件委托来处理所有点击事件
        popup.addEventListener('click', (e) => {
            const target = e.target;
            const fillButton = target.closest('.pm-btn-fill');
            const historyButton = target.closest('.pm-btn-history');
            const quickFillButton = target.closest('.pm-quick-fill');
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
            } else if (quickFillButton) {
                e.preventDefault();
                const matchData = JSON.parse(quickFillButton.dataset.match);
                fillPassword(matchData);
            } else if (loginBtn) {
                 window.open(CONFIG.API_BASE, '_blank');
            } else if (tokenDisplay) {
                window.pmExtension.copyToken(authToken);
            } else if (actionButton) {
                const action = actionButton.dataset.action;
                if(action === 'refresh-auth') window.pmExtension.refreshAuth();
                else if(action === 'set-token') window.pmExtension.setToken();
                else if(action === 'highlight-forms') window.pmExtension.highlightForms();
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

    // 获取密码匹配
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

        // 添加匹配类型说明
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

        if (matches.length === 1) {
            const match = matches[0];
            content += `
                <button class="pm-quick-fill" data-match='${escapeHtml(JSON.stringify(match))}'>
                    <span>⚡</span>
                    <span>快速填充：${escapeHtml(match.username)}</span>
                </button>
            `;
        } else {
            content += `
                <div style="margin-bottom: 16px;">
                    <h4 style="margin: 0 0 12px 0; color: #1f2937; font-size: 14px;">
                        🔐 选择要填充的账户 (${matches.length} 个)
                    </h4>
                </div>
            `;
        }

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

    // 渲染无匹配
    function renderNoMatches() {
        return `
            <div class="pm-no-matches">
                <p>🔍 未找到匹配的账户</p>
                <p style="font-size: 12px; margin-top: 4px;">登录后将自动保存新账户</p>
            </div>
        `;
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

    // 检测登录表单
    function detectLoginForms() {
        const forms = document.querySelectorAll('form');
        detectedForms = [];

        forms.forEach(form => {
            const usernameField = form.querySelector('input[type="text"], input[type="email"], input[name*="user"], input[name*="email"], input[name*="login"], input[id*="user"], input[id*="email"], input[id*="login"]');
            const passwordField = form.querySelector('input[type="password"]');

            if (usernameField && passwordField) {
                if (isElementVisible(usernameField) && isElementVisible(passwordField)) {
                    detectedForms.push(form);

                    if (CONFIG.AUTO_SAVE && !isPasswordManagerSite) {
                        form.addEventListener('submit', handleFormSubmit);
                    }
                }
            }
        });

        if (detectedForms.length > 0 && !isPasswordManagerSite) {
            console.log(`🔍 检测到 ${detectedForms.length} 个登录表单`);
        }
    }

    // 处理表单提交 - 修正版本，支持密码变更检测
    async function handleFormSubmit(e) {
        if (!isAuthenticated || isPasswordManagerSite) return;

        const form = e.target;

        // 启发式检测：如果表单中有多个可见的密码字段，则判断为注册或修改密码表单，不执行自动保存
        const passwordFields = form.querySelectorAll('input[type="password"]');
        const visiblePasswordFields = Array.from(passwordFields).filter(field => isElementVisible(field));

        if (visiblePasswordFields.length > 1) {
            console.log('📝 检测到注册/修改密码表单（存在多个密码框），本次提交将不自动保存密码。');
            return;
        }

        const usernameField = form.querySelector('input[type="text"], input[type="email"], input[name*="user"], input[name*="email"], input[name*="login"], input[id*="user"], input[id*="email"], input[id*="login"]');
        const passwordField = visiblePasswordFields[0];

        if (usernameField && passwordField && usernameField.value && passwordField.value) {
            const submitData = {
                url: window.location.href,
                username: usernameField.value,
                password: passwordField.value
            };

            // 记录提交数据，用于后续密码变更检测
            lastSubmittedData = submitData;

            setTimeout(async () => {
                try {
                    const response = await makeRequest('/api/detect-login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + authToken
                        },
                        body: JSON.stringify(submitData)
                    });

                    if (response.exists && response.identical) {
                        showNotification('🔐 账户已存在且密码相同', 'info');
                    } else if (response.exists && response.passwordChanged && response.shouldUpdate) {
                        // 修正：相同账号不同密码，显示更新提示而不是保存为新账号
                        showPasswordChangePrompt(response.existing, submitData.password);
                    } else if (response.saved) {
                        showNotification('✅ 新账户已自动保存', 'success');
                        setTimeout(checkPasswordMatches, 1000);
                    }
                } catch (error) {
                    console.error('保存密码失败:', error);
                }
            }, 1000);
        }
    }

    // 显示密码变更提示 - 修正版本，支持查看历史记录
    function showPasswordChangePrompt(existingPassword, newPassword) {
        const existingPrompt = document.querySelector('.pm-password-change-prompt');
        if (existingPrompt) {
            existingPrompt.remove();
        }

        const prompt = document.createElement('div');
        prompt.className = 'pm-password-change-prompt';

        prompt.innerHTML = `
            <h4>🔄 检测到相同账号的密码变更</h4>
            <p>网站：${escapeHtml(existingPassword.siteName)}<br>
               用户：${escapeHtml(existingPassword.username)}</p>
            <p style="font-size: 11px;"><strong>注意：</strong>相同账号不会被保存为新账户，只能选择更新现有账户的密码。</p>
            <div class="pm-password-change-actions">
                <button class="pm-btn-update">
                    ✅ 更新密码
                </button>
                <button class="pm-btn-history-view">
                    📜 查看历史
                </button>
                <button class="pm-btn-ignore">
                    ❌ 忽略
                </button>
            </div>
        `;

        document.body.appendChild(prompt);

        // 为提示框添加事件监听
        prompt.addEventListener('click', (e) => {
            if (e.target.closest('.pm-btn-update')) {
                updateExistingPassword(existingPassword.id, newPassword);
            } else if (e.target.closest('.pm-btn-history-view')) {
                viewPasswordHistory(existingPassword.id);
                prompt.remove();
            } else if (e.target.closest('.pm-btn-ignore')) {
                prompt.remove();
            }
        });

        setTimeout(() => {
            if (document.body.contains(prompt)) {
                prompt.remove();
            }
        }, 15000); // 延长显示时间到15秒
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
                                node.querySelector && (node.querySelector('form') || node.querySelector('input[type="password"]'))) {
                                shouldRedetect = true;
                            }
                        }
                    });
                }
            });

            if (shouldRedetect) {
                setTimeout(() => {
                    detectLoginForms();
                    if (isAuthenticated && !isPasswordManagerSite) {
                        checkPasswordMatches();
                    }
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
            if (isAuthenticated && !isPasswordManagerSite) {
                checkPasswordMatches();
            }
            showNotification('🔍 重新检测完成', 'info');
        });

        GM_registerMenuCommand('⚙️ 设置令牌', () => {
            const token = prompt('请输入密码管理器的登录令牌（可在密码管理器中获取）:');
            if (token) {
                authToken = token;
                GM_setValue(CONFIG.STORAGE_KEY, token);
                verifyAuth();
            }
        });

        GM_registerMenuCommand('🚪 退出登录', () => {
            authToken = '';
            GM_setValue(CONFIG.STORAGE_KEY, '');
            isAuthenticated = false;
            cachedMatches = [];
            updateFloatingButton([]);
            showNotification('👋 已退出登录', 'info');
        });

        GM_registerMenuCommand('🧪 测试填充功能', () => {
            const testData = {
                id: 'test',
                username: 'test@example.com',
                password: 'testpassword123'
            };
            fillPassword(testData);
        });

        GM_registerMenuCommand('📜 密码变更检测开关', () => {
            CONFIG.DETECT_PASSWORD_CHANGE = !CONFIG.DETECT_PASSWORD_CHANGE;
            showNotification(`密码变更检测已${CONFIG.DETECT_PASSWORD_CHANGE ? '开启' : '关闭'}`, 'info');
        });

        GM_registerMenuCommand('🔍 调试信息', () => {
            console.log('=== 密码管理助手 Pro 调试信息 ===');
            console.log('认证状态:', isAuthenticated);
            console.log('当前用户:', currentUser);
            console.log('检测到的表单:', detectedForms);
            console.log('缓存的匹配:', cachedMatches);
            console.log('页面URL:', window.location.href);
            console.log('最后提交数据:', lastSubmittedData);
            console.log('配置信息:', CONFIG);
            console.log('pmExtension 对象:', window.pmExtension);

            const allInputs = document.querySelectorAll('input');
            console.log('页面所有输入字段:', Array.from(allInputs).map(input => ({
                type: input.type,
                name: input.name,
                id: input.id,
                placeholder: input.placeholder,
                visible: isElementVisible(input)
            })));

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
