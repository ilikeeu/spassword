// 增强版密码管理器 - Cloudflare Workers + KV + OAuth
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    
    // 设置CORS头
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
    
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    
    try {
      // 路由处理
      if (path === '/' || path === '/index.html') {
        return new Response(getHTML(), {
          headers: { 'Content-Type': 'text/html', ...corsHeaders }
        });
      }
      
      if (path === '/api/oauth/login') {
        return handleOAuthLogin(request, env, corsHeaders);
      }
      
      if (path === '/api/oauth/callback') {
        return handleOAuthCallback(request, env, corsHeaders);
      }
      
      if (path === '/api/auth/verify') {
        return handleAuthVerify(request, env, corsHeaders);
      }
      
      if (path === '/api/auth/logout') {
        return handleLogout(request, env, corsHeaders);
      }
      
      if (path.startsWith('/api/passwords')) {
        return handlePasswords(request, env, corsHeaders);
      }
      
      if (path.startsWith('/api/categories')) {
        return handleCategories(request, env, corsHeaders);
      }
      
      if (path === '/api/generate-password') {
        return handleGeneratePassword(request, env, corsHeaders);
      }
      
      if (path === '/api/export') {
        return handleExport(request, env, corsHeaders);
      }
      
      if (path === '/api/import') {
        return handleImport(request, env, corsHeaders);
      }
      
      return new Response('Not Found', { status: 404, headers: corsHeaders });
    } catch (error) {
      console.error('Error:', error);
      return new Response('Internal Server Error', { 
        status: 500, 
        headers: corsHeaders 
      });
    }
  }
};

// OAuth登录处理
async function handleOAuthLogin(request, env, corsHeaders) {
  const state = generateRandomString(32);
  const authUrl = new URL(`${env.OAUTH_BASE_URL}/oauth/authorize`);
  
  authUrl.searchParams.set('client_id', env.OAUTH_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', env.OAUTH_REDIRECT_URI);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('state', state);
  
  // 存储state用于验证
  await env.PASSWORD_KV.put(`oauth_state_${state}`, 'valid', { expirationTtl: 600 });
  
  return new Response(JSON.stringify({ authUrl: authUrl.toString() }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

// OAuth回调处理
async function handleOAuthCallback(request, env, corsHeaders) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');
  
  if (error) {
    return new Response(`OAuth Error: ${error}`, { status: 400, headers: corsHeaders });
  }
  
  if (!code || !state) {
    return new Response('Missing code or state', { status: 400, headers: corsHeaders });
  }
  
  // 验证state
  const storedState = await env.PASSWORD_KV.get(`oauth_state_${state}`);
  if (!storedState) {
    return new Response('Invalid state', { status: 400, headers: corsHeaders });
  }
  
  // 清理state
  await env.PASSWORD_KV.delete(`oauth_state_${state}`);
  
  try {
    // 交换访问令牌
    const tokenResponse = await fetch(`${env.OAUTH_BASE_URL}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${btoa(`${env.OAUTH_CLIENT_ID}:${env.OAUTH_CLIENT_SECRET}`)}`
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: env.OAUTH_REDIRECT_URI
      })
    });
    
    const tokenData = await tokenResponse.json();
    
    if (!tokenResponse.ok) {
      throw new Error(tokenData.error || 'Token exchange failed');
    }
    
    // 获取用户信息
    const userResponse = await fetch(`${env.OAUTH_BASE_URL}/oauth/userinfo`, {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`
      }
    });
    
    const userData = await userResponse.json();
    
    if (!userResponse.ok) {
      throw new Error('Failed to get user info');
    }
    
    // 创建会话
    const sessionToken = generateRandomString(64);
    const userSession = {
      userId: userData.sub || userData.id,
      email: userData.email,
      name: userData.name,
      avatar: userData.picture,
      loginAt: new Date().toISOString()
    };
    
    await env.PASSWORD_KV.put(`session_${sessionToken}`, JSON.stringify(userSession), { 
      expirationTtl: 86400 * 7 // 7天
    });
    
    // 重定向到主页面并设置token
    return new Response(`
      <html>
        <script>
          localStorage.setItem('authToken', '${sessionToken}');
          window.location.href = '/';
        </script>
      </html>
    `, {
      headers: { 'Content-Type': 'text/html', ...corsHeaders }
    });
    
  } catch (error) {
    console.error('OAuth callback error:', error);
    return new Response(`Authentication failed: ${error.message}`, { 
      status: 500, 
      headers: corsHeaders 
    });
  }
}

// 验证登录状态
async function handleAuthVerify(request, env, corsHeaders) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return new Response(JSON.stringify({ authenticated: false }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  const session = await env.PASSWORD_KV.get(`session_${token}`);
  
  if (session) {
    return new Response(JSON.stringify({ 
      authenticated: true, 
      user: JSON.parse(session) 
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  return new Response(JSON.stringify({ authenticated: false }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

// 登出处理
async function handleLogout(request, env, corsHeaders) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  
  if (token) {
    await env.PASSWORD_KV.delete(`session_${token}`);
  }
  
  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

// 密码条目处理（增强版）
async function handlePasswords(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  const url = new URL(request.url);
  const id = url.pathname.split('/').pop();
  const userId = session.userId;
  
  switch (request.method) {
    case 'GET':
      if (id && id !== 'passwords') {
        // 获取单个密码
        const password = await env.PASSWORD_KV.get(`password_${userId}_${id}`);
        if (password) {
          return new Response(password, {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
        return new Response(JSON.stringify({ error: '未找到' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      } else {
        // 获取所有密码列表
        const list = await env.PASSWORD_KV.list({ prefix: `password_${userId}_` });
        const passwords = [];
        
        for (const key of list.keys) {
          const data = await env.PASSWORD_KV.get(key.name);
          if (data) {
            const passwordData = JSON.parse(data);
            // 不返回实际密码，只返回元数据
            passwords.push({
              ...passwordData,
              password: '••••••••'
            });
          }
        }
        
        // 按分类和名称排序
        passwords.sort((a, b) => {
          if (a.category !== b.category) {
            return (a.category || '其他').localeCompare(b.category || '其他');
          }
          return a.siteName.localeCompare(b.siteName);
        });
        
        return new Response(JSON.stringify(passwords), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
    case 'POST':
      const newPassword = await request.json();
      newPassword.id = generateId();
      newPassword.userId = userId;
      newPassword.createdAt = new Date().toISOString();
      newPassword.updatedAt = newPassword.createdAt;
      
      // 加密密码
      newPassword.password = await encryptPassword(newPassword.password, userId);
      
      await env.PASSWORD_KV.put(`password_${userId}_${newPassword.id}`, JSON.stringify(newPassword));
      
      // 返回时不包含实际密码
      const responseData = { ...newPassword, password: '••••••••' };
      
      return new Response(JSON.stringify(responseData), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
      
    case 'PUT':
      if (!id || id === 'passwords') {
        return new Response(JSON.stringify({ error: '缺少ID' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      const existingPassword = await env.PASSWORD_KV.get(`password_${userId}_${id}`);
      if (!existingPassword) {
        return new Response(JSON.stringify({ error: '未找到' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      const updateData = await request.json();
      const updatedPassword = { ...JSON.parse(existingPassword), ...updateData };
      updatedPassword.updatedAt = new Date().toISOString();
      
      // 如果更新了密码，重新加密
      if (updateData.password) {
        updatedPassword.password = await encryptPassword(updateData.password, userId);
      }
      
      await env.PASSWORD_KV.put(`password_${userId}_${id}`, JSON.stringify(updatedPassword));
      
      // 返回时不包含实际密码
      const updatedResponseData = { ...updatedPassword, password: '••••••••' };
      
      return new Response(JSON.stringify(updatedResponseData), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
      
    case 'DELETE':
      if (!id || id === 'passwords') {
        return new Response(JSON.stringify({ error: '缺少ID' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      await env.PASSWORD_KV.delete(`password_${userId}_${id}`);
      
      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
      
    default:
      return new Response('Method not allowed', { 
        status: 405, 
        headers: corsHeaders 
      });
  }
}

// 获取实际密码（单独接口）
async function getActualPassword(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  const url = new URL(request.url);
  const id = url.pathname.split('/').pop();
  const userId = session.userId;
  
  const password = await env.PASSWORD_KV.get(`password_${userId}_${id}`);
  if (!password) {
    return new Response(JSON.stringify({ error: '未找到' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  const passwordData = JSON.parse(password);
  const decryptedPassword = await decryptPassword(passwordData.password, userId);
  
  return new Response(JSON.stringify({ password: decryptedPassword }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

// 分类管理
async function handleCategories(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  const userId = session.userId;
  
  if (request.method === 'GET') {
    const categories = await env.PASSWORD_KV.get(`categories_${userId}`);
    return new Response(categories || JSON.stringify([
      '社交媒体', '邮箱', '银行金融', '工作', '购物', '娱乐', '其他'
    ]), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  if (request.method === 'POST') {
    const { categories } = await request.json();
    await env.PASSWORD_KV.put(`categories_${userId}`, JSON.stringify(categories));
    
    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  return new Response('Method not allowed', { status: 405, headers: corsHeaders });
}

// 密码生成器
async function handleGeneratePassword(request, env, corsHeaders) {
  const { length = 16, includeUppercase = true, includeLowercase = true, includeNumbers = true, includeSymbols = true } = await request.json();
  
  let charset = '';
  if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (includeNumbers) charset += '0123456789';
  if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  if (charset === '') {
    return new Response(JSON.stringify({ error: '至少选择一种字符类型' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  let password = '';
  const randomValues = crypto.getRandomValues(new Uint8Array(length));
  
  for (let i = 0; i < length; i++) {
    password += charset[randomValues[i] % charset.length];
  }
  
  return new Response(JSON.stringify({ password }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

// 数据导出
async function handleExport(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  const userId = session.userId;
  const list = await env.PASSWORD_KV.list({ prefix: `password_${userId}_` });
  const passwords = [];
  
  for (const key of list.keys) {
    const data = await env.PASSWORD_KV.get(key.name);
    if (data) {
      const passwordData = JSON.parse(data);
      // 解密密码用于导出
      passwordData.password = await decryptPassword(passwordData.password, userId);
      passwords.push(passwordData);
    }
  }
  
  const exportData = {
    exportDate: new Date().toISOString(),
    version: '1.0',
    passwords: passwords
  };
  
  return new Response(JSON.stringify(exportData, null, 2), {
    headers: { 
      'Content-Type': 'application/json',
      'Content-Disposition': 'attachment; filename="passwords-export.json"',
      ...corsHeaders 
    }
  });
}

// 数据导入
async function handleImport(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  const userId = session.userId;
  const importData = await request.json();
  
  let imported = 0;
  let errors = 0;
  
  for (const passwordData of importData.passwords || []) {
    try {
      const newPassword = {
        ...passwordData,
        id: generateId(),
        userId: userId,
        importedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      
      // 加密密码
      newPassword.password = await encryptPassword(passwordData.password, userId);
      
      await env.PASSWORD_KV.put(`password_${userId}_${newPassword.id}`, JSON.stringify(newPassword));
      imported++;
    } catch (error) {
      errors++;
    }
  }
  
  return new Response(JSON.stringify({ imported, errors }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

// 工具函数
async function verifySession(request, env) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return null;
  
  const session = await env.PASSWORD_KV.get(`session_${token}`);
  return session ? JSON.parse(session) : null;
}

async function encryptPassword(password, userId) {
  // 简单的加密实现，实际应用中应使用更强的加密
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(userId.slice(0, 32).padEnd(32, '0')),
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );
  
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(password)
  );
  
  return btoa(String.fromCharCode(...iv) + String.fromCharCode(...new Uint8Array(encrypted)));
}

async function decryptPassword(encryptedPassword, userId) {
  try {
    const data = atob(encryptedPassword);
    const iv = new Uint8Array(data.slice(0, 12).split('').map(c => c.charCodeAt(0)));
    const encrypted = new Uint8Array(data.slice(12).split('').map(c => c.charCodeAt(0)));
    
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(userId.slice(0, 32).padEnd(32, '0')),
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encrypted
    );
    
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    return encryptedPassword; // 如果解密失败，返回原文（向后兼容）
  }
}

function generateRandomString(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const randomValues = crypto.getRandomValues(new Uint8Array(length));
  
  for (let i = 0; i < length; i++) {
    result += chars[randomValues[i] % chars.length];
  }
  
  return result;
}

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

// HTML界面（增强版）
function getHTML() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>密码管理器 Pro</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        /* 登录界面 */
        .auth-container {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        
        .auth-card {
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 400px;
            width: 100%;
        }
        
        .auth-card h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        
        .auth-card p {
            color: #666;
            margin-bottom: 30px;
        }
        
        .oauth-button {
            background: #4285f4;
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 50px;
            font-size: 16px;
            cursor: pointer;
            transition: all 0.3s ease;
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        
        .oauth-button:hover {
            background: #3367d6;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        /* 主界面 */
        .header {
            background: white;
            padding: 20px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .user-avatar {
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: #667eea;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }
        
        .user-details h3 {
            color: #333;
            margin-bottom: 5px;
        }
        
        .user-details p {
            color: #666;
            font-size: 14px;
        }
        
        .header-actions {
            display: flex;
            gap: 10px;
        }
        
        /* 工具栏 */
        .toolbar {
            background: white;
            padding: 20px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: center;
        }
        
        .search-box {
            flex: 1;
            min-width: 300px;
            position: relative;
        }
        
        .search-box input {
            width: 100%;
            padding: 12px 15px 12px 45px;
            border: 2px solid #e0e0e0;
            border-radius: 25px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }
        
        .search-box input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .search-box i {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #999;
        }
        
        .filter-select {
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 25px;
            font-size: 16px;
            background: white;
            cursor: pointer;
        }
        
        /* 按钮样式 */
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 25px;
            font-size: 16px;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            text-decoration: none;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5a67d8;
            transform: translateY(-2px);
        }
        
        .btn-secondary {
            background: #e2e8f0;
            color: #4a5568;
        }
        
        .btn-secondary:hover {
            background: #cbd5e0;
        }
        
        .btn-danger {
            background: #e53e3e;
            color: white;
        }
        
        .btn-danger:hover {
            background: #c53030;
        }
        
        .btn-success {
            background: #38a169;
            color: white;
        }
        
        .btn-success:hover {
            background: #2f855a;
        }
        
        /* 密码卡片 */
        .passwords-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
        }
        
        .password-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            position: relative;
        }
        
        .password-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }
        
        .password-header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .site-icon {
            width: 50px;
            height: 50px;
            border-radius: 10px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 20px;
        }
        
        .password-info h3 {
            color: #333;
            margin-bottom: 5px;
            font-size: 18px;
        }
        
        .password-info .category {
            background: #e2e8f0;
            color: #4a5568;
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 12px;
            display: inline-block;
        }
        
        .password-field {
            margin: 15px 0;
        }
        
        .password-field label {
            display: block;
            color: #666;
            font-size: 14px;
            margin-bottom: 5px;
        }
        
        .password-field .value {
            color: #333;
            font-size: 16px;
            word-break: break-all;
        }
        
        .password-actions {
            display: flex;
            gap: 10px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .password-actions .btn {
            flex: 1;
            min-width: 100px;
            padding: 8px 16px;
            font-size: 14px;
        }
        
        /* 模态框 */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            backdrop-filter: blur(5px);
        }
        
        .modal.show {
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .modal-content {
            background: white;
            border-radius: 20px;
            padding: 30px;
            max-width: 500px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
        }
        
        .modal-header h2 {
            color: #333;
        }
        
        .close-btn {
            background: none;
            border: none;
            font-size: 24px;
            cursor: pointer;
            color: #999;
        }
        
        /* 表单样式 */
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            color: #333;
            margin-bottom: 8px;
            font-weight: 500;
        }
        
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }
        
        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .password-input-group {
            position: relative;
        }
        
        .password-toggle {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            cursor: pointer;
            color: #999;
        }
        
        .password-generator {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        
        .generator-options {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: auto;
        }
        
        /* 响应式设计 */
        @media (max-width: 768px) {
            .container { padding: 10px; }
            
            .header {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }
            
            .toolbar {
                flex-direction: column;
                align-items: stretch;
            }
            
            .search-box {
                min-width: auto;
            }
            
            .passwords-grid {
                grid-template-columns: 1fr;
            }
            
            .password-actions {
                flex-direction: column;
            }
        }
        
        .hidden { display: none !important; }
        
        /* 加载动画 */
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        /* 通知样式 */
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: #38a169;
            color: white;
            padding: 15px 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            z-index: 1001;
            transform: translateX(400px);
            transition: transform 0.3s ease;
        }
        
        .notification.show {
            transform: translateX(0);
        }
        
        .notification.error {
            background: #e53e3e;
        }
    </style>
</head>
<body>
    <!-- 登录界面 -->
    <div id="authContainer" class="auth-container">
        <div class="auth-card">
            <i class="fas fa-shield-alt" style="font-size: 48px; color: #667eea; margin-bottom: 20px;"></i>
            <h1>密码管理器 Pro</h1>
            <p>安全、便捷的密码管理解决方案</p>
            <button id="oauthLoginBtn" class="oauth-button">
                <i class="fab fa-google"></i>
                使用 OAuth 登录
            </button>
        </div>
    </div>

    <!-- 主界面 -->
    <div id="mainContainer" class="container hidden">
        <!-- 头部 -->
        <div class="header">
            <div class="user-info">
                <div class="user-avatar" id="userAvatar">U</div>
                <div class="user-details">
                    <h3 id="userName">用户名</h3>
                    <p id="userEmail">user@example.com</p>
                </div>
            </div>
            <div class="header-actions">
                <button class="btn btn-secondary" onclick="exportData()">
                    <i class="fas fa-download"></i> 导出
                </button>
                <button class="btn btn-secondary" onclick="showImportModal()">
                    <i class="fas fa-upload"></i> 导入
                </button>
                <button class="btn btn-danger" onclick="logout()">
                    <i class="fas fa-sign-out-alt"></i> 登出
                </button>
            </div>
        </div>

        <!-- 工具栏 -->
        <div class="toolbar">
            <div class="search-box">
                <i class="fas fa-search"></i>
                <input type="text" id="searchInput" placeholder="搜索密码...">
            </div>
            <select id="categoryFilter" class="filter-select">
                <option value="">所有分类</option>
            </select>
            <button class="btn btn-primary" onclick="showAddModal()">
                <i class="fas fa-plus"></i> 添加密码
            </button>
        </div>

        <!-- 密码列表 -->
        <div id="passwordsGrid" class="passwords-grid">
            <!-- 密码卡片将在这里动态生成 -->
        </div>
    </div>

    <!-- 添加/编辑密码模态框 -->
    <div id="passwordModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalTitle">添加密码</h2>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <form id="passwordForm">
                <div class="form-group">
                    <label for="siteName">网站名称 *</label>
                    <input type="text" id="siteName" required>
                </div>
                <div class="form-group">
                    <label for="username">用户名/邮箱 *</label>
                    <input type="text" id="username" required>
                </div>
                <div class="form-group">
                    <label for="password">密码 *</label>
                    <div class="password-input-group">
                        <input type="password" id="password" required>
                        <button type="button" class="password-toggle" onclick="togglePasswordVisibility('password')">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </div>
                <div class="password-generator">
                    <h4>密码生成器</h4>
                    <div class="generator-options">
                        <div class="form-group">
                            <label for="passwordLength">长度</label>
                            <input type="range" id="passwordLength" min="8" max="32" value="16">
                            <span id="lengthValue">16</span>
                        </div>
                        <div class="checkbox-group">
                            <input type="checkbox" id="includeUppercase" checked>
                            <label for="includeUppercase">大写字母</label>
                        </div>
                        <div class="checkbox-group">
                            <input type="checkbox" id="includeLowercase" checked>
                            <label for="includeLowercase">小写字母</label>
                        </div>
                        <div class="checkbox-group">
                            <input type="checkbox" id="includeNumbers" checked>
                            <label for="includeNumbers">数字</label>
                        </div>
                        <div class="checkbox-group">
                            <input type="checkbox" id="includeSymbols">
                            <label for="includeSymbols">符号</label>
                        </div>
                    </div>
                    <button type="button" class="btn btn-secondary" onclick="generatePassword()">
                        <i class="fas fa-random"></i> 生成密码
                    </button>
                </div>
                <div class="form-group">
                    <label for="category">分类</label>
                    <select id="category">
                        <option value="">选择分类</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="url">网站URL</label>
                    <input type="url" id="url">
                </div>
                <div class="form-group">
                    <label for="notes">备注</label>
                    <textarea id="notes" rows="3"></textarea>
                </div>
                <div style="display: flex; gap: 15px; margin-top: 25px;">
                    <button type="submit" class="btn btn-primary" style="flex: 1;">
                        <i class="fas fa-save"></i> 保存
                    </button>
                    <button type="button" class="btn btn-secondary" onclick="closeModal()">
                        取消
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- 导入模态框 -->
    <div id="importModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>导入密码</h2>
                <button class="close-btn" onclick="closeImportModal()">&times;</button>
            </div>
            <div class="form-group">
                <label for="importFile">选择JSON文件</label>
                <input type="file" id="importFile" accept=".json">
            </div>
            <div style="display: flex; gap: 15px; margin-top: 25px;">
                <button class="btn btn-primary" onclick="importData()" style="flex: 1;">
                    <i class="fas fa-upload"></i> 导入
                </button>
                <button class="btn btn-secondary" onclick="closeImportModal()">
                    取消
                </button>
            </div>
        </div>
    </div>

    <script>
        let authToken = localStorage.getItem('authToken');
        let currentUser = null;
        let passwords = [];
        let categories = [];
        let editingPasswordId = null;

        // 初始化
        document.addEventListener('DOMContentLoaded', function() {
            if (authToken) {
                verifyAuth();
            } else {
                showAuthContainer();
            }
            
            // 搜索功能
            document.getElementById('searchInput').addEventListener('input', filterPasswords);
            document.getElementById('categoryFilter').addEventListener('change', filterPasswords);
            
            // 密码长度滑块
            document.getElementById('passwordLength').addEventListener('input', function() {
                document.getElementById('lengthValue').textContent = this.value;
            });
            
            // 表单提交
            document.getElementById('passwordForm').addEventListener('submit', handlePasswordSubmit);
        });

        // OAuth登录
        document.getElementById('oauthLoginBtn').addEventListener('click', async function() {
            try {
                this.innerHTML = '<div class="loading"></div> 正在跳转...';
                this.disabled = true;
                
                const response = await fetch('/api/oauth/login', {
                    method: 'GET'
                });
                
                const data = await response.json();
                window.location.href = data.authUrl;
            } catch (error) {
                showNotification('登录失败', 'error');
                this.innerHTML = '<i class="fab fa-google"></i> 使用 OAuth 登录';
                this.disabled = false;
            }
        });

        // 验证登录状态
        async function verifyAuth() {
            try {
                const response = await fetch('/api/auth/verify', {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                const data = await response.json();
                
                if (data.authenticated) {
                    currentUser = data.user;
                    showMainContainer();
                    loadData();
                } else {
                    localStorage.removeItem('authToken');
                    authToken = null;
                    showAuthContainer();
                }
            } catch (error) {
                console.error('Auth verification failed:', error);
                showAuthContainer();
            }
        }

        // 显示界面
        function showAuthContainer() {
            document.getElementById('authContainer').classList.remove('hidden');
            document.getElementById('mainContainer').classList.add('hidden');
        }

        function showMainContainer() {
            document.getElementById('authContainer').classList.add('hidden');
            document.getElementById('mainContainer').classList.remove('hidden');
            
            // 更新用户信息
            if (currentUser) {
                document.getElementById('userName').textContent = currentUser.name || '用户';
                document.getElementById('userEmail').textContent = currentUser.email || '';
                
                const avatar = document.getElementById('userAvatar');
                if (currentUser.avatar) {
                    avatar.innerHTML = \`<img src="\${currentUser.avatar}" style="width: 100%; height: 100%; border-radius: 50%;">\`;
                } else {
                    avatar.textContent = (currentUser.name || 'U').charAt(0).toUpperCase();
                }
            }
        }

        // 加载数据
        async function loadData() {
            await Promise.all([
                loadPasswords(),
                loadCategories()
            ]);
        }

        // 加载密码列表
        async function loadPasswords() {
            try {
                const response = await fetch('/api/passwords', {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                passwords = await response.json();
                renderPasswords();
            } catch (error) {
                console.error('Failed to load passwords:', error);
                showNotification('加载密码失败', 'error');
            }
        }

        // 加载分类
        async function loadCategories() {
            try {
                const response = await fetch('/api/categories', {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                categories = await response.json();
                updateCategorySelects();
            } catch (error) {
                console.error('Failed to load categories:', error);
            }
        }

        // 更新分类选择器
        function updateCategorySelects() {
            const categoryFilter = document.getElementById('categoryFilter');
            const categorySelect = document.getElementById('category');
            
            // 清空现有选项
            categoryFilter.innerHTML = '<option value="">所有分类</option>';
            categorySelect.innerHTML = '<option value="">选择分类</option>';
            
            categories.forEach(category => {
                categoryFilter.innerHTML += \`<option value="\${category}">\${category}</option>\`;
                categorySelect.innerHTML += \`<option value="\${category}">\${category}</option>\`;
            });
        }

        // 渲染密码列表
        function renderPasswords(filteredPasswords = passwords) {
            const grid = document.getElementById('passwordsGrid');
            
            if (filteredPasswords.length === 0) {
                grid.innerHTML = \`
                    <div style="grid-column: 1 / -1; text-align: center; padding: 60px 20px; color: #666;">
                        <i class="fas fa-key" style="font-size: 48px; margin-bottom: 20px; opacity: 0.5;"></i>
                        <h3>暂无密码</h3>
                        <p>点击"添加密码"开始管理您的密码</p>
                    </div>
                \`;
                return;
            }
            
            grid.innerHTML = filteredPasswords.map(password => \`
                <div class="password-card">
                    <div class="password-header">
                        <div class="site-icon">
                            <i class="fas fa-globe"></i>
                        </div>
                        <div class="password-info">
                            <h3>\${password.siteName}</h3>
                            \${password.category ? \`<span class="category">\${password.category}</span>\` : ''}
                        </div>
                    </div>
                    
                    <div class="password-field">
                        <label>用户名</label>
                        <div class="value">\${password.username}</div>
                    </div>
                    
                    <div class="password-field">
                        <label>密码</label>
                        <div class="value" id="pwd-\${password.id}">••••••••</div>
                    </div>
                    
                    \${password.url ? \`
                        <div class="password-field">
                            <label>网址</label>
                            <div class="value"><a href="\${password.url}" target="_blank">\${password.url}</a></div>
                        </div>
                    \` : ''}
                    
                    \${password.notes ? \`
                        <div class="password-field">
                            <label>备注</label>
                            <div class="value">\${password.notes}</div>
                        </div>
                    \` : ''}
                    
                    <div class="password-actions">
                        <button class="btn btn-secondary" onclick="togglePasswordDisplay('\${password.id}')">
                            <i class="fas fa-eye"></i> 显示
                        </button>
                        <button class="btn btn-secondary" onclick="copyPassword('\${password.id}')">
                            <i class="fas fa-copy"></i> 复制
                        </button>
                        <button class="btn btn-secondary" onclick="editPassword('\${password.id}')">
                            <i class="fas fa-edit"></i> 编辑
                        </button>
                        <button class="btn btn-danger" onclick="deletePassword('\${password.id}')">
                            <i class="fas fa-trash"></i> 删除
                        </button>
                    </div>
                </div>
            \`).join('');
        }

        // 过滤密码
        function filterPasswords() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const categoryFilter = document.getElementById('categoryFilter').value;
            
            let filtered = passwords.filter(password => {
                const matchesSearch = password.siteName.toLowerCase().includes(searchTerm) ||
                                    password.username.toLowerCase().includes(searchTerm) ||
                                    (password.notes && password.notes.toLowerCase().includes(searchTerm));
                
                const matchesCategory = !categoryFilter || password.category === categoryFilter;
                
                return matchesSearch && matchesCategory;
            });
            
            renderPasswords(filtered);
        }

        // 显示/隐藏密码
        async function togglePasswordDisplay(passwordId) {
            const element = document.getElementById(\`pwd-\${passwordId}\`);
            const button = event.target.closest('button');
            
            if (element.textContent === '••••••••') {
                try {
                    const response = await fetch(\`/api/passwords/\${passwordId}/reveal\`, {
                        headers: {
                            'Authorization': 'Bearer ' + authToken
                        }
                    });
                    
                    const data = await response.json();
                    element.textContent = data.password;
                    button.innerHTML = '<i class="fas fa-eye-slash"></i> 隐藏';
                } catch (error) {
                    showNotification('获取密码失败', 'error');
                }
            } else {
                element.textContent = '••••••••';
                button.innerHTML = '<i class="fas fa-eye"></i> 显示';
            }
        }

        // 复制密码
        async function copyPassword(passwordId) {
            try {
                const response = await fetch(\`/api/passwords/\${passwordId}/reveal\`, {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                const data = await response.json();
                await navigator.clipboard.writeText(data.password);
                showNotification('密码已复制到剪贴板');
            } catch (error) {
                showNotification('复制失败', 'error');
            }
        }

        // 编辑密码
        function editPassword(passwordId) {
            const password = passwords.find(p => p.id === passwordId);
            if (!password) return;
            
            editingPasswordId = passwordId;
            document.getElementById('modalTitle').textContent = '编辑密码';
            
            // 填充表单
            document.getElementById('siteName').value = password.siteName;
            document.getElementById('username').value = password.username;
            document.getElementById('password').value = ''; // 不显示现有密码
            document.getElementById('category').value = password.category || '';
            document.getElementById('url').value = password.url || '';
            document.getElementById('notes').value = password.notes || '';
            
            showModal();
        }

        // 删除密码
        async function deletePassword(passwordId) {
            if (!confirm('确定要删除这个密码吗？此操作无法撤销。')) return;
            
            try {
                const response = await fetch(\`/api/passwords/\${passwordId}\`, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                if (response.ok) {
                    showNotification('密码已删除');
                    loadPasswords();
                } else {
                    showNotification('删除失败', 'error');
                }
            } catch (error) {
                showNotification('删除失败', 'error');
            }
        }

        // 显示添加模态框
        function showAddModal() {
            editingPasswordId = null;
            document.getElementById('modalTitle').textContent = '添加密码';
            document.getElementById('passwordForm').reset();
            showModal();
        }

        // 显示模态框
        function showModal() {
            document.getElementById('passwordModal').classList.add('show');
        }

        // 关闭模态框
        function closeModal() {
            document.getElementById('passwordModal').classList.remove('show');
            document.getElementById('passwordForm').reset();
            editingPasswordId = null;
        }

        // 处理密码表单提交
        async function handlePasswordSubmit(e) {
            e.preventDefault();
            
            const formData = {
                siteName: document.getElementById('siteName').value,
                username: document.getElementById('username').value,
                password: document.getElementById('password').value,
                category: document.getElementById('category').value,
                url: document.getElementById('url').value,
                notes: document.getElementById('notes').value
            };
            
            try {
                const url = editingPasswordId ? \`/api/passwords/\${editingPasswordId}\` : '/api/passwords';
                const method = editingPasswordId ? 'PUT' : 'POST';
                
                const response = await fetch(url, {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify(formData)
                });
                
                if (response.ok) {
                    showNotification(editingPasswordId ? '密码已更新' : '密码已添加');
                    closeModal();
                    loadPasswords();
                } else {
                    showNotification('保存失败', 'error');
                }
            } catch (error) {
                showNotification('保存失败', 'error');
            }
        }

        // 生成密码
        async function generatePassword() {
            const options = {
                length: parseInt(document.getElementById('passwordLength').value),
                includeUppercase: document.getElementById('includeUppercase').checked,
                includeLowercase: document.getElementById('includeLowercase').checked,
                includeNumbers: document.getElementById('includeNumbers').checked,
                includeSymbols: document.getElementById('includeSymbols').checked
            };
            
            try {
                const response = await fetch('/api/generate-password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(options)
                });
                
                const data = await response.json();
                document.getElementById('password').value = data.password;
                document.getElementById('password').type = 'text';
            } catch (error) {
                showNotification('生成密码失败', 'error');
            }
        }

        // 切换密码可见性
        function togglePasswordVisibility(fieldId) {
            const field = document.getElementById(fieldId);
            const button = event.target.closest('button');
            const icon = button.querySelector('i');
            
            if (field.type === 'password') {
                field.type = 'text';
                icon.className = 'fas fa-eye-slash';
            } else {
                field.type = 'password';
                icon.className = 'fas fa-eye';
            }
        }

        // 导出数据
        async function exportData() {
            try {
                const response = await fetch('/api/export', {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = \`passwords-export-\${new Date().toISOString().split('T')[0]}.json\`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                
                showNotification('数据导出成功');
            } catch (error) {
                showNotification('导出失败', 'error');
            }
        }

        // 显示导入模态框
        function showImportModal() {
            document.getElementById('importModal').classList.add('show');
        }

        // 关闭导入模态框
        function closeImportModal() {
            document.getElementById('importModal').classList.remove('show');
            document.getElementById('importFile').value = '';
        }

        // 导入数据
        async function importData() {
            const fileInput = document.getElementById('importFile');
            const file = fileInput.files[0];
            
            if (!file) {
                showNotification('请选择文件', 'error');
                return;
            }
            
            try {
                const text = await file.text();
                const data = JSON.parse(text);
                
                const response = await fetch('/api/import', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                showNotification(\`导入完成：成功 \${result.imported} 条，失败 \${result.errors} 条\`);
                closeImportModal();
                loadPasswords();
            } catch (error) {
                showNotification('导入失败：文件格式错误', 'error');
            }
        }

        // 登出
        async function logout() {
            try {
                await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
            } catch (error) {
                console.error('Logout error:', error);
            }
            
            localStorage.removeItem('authToken');
            authToken = null;
            currentUser = null;
            showAuthContainer();
        }

        // 显示通知
        function showNotification(message, type = 'success') {
            const notification = document.createElement('div');
            notification.className = \`notification \${type}\`;
            notification.innerHTML = \`
                <i class="fas fa-\${type === 'success' ? 'check' : 'exclamation-triangle'}"></i>
                \${message}
            \`;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.classList.add('show');
            }, 100);
            
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => {
                    document.body.removeChild(notification);
                }, 300);
            }, 3000);
        }
    </script>
</body>
</html>`;
}
