// 基于HTML5的增强版密码管理器 - Cloudflare Workers + KV + OAuth + 分页功能 + 密码历史管理
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
        return new Response(getHTML5(), {
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
        if (path.endsWith('/reveal')) {
          return getActualPassword(request, env, corsHeaders);
        }
        if (path.endsWith('/history')) {
          return handlePasswordHistory(request, env, corsHeaders);
        }
        return handlePasswords(request, env, corsHeaders);
      }
      
      if (path === '/api/passwords/restore') {
        return handleRestorePassword(request, env, corsHeaders);
      }
      
      if (path.startsWith('/api/categories')) {
        return handleCategories(request, env, corsHeaders);
      }
      
      if (path === '/api/generate-password') {
        return handleGeneratePassword(request, env, corsHeaders);
      }
      
      if (path === '/api/export-encrypted') {
        return handleEncryptedExport(request, env, corsHeaders);
      }
      
      if (path === '/api/import-encrypted') {
        return handleEncryptedImport(request, env, corsHeaders);
      }
      
      if (path.startsWith('/api/webdav')) {
        return handleWebDAV(request, env, corsHeaders);
      }
      
      if (path === '/api/detect-login') {
        return handleDetectLogin(request, env, corsHeaders);
      }
      
      if (path === '/api/auto-fill') {
        return handleAutoFill(request, env, corsHeaders);
      }
      
      if (path === '/api/check-duplicate') {
        return handleCheckDuplicate(request, env, corsHeaders);
      }
      
      if (path === '/api/update-existing-password') {
        return handleUpdateExistingPassword(request, env, corsHeaders);
      }
      
      if (path === '/api/user') {
        return handleGetUser(request, env, corsHeaders);
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

// OAuth登录处理 - 完全修正版本
async function handleOAuthLogin(request, env, corsHeaders) {
  try {
    console.log('OAuth login request received, method:', request.method);
    
    // 检查必要的环境变量
    if (!env.OAUTH_BASE_URL || !env.OAUTH_CLIENT_ID || !env.OAUTH_REDIRECT_URI) {
      console.error('Missing OAuth configuration:', {
        OAUTH_BASE_URL: !!env.OAUTH_BASE_URL,
        OAUTH_CLIENT_ID: !!env.OAUTH_CLIENT_ID,
        OAUTH_REDIRECT_URI: !!env.OAUTH_REDIRECT_URI
      });
      
      return new Response(JSON.stringify({ 
        error: 'OAuth configuration missing',
        details: 'Please configure OAUTH_BASE_URL, OAUTH_CLIENT_ID, and OAUTH_REDIRECT_URI',
        config: {
          OAUTH_BASE_URL: env.OAUTH_BASE_URL || 'NOT_SET',
          OAUTH_CLIENT_ID: env.OAUTH_CLIENT_ID || 'NOT_SET',
          OAUTH_REDIRECT_URI: env.OAUTH_REDIRECT_URI || 'NOT_SET'
        }
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    const state = generateRandomString(32);
    
    // 构建授权URL
    const authUrl = new URL(`${env.OAUTH_BASE_URL}/oauth2/authorize`);
    authUrl.searchParams.set('client_id', env.OAUTH_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', env.OAUTH_REDIRECT_URI);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('scope', 'read');
    
    // 保存state到KV，有效期10分钟
    await env.PASSWORD_KV.put(`oauth_state_${state}`, 'valid', { expirationTtl: 600 });
    
    console.log('Generated OAuth URL:', authUrl.toString());
    
    return new Response(JSON.stringify({ 
      success: true,
      authUrl: authUrl.toString(),
      state: state,
      debug: {
        baseUrl: env.OAUTH_BASE_URL,
        clientId: env.OAUTH_CLIENT_ID,
        redirectUri: env.OAUTH_REDIRECT_URI
      }
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  } catch (error) {
    console.error('OAuth login error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to generate OAuth URL',
      details: error.message,
      stack: error.stack
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// OAuth回调处理
async function handleOAuthCallback(request, env, corsHeaders) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');
  
  console.log('OAuth callback received:', { code: !!code, state, error });
  
  if (error) {
    return new Response(createErrorPage('OAuth 登录失败', `错误信息: ${error}`), { 
      status: 400, 
      headers: { 'Content-Type': 'text/html', ...corsHeaders }
    });
  }
  
  if (!code || !state) {
    return new Response(createErrorPage('OAuth 参数错误', 'OAuth 回调缺少 code 或 state 参数'), { 
      status: 400, 
      headers: { 'Content-Type': 'text/html', ...corsHeaders }
    });
  }
  
  // 验证state
  const storedState = await env.PASSWORD_KV.get(`oauth_state_${state}`);
  if (!storedState) {
    return new Response(createErrorPage('OAuth State 验证失败', '无效的 state 参数，可能是过期或被篡改'), { 
      status: 400, 
      headers: { 'Content-Type': 'text/html', ...corsHeaders }
    });
  }
  
  // 删除已使用的state
  await env.PASSWORD_KV.delete(`oauth_state_${state}`);
  
  try {
    console.log('Exchanging code for token...');
    
    // 交换授权码获取访问令牌
    const tokenResponse = await fetch(`${env.OAUTH_BASE_URL}/oauth2/token`, {
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
    
    console.log('Token response status:', tokenResponse.status);
    
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error('Token exchange failed:', errorText);
      throw new Error(`Token exchange failed: ${tokenResponse.status} - ${errorText}`);
    }
    
    const tokenData = await tokenResponse.json();
    console.log('Token data received:', { access_token: !!tokenData.access_token });
    
    // 获取用户信息
    const userResponse = await fetch(`${env.OAUTH_BASE_URL}/api/user`, {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'Accept': 'application/json'
      }
    });
    
    console.log('User response status:', userResponse.status);
    
    if (!userResponse.ok) {
      const errorText = await userResponse.text();
      console.error('Failed to get user info:', errorText);
      throw new Error(`Failed to get user info: ${userResponse.status} - ${errorText}`);
    }
    
    const userData = await userResponse.json();
    console.log('User data received:', { id: userData.id, username: userData.username });
    
    // 检查用户授权
    if (env.OAUTH_ID && userData.id.toString() !== env.OAUTH_ID) {
      return new Response(createUnauthorizedPage(userData, env.OAUTH_ID), {
        status: 403,
        headers: { 'Content-Type': 'text/html', ...corsHeaders }
      });
    }
    
    // 创建会话令牌
    const sessionToken = generateRandomString(64);
    const userSession = {
      userId: userData.id.toString(),
      username: userData.username,
      nickname: userData.nickname || userData.username,
      email: userData.email || '',
      avatar: userData.avatar_template ? `${env.OAUTH_BASE_URL}${userData.avatar_template}`.replace('{size}', '120') : '',
      loginAt: new Date().toISOString()
    };
    
    // 保存会话，有效期7天
    await env.PASSWORD_KV.put(`session_${sessionToken}`, JSON.stringify(userSession), { 
      expirationTtl: 86400 * 7
    });
    
    console.log('Session created for user:', userData.username);
    
    return new Response(createSuccessPage(userSession, sessionToken), {
      headers: { 'Content-Type': 'text/html', ...corsHeaders }
    });
    
  } catch (error) {
    console.error('OAuth callback error:', error);
    return new Response(createErrorPage('登录处理失败', `OAuth 认证过程中发生错误，请稍后重试。\n错误详情: ${error.message}`), { 
      status: 500, 
      headers: { 'Content-Type': 'text/html', ...corsHeaders }
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
    const userData = JSON.parse(session);
    
    // 检查用户授权
    if (env.OAUTH_ID && userData.userId !== env.OAUTH_ID) {
      return new Response(JSON.stringify({ 
        authenticated: false,
        error: 'Unauthorized user'
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    
    return new Response(JSON.stringify({ 
      authenticated: true, 
      user: userData 
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

// 密码历史记录功能
async function savePasswordHistory(existingPassword, userId, env) {
  const historyEntry = {
    id: generateId(),
    passwordId: existingPassword.id,
    oldPassword: existingPassword.password, // 已加密
    changedAt: new Date().toISOString(),
    reason: 'password_update'
  };
  
  // 保存到历史记录（保留最近5次变更）
  const historyKey = `password_history_${userId}_${existingPassword.id}`;
  const existingHistory = await env.PASSWORD_KV.get(historyKey);
  let history = existingHistory ? JSON.parse(existingHistory) : [];
  
  history.unshift(historyEntry);
  if (history.length > 5) {
    history = history.slice(0, 5); // 只保留最近5次
  }
  
  await env.PASSWORD_KV.put(historyKey, JSON.stringify(history));
}

// 获取密码历史记录API
async function handlePasswordHistory(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  const url = new URL(request.url);
  const pathParts = url.pathname.split('/');
  const passwordId = pathParts[pathParts.length - 2]; // 获取密码ID
  const userId = session.userId;
  
  try {
    const historyData = await env.PASSWORD_KV.get(`password_history_${userId}_${passwordId}`);
    const history = historyData ? JSON.parse(historyData) : [];
    
    // 解密历史密码
    const decryptedHistory = await Promise.all(
      history.map(async (entry) => ({
        ...entry,
        oldPassword: await decryptPassword(entry.oldPassword, userId)
      }))
    );
    
    return new Response(JSON.stringify({ history: decryptedHistory }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: '获取历史记录失败' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// 恢复历史密码API
async function handleRestorePassword(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  const { passwordId, historyId } = await request.json();
  const userId = session.userId;
  
  try {
    // 获取当前密码
    const currentPasswordData = await env.PASSWORD_KV.get(`password_${userId}_${passwordId}`);
    if (!currentPasswordData) {
      return new Response(JSON.stringify({ error: '密码不存在' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    
    const currentPassword = JSON.parse(currentPasswordData);
    
    // 获取历史记录
    const historyData = await env.PASSWORD_KV.get(`password_history_${userId}_${passwordId}`);
    const history = historyData ? JSON.parse(historyData) : [];
    
    const historyEntry = history.find(h => h.id === historyId);
    if (!historyEntry) {
      return new Response(JSON.stringify({ error: '历史记录不存在' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    
    // 保存当前密码到历史记录
    await savePasswordHistory(currentPassword, userId, env);
    
    // 恢复历史密码
    const updatedPassword = {
      ...currentPassword,
      password: historyEntry.oldPassword, // 历史密码已经是加密的
      updatedAt: new Date().toISOString(),
      restoredFrom: historyEntry.id
    };
    
    await env.PASSWORD_KV.put(`password_${userId}_${passwordId}`, JSON.stringify(updatedPassword));
    
    return new Response(JSON.stringify({ 
      success: true, 
      message: '密码已恢复到历史版本' 
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ error: '恢复密码失败' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// 密码条目处理 - 增加分页功能和历史记录
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
  
  // 获取分页参数
  const page = parseInt(url.searchParams.get('page')) || 1;
  const limit = parseInt(url.searchParams.get('limit')) || 50;
  const search = url.searchParams.get('search') || '';
  const category = url.searchParams.get('category') || '';
  
  switch (request.method) {
    case 'GET':
      if (id && id !== 'passwords') {
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
        // 获取所有密码
        const list = await env.PASSWORD_KV.list({ prefix: `password_${userId}_` });
        let passwords = [];
        
        for (const key of list.keys) {
          const data = await env.PASSWORD_KV.get(key.name);
          if (data) {
            const passwordData = JSON.parse(data);
            passwords.push({
              ...passwordData,
              password: '••••••••'
            });
          }
        }
        
        // 排序
        passwords.sort((a, b) => {
          if (a.category !== b.category) {
            return (a.category || '其他').localeCompare(b.category || '其他');
          }
          return a.siteName.localeCompare(b.siteName);
        });
        
        // 过滤
        let filteredPasswords = passwords;
        
        if (search) {
          const searchLower = search.toLowerCase();
          filteredPasswords = filteredPasswords.filter(p => 
            p.siteName.toLowerCase().includes(searchLower) ||
            p.username.toLowerCase().includes(searchLower) ||
            (p.notes && p.notes.toLowerCase().includes(searchLower)) ||
            (p.url && p.url.toLowerCase().includes(searchLower))
          );
        }
        
        if (category) {
          filteredPasswords = filteredPasswords.filter(p => p.category === category);
        }
        
        // 分页
        const total = filteredPasswords.length;
        const totalPages = Math.ceil(total / limit);
        const startIndex = (page - 1) * limit;
        const endIndex = startIndex + limit;
        const paginatedPasswords = filteredPasswords.slice(startIndex, endIndex);
        
        return new Response(JSON.stringify({
          passwords: paginatedPasswords,
          pagination: {
            page,
            limit,
            total,
            totalPages,
            hasNext: page < totalPages,
            hasPrev: page > 1
          }
        }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
    case 'POST':
      const newPassword = await request.json();
      
      // 检查重复 - 修正版本：相同账号不同密码不保存为新账号
      const duplicateCheck = await checkForDuplicates(newPassword, userId, env, true);
      if (duplicateCheck.isDuplicate) {
        if (duplicateCheck.isIdentical) {
          return new Response(JSON.stringify({
            error: '检测到完全相同的账户',
            duplicate: true,
            identical: true,
            existing: duplicateCheck.existing,
            message: '该账户已存在且密码相同：' + duplicateCheck.existing.siteName + ' - ' + duplicateCheck.existing.username
          }), {
            status: 409,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } else if (duplicateCheck.passwordChanged) {
          // 相同账号不同密码：不保存为新账号，而是返回更新提示
          return new Response(JSON.stringify({
            error: '检测到相同账号的密码变更',
            duplicate: true,
            passwordChanged: true,
            existing: duplicateCheck.existing,
            newPassword: newPassword.password,
            message: '检测到相同账号的密码变更，是否更新现有账户的密码？',
            updateAction: 'update_password',
            shouldUpdate: true // 标记为应该更新而不是新建
          }), {
            status: 409,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }
      
      newPassword.id = generateId();
      newPassword.userId = userId;
      newPassword.createdAt = new Date().toISOString();
      newPassword.updatedAt = newPassword.createdAt;
      
      // 自动提取域名作为网站名称
      if (newPassword.url && !newPassword.siteName) {
        try {
          const urlObj = new URL(newPassword.url);
          newPassword.siteName = urlObj.hostname.replace('www.', '');
        } catch (e) {
          // 忽略URL解析错误
        }
      }
      
      newPassword.password = await encryptPassword(newPassword.password, userId);
      
      await env.PASSWORD_KV.put(`password_${userId}_${newPassword.id}`, JSON.stringify(newPassword));
      
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
      const existingPasswordData = JSON.parse(existingPassword);
      const updatedPassword = { ...existingPasswordData, ...updateData };
      updatedPassword.updatedAt = new Date().toISOString();
      
      // 如果密码发生变更，保存历史记录
      if (updateData.password) {
        const newEncryptedPassword = await encryptPassword(updateData.password, userId);
        const oldDecryptedPassword = await decryptPassword(existingPasswordData.password, userId);
        
        if (oldDecryptedPassword !== updateData.password) {
          // 保存历史记录
          await savePasswordHistory(existingPasswordData, userId, env);
        }
        
        updatedPassword.password = newEncryptedPassword;
      }
      
      await env.PASSWORD_KV.put(`password_${userId}_${id}`, JSON.stringify(updatedPassword));
      
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
      
      // 删除密码和相关历史记录
      await env.PASSWORD_KV.delete(`password_${userId}_${id}`);
      await env.PASSWORD_KV.delete(`password_history_${userId}_${id}`);
      
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

// 检查重复账户 - 修正版本：包括密码检查
async function checkForDuplicates(newPassword, userId, env, checkPassword = false) {
  if (!newPassword.url || !newPassword.username) {
    return { isDuplicate: false };
  }
  
  try {
    const newUrl = new URL(newPassword.url);
    const newDomain = newUrl.hostname.replace('www.', '').toLowerCase();
    const newUsername = newPassword.username.toLowerCase().trim();
    
    const list = await env.PASSWORD_KV.list({ prefix: `password_${userId}_` });
    
    for (const key of list.keys) {
      const data = await env.PASSWORD_KV.get(key.name);
      if (data) {
        const existingPassword = JSON.parse(data);
        
        // 跳过正在编辑的同一条记录
        if (newPassword.id && existingPassword.id === newPassword.id) {
          continue;
        }
        
        if (existingPassword.url && existingPassword.username) {
          try {
            const existingUrl = new URL(existingPassword.url);
            const existingDomain = existingUrl.hostname.replace('www.', '').toLowerCase();
            const existingUsername = existingPassword.username.toLowerCase().trim();
            
            // 检查域名和用户名是否完全匹配
            if (existingDomain === newDomain && existingUsername === newUsername) {
              // 如果需要检查密码，则解密比较
              if (checkPassword && newPassword.password) {
                const existingDecryptedPassword = await decryptPassword(existingPassword.password, userId);
                if (existingDecryptedPassword === newPassword.password) {
                  // 完全相同的账户（URL+用户名+密码）
                  return {
                    isDuplicate: true,
                    isIdentical: true,
                    existing: {
                      ...existingPassword,
                      password: existingDecryptedPassword
                    }
                  };
                } else {
                  // 相同网站和用户名，但密码不同
                  return {
                    isDuplicate: true,
                    isIdentical: false,
                    passwordChanged: true,
                    existing: {
                      ...existingPassword,
                      password: existingDecryptedPassword
                    }
                  };
                }
              } else {
                // 不检查密码时，只要URL和用户名匹配就算重复
                return {
                  isDuplicate: true,
                  existing: {
                    ...existingPassword,
                    password: '••••••••' // 不返回真实密码
                  }
                };
              }
            }
          } catch (e) {
            // URL解析失败，跳过此条记录
            continue;
          }
        }
      }
    }
    
    return { isDuplicate: false };
  } catch (error) {
    console.error('检查重复时出错:', error);
    return { isDuplicate: false };
  }
}

// 获取实际密码
async function getActualPassword(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  const url = new URL(request.url);
  const pathParts = url.pathname.split('/');
  const id = pathParts[pathParts.length - 2];
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
    return new Response(categories || JSON.stringify([]), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  if (request.method === 'POST') {
    const { action, category } = await request.json();
    const categoriesData = await env.PASSWORD_KV.get(`categories_${userId}`);
    let categories = categoriesData ? JSON.parse(categoriesData) : [];
    
    if (action === 'add' && category && !categories.includes(category)) {
      categories.push(category);
      await env.PASSWORD_KV.put(`categories_${userId}`, JSON.stringify(categories));
    } else if (action === 'remove' && category) {
      categories = categories.filter(c => c !== category);
      await env.PASSWORD_KV.put(`categories_${userId}`, JSON.stringify(categories));
    }
    
    return new Response(JSON.stringify({ success: true, categories }), {
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

// 其他API处理函数的占位符实现
async function handleEncryptedExport(request, env, corsHeaders) {
  return new Response(JSON.stringify({ error: 'Not implemented yet' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

async function handleEncryptedImport(request, env, corsHeaders) {
  return new Response(JSON.stringify({ error: 'Not implemented yet' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

async function handleWebDAV(request, env, corsHeaders) {
  return new Response(JSON.stringify({ error: 'Not implemented yet' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

async function handleDetectLogin(request, env, corsHeaders) {
  return new Response(JSON.stringify({ error: 'Not implemented yet' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

async function handleAutoFill(request, env, corsHeaders) {
  return new Response(JSON.stringify({ error: 'Not implemented yet' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

async function handleCheckDuplicate(request, env, corsHeaders) {
  return new Response(JSON.stringify({ isDuplicate: false }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

async function handleUpdateExistingPassword(request, env, corsHeaders) {
  return new Response(JSON.stringify({ error: 'Not implemented yet' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

async function handleGetUser(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  return new Response(JSON.stringify({
    id: session.userId,
    username: session.username,
    nickname: session.nickname,
    email: session.email,
    avatar: session.avatar
  }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

// 工具函数
async function verifySession(request, env) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return null;
  
  const session = await env.PASSWORD_KV.get(`session_${token}`);
  if (!session) return null;
  
  const userData = JSON.parse(session);
  
  // 检查用户授权
  if (env.OAUTH_ID && userData.userId !== env.OAUTH_ID) {
    return null;
  }
  
  return userData;
}

async function encryptPassword(password, userId) {
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
    return encryptedPassword;
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

// HTML页面生成函数
function createErrorPage(title, message) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <title>${title}</title>
    <style>
      body { 
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
        display: flex; 
        justify-content: center; 
        align-items: center; 
        height: 100vh; 
        background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
        margin: 0;
      }
      .message { 
        background: white; 
        padding: 30px; 
        border-radius: 15px; 
        text-align: center;
        box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        max-width: 500px;
      }
      h3 { color: #ef4444; margin-bottom: 15px; }
      p { color: #6b7280; margin-bottom: 20px; white-space: pre-line; }
    </style>
  </head>
  <body>
    <div class="message">
      <h3>❌ ${title}</h3>
      <p>${message}</p>
      <button onclick="window.location.href='/'" style="padding: 10px 20px; background: #6366f1; color: white; border: none; border-radius: 5px; cursor: pointer;">返回首页</button>
    </div>
  </body>
</html>`;
}

function createUnauthorizedPage(userData, authorizedId) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <title>访问被拒绝</title>
    <style>
      body { 
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
        display: flex; 
        justify-content: center; 
        align-items: center; 
        height: 100vh; 
        background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
        margin: 0;
      }
      .message { 
        background: white; 
        padding: 30px; 
        border-radius: 15px; 
        text-align: center;
        box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        max-width: 400px;
      }
      h3 { color: #ef4444; margin-bottom: 15px; }
      p { color: #6b7280; margin-bottom: 20px; }
      .user-info { 
        background: #f8fafc; 
        padding: 15px; 
        border-radius: 8px; 
        margin: 15px 0;
        font-family: monospace;
        font-size: 14px;
      }
    </style>
  </head>
  <body>
    <div class="message">
      <h3>🚫 访问被拒绝</h3>
      <p>抱歉，您没有访问此密码管理器的权限。</p>
      <div class="user-info">
        用户ID: ${userData.id}<br>
        用户名: ${userData.username}<br>
        授权ID: ${authorizedId || '未设置'}
      </div>
      <p style="font-size: 12px;">如需访问权限，请联系管理员。</p>
      <button onclick="window.location.href='/'" style="padding: 10px 20px; background: #ef4444; color: white; border: none; border-radius: 5px; cursor: pointer;">返回首页</button>
    </div>
  </body>
</html>`;
}

function createSuccessPage(userSession, sessionToken) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <title>登录成功</title>
    <style>
      body { 
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
        display: flex; 
        justify-content: center; 
        align-items: center; 
        height: 100vh; 
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        margin: 0;
      }
      .message { 
        background: white; 
        padding: 30px; 
        border-radius: 15px; 
        text-align: center;
        box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        max-width: 400px;
      }
      h3 { color: #10b981; margin-bottom: 15px; }
      .user-info {
        display: flex;
        align-items: center;
        gap: 15px;
        margin: 20px 0;
        padding: 15px;
        background: #f8fafc;
        border-radius: 10px;
      }
      .avatar {
        width: 50px;
        height: 50px;
        border-radius: 50%;
        background: linear-gradient(135deg, #6366f1, #8b5cf6);
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-weight: bold;
        font-size: 18px;
      }
      .loading {
        display: inline-block;
        width: 20px;
        height: 20px;
        border: 3px solid #f3f3f3;
        border-top: 3px solid #10b981;
        border-radius: 50%;
        animation: spin 1s linear infinite;
      }
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
    </style>
  </head>
  <body>
    <div class="message">
      <h3>✅ 登录成功</h3>
      <div class="user-info">
        <div class="avatar">${userSession.avatar ? `<img src="${userSession.avatar}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">` : userSession.nickname.charAt(0).toUpperCase()}</div>
        <div>
          <div style="font-weight: bold;">${userSession.nickname}</div>
          <div style="color: #6b7280; font-size: 14px;">${userSession.email}</div>
        </div>
      </div>
      <p><div class="loading"></div> 正在跳转到密码管理器...</p>
    </div>
    <script>
      localStorage.setItem('authToken', '${sessionToken}');
      setTimeout(() => {
        window.location.href = '/';
      }, 3000);
    </script>
  </body>
</html>`;
}

// HTML5界面 - 完整版本
function getHTML5() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔐 密码管理器 Pro</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🔐</text></svg>">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    
    <style>
        :root {
            --primary-color: #6366f1;
            --primary-dark: #4f46e5;
            --secondary-color: #8b5cf6;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --info-color: #3b82f6;
            --dark-color: #1f2937;
            --light-color: #f8fafc;
            --border-color: #e5e7eb;
            --text-primary: #111827;
            --text-secondary: #6b7280;
            --text-muted: #9ca3af;
            --background-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --card-background: rgba(255, 255, 255, 0.95);
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
            --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
            --border-radius-sm: 8px;
            --border-radius-md: 12px;
            --border-radius-lg: 16px;
            --border-radius-xl: 20px;
            --border-radius-2xl: 24px;
            --transition-fast: 0.15s ease;
            --transition-normal: 0.3s ease;
            --transition-slow: 0.5s ease;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--background-gradient);
            min-height: 100vh;
            color: var(--text-primary);
            line-height: 1.6;
        }

        .particles {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: -1;
            overflow: hidden;
        }

        .particle {
            position: absolute;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            animation: float 20s infinite linear;
        }

        @keyframes float {
            0% {
                transform: translateY(100vh) rotate(0deg);
                opacity: 0;
            }
            10% {
                opacity: 1;
            }
            90% {
                opacity: 1;
            }
            100% {
                transform: translateY(-100px) rotate(360deg);
                opacity: 0;
            }
        }

        /* 登录界面 */
        .auth-section {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 1.25rem;
        }

        .auth-card {
            background: var(--card-background);
            backdrop-filter: blur(20px);
            padding: 3rem 2.5rem;
            border-radius: var(--border-radius-2xl);
            box-shadow: var(--shadow-xl);
            text-align: center;
            max-width: 28rem;
            width: 100%;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .auth-card .logo {
            font-size: 4rem;
            margin-bottom: 1.5rem;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .auth-card h1 {
            color: var(--text-primary);
            margin-bottom: 0.75rem;
            font-size: 2rem;
            font-weight: 700;
        }

        .auth-card p {
            color: var(--text-secondary);
            margin-bottom: 2.5rem;
            font-size: 1rem;
        }

        /* 主应用容器 */
        .app-container {
            max-width: 87.5rem;
            margin: 0 auto;
            padding: 1.25rem;
        }

        /* 头部区域 */
        .app-header {
            background: var(--card-background);
            backdrop-filter: blur(20px);
            padding: 1.5rem;
            border-radius: var(--border-radius-xl);
            box-shadow: var(--shadow-lg);
            margin-bottom: 1.875rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .user-profile {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .user-avatar {
            width: 3.5rem;
            height: 3.5rem;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 1.25rem;
            overflow: hidden;
            box-shadow: var(--shadow-md);
        }

        .user-avatar img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }

        .user-info h2 {
            color: var(--text-primary);
            margin-bottom: 0.25rem;
            font-size: 1.125rem;
            font-weight: 600;
        }

        .user-info p {
            color: var(--text-secondary);
            font-size: 0.875rem;
        }

        .header-actions {
            display: flex;
            gap: 0.75rem;
            flex-wrap: wrap;
        }

        /* 按钮组件 */
        .btn {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 50px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all var(--transition-normal);
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            text-decoration: none;
            box-shadow: var(--shadow-sm);
            white-space: nowrap;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }

        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
            color: white;
        }

        .btn-secondary {
            background: #f1f5f9;
            color: var(--text-primary);
        }

        .btn-danger {
            background: linear-gradient(135deg, var(--danger-color), #dc2626);
            color: white;
        }

        .btn-success {
            background: linear-gradient(135deg, var(--success-color), #059669);
            color: white;
        }

        .btn-warning {
            background: linear-gradient(135deg, var(--warning-color), #d97706);
            color: white;
        }

        .btn-info {
            background: linear-gradient(135deg, var(--info-color), #2563eb);
            color: white;
        }

        .btn-sm {
            padding: 0.5rem 1rem;
            font-size: 0.875rem;
        }

        .btn-lg {
            padding: 1rem 2rem;
            font-size: 1.125rem;
        }

        /* 导航标签 */
        .nav-tabs {
            display: flex;
            background: var(--card-background);
            border-radius: var(--border-radius-xl);
            padding: 0.5rem;
            margin-bottom: 1.5rem;
            box-shadow: var(--shadow-lg);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .nav-tab {
            flex: 1;
            padding: 1rem;
            text-align: center;
            border-radius: var(--border-radius-lg);
            cursor: pointer;
            transition: all var(--transition-normal);
            font-weight: 600;
            color: var(--text-secondary);
        }

        .nav-tab.active {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            box-shadow: var(--shadow-md);
        }

        .nav-tab:hover:not(.active) {
            background: rgba(99, 102, 241, 0.1);
            color: var(--primary-color);
        }

        /* 内容区域 */
        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        /* 工具栏 */
        .toolbar {
            background: var(--card-background);
            backdrop-filter: blur(20px);
            padding: 1.5rem;
            border-radius: var(--border-radius-xl);
            box-shadow: var(--shadow-lg);
            margin-bottom: 1.875rem;
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            align-items: center;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .search-container {
            flex: 1;
            min-width: 18.75rem;
            position: relative;
        }

        .search-input {
            width: 100%;
            padding: 0.875rem 1rem 0.875rem 3rem;
            border: 2px solid var(--border-color);
            border-radius: 50px;
            font-size: 1rem;
            transition: all var(--transition-normal);
            background: rgba(255, 255, 255, 0.8);
        }

        .search-input:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
        }

        .search-icon {
            position: absolute;
            left: 1rem;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-secondary);
            font-size: 1.125rem;
        }

        .filter-select {
            padding: 0.875rem 1.25rem;
            border: 2px solid var(--border-color);
            border-radius: 50px;
            font-size: 1rem;
            background: rgba(255, 255, 255, 0.8);
            cursor: pointer;
            transition: all var(--transition-normal);
        }

        .filter-select:focus {
            outline: none;
            border-color: var(--primary-color);
        }

        /* 密码网格 - 改为列表形式 */
        .passwords-list {
            background: var(--card-background);
            backdrop-filter: blur(20px);
            border-radius: var(--border-radius-xl);
            box-shadow: var(--shadow-lg);
            border: 1px solid rgba(255, 255, 255, 0.2);
            overflow: hidden;
        }

        /* 密码条目 - 列表形式 */
        .password-item {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-color);
            transition: all var(--transition-normal);
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: white;
        }

        .password-item:last-child {
            border-bottom: none;
        }

        .password-item:hover {
            background: #f8fafc;
            transform: translateX(4px);
        }

        .password-item-content {
            display: flex;
            align-items: center;
            gap: 1rem;
            flex: 1;
        }

        .password-item-icon {
            width: 3rem;
            height: 3rem;
            border-radius: var(--border-radius-lg);
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.25rem;
            box-shadow: var(--shadow-md);
            flex-shrink: 0;
        }

        .password-item-info {
            flex: 1;
            min-width: 0;
        }

        .password-item-title {
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 0.25rem;
            font-size: 1.125rem;
        }

        .password-item-username {
            color: var(--text-secondary);
            font-size: 0.875rem;
            margin-bottom: 0.25rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .password-item-url {
            color: var(--info-color);
            font-size: 0.75rem;
            text-decoration: none;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .password-item-url:hover {
            text-decoration: underline;
        }

        .password-item-meta {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 0.5rem;
            margin-right: 1rem;
            flex-shrink: 0;
        }

        .category-badge {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: var(--border-radius-xl);
            font-size: 0.75rem;
            font-weight: 600;
            white-space: nowrap;
        }

        .password-item-date {
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .password-item-actions {
            display: flex;
            gap: 0.5rem;
            flex-shrink: 0;
        }

        .password-item-actions .btn {
            padding: 0.5rem;
            border-radius: 50%;
            width: 2.5rem;
            height: 2.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        /* 分页组件 */
        .pagination-container {
            margin-top: 2rem;
            padding: 1.5rem;
            background: var(--card-background);
            border-radius: var(--border-radius-xl);
            box-shadow: var(--shadow-lg);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .pagination {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }
        
        .pagination-info {
            color: var(--text-secondary);
            font-size: 0.875rem;
            font-weight: 500;
        }
        
        .pagination-controls {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex-wrap: wrap;
        }
        
        .pagination-ellipsis {
            color: var(--text-secondary);
            padding: 0 0.5rem;
            font-weight: 600;
        }

        /* 表单组件 */
        .form-section {
            background: var(--card-background);
            backdrop-filter: blur(20px);
            border-radius: var(--border-radius-xl);
            padding: 2rem;
            box-shadow: var(--shadow-lg);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-group label {
            display: block;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
            font-weight: 600;
            font-size: 0.875rem;
        }

        .form-control {
            width: 100%;
            padding: 0.875rem 1rem;
            border: 2px solid var(--border-color);
            border-radius: var(--border-radius-md);
            font-size: 1rem;
            transition: all var(--transition-normal);
            background: rgba(255, 255, 255, 0.8);
        }

        .form-control:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
        }

        .input-group {
            position: relative;
        }

        .input-group-append {
            position: absolute;
            right: 1rem;
            top: 50%;
            transform: translateY(-50%);
        }

        .toggle-btn {
            background: none;
            border: none;
            cursor: pointer;
            color: var(--text-secondary);
            padding: 0.5rem;
            border-radius: var(--border-radius-sm);
            transition: all var(--transition-normal);
        }

        .toggle-btn:hover {
            background: var(--border-color);
            color: var(--text-primary);
        }

        /* 密码生成器 */
        .password-generator {
            background: linear-gradient(135deg, #f8fafc, #f1f5f9);
            padding: 1.5rem;
            border-radius: var(--border-radius-lg);
            margin-bottom: 1.5rem;
            border: 2px solid var(--border-color);
        }

        .password-generator h4 {
            color: var(--text-primary);
            margin-bottom: 1rem;
            font-size: 1rem;
            font-weight: 700;
        }

        .generator-options {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(12.5rem, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .checkbox-group input[type="checkbox"] {
            width: auto;
            accent-color: var(--primary-color);
        }

        .range-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .range-input {
            width: 100%;
            accent-color: var(--primary-color);
        }

        .range-value {
            font-weight: 600;
            color: var(--primary-color);
        }

        /* 空状态 */
        .empty-state {
            text-align: center;
            padding: 5rem 1.25rem;
            color: var(--text-secondary);
        }

        .empty-state .icon {
            font-size: 4rem;
            margin-bottom: 1.5rem;
            opacity: 0.5;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .empty-state h3 {
            font-size: 1.5rem;
            margin-bottom: 0.75rem;
            color: var(--text-primary);
        }

        .empty-state p {
            font-size: 1rem;
        }

        /* 通知组件 */
        .notification {
            position: fixed;
            top: 1.5rem;
            right: 1.5rem;
            background: var(--success-color);
            color: white;
            padding: 1rem 1.5rem;
            border-radius: var(--border-radius-md);
            box-shadow: var(--shadow-lg);
            z-index: 1001;
            transform: translateX(25rem);
            transition: transform var(--transition-normal);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-weight: 600;
            max-width: 20rem;
        }

        .notification.show {
            transform: translateX(0);
        }

        .notification.error {
            background: var(--danger-color);
        }

        .notification.warning {
            background: var(--warning-color);
        }

        .notification.info {
            background: var(--info-color);
        }

        /* 加载动画 */
        .loading {
            display: inline-block;
            width: 1.25rem;
            height: 1.25rem;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-top: 3px solid white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* 调试信息样式 */
        .debug-info {
            background: #f8fafc;
            border: 1px solid #e5e7eb;
            border-radius: var(--border-radius-lg);
            padding: 1rem;
            margin-top: 1rem;
            font-family: monospace;
            font-size: 0.875rem;
            color: #374151;
            max-height: 300px;
            overflow-y: auto;
            text-align: left;
        }

        .debug-info h4 {
            margin: 0 0 0.5rem 0;
            color: #1f2937;
            font-family: inherit;
        }

        .debug-entry {
            margin-bottom: 0.25rem;
            padding: 0.25rem;
            border-radius: 4px;
        }

        .debug-entry.error {
            background: #fef2f2;
            color: #991b1b;
        }

        .debug-entry.success {
            background: #f0fdf4;
            color: #166534;
        }

        /* 响应式设计 */
        @media (max-width: 768px) {
            .app-container { 
                padding: 0.75rem; 
            }
            
            .app-header {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }
            
            .header-actions {
                justify-content: center;
            }
            
            .toolbar {
                flex-direction: column;
                align-items: stretch;
            }
            
            .search-container {
                min-width: auto;
            }
            
            .password-item {
                flex-direction: column;
                align-items: stretch;
                gap: 1rem;
            }
            
            .password-item-content {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .password-item-meta {
                align-items: flex-start;
                margin-right: 0;
            }
            
            .password-item-actions {
                justify-content: center;
            }

            .generator-options {
                grid-template-columns: 1fr;
            }

            .notification {
                right: 0.75rem;
                left: 0.75rem;
                max-width: none;
                transform: translateY(-5rem);
            }

            .notification.show {
                transform: translateY(0);
            }

            .pagination {
                flex-direction: column;
                text-align: center;
            }
            
            .pagination-controls {
                justify-content: center;
            }
        }

        /* 工具类 */
        .hidden { 
            display: none !important; 
        }

        .text-center { 
            text-align: center; 
        }

        .flex { display: flex; }
        .flex-col { flex-direction: column; }
        .items-center { align-items: center; }
        .justify-center { justify-content: center; }
        .justify-between { justify-content: space-between; }
        .gap-1 { gap: 0.25rem; }
        .gap-2 { gap: 0.5rem; }
        .gap-3 { gap: 0.75rem; }
        .gap-4 { gap: 1rem; }

        .w-full { width: 100%; }
        .h-full { height: 100%; }

        .mb-0 { margin-bottom: 0; }
        .mb-1 { margin-bottom: 0.25rem; }
        .mb-2 { margin-bottom: 0.5rem; }
        .mb-3 { margin-bottom: 0.75rem; }
        .mb-4 { margin-bottom: 1rem; }

        .mt-0 { margin-top: 0; }
        .mt-1 { margin-top: 0.25rem; }
        .mt-2 { margin-top: 0.5rem; }
        .mt-3 { margin-top: 0.75rem; }
        .mt-4 { margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="particles" id="particles"></div>

    <!-- 登录界面 -->
    <section id="authSection" class="auth-section">
        <article class="auth-card">
            <div class="logo">🔐</div>
            <header>
                <h1>密码管理器 Pro</h1>
                <p>安全、便捷、智能的密码管理解决方案</p>
            </header>
            <button id="oauthLoginBtn" class="btn btn-primary btn-lg" type="button">
                <i class="fas fa-sign-in-alt"></i>
                开始使用 OAuth 登录
            </button>
            
            <!-- 调试信息区域 -->
            <div id="debugInfo" class="debug-info hidden">
                <h4>🔧 调试信息</h4>
                <div id="debugContent"></div>
            </div>
        </article>
    </section>

    <!-- 主应用界面 -->
    <div id="mainApp" class="app-container hidden">
        <!-- 应用头部 -->
        <header class="app-header">
            <div class="user-profile">
                <div class="user-avatar" id="userAvatar">
                    <i class="fas fa-user"></i>
                </div>
                <div class="user-info">
                    <h2 id="userName">用户名</h2>
                    <p id="userEmail">user@example.com</p>
                </div>
            </div>
            <nav class="header-actions">
                <button class="btn btn-danger" onclick="logout()" type="button">
                    <i class="fas fa-sign-out-alt"></i> 
                    <span>登出</span>
                </button>
            </nav>
        </header>

        <!-- 导航标签 -->
        <nav class="nav-tabs">
            <div class="nav-tab active" onclick="switchTab('passwords')">
                <i class="fas fa-key"></i> 密码管理
            </div>
            <div class="nav-tab" onclick="switchTab('add-password')">
                <i class="fas fa-plus"></i> 添加密码
            </div>
            <div class="nav-tab" onclick="switchTab('tools')">
                <i class="fas fa-tools"></i> 工具
            </div>
        </nav>

        <!-- 密码管理标签页 -->
        <div id="passwords-tab" class="tab-content active">
            <!-- 工具栏 -->
            <section class="toolbar">
                <div class="search-container">
                    <i class="fas fa-search search-icon"></i>
                    <input 
                        type="search" 
                        id="searchInput" 
                        class="search-input"
                        placeholder="搜索网站、用户名或备注..."
                        autocomplete="off"
                    >
                </div>
                <div>
                    <select id="categoryFilter" class="filter-select">
                        <option value="">🏷️ 所有分类</option>
                    </select>
                </div>
            </section>

            <!-- 密码列表 -->
            <main>
                <section class="passwords-list" id="passwordsList">
                    <!-- 密码条目将在这里动态生成 -->
                </section>
                <!-- 分页容器将在这里动态生成 -->
            </main>
        </div>

        <!-- 添加密码标签页 -->
        <div id="add-password-tab" class="tab-content">
            <div class="form-section">
                <h2 style="margin-bottom: 1.5rem; color: var(--text-primary);">✨ 添加新密码</h2>
                
                <form id="passwordForm">
                    <div class="form-group">
                        <label for="siteName">🌐 网站名称 *</label>
                        <input type="text" id="siteName" class="form-control" required placeholder="例如：GitHub、Gmail" autocomplete="off">
                    </div>
                    <div class="form-group">
                        <label for="username">👤 用户名/邮箱 *</label>
                        <input type="text" id="username" class="form-control" required placeholder="your@email.com" autocomplete="username">
                    </div>
                    <div class="form-group">
                        <label for="password">🔑 密码 *</label>
                        <div class="input-group">
                            <input type="password" id="password" class="form-control" required placeholder="输入密码" autocomplete="new-password">
                            <div class="input-group-append">
                                <button type="button" class="toggle-btn" onclick="togglePasswordVisibility('password')">
                                    <i class="fas fa-eye"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <!-- 密码生成器 -->
                    <fieldset class="password-generator">
                        <legend>🎲 智能密码生成器</legend>
                        <div class="generator-options">
                            <div class="form-group">
                                <label for="passwordLength">长度: <span id="lengthValue" class="range-value">16</span></label>
                                <input type="range" id="passwordLength" class="range-input" min="8" max="32" value="16">
                            </div>
                            <div class="checkbox-group">
                                <input type="checkbox" id="includeUppercase" checked>
                                <label for="includeUppercase">ABC 大写字母</label>
                            </div>
                            <div class="checkbox-group">
                                <input type="checkbox" id="includeLowercase" checked>
                                <label for="includeLowercase">abc 小写字母</label>
                            </div>
                            <div class="checkbox-group">
                                <input type="checkbox" id="includeNumbers" checked>
                                <label for="includeNumbers">123 数字</label>
                            </div>
                            <div class="checkbox-group">
                                <input type="checkbox" id="includeSymbols">
                                <label for="includeSymbols">!@# 特殊符号</label>
                            </div>
                        </div>
                        <button type="button" class="btn btn-secondary" onclick="generatePassword()">
                            <i class="fas fa-magic"></i> 生成强密码
                        </button>
                    </fieldset>

                    <div class="form-group">
                        <label for="category">📁 选择分类</label>
                        <select id="category" class="form-control">
                            <option value="">选择分类</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="url">🔗 网站链接</label>
                        <input type="url" id="url" class="form-control" placeholder="https://example.com" autocomplete="url">
                    </div>
                    <div class="form-group">
                        <label for="notes">📝 备注信息</label>
                        <textarea id="notes" class="form-control" rows="3" placeholder="添加备注信息..."></textarea>
                    </div>
                    <div class="flex gap-4 mt-4">
                        <button type="submit" class="btn btn-primary w-full">
                            <i class="fas fa-save"></i> 保存密码
                        </button>
                        <button type="button" class="btn btn-secondary" onclick="clearForm()">
                            <i class="fas fa-eraser"></i> 清空表单
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- 工具标签页 -->
        <div id="tools-tab" class="tab-content">
            <div class="form-section">
                <h2 style="margin-bottom: 1.5rem; color: var(--text-primary);">🛠️ 工具集合</h2>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem;">
                    <div style="padding: 1.5rem; background: linear-gradient(135deg, #f0f9ff, #e0f2fe); border-radius: var(--border-radius-lg); border: 2px solid #bae6fd;">
                        <h3 style="color: var(--text-primary); margin-bottom: 1rem;">🎲 密码生成器</h3>
                        <p style="color: var(--text-secondary); margin-bottom: 1rem;">生成安全的随机密码</p>
                        <button class="btn btn-info" onclick="showNotification('功能开发中...', 'info')" type="button">
                            <i class="fas fa-magic"></i> 打开工具
                        </button>
                    </div>
                    <div style="padding: 1.5rem; background: linear-gradient(135deg, #f0fdf4, #dcfce7); border-radius: var(--border-radius-lg); border: 2px solid #bbf7d0;">
                        <h3 style="color: var(--text-primary); margin-bottom: 1rem;">📤 数据导出</h3>
                        <p style="color: var(--text-secondary); margin-bottom: 1rem;">导出密码数据</p>
                        <button class="btn btn-success" onclick="showNotification('功能开发中...', 'info')" type="button">
                            <i class="fas fa-download"></i> 导出数据
                        </button>
                    </div>
                    <div style="padding: 1.5rem; background: linear-gradient(135deg, #fefbf2, #fef3c7); border-radius: var(--border-radius-lg); border: 2px solid #fde68a;">
                        <h3 style="color: var(--text-primary); margin-bottom: 1rem;">📥 数据导入</h3>
                        <p style="color: var(--text-secondary); margin-bottom: 1rem;">导入密码数据</p>
                        <button class="btn btn-warning" onclick="showNotification('功能开发中...', 'info')" type="button">
                            <i class="fas fa-upload"></i> 导入数据
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // 全局变量
        let authToken = localStorage.getItem('authToken');
        let currentUser = null;
        let passwords = [];
        let categories = [];
        let editingPasswordId = null;
        let currentTab = 'passwords';
        
        // 分页相关变量
        let currentPage = 1;
        let totalPages = 1;
        let pageLimit = 50;
        let searchQuery = '';
        let categoryFilter = '';

        // 调试模式
        let debugMode = false;

        // 创建粒子背景
        function createParticles() {
            const particles = document.getElementById('particles');
            for (let i = 0; i < 50; i++) {
                const particle = document.createElement('div');
                particle.className = 'particle';
                particle.style.left = Math.random() * 100 + '%';
                particle.style.width = particle.style.height = Math.random() * 10 + 5 + 'px';
                particle.style.animationDelay = Math.random() * 20 + 's';
                particle.style.animationDuration = (Math.random() * 10 + 10) + 's';
                particles.appendChild(particle);
            }
        }

        // 调试函数
        function addDebugInfo(message, type = 'info') {
            if (!debugMode) return;
            
            const debugContent = document.getElementById('debugContent');
            const timestamp = new Date().toLocaleTimeString();
            const debugEntry = document.createElement('div');
            debugEntry.className = 'debug-entry ' + type;
            debugEntry.textContent = timestamp + ': ' + message;
            debugContent.appendChild(debugEntry);
            
            // 自动滚动到底部
            debugContent.scrollTop = debugContent.scrollHeight;
            
            // 显示调试信息区域
            document.getElementById('debugInfo').classList.remove('hidden');
            
            // 限制条目数量
            if (debugContent.children.length > 50) {
                debugContent.removeChild(debugContent.firstChild);
            }
        }

        // 切换调试模式
        function toggleDebugMode() {
            debugMode = !debugMode;
            const debugInfo = document.getElementById('debugInfo');
            if (debugMode) {
                debugInfo.classList.remove('hidden');
                addDebugInfo('调试模式已启用', 'success');
            } else {
                debugInfo.classList.add('hidden');
            }
        }

        // 初始化应用
        document.addEventListener('DOMContentLoaded', function() {
            createParticles();
            
            // 检查URL参数是否有调试模式
            const urlParams = new URLSearchParams(window.location.search);
            if (urlParams.get('debug') === 'true') {
                toggleDebugMode();
            }
            
            addDebugInfo('应用初始化开始');
            addDebugInfo('当前authToken: ' + (authToken ? '已存在' : '不存在'));
            
            if (authToken) {
                addDebugInfo('尝试验证现有认证令牌');
                verifyAuth();
            } else {
                addDebugInfo('显示登录界面');
                showAuthSection();
            }
            
            setupEventListeners();
        });

        // 设置事件监听器
        function setupEventListeners() {
            const loginBtn = document.getElementById('oauthLoginBtn');
            if (loginBtn) {
                loginBtn.addEventListener('click', handleOAuthLogin);
                addDebugInfo('OAuth登录按钮事件监听器已设置');
            }
            
            const searchInput = document.getElementById('searchInput');
            const categoryFilter = document.getElementById('categoryFilter');
            
            if (searchInput) {
                // 防抖搜索
                let searchTimeout;
                searchInput.addEventListener('input', function() {
                    clearTimeout(searchTimeout);
                    searchTimeout = setTimeout(() => {
                        filterPasswords();
                    }, 500);
                });
            }
            
            if (categoryFilter) {
                categoryFilter.addEventListener('change', filterPasswords);
            }
            
            const passwordForm = document.getElementById('passwordForm');
            if (passwordForm) {
                passwordForm.addEventListener('submit', handlePasswordSubmit);
            }
            
            const passwordLength = document.getElementById('passwordLength');
            if (passwordLength) {
                passwordLength.addEventListener('input', function() {
                    document.getElementById('lengthValue').textContent = this.value;
                });
            }
            
            document.addEventListener('keydown', function(e) {
                // 调试模式快捷键
                if (e.ctrlKey && e.shiftKey && e.key === 'D') {
                    e.preventDefault();
                    toggleDebugMode();
                }
                if (e.key === 'Escape') {
                    // 关闭模态框等
                }
                if (e.ctrlKey && e.key === 'k') {
                    e.preventDefault();
                    const searchInput = document.getElementById('searchInput');
                    if (searchInput) {
                        searchInput.focus();
                    }
                }
            });
        }

        // 标签页切换
        function switchTab(tabName) {
            // 移除所有活动状态
            document.querySelectorAll('.nav-tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            
            // 激活当前标签
            event.target.classList.add('active');
            document.getElementById(tabName + '-tab').classList.add('active');
            currentTab = tabName;
            
            addDebugInfo('切换到标签页: ' + tabName);
            
            // 如果切换到密码管理页面，刷新数据
            if (tabName === 'passwords') {
                loadPasswords(1);
            }
        }

        // OAuth登录处理
        async function handleOAuthLogin() {
            const button = document.getElementById('oauthLoginBtn');
            const originalText = button.innerHTML;
            
            try {
                addDebugInfo('开始 OAuth 登录流程');
                
                button.innerHTML = '<div class="loading"></div> 正在获取授权链接...';
                button.disabled = true;
                
                addDebugInfo('发送请求到 /api/oauth/login');
                
                const response = await fetch('/api/oauth/login', {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({})
                });
                
                addDebugInfo('OAuth 登录响应状态: ' + response.status);
                
                if (!response.ok) {
                    const errorText = await response.text();
                    addDebugInfo('OAuth 登录失败响应: ' + errorText, 'error');
                    throw new Error('HTTP ' + response.status + ': ' + errorText);
                }
                
                const data = await response.json();
                addDebugInfo('OAuth 登录响应数据: ' + JSON.stringify(data), 'success');
                
                if (data.error) {
                    addDebugInfo('OAuth 配置错误: ' + data.error, 'error');
                    if (data.config) {
                        addDebugInfo('OAuth 配置详情: ' + JSON.stringify(data.config), 'error');
                    }
                    throw new Error(data.error + (data.details ? ': ' + data.details : ''));
                }
                
                if (!data.authUrl) {
                    addDebugInfo('响应中缺少 authUrl', 'error');
                    throw new Error('响应中缺少授权URL');
                }
                
                addDebugInfo('准备跳转到: ' + data.authUrl, 'success');
                
                // 更新按钮状态
                button.innerHTML = '<div class="loading"></div> 正在跳转到授权页面...';
                
                // 延迟跳转，让用户看到状态变化
                setTimeout(() => {
                    addDebugInfo('执行页面跳转', 'success');
                    window.location.href = data.authUrl;
                }, 1000);
                
            } catch (error) {
                addDebugInfo('OAuth 登录错误: ' + error.message, 'error');
                console.error('OAuth登录失败:', error);
                
                showNotification('登录失败: ' + error.message, 'error');
                
                button.innerHTML = originalText;
                button.disabled = false;
            }
        }

        // 验证登录状态
        async function verifyAuth() {
            try {
                addDebugInfo('验证认证状态');
                
                const response = await fetch('/api/auth/verify', {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                addDebugInfo('认证验证响应状态: ' + response.status);
                
                const data = await response.json();
                addDebugInfo('认证验证响应: ' + JSON.stringify(data));
                
                if (data.authenticated) {
                    currentUser = data.user;
                    addDebugInfo('认证成功，用户: ' + currentUser.username, 'success');
                    showMainApp();
                    loadData();
                } else {
                    addDebugInfo('认证失败: ' + (data.error || '未知错误'), 'error');
                    localStorage.removeItem('authToken');
                    authToken = null;
                    showAuthSection();
                }
            } catch (error) {
                addDebugInfo('认证验证异常: ' + error.message, 'error');
                console.error('Auth verification failed:', error);
                showAuthSection();
            }
        }

        // 显示界面
        function showAuthSection() {
            addDebugInfo('显示登录界面');
            document.getElementById('authSection').classList.remove('hidden');
            document.getElementById('mainApp').classList.add('hidden');
        }

        function showMainApp() {
            addDebugInfo('显示主应用界面');
            document.getElementById('authSection').classList.add('hidden');
            document.getElementById('mainApp').classList.remove('hidden');
            
            if (currentUser) {
                const displayName = currentUser.nickname || currentUser.username || '用户';
                document.getElementById('userName').textContent = displayName;
                document.getElementById('userEmail').textContent = currentUser.email || '';
                
                const avatar = document.getElementById('userAvatar');
                if (currentUser.avatar) {
                    avatar.innerHTML = '<img src="' + currentUser.avatar + '" alt="用户头像">';
                } else {
                    avatar.innerHTML = displayName.charAt(0).toUpperCase();
                }
                
                addDebugInfo('用户信息已更新: ' + displayName, 'success');
            }
        }

        // 加载数据
        async function loadData() {
            addDebugInfo('开始加载应用数据');
            await Promise.all([
                loadPasswords(1),
                loadCategories()
            ]);
            addDebugInfo('应用数据加载完成');
        }

        // 加载密码列表 - 支持分页
        async function loadPasswords(page = 1, search = '', category = '') {
            try {
                addDebugInfo('加载密码列表 - 页码: ' + page + ', 搜索: ' + search + ', 分类: ' + category);
                
                currentPage = page;
                searchQuery = search;
                categoryFilter = category;
                
                const params = new URLSearchParams({
                    page: page.toString(),
                    limit: pageLimit.toString()
                });
                
                if (search) params.append('search', search);
                if (category) params.append('category', category);
                
                const response = await fetch('/api/passwords?' + params, {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                
                const data = await response.json();
                passwords = data.passwords || [];
                
                addDebugInfo('加载了 ' + passwords.length + ' 个密码条目');
                
                if (data.pagination) {
                    currentPage = data.pagination.page;
                    totalPages = data.pagination.totalPages;
                    updatePaginationInfo(data.pagination);
                    addDebugInfo('分页信息: ' + JSON.stringify(data.pagination));
                }
                
                renderPasswords();
                renderPagination(data.pagination);
            } catch (error) {
                addDebugInfo('加载密码失败: ' + error.message, 'error');
                console.error('Failed to load passwords:', error);
                showNotification('加载密码失败', 'error');
            }
        }

        // 加载分类
        async function loadCategories() {
            try {
                addDebugInfo('加载分类列表');
                
                const response = await fetch('/api/categories', {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                categories = await response.json();
                updateCategorySelects();
                
                addDebugInfo('加载了 ' + categories.length + ' 个分类');
            } catch (error) {
                addDebugInfo('加载分类失败: ' + error.message, 'error');
                console.error('Failed to load categories:', error);
            }
        }

        // 更新分类选择器
        function updateCategorySelects() {
            const categoryFilterSelect = document.getElementById('categoryFilter');
            const categorySelect = document.getElementById('category');
            
            if (categoryFilterSelect) {
                categoryFilterSelect.innerHTML = '<option value="">🏷️ 所有分类</option>';
                categories.forEach(category => {
                    categoryFilterSelect.innerHTML += '<option value="' + category + '">🏷️ ' + category + '</option>';
                });
            }
            
            if (categorySelect) {
                categorySelect.innerHTML = '<option value="">选择分类</option>';
                categories.forEach(category => {
                    categorySelect.innerHTML += '<option value="' + category + '">' + category + '</option>';
                });
            }
        }

        // 渲染密码列表 - 列表形式
        function renderPasswords() {
            const list = document.getElementById('passwordsList');
            
            if (passwords.length === 0) {
                list.innerHTML = '<div class="empty-state"><div class="icon">🔑</div><h3>没有找到密码</h3><p>' + (searchQuery || categoryFilter ? '尝试调整搜索条件或清空筛选' : '点击"添加密码"标签页开始管理您的密码吧！') + '</p></div>';
                return;
            }
            
            list.innerHTML = passwords.map(password => 
                '<div class="password-item">' +
                    '<div class="password-item-content">' +
                        '<div class="password-item-icon">' +
                            '<i class="fas fa-globe"></i>' +
                        '</div>' +
                        '<div class="password-item-info">' +
                            '<div class="password-item-title">' + password.siteName + '</div>' +
                            '<div class="password-item-username">' +
                                '<i class="fas fa-user"></i>' +
                                '<span>' + password.username + '</span>' +
                            '</div>' +
                            (password.url ? '<a href="' + password.url + '" target="_blank" rel="noopener noreferrer" class="password-item-url">' + password.url + '</a>' : '') +
                        '</div>' +
                    '</div>' +
                    '<div class="password-item-meta">' +
                        (password.category ? '<span class="category-badge">' + password.category + '</span>' : '') +
                        '<div class="password-item-date">' +
                            new Date(password.updatedAt).toLocaleDateString() +
                        '</div>' +
                    '</div>' +
                    '<div class="password-item-actions">' +
                        '<button class="btn btn-secondary btn-sm" onclick="copyPassword(\'' + password.id + '\')" type="button" title="复制密码">' +
                            '<i class="fas fa-copy"></i>' +
                        '</button>' +
                        '<button class="btn btn-secondary btn-sm" onclick="editPassword(\'' + password.id + '\')" type="button" title="编辑">' +
                            '<i class="fas fa-edit"></i>' +
                        '</button>' +
                        '<button class="btn btn-danger btn-sm" onclick="deletePassword(\'' + password.id + '\')" type="button" title="删除">' +
                            '<i class="fas fa-trash"></i>' +
                        '</button>' +
                    '</div>' +
                '</div>'
            ).join('');
        }

        // 渲染分页
        function renderPagination(pagination) {
            let container = document.getElementById('paginationContainer');
            if (!container) {
                // 创建分页容器
                container = document.createElement('div');
                container.id = 'paginationContainer';
                container.className = 'pagination-container';
                document.getElementById('passwordsList').parentNode.appendChild(container);
            }
            
            if (!pagination || pagination.totalPages <= 1) {
                container.innerHTML = '';
                return;
            }
            
            let paginationHTML = '<div class="pagination"><div class="pagination-info">显示第 ' + (((pagination.page - 1) * pagination.limit) + 1) + '-' + Math.min(pagination.page * pagination.limit, pagination.total) + ' 条，共 ' + pagination.total + ' 条</div><div class="pagination-controls">';
            
            // 上一页按钮
            if (pagination.hasPrev) {
                paginationHTML += '<button class="btn btn-secondary btn-sm" onclick="loadPasswords(' + (pagination.page - 1) + ', \'' + searchQuery + '\', \'' + categoryFilter + '\')" type="button"><i class="fas fa-chevron-left"></i> 上一页</button>';
            }
            
            // 页码按钮
            const startPage = Math.max(1, pagination.page - 2);
            const endPage = Math.min(pagination.totalPages, pagination.page + 2);
            
            if (startPage > 1) {
                paginationHTML += '<button class="btn btn-secondary btn-sm" onclick="loadPasswords(1, \'' + searchQuery + '\', \'' + categoryFilter + '\')" type="button">1</button>';
                if (startPage > 2) {
                    paginationHTML += '<span class="pagination-ellipsis">...</span>';
                }
            }
            
            for (let i = startPage; i <= endPage; i++) {
                const isActive = i === pagination.page;
                paginationHTML += '<button class="btn ' + (isActive ? 'btn-primary' : 'btn-secondary') + ' btn-sm" onclick="loadPasswords(' + i + ', \'' + searchQuery + '\', \'' + categoryFilter + '\')" type="button"' + (isActive ? ' disabled' : '') + '>' + i + '</button>';
            }
            
            if (endPage < pagination.totalPages) {
                if (endPage < pagination.totalPages - 1) {
                    paginationHTML += '<span class="pagination-ellipsis">...</span>';
                }
                paginationHTML += '<button class="btn btn-secondary btn-sm" onclick="loadPasswords(' + pagination.totalPages + ', \'' + searchQuery + '\', \'' + categoryFilter + '\')" type="button">' + pagination.totalPages + '</button>';
            }
            
            // 下一页按钮
            if (pagination.hasNext) {
                paginationHTML += '<button class="btn btn-secondary btn-sm" onclick="loadPasswords(' + (pagination.page + 1) + ', \'' + searchQuery + '\', \'' + categoryFilter + '\')" type="button">下一页 <i class="fas fa-chevron-right"></i></button>';
            }
            
            paginationHTML += '</div></div>';
            
            container.innerHTML = paginationHTML;
        }

        // 更新分页信息
        function updatePaginationInfo(pagination) {
            addDebugInfo('分页信息更新: 第' + pagination.page + '页，共' + pagination.totalPages + '页');
        }

        // 过滤密码 - 支持分页
        function filterPasswords() {
            const searchTerm = document.getElementById('searchInput').value;
            const categoryFilter = document.getElementById('categoryFilter').value;
            
            addDebugInfo('过滤密码 - 搜索: ' + searchTerm + ', 分类: ' + categoryFilter);
            
            // 重置到第一页并重新加载
            loadPasswords(1, searchTerm, categoryFilter);
        }

        // 复制密码
        async function copyPassword(passwordId) {
            try {
                addDebugInfo('复制密码: ' + passwordId);
                
                const response = await fetch('/api/passwords/' + passwordId + '/reveal', {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                const data = await response.json();
                await navigator.clipboard.writeText(data.password);
                showNotification('密码已复制到剪贴板 📋');
            } catch (error) {
                addDebugInfo('复制密码失败: ' + error.message, 'error');
                showNotification('复制失败', 'error');
            }
        }

        // 编辑密码
        function editPassword(passwordId) {
            const password = passwords.find(p => p.id === passwordId);
            if (!password) return;
            
            addDebugInfo('编辑密码: ' + passwordId);
            
            editingPasswordId = passwordId;
            
            document.getElementById('siteName').value = password.siteName;
            document.getElementById('username').value = password.username;
            document.getElementById('password').value = '';
            document.getElementById('category').value = password.category || '';
            document.getElementById('url').value = password.url || '';
            document.getElementById('notes').value = password.notes || '';
            
            // 切换到添加密码标签页
            switchTab('add-password');
            
            // 更新按钮文本
            const submitBtn = document.querySelector('#passwordForm button[type="submit"]');
            submitBtn.innerHTML = '<i class="fas fa-save"></i> 更新密码';
        }

        // 删除密码 - 支持分页
        async function deletePassword(passwordId) {
            if (!confirm('🗑️ 确定要删除这个密码吗？此操作无法撤销。')) return;
            
            try {
                addDebugInfo('删除密码: ' + passwordId);
                
                const response = await fetch('/api/passwords/' + passwordId, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                if (response.ok) {
                    showNotification('密码已删除 🗑️');
                    // 重新加载当前页
                    loadPasswords(currentPage, searchQuery, categoryFilter);
                } else {
                    showNotification('删除失败', 'error');
                }
            } catch (error) {
                addDebugInfo('删除密码失败: ' + error.message, 'error');
                showNotification('删除失败', 'error');
            }
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
            
            // 如果是编辑模式，添加ID
            if (editingPasswordId) {
                formData.id = editingPasswordId;
            }
            
            addDebugInfo('提交密码表单: ' + JSON.stringify(formData));
            
            try {
                const url = editingPasswordId ? '/api/passwords/' + editingPasswordId : '/api/passwords';
                const method = editingPasswordId ? 'PUT' : 'POST';
                
                addDebugInfo('发送密码保存请求: ' + method + ' ' + url);
                
                const response = await fetch(url, {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify(formData)
                });
                
                addDebugInfo('密码保存响应状态: ' + response.status);
                
                if (response.ok) {
                    showNotification(editingPasswordId ? '密码已更新 ✅' : '密码已添加 ✅');
                    clearForm();
                    loadPasswords(currentPage, searchQuery, categoryFilter);
                } else {
                    const errorData = await response.json();
                    addDebugInfo('密码保存失败: ' + JSON.stringify(errorData), 'error');
                    showNotification(errorData.message || '保存失败', 'error');
                }
            } catch (error) {
                addDebugInfo('密码表单提交异常: ' + error.message, 'error');
                showNotification('保存失败', 'error');
            }
        }

        // 清空表单
        function clearForm() {
            document.getElementById('passwordForm').reset();
            document.getElementById('lengthValue').textContent = '16';
            editingPasswordId = null;
            
            // 恢复按钮文本
            const submitBtn = document.querySelector('#passwordForm button[type="submit"]');
            submitBtn.innerHTML = '<i class="fas fa-save"></i> 保存密码';
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
                addDebugInfo('生成密码，选项: ' + JSON.stringify(options));
                
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
                showNotification('强密码已生成 🎲');
            } catch (error) {
                addDebugInfo('生成密码失败: ' + error.message, 'error');
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

        // 登出
        async function logout() {
            try {
                addDebugInfo('执行登出操作');
                
                await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
            } catch (error) {
                addDebugInfo('登出请求失败: ' + error.message, 'error');
                console.error('Logout error:', error);
            }
            
            localStorage.removeItem('authToken');
            authToken = null;
            currentUser = null;
            showAuthSection();
            addDebugInfo('登出完成', 'success');
        }

        // 显示通知
        function showNotification(message, type = 'success') {
            const notification = document.createElement('div');
            notification.className = 'notification ' + type;
            
            const icons = {
                success: 'check-circle',
                error: 'exclamation-triangle',
                warning: 'exclamation-circle',
                info: 'info-circle'
            };
            
            notification.innerHTML = '<i class="fas fa-' + (icons[type] || icons.success) + '"></i>' + message;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.classList.add('show');
            }, 100);
            
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => {
                    if (document.body.contains(notification)) {
                        document.body.removeChild(notification);
                    }
                }, 300);
            }, 3000);
        }
    </script>
</body>
</html>`;
}
