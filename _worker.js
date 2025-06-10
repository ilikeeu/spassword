export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
    
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    
    try {
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
        if (path.endsWith('/reveal')) {
          return getActualPassword(request, env, corsHeaders);
        }
        return handlePasswords(request, env, corsHeaders);
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

async function handleOAuthLogin(request, env, corsHeaders) {
  const state = generateRandomString(32);
  const authUrl = new URL(`${env.OAUTH_BASE_URL}/oauth/authorize`);
  
  authUrl.searchParams.set('client_id', env.OAUTH_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', env.OAUTH_REDIRECT_URI);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('state', state);
  
  await env.PASSWORD_KV.put(`oauth_state_${state}`, 'valid', { expirationTtl: 600 });
  
  return new Response(JSON.stringify({ authUrl: authUrl.toString() }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

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
  
  const storedState = await env.PASSWORD_KV.get(`oauth_state_${state}`);
  if (!storedState) {
    return new Response('Invalid state', { status: 400, headers: corsHeaders });
  }
  
  await env.PASSWORD_KV.delete(`oauth_state_${state}`);
  
  try {
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
    
    if (!tokenResponse.ok) {
      throw new Error(`Token exchange failed: ${tokenResponse.status}`);
    }
    
    const tokenData = await tokenResponse.json();
    
    if (!tokenData.access_token) {
      throw new Error('No access token received');
    }
    
    const userResponse = await fetch(`${env.OAUTH_BASE_URL}/api/user`, {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'Accept': 'application/json'
      }
    });
    
    if (!userResponse.ok) {
      throw new Error(`Failed to get user info: ${userResponse.status}`);
    }
    
    const userData = await userResponse.json();
    
    const sessionToken = generateRandomString(64);
    const userSession = {
      userId: userData.id.toString(),
      username: userData.username,
      nickname: userData.nickname,
      email: userData.email,
      avatar: userData.avatar_url || 'https://yanxuan.nosdn.127.net/233a2a8170847d3287ec058c51cf60a9.jpg',
      loginAt: new Date().toISOString()
    };
    
    await env.PASSWORD_KV.put(`session_${sessionToken}`, JSON.stringify(userSession), { 
      expirationTtl: 86400 * 7
    });
    
    return new Response(`
      <!DOCTYPE html>
      <html><head><meta charset="UTF-8"><title>登录成功</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);margin:0}.message{background:white;padding:30px;border-radius:15px;text-align:center;box-shadow:0 10px 25px rgba(0,0,0,0.1)}.loading{display:inline-block;width:20px;height:20px;border:3px solid #f3f3f3;border-top:3px solid #667eea;border-radius:50%;animation:spin 1s linear infinite;margin-right:10px}@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}</style></head><body><div class="message"><div class="loading"></div>登录成功，正在跳转...</div><script>localStorage.setItem('authToken','${sessionToken}');setTimeout(()=>{window.location.href='/'},1000)</script></body></html>
    `, {
      headers: { 'Content-Type': 'text/html', ...corsHeaders }
    });
    
  } catch (error) {
    console.error('OAuth callback error:', error);
    return new Response(`
      <!DOCTYPE html>
      <html><head><meta charset="UTF-8"><title>登录失败</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);margin:0}.message{background:white;padding:30px;border-radius:15px;text-align:center;box-shadow:0 10px 25px rgba(0,0,0,0.1);color:#e53e3e}.btn{background:#667eea;color:white;border:none;padding:10px 20px;border-radius:5px;cursor:pointer;margin-top:15px}</style></head><body><div class="message"><h3>登录失败</h3><p>${error.message}</p><button class="btn" onclick="window.location.href='/'">返回首页</button></div></body></html>
    `, { 
      status: 500, 
      headers: { 'Content-Type': 'text/html', ...corsHeaders }
    });
  }
}

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

async function handleLogout(request, env, corsHeaders) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  
  if (token) {
    await env.PASSWORD_KV.delete(`session_${token}`);
  }
  
  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

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
        const list = await env.PASSWORD_KV.list({ prefix: `password_${userId}_` });
        const passwords = [];
        
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
      const updatedPassword = { ...JSON.parse(existingPassword), ...updateData };
      updatedPassword.updatedAt = new Date().toISOString();
      
      if (updateData.password) {
        updatedPassword.password = await encryptPassword(updateData.password, userId);
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

async function handleEncryptedExport(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  const { exportPassword } = await request.json();
  if (!exportPassword) {
    return new Response(JSON.stringify({ error: '需要导出密码' }), {
      status: 400,
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
      passwordData.password = await decryptPassword(passwordData.password, userId);
      passwords.push(passwordData);
    }
  }
  
  const exportData = {
    exportDate: new Date().toISOString(),
    version: '1.0',
    encrypted: true,
    passwords: passwords
  };
  
  const encryptedData = await encryptExportData(JSON.stringify(exportData), exportPassword);
  
  return new Response(JSON.stringify({
    encrypted: true,
    data: encryptedData,
    exportDate: new Date().toISOString()
  }, null, 2), {
    headers: { 
      'Content-Type': 'application/json',
      'Content-Disposition': 'attachment; filename="passwords-encrypted-export.json"',
      ...corsHeaders 
    }
  });
}

async function handleEncryptedImport(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  const { encryptedData, importPassword } = await request.json();
  
  if (!encryptedData || !importPassword) {
    return new Response(JSON.stringify({ error: '缺少加密数据或密码' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  try {
    const decryptedText = await decryptExportData(encryptedData, importPassword);
    const importData = JSON.parse(decryptedText);
    
    const userId = session.userId;
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
  } catch (error) {
    return new Response(JSON.stringify({ error: '解密失败，请检查密码' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

async function handleWebDAV(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  const url = new URL(request.url);
  const action = url.pathname.split('/').pop();
  
  switch (action) {
    case 'config':
      return handleWebDAVConfig(request, env, corsHeaders, session);
    case 'backup':
      return handleWebDAVBackup(request, env, corsHeaders, session);
    case 'restore':
      return handleWebDAVRestore(request, env, corsHeaders, session);
    case 'delete':
      return handleWebDAVDelete(request, env, corsHeaders, session);
    case 'list':
      return handleWebDAVList(request, env, corsHeaders, session);
    default:
      return new Response('Invalid action', { status: 400, headers: corsHeaders });
  }
}

async function handleWebDAVConfig(request, env, corsHeaders, session) {
  const userId = session.userId;
  
  if (request.method === 'GET') {
    const config = await env.PASSWORD_KV.get(`webdav_config_${userId}`);
    if (config) {
      const configData = JSON.parse(config);
      return new Response(JSON.stringify({
        url: configData.url,
        username: configData.username,
        hasPassword: !!configData.password
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    return new Response(JSON.stringify({}), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  if (request.method === 'POST') {
    const { url, username, password } = await request.json();
    
    if (!url || !username || !password) {
      return new Response(JSON.stringify({ error: '缺少必要配置' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    
    const encryptedPassword = await encryptPassword(password, userId);
    const config = { url, username, password: encryptedPassword };
    
    await env.PASSWORD_KV.put(`webdav_config_${userId}`, JSON.stringify(config));
    
    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  return new Response('Method not allowed', { status: 405, headers: corsHeaders });
}

async function getWebDAVConfig(env, userId) {
  const config = await env.PASSWORD_KV.get(`webdav_config_${userId}`);
  if (!config) {
    throw new Error('WebDAV配置不存在');
  }
  
  const configData = JSON.parse(config);
  const decryptedPassword = await decryptPassword(configData.password, userId);
  
  return {
    url: configData.url,
    username: configData.username,
    password: decryptedPassword
  };
}

async function handleWebDAVBackup(request, env, corsHeaders, session) {
  const { filename, backupPassword } = await request.json();
  
  if (!backupPassword) {
    return new Response(JSON.stringify({ error: '需要备份密码' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  try {
    const config = await getWebDAVConfig(env, session.userId);
    
    const userId = session.userId;
    const list = await env.PASSWORD_KV.list({ prefix: `password_${userId}_` });
    const passwords = [];
    
    for (const key of list.keys) {
      const data = await env.PASSWORD_KV.get(key.name);
      if (data) {
        const passwordData = JSON.parse(data);
        passwordData.password = await decryptPassword(passwordData.password, userId);
        passwords.push(passwordData);
      }
    }
    
    const backupData = {
      backupDate: new Date().toISOString(),
      version: '1.0',
      user: session.username,
      passwords: passwords
    };
    
    const encryptedBackup = await encryptExportData(JSON.stringify(backupData), backupPassword);
    const backupFilename = filename || `password-backup-${new Date().toISOString().split('T')[0]}.json`;
    
    const uploadUrl = `${config.url.replace(/\/$/, '')}/${backupFilename}`;
    const uploadResponse = await fetch(uploadUrl, {
      method: 'PUT',
      headers: {
        'Authorization': `Basic ${btoa(`${config.username}:${config.password}`)}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        encrypted: true,
        data: encryptedBackup,
        backupDate: new Date().toISOString()
      })
    });
    
    if (uploadResponse.ok) {
      return new Response(JSON.stringify({ 
        success: true, 
        message: '加密备份成功',
        filename: backupFilename
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } else {
      throw new Error(`Upload failed: ${uploadResponse.status}`);
    }
  } catch (error) {
    return new Response(JSON.stringify({ 
      error: `备份失败: ${error.message}` 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

async function handleWebDAVRestore(request, env, corsHeaders, session) {
  const { filename, restorePassword } = await request.json();
  
  if (!filename || !restorePassword) {
    return new Response(JSON.stringify({ error: '缺少文件名或恢复密码' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  try {
    const config = await getWebDAVConfig(env, session.userId);
    
    const downloadUrl = `${config.url.replace(/\/$/, '')}/${filename}`;
    const downloadResponse = await fetch(downloadUrl, {
      headers: {
        'Authorization': `Basic ${btoa(`${config.username}:${config.password}`)}`,
      }
    });
    
    if (!downloadResponse.ok) {
      throw new Error(`Download failed: ${downloadResponse.status}`);
    }
    
    const encryptedBackup = await downloadResponse.json();
    const decryptedText = await decryptExportData(encryptedBackup.data, restorePassword);
    const backupData = JSON.parse(decryptedText);
    
    const userId = session.userId;
    let imported = 0;
    let errors = 0;
    
    for (const passwordData of backupData.passwords || []) {
      try {
        const newPassword = {
          ...passwordData,
          id: generateId(),
          userId: userId,
          restoredAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };
        
        newPassword.password = await encryptPassword(passwordData.password, userId);
        
        await env.PASSWORD_KV.put(`password_${userId}_${newPassword.id}`, JSON.stringify(newPassword));
        imported++;
      } catch (error) {
        errors++;
      }
    }
    
    return new Response(JSON.stringify({ 
      success: true, 
      imported, 
      errors,
      message: `恢复完成：成功 ${imported} 条，失败 ${errors} 条`
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  } catch (error) {
    return new Response(JSON.stringify({ 
      error: `恢复失败: ${error.message}` 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

async function handleWebDAVDelete(request, env, corsHeaders, session) {
  const { filename } = await request.json();
  
  if (!filename) {
    return new Response(JSON.stringify({ error: '缺少文件名' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  try {
    const config = await getWebDAVConfig(env, session.userId);
    
    const deleteUrl = `${config.url.replace(/\/$/, '')}/${filename}`;
    const deleteResponse = await fetch(deleteUrl, {
      method: 'DELETE',
      headers: {
        'Authorization': `Basic ${btoa(`${config.username}:${config.password}`)}`,
      }
    });
    
    if (deleteResponse.ok) {
      return new Response(JSON.stringify({ 
        success: true, 
        message: '删除成功' 
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } else {
      throw new Error(`Delete failed: ${deleteResponse.status}`);
    }
  } catch (error) {
    return new Response(JSON.stringify({ 
      error: `删除失败: ${error.message}` 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

async function handleWebDAVList(request, env, corsHeaders, session) {
  try {
    const config = await getWebDAVConfig(env, session.userId);
    
    const listResponse = await fetch(config.url, {
      method: 'PROPFIND',
      headers: {
        'Authorization': `Basic ${btoa(`${config.username}:${config.password}`)}`,
        'Depth': '1'
      }
    });
    
    if (listResponse.ok) {
      const xmlText = await listResponse.text();
      const files = [];
      const regex = /<d:href>([^<]+\.json)<\/d:href>/g;
      let match;
      
      while ((match = regex.exec(xmlText)) !== null) {
        const filename = match[1].split('/').pop();
        if (filename.includes('password-backup')) {
          files.push(filename);
        }
      }
      
      return new Response(JSON.stringify({ 
        success: true, 
        files 
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } else {
      throw new Error(`List failed: ${listResponse.status}`);
    }
  } catch (error) {
    return new Response(JSON.stringify({ 
      error: `获取文件列表失败: ${error.message}` 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

async function verifySession(request, env) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return null;
  
  const session = await env.PASSWORD_KV.get(`session_${token}`);
  return session ? JSON.parse(session) : null;
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

async function encryptExportData(data, password) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password.slice(0, 32).padEnd(32, '0')),
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );
  
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(data)
  );
  
  return btoa(String.fromCharCode(...iv) + String.fromCharCode(...new Uint8Array(encrypted)));
}

async function decryptExportData(encryptedData, password) {
  const data = atob(encryptedData);
  const iv = new Uint8Array(data.slice(0, 12).split('').map(c => c.charCodeAt(0)));
  const encrypted = new Uint8Array(data.slice(12).split('').map(c => c.charCodeAt(0)));
  
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password.slice(0, 32).padEnd(32, '0')),
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

function getHTML() {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><meta name="description" content="安全、便捷、智能的密码管理解决方案"><title>🔐 密码管理器 Pro</title><link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🔐</text></svg>"><style>:root{--primary:#6366f1;--primary-dark:#4f46e5;--secondary:#8b5cf6;--success:#10b981;--warning:#f59e0b;--danger:#ef4444;--info:#3b82f6;--dark:#1f2937;--light:#f8fafc;--border:#e5e7eb;--text-primary:#111827;--text-secondary:#6b7280;--bg-gradient:linear-gradient(135deg,#667eea 0%,#764ba2 100%);--card-bg:rgba(255,255,255,0.95);--shadow-md:0 4px 6px -1px rgba(0,0,0,0.1);--shadow-lg:0 10px 15px -3px rgba(0,0,0,0.1);--radius-md:12px;--radius-lg:16px;--radius-xl:20px;--transition:0.3s ease}*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}html{font-size:16px;scroll-behavior:smooth}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg-gradient);min-height:100vh;color:var(--text-primary);line-height:1.6;-webkit-font-smoothing:antialiased}.particles{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:-1;overflow:hidden}.particle{position:absolute;background:rgba(255,255,255,0.1);border-radius:50%;animation:float 20s infinite linear}@keyframes float{0%{transform:translateY(100vh) rotate(0deg);opacity:0}10%{opacity:1}90%{opacity:1}100%{transform:translateY(-100px) rotate(360deg);opacity:0}}@keyframes slideInUp{from{opacity:0;transform:translateY(30px)}to{opacity:1;transform:translateY(0)}}@keyframes slideInDown{from{opacity:0;transform:translateY(-30px)}to{opacity:1;transform:translateY(0)}}@keyframes slideInLeft{from{opacity:0;transform:translateX(-30px)}to{opacity:1;transform:translateX(0)}}@keyframes fadeIn{from{opacity:0}to{opacity:1}}@keyframes pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.05)}}@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}.auth-section{display:flex;justify-content:center;align-items:center;min-height:100vh;padding:1.25rem}.auth-card{background:var(--card-bg);backdrop-filter:blur(20px);padding:3.125rem 2.5rem;border-radius:var(--radius-xl);box-shadow:var(--shadow-lg);text-align:center;max-width:28.125rem;width:100%;border:1px solid rgba(255,255,255,0.2);animation:slideInUp 0.6s ease-out}.auth-card .logo{font-size:4rem;margin-bottom:1.5rem;background:linear-gradient(135deg,var(--primary),var(--secondary));-webkit-background-clip:text;-webkit-text-fill-color:transparent;animation:pulse 2s infinite}.auth-card h1{color:var(--text-primary);margin-bottom:0.75rem;font-size:2rem;font-weight:700}.auth-card p{color:var(--text-secondary);margin-bottom:2.5rem;font-size:1rem}.app-container{max-width:87.5rem;margin:0 auto;padding:1.25rem}.app-header{background:var(--card-bg);backdrop-filter:blur(20px);padding:1.5rem;border-radius:var(--radius-lg);box-shadow:var(--shadow-lg);margin-bottom:1.875rem;display:flex;justify-content:space-between;align-items:center;border:1px solid rgba(255,255,255,0.2);animation:slideInDown 0.6s ease-out}.user-profile{display:flex;align-items:center;gap:1rem}.user-avatar{width:3.5rem;height:3.5rem;border-radius:50%;background:linear-gradient(135deg,var(--primary),var(--secondary));display:flex;align-items:center;justify-content:center;color:white;font-weight:bold;font-size:1.25rem;overflow:hidden;box-shadow:var(--shadow-md);transition:transform var(--transition)}.user-avatar:hover{transform:scale(1.05)}.user-avatar img{width:100%;height:100%;object-fit:cover}.user-info h2{color:var(--text-primary);margin-bottom:0.25rem;font-size:1.125rem;font-weight:600}.user-info p{color:var(--text-secondary);font-size:0.875rem}.header-actions{display:flex;gap:0.75rem;flex-wrap:wrap}.app-toolbar{background:var(--card-bg);backdrop-filter:blur(20px);padding:1.5rem;border-radius:var(--radius-lg);box-shadow:var(--shadow-lg);margin-bottom:1.875rem;display:flex;flex-wrap:wrap;gap:1rem;align-items:center;border:1px solid rgba(255,255,255,0.2);animation:slideInLeft 0.6s ease-out}.search-container{flex:1;min-width:18.75rem;position:relative}.search-input{width:100%;padding:0.875rem 1rem 0.875rem 3rem;border:2px solid var(--border);border-radius:50px;font-size:1rem;transition:all var(--transition);background:rgba(255,255,255,0.8)}.search-input:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(99,102,241,0.1)}.search-icon{position:absolute;left:1rem;top:50%;transform:translateY(-50%);color:var(--text-secondary);font-size:1.125rem}.filter-select{padding:0.875rem 1.25rem;border:2px solid var(--border);border-radius:50px;font-size:1rem;background:rgba(255,255,255,0.8);cursor:pointer;transition:all var(--transition)}.filter-select:focus{outline:none;border-color:var(--primary)}.btn{padding:0.75rem 1.5rem;border:none;border-radius:50px;font-size:1rem;font-weight:600;cursor:pointer;transition:all var(--transition);display:inline-flex;align-items:center;gap:0.5rem;text-decoration:none;box-shadow:0 1px 2px 0 rgba(0,0,0,0.05);white-space:nowrap}.btn:hover{transform:translateY(-2px);box-shadow:var(--shadow-md)}.btn:active{transform:translateY(0)}.btn:disabled{opacity:0.6;cursor:not-allowed;transform:none}.btn-primary{background:linear-gradient(135deg,var(--primary),var(--primary-dark));color:white}.btn-secondary{background:#f1f5f9;color:var(--text-primary)}.btn-danger{background:linear-gradient(135deg,var(--danger),#dc2626);color:white}.btn-success{background:linear-gradient(135deg,var(--success),#059669);color:white}.btn-warning{background:linear-gradient(135deg,var(--warning),#d97706);color:white}.btn-info{background:linear-gradient(135deg,var(--info),#2563eb);color:white}.btn-sm{padding:0.5rem 1rem;font-size:0.875rem}.btn-lg{padding:1rem 2rem;font-size:1.125rem}.passwords-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(23.75rem,1fr));gap:1.5rem;animation:fadeIn 0.6s ease-out}.password-card{background:var(--card-bg);backdrop-filter:blur(20px);border-radius:var(--radius-lg);padding:1.75rem;box-shadow:var(--shadow-lg);transition:all var(--transition);position:relative;border:1px solid rgba(255,255,255,0.2);overflow:hidden}.password-card::before{content:'';position:absolute;top:0;left:0;right:0;height:4px;background:linear-gradient(90deg,var(--primary),var(--secondary))}.password-card:hover{transform:translateY(-8px);box-shadow:0 20px 25px -5px rgba(0,0,0,0.1)}.password-header{display:flex;align-items:center;gap:1rem;margin-bottom:1.5rem}.site-icon{width:3.5rem;height:3.5rem;border-radius:var(--radius-md);background:linear-gradient(135deg,var(--primary),var(--secondary));display:flex;align-items:center;justify-content:center;color:white;font-size:1.5rem;box-shadow:var(--shadow-md)}.password-meta h3{color:var(--text-primary);margin-bottom:0.5rem;font-size:1.25rem;font-weight:700}.category-badge{background:linear-gradient(135deg,var(--primary),var(--secondary));color:white;padding:0.25rem 0.75rem;border-radius:var(--radius-xl);font-size:0.75rem;font-weight:600;display:inline-block}.password-field{margin:1rem 0}.password-field label{display:block;color:var(--text-secondary);font-size:0.875rem;font-weight:600;margin-bottom:0.375rem;text-transform:uppercase;letter-spacing:0.5px}.password-field .value{color:var(--text-primary);font-size:1rem;word-break:break-all;font-family:'SF Mono','Monaco','Cascadia Code',monospace}.password-field .value a{color:var(--primary);text-decoration:none}.password-field .value a:hover{text-decoration:underline}.password-actions{display:flex;gap:0.5rem;margin-top:1.5rem;flex-wrap:wrap}.password-actions .btn{flex:1;min-width:5rem;justify-content:center}.empty-state{grid-column:1/-1;text-align:center;padding:5rem 1.25rem;color:var(--text-secondary)}.empty-state .icon{font-size:4rem;margin-bottom:1.5rem;opacity:0.5;background:linear-gradient(135deg,var(--primary),var(--secondary));-webkit-background-clip:text;-webkit-text-fill-color:transparent}.empty-state h3{font-size:1.5rem;margin-bottom:0.75rem;color:var(--text-primary)}.empty-state p{font-size:1rem}.form-group{margin-bottom:1.5rem}.form-group label{display:block;color:var(--text-primary);margin-bottom:0.5rem;font-weight:600;font-size:0.875rem}.form-control{width:100%;padding:0.875rem 1rem;border:2px solid var(--border);border-radius:var(--radius-md);font-size:1rem;transition:all var(--transition);background:rgba(255,255,255,0.8)}.form-control:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(99,102,241,0.1)}.input-group{position:relative}.input-group-append{position:absolute;right:1rem;top:50%;transform:translateY(-50%)}.toggle-btn{background:none;border:none;cursor:pointer;color:var(--text-secondary);padding:0.5rem;border-radius:8px;transition:all var(--transition)}.toggle-btn:hover{background:var(--border);color:var(--text-primary)}.password-generator{background:linear-gradient(135deg,#f8fafc,#f1f5f9);padding:1.5rem;border-radius:var(--radius-md);margin-bottom:1.5rem;border:2px solid var(--border)}.password-generator h4{color:var(--text-primary);margin-bottom:1rem;font-size:1rem;font-weight:700}.generator-options{display:grid;grid-template-columns:repeat(auto-fit,minmax(12.5rem,1fr));gap:1rem;margin-bottom:1rem}.checkbox-group{display:flex;align-items:center;gap:0.5rem}.checkbox-group input[type="checkbox"]{width:auto;accent-color:var(--primary)}.range-group{display:flex;flex-direction:column;gap:0.5rem}.range-input{width:100%;accent-color:var(--primary)}.range-value{font-weight:600;color:var(--primary)}.category-manager{background:linear-gradient(135deg,#f8fafc,#f1f5f9);padding:1.25rem;border-radius:var(--radius-md);margin-bottom:1.5rem;border:2px solid var(--border)}.category-input-group{display:flex;gap:0.75rem;margin-bottom:1rem}.category-input-group input{flex:1}.category-tags{display:flex;flex-wrap:wrap;gap:0.5rem}.category-tag{background:linear-gradient(135deg,var(--primary),var(--secondary));color:white;padding:0.375rem 0.75rem;border-radius:var(--radius-xl);font-size:0.75rem;font-weight:600;display:flex;align-items:center;gap:0.375rem}.category-tag .remove{cursor:pointer;opacity:0.7;transition:opacity var(--transition)}.category-tag .remove:hover{opacity:1}.webdav-section{background:linear-gradient(135deg,#f0f9ff,#e0f2fe);padding:1.5rem;border-radius:var(--radius-md);margin-bottom:1.5rem;border:2px solid #bae6fd}.webdav-section h4{color:var(--text-primary);margin-bottom:1rem;font-size:1.125rem;font-weight:700;display:flex;align-items:center;gap:0.5rem}.backup-files{max-height:12.5rem;overflow-y:auto;border:1px solid var(--border);border-radius:8px;padding:0.75rem;background:white}.backup-file{display:flex;justify-content:space-between;align-items:center;padding:0.5rem 0;border-bottom:1px solid var(--border)}.backup-file:last-child{border-bottom:none}.backup-file-actions{display:flex;gap:0.5rem}.notification{position:fixed;top:1.5rem;right:1.5rem;background:var(--success);color:white;padding:1rem 1.5rem;border-radius:var(--radius-md);box-shadow:var(--shadow-lg);z-index:1001;transform:translateX(25rem);transition:transform var(--transition);display:flex;align-items:center;gap:0.75rem;font-weight:600;max-width:20rem}.notification.show{transform:translateX(0)}.notification.error{background:var(--danger)}.notification.warning{background:var(--warning)}.notification.info{background:var(--info)}.loading{display:inline-block;width:1.25rem;height:1.25rem;border:3px solid rgba(255,255,255,0.3);border-top:3px solid white;border-radius:50%;animation:spin 1s linear infinite}.hidden{display:none!important}.text-center{text-align:center}.text-left{text-align:left}.text-right{text-align:right}.mb-0{margin-bottom:0}.mb-1{margin-bottom:0.25rem}.mb-2{margin-bottom:0.5rem}.mb-3{margin-bottom:0.75rem}.mb-4{margin-bottom:1rem}.mt-0{margin-top:0}.mt-1{margin-top:0.25rem}.mt-2{margin-top:0.5rem}.mt-3{margin-top:0.75rem}.mt-4{margin-top:1rem}.flex{display:flex}.flex-col{flex-direction:column}.items-center{align-items:center}.justify-center{justify-content:center}.justify-between{justify-content:space-between}.gap-1{gap:0.25rem}.gap-2{gap:0.5rem}.gap-3{gap:0.75rem}.gap-4{gap:1rem}.w-full{width:100%}.h-full{height:100%}@media (max-width:768px){.app-container{padding:0.75rem}.app-header{flex-direction:column;gap:1rem;text-align:center}.header-actions{justify-content:center}.app-toolbar{flex-direction:column;align-items:stretch}.search-container{min-width:auto}.passwords-grid{grid-template-columns:1fr}.password-actions{flex-direction:column}.generator-options{grid-template-columns:1fr}.notification{right:0.75rem;left:0.75rem;max-width:none;transform:translateY(-5rem)}.notification.show{transform:translateY(0)}}@media (max-width:480px){.auth-card{padding:2rem 1.5rem}.passwords-grid{gap:1rem}.password-card{padding:1.25rem}}@media (prefers-color-scheme:dark){:root{--text-primary:#f9fafb;--text-secondary:#d1d5db;--border:#374151;--card-bg:rgba(31,41,55,0.95);--light:#1f2937}}@media print{.particles,.header-actions,.app-toolbar,.password-actions{display:none!important}body{background:white}.password-card{break-inside:avoid;box-shadow:none;border:1px solid #e5e7eb}}</style></head><body><div class="particles" id="particles"></div><section id="authSection" class="auth-section"><article class="auth-card"><div class="logo">🔐</div><header><h1>密码管理器 Pro</h1><p>安全、便捷、智能的密码管理解决方案</p></header><button id="oauthLoginBtn" class="btn btn-primary btn-lg" type="button"><i class="fas fa-sign-in-alt"></i> 开始使用 OAuth 登录</button></article></section><div id="mainApp" class="app-container hidden"><header class="app-header"><div class="user-profile"><div class="user-avatar" id="userAvatar"><i class="fas fa-user"></i></div><div class="user-info"><h2 id="userName">用户名</h2><p id="userEmail">user@example.com</p></div></div><nav class="header-actions"><button class="btn btn-warning" onclick="showPage('webdav')" type="button"><i class="fas fa-cloud"></i> <span>备份</span></button><button class="btn btn-secondary" onclick="showPage('export')" type="button"><i class="fas fa-download"></i> <span>导出</span></button><button class="btn btn-secondary" onclick="showPage('import')" type="button"><i class="fas fa-upload"></i> <span>导入</span></button><button class="btn btn-danger" onclick="logout()" type="button"><i class="fas fa-sign-out-alt"></i> <span>登出</span></button></nav></header><section class="app-toolbar"><div class="search-container"><i class="fas fa-search search-icon"></i><input type="search" id="searchInput" class="search-input" placeholder="搜索网站、用户名或备注..."></div><div><select id="categoryFilter" class="filter-select"><option value="">🏷️ 所有分类</option></select></div><button class="btn btn-primary" onclick="showPage('add')" type="button"><i class="fas fa-plus"></i> <span>添加密码</span></button></section><main id="main-content"><div id="passwordsPage"><section class="passwords-grid" id="passwordsGrid"></section></div><div id="addPage" class="hidden"><section class="webdav-section"><h4>✨ 添加新密码</h4><form id="passwordForm"><div class="form-group"><label for="siteName">🌐 网站名称 *</label><input type="text" id="siteName" class="form-control" required placeholder="例如：GitHub、Gmail"></div><div class="form-group"><label for="username">👤 用户名/邮箱 *</label><input type="text" id="username" class="form-control" required placeholder="your@email.com"></div><div class="form-group"><label for="password">🔑 密码 *</label><div class="input-group"><input type="password" id="password" class="form-control" required placeholder="输入密码"><div class="input-group-append"><button type="button" class="toggle-btn" onclick="togglePasswordVisibility('password')"><i class="fas fa-eye"></i></button></div></div></div><fieldset class="password-generator"><legend>🎲 智能密码生成器</legend><div class="generator-options"><div class="form-group"><label for="passwordLength">长度: <span id="lengthValue" class="range-value">16</span></label><input type="range" id="passwordLength" class="range-input" min="8" max="32" value="16"></div><div class="checkbox-group"><input type="checkbox" id="includeUppercase" checked><label for="includeUppercase">ABC 大写字母</label></div><div class="checkbox-group"><input type="checkbox" id="includeLowercase" checked><label for="includeLowercase">abc 小写字母</label></div><div class="checkbox-group"><input type="checkbox" id="includeNumbers" checked><label for="includeNumbers">123 数字</label></div><div class="checkbox-group"><input type="checkbox" id="includeSymbols"><label for="includeSymbols">!@# 特殊符号</label></div></div><button type="button" class="btn btn-secondary" onclick="generatePassword()"><i class="fas fa-magic"></i> 生成强密码</button></fieldset><fieldset class="category-manager"><legend>🏷️ 分类管理</legend><div class="category-input-group"><input type="text" id="newCategoryInput" class="form-control" placeholder="添加新分类"><button type="button" class="btn btn-primary" onclick="addCategory()"><i class="fas fa-plus"></i></button></div><div class="category-tags" id="categoryTags"></div></fieldset><div class="form-group"><label for="category">📁 选择分类</label><select id="category" class="form-control"><option value="">选择分类</option></select></div><div class="form-group"><label for="url">🔗 网站链接</label><input type="url" id="url" class="form-control" placeholder="https://example.com"></div><div class="form-group"><label for="notes">📝 备注信息</label><textarea id="notes" class="form-control" rows="3" placeholder="添加备注信息..."></textarea></div><div class="flex gap-4 mt-4"><button type="submit" class="btn btn-primary w-full"><i class="fas fa-save"></i> 保存密码</button><button type="button" class="btn btn-secondary" onclick="showPage('passwords')"><i class="fas fa-times"></i> 取消</button></div></form></section></div><div id="exportPage" class="hidden"><section class="webdav-section"><h4>📤 加密导出密码数据</h4><div class="form-group"><label for="exportPassword">🔐 导出密码</label><input type="password" id="exportPassword" class="form-control" placeholder="设置导出密码"></div><button class="btn btn-primary w-full" onclick="exportData()" type="button"><i class="fas fa-download"></i> 加密导出</button></section></div><div id="importPage" class="hidden"><section class="webdav-section"><h4>📥 导入加密密码数据</h4><div class="form-group"><label for="importFile">📁 选择文件</label><input type="file" id="importFile" class="form-control" accept=".json" onchange="handleFileSelect()"></div><div id="encryptedImportForm" class="hidden"><div class="form-group"><label for="importPassword">🔐 导入密码</label><input type="password" id="importPassword" class="form-control" placeholder="输入导入密码"></div></div><div class="flex gap-4 mt-4"><button class="btn btn-primary w-full" onclick="importData()" type="button"><i class="fas fa-upload"></i> 开始导入</button><button class="btn btn-secondary" onclick="showPage('passwords')" type="button"><i class="fas fa-times"></i> 取消</button></div></section></div><div id="webdavPage" class="hidden"><section class="webdav-section"><h4><i class="fas fa-cog"></i> WebDAV 连接配置</h4><div class="form-group"><label for="webdavUrl">🌐 WebDAV 地址</label><input type="url" id="webdavUrl" class="form-control" placeholder="https://webdav.teracloud.jp/dav/"></div><div class="form-group"><label for="webdavUsername">👤 用户名</label><input type="text" id="webdavUsername" class="form-control" placeholder="WebDAV用户名"></div><div class="form-group"><label for="webdavPassword">🔑 密码</label><input type="password" id="webdavPassword" class="form-control" placeholder="WebDAV密码"></div><div class="flex gap-3 mt-4"><button class="btn btn-primary" onclick="saveWebDAVConfig()" type="button"><i class="fas fa-save"></i> 保存配置</button><button class="btn btn-secondary" onclick="loadWebDAVFiles()" type="button"><i class="fas fa-list"></i> 列出文件</button></div></section><section class="webdav-section"><h4><i class="fas fa-cloud-upload-alt"></i> 创建加密备份</h4><div class="form-group"><label for="backupFilename">📁 备份文件名</label><input type="text" id="backupFilename" class="form-control" placeholder="password-backup-2024-01-01.json"></div><div class="form-group"><label for="backupPassword">🔐 备份密码</label><input type="password" id="backupPassword" class="form-control" placeholder="设置备份密码"></div><button class="btn btn-success w-full" onclick="createWebDAVBackup()" type="button"><i class="fas fa-cloud-upload-alt"></i> 创建加密备份</button></section><section class="webdav-section"><h4><i class="fas fa-history"></i> 备份文件管理</h4><div class="backup-files" id="backupFilesList"><p class="text-center" style="color:#6b7280">点击"列出文件"查看备份</p></div></section></div></main></div><script>let authToken=localStorage.getItem('authToken'),currentUser=null,passwords=[],categories=[],editingPasswordId=null,selectedFile=null,currentPage='passwords';function createParticles(){const particles=document.getElementById('particles');for(let i=0;i<50;i++){const particle=document.createElement('div');particle.className='particle';particle.style.left=Math.random()*100+'%';particle.style.width=particle.style.height=Math.random()*10+5+'px';particle.style.animationDelay=Math.random()*20+'s';particle.style.animationDuration=(Math.random()*10+10)+'s';particles.appendChild(particle)}}document.addEventListener('DOMContentLoaded',function(){createParticles();authToken?verifyAuth():showAuthSection();setupEventListeners()});function setupEventListeners(){document.getElementById('searchInput').addEventListener('input',filterPasswords);document.getElementById('categoryFilter').addEventListener('change',filterPasswords);document.getElementById('passwordLength').addEventListener('input',function(){document.getElementById('lengthValue').textContent=this.value});document.getElementById('passwordForm').addEventListener('submit',handlePasswordSubmit);document.getElementById('oauthLoginBtn').addEventListener('click',handleOAuthLogin);document.addEventListener('keydown',function(e){if(e.key==='Escape')showPage('passwords');if(e.ctrlKey&&e.key==='k'){e.preventDefault();document.getElementById('searchInput').focus()}if(e.ctrlKey&&e.key==='n'){e.preventDefault();if(!document.getElementById('authSection').classList.contains('hidden'))return;showPage('add')}})}async function handleOAuthLogin(){const button=document.getElementById('oauthLoginBtn');try{button.innerHTML='<div class="loading"></div> 正在跳转...';button.disabled=true;const response=await fetch('/api/oauth/login',{method:'GET'});const data=await response.json();window.location.href=data.authUrl}catch(error){showNotification('登录失败','error');button.innerHTML='<i class="fas fa-sign-in-alt"></i> 开始使用 OAuth 登录';button.disabled=false}}async function verifyAuth(){try{const response=await fetch('/api/auth/verify',{headers:{'Authorization':'Bearer '+authToken}});const data=await response.json();if(data.authenticated){currentUser=data.user;showMainApp();loadData()}else{localStorage.removeItem('authToken');authToken=null;showAuthSection()}}catch(error){console.error('Auth verification failed:',error);showAuthSection()}}function showAuthSection(){document.getElementById('authSection').classList.remove('hidden');document.getElementById('mainApp').classList.add('hidden')}function showMainApp(){document.getElementById('authSection').classList.add('hidden');document.getElementById('mainApp').classList.remove('hidden');if(currentUser){const displayName=currentUser.nickname||currentUser.username||'用户';document.getElementById('userName').textContent=displayName;document.getElementById('userEmail').textContent=currentUser.email||'';const avatar=document.getElementById('userAvatar');if(currentUser.avatar){avatar.innerHTML=\`<img src="\${currentUser.avatar}" alt="用户头像">\`}else{avatar.innerHTML=displayName.charAt(0).toUpperCase()}}}function showPage(page){document.querySelectorAll('#main-content > div').forEach(div=>div.classList.add('hidden'));if(page==='passwords'){document.getElementById('passwordsPage').classList.remove('hidden')}else{document.getElementById(page+'Page').classList.remove('hidden')}currentPage=page;if(page==='webdav')loadWebDAVConfig()}async function loadData(){await Promise.all([loadPasswords(),loadCategories()])}async function loadPasswords(){try{const response=await fetch('/api/passwords',{headers:{'Authorization':'Bearer '+authToken}});passwords=await response.json();renderPasswords()}catch(error){console.error('Failed to load passwords:',error);showNotification('加载密码失败','error')}}async function loadCategories(){try{const response=await fetch('/api/categories',{headers:{'Authorization':'Bearer '+authToken}});categories=await response.json();updateCategorySelects();renderCategoryTags()}catch(error){console.error('Failed to load categories:',error)}}function updateCategorySelects(){const categoryFilter=document.getElementById('categoryFilter');const categorySelect=document.getElementById('category');categoryFilter.innerHTML='<option value="">🏷️ 所有分类</option>';categorySelect.innerHTML='<option value="">选择分类</option>';categories.forEach(category=>{categoryFilter.innerHTML+=\`<option value="\${category}">🏷️ \${category}</option>\`;categorySelect.innerHTML+=\`<option value="\${category}">\${category}</option>\`})}function renderCategoryTags(){const container=document.getElementById('categoryTags');container.innerHTML=categories.map(category=>\`<div class="category-tag">\${category} <span class="remove" onclick="removeCategory('\${category}')">×</span></div>\`).join('')}async function addCategory(){const input=document.getElementById('newCategoryInput');const category=input.value.trim();if(!category)return;try{const response=await fetch('/api/categories',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+authToken},body:JSON.stringify({action:'add',category})});const data=await response.json();if(data.success){categories=data.categories;updateCategorySelects();renderCategoryTags();input.value='';showNotification('分类添加成功')}}catch(error){showNotification('添加分类失败','error')}}async function removeCategory(category){try{const response=await fetch('/api/categories',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+authToken},body:JSON.stringify({action:'remove',category})});const data=await response.json();if(data.success){categories=data.categories;updateCategorySelects();renderCategoryTags();showNotification('分类删除成功')}}catch(error){showNotification('删除分类失败','error')}}function renderPasswords(filteredPasswords=passwords){const grid=document.getElementById('passwordsGrid');if(filteredPasswords.length===0){grid.innerHTML=\`<div class="empty-state"><div class="icon">🔑</div><h3>还没有保存的密码</h3><p>点击"添加密码"开始管理您的密码吧！</p></div>\`;return}grid.innerHTML=filteredPasswords.map(password=>\`<article class="password-card"><header class="password-header"><div class="site-icon"><i class="fas fa-globe"></i></div><div class="password-meta"><h3>\${password.siteName}</h3>\${password.category?\`<span class="category-badge">\${password.category}</span>\`:''}</div></header><div class="password-field"><label>👤 用户名</label><div class="value">\${password.username}</div></div><div class="password-field"><label>🔑 密码</label><div class="value" id="pwd-\${password.id}">••••••••</div></div>\${password.url?\`<div class="password-field"><label>🔗 网址</label><div class="value"><a href="\${password.url}" target="_blank" rel="noopener noreferrer">\${password.url}</a></div></div>\`:''}\${password.notes?\`<div class="password-field"><label>📝 备注</label><div class="value">\${password.notes}</div></div>\`:''}<footer class="password-actions"><button class="btn btn-secondary btn-sm" onclick="togglePasswordDisplay('\${password.id}')" type="button"><i class="fas fa-eye"></i></button><button class="btn btn-secondary btn-sm" onclick="copyPassword('\${password.id}')" type="button"><i class="fas fa-copy"></i></button><button class="btn btn-secondary btn-sm" onclick="editPassword('\${password.id}')" type="button"><i class="fas fa-edit"></i></button><button class="btn btn-danger btn-sm" onclick="deletePassword('\${password.id}')" type="button"><i class="fas fa-trash"></i></button></footer></article>\`).join('')}function filterPasswords(){const searchTerm=document.getElementById('searchInput').value.toLowerCase();const categoryFilter=document.getElementById('categoryFilter').value;let filtered=passwords.filter(password=>{const matchesSearch=password.siteName.toLowerCase().includes(searchTerm)||password.username.toLowerCase().includes(searchTerm)||(password.notes&&password.notes.toLowerCase().includes(searchTerm));const matchesCategory=!categoryFilter||password.category===categoryFilter;return matchesSearch&&matchesCategory});renderPasswords(filtered)}async function togglePasswordDisplay(passwordId){const element=document.getElementById(\`pwd-\${passwordId}\`);const button=event.target.closest('button');if(element.textContent==='••••••••'){try{const response=await fetch(\`/api/passwords/\${passwordId}/reveal\`,{headers:{'Authorization':'Bearer '+authToken}});const data=await response.json();element.textContent=data.password;button.innerHTML='<i class="fas fa-eye-slash"></i>'}catch(error){showNotification('获取密码失败','error')}}else{element.textContent='••••••••';button.innerHTML='<i class="fas fa-eye"></i>'}}async function copyPassword(passwordId){try{const response=await fetch(\`/api/passwords/\${passwordId}/reveal\`,{headers:{'Authorization':'Bearer '+authToken}});const data=await response.json();await navigator.clipboard.writeText(data.password);showNotification('密码已复制到剪贴板 📋')}catch(error){showNotification('复制失败','error')}}function editPassword(passwordId){const password=passwords.find(p=>p.id===passwordId);if(!password)return;editingPasswordId=passwordId;document.getElementById('siteName').value=password.siteName;document.getElementById('username').value=password.username;document.getElementById('password').value='';document.getElementById('category').value=password.category||'';document.getElementById('url').value=password.url||'';document.getElementById('notes').value=password.notes||'';showPage('add')}async function deletePassword(passwordId){if(!confirm('🗑️ 确定要删除这个密码吗？此操作无法撤销。'))return;try{const response=await fetch(\`/api/passwords/\${passwordId}\`,{method:'DELETE',headers:{'Authorization':'Bearer '+authToken}});if(response.ok){showNotification('密码已删除 🗑️');loadPasswords()}else{showNotification('删除失败','error')}}catch(error){showNotification('删除失败','error')}}async function handlePasswordSubmit(e){e.preventDefault();const formData={siteName:document.getElementById('siteName').value,username:document.getElementById('username').value,password:document.getElementById('password').value,category:document.getElementById('category').value,url:document.getElementById('url').value,notes:document.getElementById('notes').value};try{const url=editingPasswordId?\`/api/passwords/\${editingPasswordId}\`:'/api/passwords';const method=editingPasswordId?'PUT':'POST';const response=await fetch(url,{method:method,headers:{'Content-Type':'application/json','Authorization':'Bearer '+authToken},body:JSON.stringify(formData)});if(response.ok){showNotification(editingPasswordId?'密码已更新 ✅':'密码已添加 ✅');document.getElementById('passwordForm').reset();editingPasswordId=null;showPage('passwords');loadPasswords()}else{showNotification('保存失败','error')}}catch(error){showNotification('保存失败','error')}}async function generatePassword(){const options={length:parseInt(document.getElementById('passwordLength').value),includeUppercase:document.getElementById('includeUppercase').checked,includeLowercase:document.getElementById('includeLowercase').checked,includeNumbers:document.getElementById('includeNumbers').checked,includeSymbols:document.getElementById('includeSymbols').checked};try{const response=await fetch('/api/generate-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(options)});const data=await response.json();document.getElementById('password').value=data.password;document.getElementById('password').type='text';showNotification('强密码已生成 🎲')}catch(error){showNotification('生成密码失败','error')}}function togglePasswordVisibility(fieldId){const field=document.getElementById(fieldId);const button=event.target.closest('button');const icon=button.querySelector('i');if(field.type==='password'){field.type='text';icon.className='fas fa-eye-slash'}else{field.type='password';icon.className='fas fa-eye'}}async function exportData(){const exportPassword=document.getElementById('exportPassword').value;if(!exportPassword){showNotification('请设置导出密码','error');return}try{const response=await fetch('/api/export-encrypted',{method:'POST',headers:{'Authorization':'Bearer '+authToken,'Content-Type':'application/json'},body:JSON.stringify({exportPassword})});const blob=await response.blob();const downloadUrl=window.URL.createObjectURL(blob);const a=document.createElement('a');a.href=downloadUrl;a.download=\`passwords-encrypted-export-\${new Date().toISOString().split('T')[0]}.json\`;document.body.appendChild(a);a.click();document.body.removeChild(a);window.URL.revokeObjectURL(downloadUrl);showNotification('数据导出成功 📤');document.getElementById('exportPassword').value=''}catch(error){showNotification('导出失败','error')}}function handleFileSelect(){const fileInput=document.getElementById('importFile');selectedFile=fileInput.files[0];if(selectedFile){const reader=new FileReader();reader.onload=function(e){try{const data=JSON.parse(e.target.result);if(data.encrypted){document.getElementById('encryptedImportForm').classList.remove('hidden')}else{document.getElementById('encryptedImportForm').classList.add('hidden')}}catch(error){showNotification('文件格式错误','error')}};reader.readAsText(selectedFile)}}async function importData(){if(!selectedFile){showNotification('请选择文件','error');return}try{const reader=new FileReader();reader.onload=async function(e){const fileContent=e.target.result;const data=JSON.parse(fileContent);let body=data;if(data.encrypted){const importPassword=document.getElementById('importPassword').value;if(!importPassword){showNotification('请输入导入密码','error');return}body={encryptedData:data.data,importPassword:importPassword}}const response=await fetch('/api/import-encrypted',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+authToken},body:JSON.stringify(body)});const result=await response.json();if(response.ok){showNotification(\`导入完成：成功 \${result.imported} 条，失败 \${result.errors} 条 📥\`);document.getElementById('importFile').value='';selectedFile=null;document.getElementById('importPassword').value='';showPage('passwords');loadPasswords()}else{showNotification(result.error||'导入失败','error')}};reader.readAsText(selectedFile)}catch(error){showNotification('导入失败：文件格式错误','error')}}async function loadWebDAVConfig(){try{const response=await fetch('/api/webdav/config',{headers:{'Authorization':'Bearer '+authToken}});const config=await response.json();document.getElementById('webdavUrl').value=config.url||'';document.getElementById('webdavUsername').value=config.username||''}catch(error){console.error('Failed to load WebDAV config:',error)}}async function saveWebDAVConfig(){const url=document.getElementById('webdavUrl').value;const username=document.getElementById('webdavUsername').value;const password=document.getElementById('webdavPassword').value;if(!url||!username||!password){showNotification('请填写完整的配置信息','error');return}try{const response=await fetch('/api/webdav/config',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+authToken},body:JSON.stringify({url,username,password})});if(response.ok){showNotification('WebDAV配置保存成功 ☁️');document.getElementById('webdavPassword').value=''}else{showNotification('保存配置失败','error')}}catch(error){showNotification('保存配置失败','error')}}async function loadWebDAVFiles(){try{const response=await fetch('/api/webdav/list',{method:'POST',headers:{'Authorization':'Bearer '+authToken}});const result=await response.json();if(result.success){renderBackupFiles(result.files)}else{showNotification(result.error||'获取文件列表失败','error')}}catch(error){showNotification('获取文件列表失败','error')}}async function createWebDAVBackup(){const filename=document.getElementById('backupFilename').value||'password-backup-\${new Date().toISOString().split('T')[0]}.json';const backupPassword=document.getElementById('backupPassword').value;if(!backupPassword){showNotification('请设置备份密码','error');return}try{const response=await fetch('/api/webdav/backup',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+authToken},body:JSON.stringify({filename,backupPassword})});const result=await response.json();if(result.success){showNotification(\`备份成功：\${result.filename} ☁️\`);document.getElementById('backupFilename').value='';document.getElementById('backupPassword').value='';loadWebDAVFiles()}else{showNotification(result.error||'备份失败','error')}}catch(error){showNotification('备份失败','error')}}async function restoreWebDAVBackup(filename){const restorePassword=prompt(\`请输入 \${filename} 的恢复密码：\`);if(!restorePassword)return;try{const response=await fetch('/api/webdav/restore',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+authToken},body:JSON.stringify({filename,restorePassword})});const result=await response.json();if(result.success){showNotification(result.message+' 🔄');loadPasswords()}else{showNotification(result.error||'恢复失败','error')}}catch(error){showNotification('恢复失败','error')}}async function deleteWebDAVBackup(filename){if(!confirm(\`确定要删除 \${filename} 吗？\`))return;try{const response=await fetch('/api/webdav/delete',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+authToken},body:JSON.stringify({filename})});const result=await response.json();if(result.success){showNotification('删除成功 🗑️');loadWebDAVFiles()}else{showNotification(result.error||'删除失败','error')}}catch(error){showNotification('删除失败','error')}}function renderBackupFiles(files){const container=document.getElementById('backupFilesList');if(files.length===0){container.innerHTML='<p class="text-center" style="color:#6b7280">没有找到备份文件</p>';return}container.innerHTML=files.map(file=>\`<div class="backup-file"><span>📁 \${file}</span><div class="backup-file-actions"><button class="btn btn-success btn-sm" onclick="restoreWebDAVBackup('\${file}')" type="button"><i class="fas fa-download"></i> 恢复</button><button class="btn btn-danger btn-sm" onclick="deleteWebDAVBackup('\${file}')" type="button"><i class="fas fa-trash"></i> 删除</button></div></div>\`).join('')}async function logout(){try{await fetch('/api/auth/logout',{method:'POST',headers:{'Authorization':'Bearer '+authToken}})}catch(error){console.error('Logout error:',error)}localStorage.removeItem('authToken');authToken=null;currentUser=null;showAuthSection()}function showNotification(message,type='success'){const notification=document.createElement('div');notification.className=\`notification \${type}\`;const icons={success:'check-circle',error:'exclamation-triangle',warning:'exclamation-circle',info:'info-circle'};notification.innerHTML=\`<i class="fas fa-\${icons[type]||icons.success}"></i> \${message}\`;document.body.appendChild(notification);setTimeout(()=>{notification.classList.add('show')},100);setTimeout(()=>{notification.classList.remove('show');setTimeout(()=>{if(document.body.contains(notification)){document.body.removeChild(notification)}},300)},3000)}</script><link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet"></body></html>`;
}
