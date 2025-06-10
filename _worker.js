// 密码管理器 - Cloudflare Workers + KV
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
      
      if (path === '/api/auth') {
        return handleAuth(request, env, corsHeaders);
      }
      
      if (path.startsWith('/api/passwords')) {
        return handlePasswords(request, env, corsHeaders);
      }
      
      return new Response('Not Found', { status: 404, headers: corsHeaders });
    } catch (error) {
      return new Response('Internal Server Error', { 
        status: 500, 
        headers: corsHeaders 
      });
    }
  }
};

// 身份验证处理
async function handleAuth(request, env, corsHeaders) {
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  }
  
  const { masterPassword } = await request.json();
  
  // 简单的主密码验证（实际应用中应该使用更安全的方式）
  const storedHash = await env.PASSWORD_KV.get('master_password_hash');
  const inputHash = await hashPassword(masterPassword);
  
  if (!storedHash) {
    // 首次设置主密码
    await env.PASSWORD_KV.put('master_password_hash', inputHash);
    const token = generateToken();
    await env.PASSWORD_KV.put(`session_${token}`, 'valid', { expirationTtl: 3600 });
    
    return new Response(JSON.stringify({ success: true, token, isFirstTime: true }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  if (inputHash === storedHash) {
    const token = generateToken();
    await env.PASSWORD_KV.put(`session_${token}`, 'valid', { expirationTtl: 3600 });
    
    return new Response(JSON.stringify({ success: true, token }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  return new Response(JSON.stringify({ success: false, message: '密码错误' }), {
    status: 401,
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

// 密码条目处理
async function handlePasswords(request, env, corsHeaders) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  
  if (!token || !(await env.PASSWORD_KV.get(`session_${token}`))) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
  
  const url = new URL(request.url);
  const id = url.pathname.split('/').pop();
  
  switch (request.method) {
    case 'GET':
      if (id && id !== 'passwords') {
        // 获取单个密码
        const password = await env.PASSWORD_KV.get(`password_${id}`);
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
        const list = await env.PASSWORD_KV.list({ prefix: 'password_' });
        const passwords = [];
        
        for (const key of list.keys) {
          const data = await env.PASSWORD_KV.get(key.name);
          if (data) {
            passwords.push(JSON.parse(data));
          }
        }
        
        return new Response(JSON.stringify(passwords), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
    case 'POST':
      const newPassword = await request.json();
      newPassword.id = generateId();
      newPassword.createdAt = new Date().toISOString();
      newPassword.updatedAt = newPassword.createdAt;
      
      await env.PASSWORD_KV.put(`password_${newPassword.id}`, JSON.stringify(newPassword));
      
      return new Response(JSON.stringify(newPassword), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
      
    case 'PUT':
      if (!id || id === 'passwords') {
        return new Response(JSON.stringify({ error: '缺少ID' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      const existingPassword = await env.PASSWORD_KV.get(`password_${id}`);
      if (!existingPassword) {
        return new Response(JSON.stringify({ error: '未找到' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      const updatedPassword = { ...JSON.parse(existingPassword), ...await request.json() };
      updatedPassword.updatedAt = new Date().toISOString();
      
      await env.PASSWORD_KV.put(`password_${id}`, JSON.stringify(updatedPassword));
      
      return new Response(JSON.stringify(updatedPassword), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
      
    case 'DELETE':
      if (!id || id === 'passwords') {
        return new Response(JSON.stringify({ error: '缺少ID' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      await env.PASSWORD_KV.delete(`password_${id}`);
      
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

// 工具函数
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function generateToken() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

// HTML界面
function getHTML() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>密码管理器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .auth-form, .password-form { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .hidden { display: none; }
        input, button { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; }
        button { background: #007AFF; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056CC; }
        .password-item { background: white; padding: 20px; border-radius: 8px; margin-bottom: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .password-item h3 { color: #333; margin-bottom: 10px; }
        .password-item p { color: #666; margin: 5px 0; }
        .password-actions { margin-top: 15px; }
        .password-actions button { width: auto; margin-right: 10px; padding: 8px 16px; }
        .btn-danger { background: #FF3B30; }
        .btn-danger:hover { background: #D70015; }
        .btn-secondary { background: #8E8E93; }
        .btn-secondary:hover { background: #636366; }
        .password-field { position: relative; }
        .toggle-password { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; width: auto; }
    </style>
</head>
<body>
    <div class="container">
        <div id="authSection" class="auth-form">
            <h2>密码管理器</h2>
            <input type="password" id="masterPassword" placeholder="输入主密码">
            <button onclick="authenticate()">登录</button>
            <p id="authMessage"></p>
        </div>

        <div id="mainSection" class="hidden">
            <div class="password-form">
                <h2>添加新密码</h2>
                <input type="text" id="siteName" placeholder="网站名称">
                <input type="text" id="username" placeholder="用户名/邮箱">
                <div class="password-field">
                    <input type="password" id="password" placeholder="密码">
                    <button type="button" class="toggle-password" onclick="togglePassword('password')">👁️</button>
                </div>
                <input type="url" id="url" placeholder="网站URL (可选)">
                <textarea id="notes" placeholder="备注 (可选)" style="height: 80px; resize: vertical;"></textarea>
                <button onclick="savePassword()">保存密码</button>
            </div>

            <div id="passwordsList">
                <h2>已保存的密码</h2>
                <div id="passwords"></div>
            </div>
        </div>
    </div>

    <script>
        let authToken = null;

        async function authenticate() {
            const masterPassword = document.getElementById('masterPassword').value;
            if (!masterPassword) {
                document.getElementById('authMessage').textContent = '请输入主密码';
                return;
            }

            try {
                const response = await fetch('/api/auth', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ masterPassword })
                });

                const result = await response.json();
                
                if (result.success) {
                    authToken = result.token;
                    document.getElementById('authSection').classList.add('hidden');
                    document.getElementById('mainSection').classList.remove('hidden');
                    if (result.isFirstTime) {
                        alert('主密码设置成功！请妥善保管，忘记后无法恢复。');
                    }
                    loadPasswords();
                } else {
                    document.getElementById('authMessage').textContent = result.message || '认证失败';
                }
            } catch (error) {
                document.getElementById('authMessage').textContent = '网络错误';
            }
        }

        async function savePassword() {
            const siteName = document.getElementById('siteName').value;
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const url = document.getElementById('url').value;
            const notes = document.getElementById('notes').value;

            if (!siteName || !username || !password) {
                alert('请填写必要信息');
                return;
            }

            try {
                const response = await fetch('/api/passwords', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify({ siteName, username, password, url, notes })
                });

                if (response.ok) {
                    document.getElementById('siteName').value = '';
                    document.getElementById('username').value = '';
                    document.getElementById('password').value = '';
                    document.getElementById('url').value = '';
                    document.getElementById('notes').value = '';
                    loadPasswords();
                } else {
                    alert('保存失败');
                }
            } catch (error) {
                alert('网络错误');
            }
        }

        async function loadPasswords() {
            try {
                const response = await fetch('/api/passwords', {
                    headers: { 'Authorization': 'Bearer ' + authToken }
                });

                const passwords = await response.json();
                const container = document.getElementById('passwords');
                
                if (passwords.length === 0) {
                    container.innerHTML = '<p>暂无保存的密码</p>';
                    return;
                }

                container.innerHTML = passwords.map(p => \`
                    <div class="password-item">
                        <h3>\${p.siteName}</h3>
                        <p><strong>用户名:</strong> \${p.username}</p>
                        <p><strong>密码:</strong> <span id="pwd-\${p.id}" style="font-family: monospace;">••••••••</span></p>
                        \${p.url ? \`<p><strong>网址:</strong> <a href="\${p.url}" target="_blank">\${p.url}</a></p>\` : ''}
                        \${p.notes ? \`<p><strong>备注:</strong> \${p.notes}</p>\` : ''}
                        <div class="password-actions">
                            <button class="btn-secondary" onclick="togglePasswordVisibility('\${p.id}', '\${p.password}')">显示密码</button>
                            <button class="btn-secondary" onclick="copyToClipboard('\${p.password}')">复制密码</button>
                            <button class="btn-danger" onclick="deletePassword('\${p.id}')">删除</button>
                        </div>
                    </div>
                \`).join('');
            } catch (error) {
                console.error('加载密码失败:', error);
            }
        }

        function togglePasswordVisibility(id, password) {
            const element = document.getElementById('pwd-' + id);
            const button = event.target;
            
            if (element.textContent === '••••••••') {
                element.textContent = password;
                button.textContent = '隐藏密码';
            } else {
                element.textContent = '••••••••';
                button.textContent = '显示密码';
            }
        }

        function togglePassword(fieldId) {
            const field = document.getElementById(fieldId);
            field.type = field.type === 'password' ? 'text' : 'password';
        }

        async function copyToClipboard(text) {
            try {
                await navigator.clipboard.writeText(text);
                alert('密码已复制到剪贴板');
            } catch (error) {
                alert('复制失败');
            }
        }

        async function deletePassword(id) {
            if (!confirm('确定要删除这个密码吗？')) return;

            try {
                const response = await fetch('/api/passwords/' + id, {
                    method: 'DELETE',
                    headers: { 'Authorization': 'Bearer ' + authToken }
                });

                if (response.ok) {
                    loadPasswords();
                } else {
                    alert('删除失败');
                }
            } catch (error) {
                alert('网络错误');
            }
        }

        // 回车键登录
        document.getElementById('masterPassword').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                authenticate();
            }
        });
    </script>
</body>
</html>`;
}
