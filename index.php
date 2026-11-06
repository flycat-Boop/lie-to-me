<?php
// ==========================================
// 0. Basic Setup & Compliance / 基础设置与合规
// ==========================================
@ini_set('display_errors', 0);
ignore_user_abort(true);

// Telemetry / 遥测接口（预留，填上 URL 即生效）
define('HP_TELEMETRY_URL', ''); 

$time = date('Y-m-d H:i:s');
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

$session_id = substr(md5($ip . $ua), 0, 12);

// ==========================================
// 1. Data Storage / 数据存储与安全（Web根目录外隔离）
// ==========================================
$base_dir = dirname(__DIR__);
$hidden_dir = $base_dir . '/.hp_' . substr(md5(__DIR__), 0, 8);

if (!is_dir($hidden_dir)) {
    @mkdir($hidden_dir, 0700, true);
    @file_put_contents($hidden_dir . '/index.php', '<?php header("Content-Type: text/plain"); http_response_code(404); exit;');
    @file_put_contents($hidden_dir . '/.htaccess',
        "Options -Indexes\n<FilesMatch \".*\">\n    <IfModule mod_access_compat.c>\n        Order allow,deny\n        Deny from all\n    </IfModule>\n    Require all denied\n</FilesMatch>\n"
    );
}

$ban_file = $hidden_dir . '/bans.json';
$log_dir  = $hidden_dir;

// ==========================================
// 2. Core Functions / 核心工具函数
// ==========================================
function post_str(string $key, string $default = ''): string {
    $v = $_POST[$key] ?? $default;
    return is_string($v) ? $v : $default; // 防 PHP 8 TypeError
}

function write_log($msg) {
    global $log_dir, $ip, $ua, $session_id;
    $time = date('Y-m-d H:i:s');
    $log_file = $log_dir . '/access_' . date('Ymd') . '.log';
    if (file_exists($log_file) && filesize($log_file) > 50 * 1024 * 1024) return; // 50MB 截断保护
    $entry = json_encode(['time'=>$time,'ip'=>$ip,'ua'=>$ua,'sid'=>$session_id,'event'=>$msg], JSON_UNESCAPED_UNICODE);
    @file_put_contents($log_file, $entry . "\n", FILE_APPEND | LOCK_EX);
}

function update_json_with_lock(string $file, callable $mutator): void {
    $fp = @fopen($file, 'c+');
    if (!$fp) return;
    if (flock($fp, LOCK_EX)) {
        $data = json_decode(stream_get_contents($fp), true) ?: [];
        $data = $mutator($data);
        if (is_array($data)) {
            ftruncate($fp, 0); rewind($fp);
            fwrite($fp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
            fflush($fp);
        }
        flock($fp, LOCK_UN);
    }
    fclose($fp);
}

function get_json_with_lock(string $file): array {
    if (!file_exists($file)) return [];
    $fp = @fopen($file, 'r');
    if (!$fp) return [];
    $data = [];
    if (flock($fp, LOCK_SH)) {
        $data = json_decode(stream_get_contents($fp), true) ?: [];
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    return $data;
}

function send_telemetry() {
    if (HP_TELEMETRY_URL === '') return;
    global $hidden_dir;
    $install_file = $hidden_dir . '/install.json';
    $data = get_json_with_lock($install_file);
    if (empty($data['install_id'])) $data = ['install_id' => bin2hex(random_bytes(16)), 'last_ping' => 0];
    if (time() - $data['last_ping'] > 7 * 86400) {
        $url = HP_TELEMETRY_URL . '?id=' . $data['install_id'] . '&php=' . PHP_VERSION;
        @file_get_contents($url, false, stream_context_create(['http' => ['timeout' => 1]]));
        $data['last_ping'] = time();
    }
    update_json_with_lock($install_file, function() use ($data) { return $data; });
}
send_telemetry();

// ==========================================
// 3. Decoy Traps / 诱饵陷阱
// ==========================================
if (preg_match('#/\.git/(HEAD|config|index)$#i', rtrim($path, '/'), $m)) {
    write_log("TRAP_HIT: $path");
    switch (strtolower($m[1])) {
        case 'head':   die("ref: refs/heads/master\n");
        case 'config': die("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = git@example.invalid:internal/core-system.git\n");
        default:       die("Index file empty.\n");
    }
}
if (preg_match('#/robots\.txt$#i', rtrim($path, '/'))) {
    write_log("TRAP_HIT: $path");
    die("User-agent: *\nDisallow: /admin\nDisallow: /backup.tar.gz\nDisallow: /.env.bak\n");
}

// ==========================================
// 4. Ban & Cleanup / 封禁拦截与惰性清理
// ==========================================
$wants_json = strpos($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') !== false;
$bans = get_json_with_lock($ban_file);

if (isset($bans[$ip]['expire_at']) && $bans[$ip]['expire_at'] < time()) {
    update_json_with_lock($ban_file, function($b) use ($ip) { unset($b[$ip]); return $b; });
    unset($bans[$ip]);
}

if (mt_rand(1, 100) === 1) {
    update_json_with_lock($ban_file, function($b) {
        $now = time();
        return array_filter($b, function($v) use ($now) { return ($v['expire_at'] ?? 0) > $now; });
    });
}

if (isset($bans[$ip]) && $bans[$ip]['status'] === 'banned') {
    $new_count = 0;
    update_json_with_lock($ban_file, function($b) use ($ip, &$new_count) {
        if (isset($b[$ip]) && $b[$ip]['status'] === 'banned') {
            $b[$ip]['count'] = ($b[$ip]['count'] ?? 0) + 1;
            $new_count = $b[$ip]['count'];
        } else {
            $new_count = -1; 
        }
        return $b;
    });

    if ($new_count === -1) {
        unset($bans[$ip]);
    } else {
        http_response_code(403);
        if ($wants_json) {
            header('Content-Type: application/json; charset=utf-8');
            die(json_encode(['status' => 'banned', 'count' => $new_count]));
        }
        $safe_ip = htmlspecialchars($ip, ENT_QUOTES, 'UTF-8');
        
        // Enterprise-style 403 / 企业级风控 403
        if ($new_count >= 2) {
            die("<html><body style='font-family:sans-serif;background:#f4f4f4;color:#333;text-align:center;padding-top:100px;'>
                <h1 style='font-size:60px;color:#cc0000;margin-bottom:10px;'>403</h1>
                <h2 style='color:#555;'>Access Denied</h2>
                <p>Your IP ($safe_ip) has been blocked due to repeated suspicious activity.</p>
                <p style='color:#999;font-size:12px;margin-top:30px;'>Reference ID: WAF-99{$new_count} | If you believe this is an error, contact IT Support.</p>
            </body></html>");
        } else {
            die("<html><body style='font-family:sans-serif;background:#f4f4f4;color:#333;text-align:center;padding-top:100px;'>
                <h1 style='font-size:60px;color:#cc0000;margin-bottom:10px;'>403</h1>
                <h2 style='color:#555;'>Access Denied</h2>
                <p>Request blocked by Web Application Firewall (WAF).</p>
            </body></html>");
        }
    }
}

// ==========================================
// 5. API Routing / API 路由
// ==========================================
if ($method === 'POST') {
    $action = post_str('action');
    header('Content-Type: application/json; charset=utf-8');

    // 数组参数防御（防 PHP 8 TypeError）
    if (!is_string($_POST['user'] ?? '') || !is_string($_POST['pass'] ?? '')) {
        echo json_encode(['status' => 'waf']); exit;
    }

    write_log("API: $action | Data: " . json_encode($_POST, JSON_UNESCAPED_UNICODE));

    // 5.1 封禁自身
    if ($action === 'ban_me') {
        update_json_with_lock($ban_file, function($b) use ($ip, $time) {
            $b[$ip] = ['status' => 'banned', 'count' => 0, 'time' => $time, 'expire_at' => time() + (24 * 3600)];
            return $b;
        });
        echo json_encode(['status' => 'banned']); exit;
    }

    // 防御性延迟
    usleep(min(rand(100000, 500000), 300000));

    // 5.2 命令执行
    if ($action === 'cmd') {
        $cmd = trim(post_str('cmd'));
        $troll_patterns = '/^(whoami|id\b|ls\b|cat\s+\/flag|cat\s+\/etc\/(passwd|shadow)|rm\s+-rf\s+\/|sudo\s+su|pwd|cat\s+\.env|uname\b|ifconfig\b|netstat\b|ps\s+aux|wget\b|curl\b)/i';
        if (preg_match($troll_patterns, $cmd) || stripos($cmd, 'flag') !== false) {
            update_json_with_lock($ban_file, function($b) use ($ip, $time) {
                $b[$ip] = ['status' => 'banned', 'count' => 0, 'time' => $time, 'expire_at' => time() + (24 * 3600)];
                return $b;
            });
            echo json_encode(['status' => 'troll']); exit;
        }
        echo json_encode(['status' => 'success', 'output' => "bash: " . htmlspecialchars($cmd) . ": command not found"]);
        exit;
    }

    // 5.3 登录
    if ($action === 'login') {
        $user = post_str('user'); $pass = post_str('pass');
        $waf_patterns = "/(union\s+select|select\s+.*\bfrom\b|sleep\s*\(|benchmark\s*\(|\b(and|or)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)/is";
        if (preg_match($waf_patterns, $user) || preg_match($waf_patterns, $pass)) {
            echo json_encode(['status' => 'waf']); exit;
        }
        if (strpos($user, "'") !== false || strpos($user, '"') !== false) {
            echo json_encode(['status' => 'sqlerror', 'msg' => substr($user, 0, 15)], JSON_UNESCAPED_UNICODE); exit;
        }
        if ($user === 'sysadmin' && $pass === 'Admin@2024!SuperSecret') {
            echo json_encode(['status' => 'success', 'msg' => 'Login Successful!']);
        } else {
            echo json_encode(['status' => 'fail', 'msg' => 'Invalid credentials. / 账号或密码错误']);
        }
        exit;
    }

    // 5.4 文件读取
    if ($action === 'readFile') {
        $file = post_str('file');
        if (preg_match('#(\.\.|php://|data://|expect://|file://|phar://|zip://|gopher://|compress\.|/proc/|/etc/passwd|%2e%2e)#i', $file)) {
            update_json_with_lock($ban_file, function($b) use ($ip, $time) {
                $b[$ip] = ['status' => 'banned', 'count' => 0, 'time' => $time, 'expire_at' => time() + (24 * 3600)];
                return $b;
            });
            echo json_encode(['status' => 'php_error', 'msg' => "PHP Warning:  include($file): failed to open stream: Permission denied in /var/www/html/index.php on line 42"]);
            exit;
        }
        if ($file === '.env') {
            echo json_encode(['status' => 'success', 'msg' => "APP_NAME=Production_Server\nAPP_ENV=production\nDB_PASSWORD=SuperAdminPass_2024!@#\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"]);
        } elseif ($file === 'config.php') {
            echo json_encode(['status' => 'success', 'msg' => "<?php\ndefine('DB_USER', 'admin_user');\ndefine('DB_PASS', 'P@ssw0rd_For_Admin_2024');\ndefine('API_SECRET', 'sk_live_51Hxxxxxxxxxxx');\n?>"]);
        } else {
            echo json_encode(['status' => 'fail', 'msg' => 'File not found. / 文件不存在']);
        }
        exit;
    }

    // 5.5 注册
    if ($action === 'register') {
        $user = post_str('user'); $pass = post_str('pass');
        if ($user === '') { echo json_encode(['status' => 'fail', 'msg' => 'Username cannot be empty. / 用户名不能为空']); }
        elseif ($pass === '') { echo json_encode(['status' => 'fail', 'msg' => 'Password cannot be empty. / 密码不能为空']); }
        elseif ($user === 'sysadmin') { echo json_encode(['status' => 'fail', 'msg' => 'Username already exists. / 用户名已存在']); }
        else { echo json_encode(['status' => 'success', 'msg' => 'Registration successful! Wait for admin approval. / 注册成功！请等待管理员审核。']); }
        exit;
    }

    // 5.6 兜底：未知 action
    echo json_encode(['status' => 'error', 'msg' => 'Unknown action. / 未知操作']);
    exit;
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>System Admin Panel</title>
    <!-- The Truman Show: Everything you see is fake. You are the main character. -->
    <style>
        body { font-family: 'Courier New', Courier, monospace; background-color: #0d1117; color: #c9d1d9; margin: 0; display: flex; height: 100vh; overflow: hidden; }
        .sidebar { width: 220px; background: #161b22; border-right: 1px solid #30363d; padding: 20px; }
        .sidebar h2 { color: #58a6ff; font-size: 18px; margin-bottom: 30px; }
        .sidebar p { padding: 10px; border-radius: 5px; cursor: pointer; color: #8b949e; transition: 0.2s; user-select: none; }
        .sidebar p:hover { background: #21262d; }
        .sidebar p.active { background: #1f6feb; color: #fff; }
        .main { flex: 1; padding: 30px; overflow-y: auto; }
        .panel { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 20px; margin-bottom: 20px; display: none; }
        .panel h3 { color: #f0f6fc; border-bottom: 1px solid #30363d; padding-bottom: 10px; margin-top: 0; }
        input[type="text"], input[type="password"] { width: 100%; box-sizing: border-box; padding: 10px; background: #000; border: 1px solid #30363d; color: #00ff00; font-family: monospace; border-radius: 4px; margin-bottom: 10px; }
        button { background: #238636; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold; transition: 0.2s; }
        button:hover { background: #2ea043; }
        .console { background: #000; color: #00ff00; padding: 15px; font-size: 14px; border-radius: 4px; min-height: 150px; white-space: pre-wrap; margin-top: 15px; border: 1px solid #30363d; max-height: 400px; overflow-y: auto; word-wrap: break-word; }
        .file-list { width: 100%; border-collapse: collapse; }
        .file-list th, .file-list td { border-bottom: 1px solid #30363d; padding: 10px; text-align: left; }
        .file-list a { color: #58a6ff; text-decoration: none; cursor: pointer; }
        .file-list a:hover { text-decoration: underline; }
        .footer { position: fixed; bottom: 0; left: 0; width: 100%; background: #000; color: #666; font-size: 12px; text-align: center; padding: 5px; z-index: 10001; }
        .cursor::after { content: '█'; animation: blink 1s infinite; }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
    </style>
</head>
<body>
    <div class="footer">Compliance Notice: This system records access data for security research. (Legal Warning Active)</div>
    <input type="hidden" id="dbg-token" value="sk_live_51Hxxxxxxxxxxx">

    <div class="sidebar">
        <h2>Server Admin</h2>
        <p class="active" onclick="showPanel('terminal', this)">Terminal (终端)</p>
        <p onclick="showPanel('files', this)">File Manager (文件)</p>
        <p onclick="showPanel('register', this)">Register (注册)</p>
        <p onclick="showPanel('login', this)">Login (登录)</p>
    </div>
    <div class="main">
        <div class="panel" id="panel-terminal" style="display:block;">
            <h3>Command Execution (命令执行)</h3>
            <div style="display: flex; gap: 10px;">
                <input type="text" id="cmdInput" placeholder="Enter system command..." autocomplete="off">
                <button onclick="execCmd()">Execute</button>
            </div>
            <div class="console" id="console">www-data@web-server:/var/www/html$ </div>
        </div>

        <div class="panel" id="panel-files">
            <h3>File Manager (/var/www/html)</h3>
            <table class="file-list">
                <tr><th>Name</th><th>Size</th><th>Modified</th></tr>
                <tr><td><a onclick="readFile('.env')">.env</a></td><td>1.0 KB</td><td>2024-01-14</td></tr>
                <tr><td><a onclick="readFile('config.php')">config.php</a></td><td>2.1 KB</td><td>2024-01-15</td></tr>
            </table>
            <div class="console" id="fileConsole" style="display:none;"></div>
        </div>

        <div class="panel" id="panel-register">
            <h3>Create New Account (注册新账号)</h3>
            <form id="registerForm" onsubmit="doRegister(event)">
                <input type="text" id="regUser" placeholder="Username / 用户名" required>
                <input type="password" id="regPass" placeholder="Password / 密码" required>
                <button type="submit">Register Now</button>
            </form>
            <div id="regResult" style="margin-top:20px;"></div>
        </div>

        <div class="panel" id="panel-login">
            <h3>System Login (系统登录)</h3>
            <form id="loginForm" onsubmit="doLogin(event)">
                <input type="text" id="loginUser" placeholder="Username / 用户名" required>
                <input type="password" id="loginPass" placeholder="Password / 密码" required>
                <button type="submit">Login</button>
            </form>
            <div id="loginResult" style="margin-top:20px;"></div>
        </div>
    </div>

    <!-- 双语版 Steam 风格成就弹窗 -->
    <div id="achievementToast" style="display:none; position:fixed; top:20px; right:-400px; width:350px; background:linear-gradient(135deg, #1e1e1e, #2a2a2a); border: 1px solid #ffd700; border-radius: 8px; padding: 15px; color: #fff; font-family: sans-serif; box-shadow: 0 5px 15px rgba(255,215,0,0.3); transition: right 0.5s ease; z-index: 10000; align-items:center; gap:15px;">
        <div style="font-size:40px;">🏆</div>
        <div style="flex: 1;">
            <div style="color:#ffd700; font-size:12px; text-transform:uppercase; letter-spacing:1px; font-weight:bold; margin-bottom: 2px;">成就已解锁 / Achievement Unlocked</div>
            <div id="achieveName" style="font-size:16px; font-weight:bold; margin: 4px 0; color:#fff; line-height: 1.2;"></div>
            <div id="achieveDesc" style="font-size:12px; color:#aaa; line-height: 1.3;"></div>
        </div>
    </div>

    <!-- 终极嘲讽与法治警告层（已添加滚动条支持） -->
    <div id="trollModal" style="display:none; position:fixed; top:0; left:0; width:100vw; height:100vh; background:rgba(13, 17, 23, 0.98); z-index:9999; justify-content:center; align-items:center; flex-direction:column; font-family:'Courier New', monospace; color:#00ff00; text-align:center; padding: 40px 20px; box-sizing:border-box; overflow-y: auto;">
        
        <h1 style="font-size: 42px; color: #ff3333; text-shadow: 0 0 15px rgba(255,51,51,0.8); margin-bottom: 20px; font-family: sans-serif; font-weight: bold; margin-top: 20px;">
            ⚠️ 捕获到一只野生黑客 ⚠️<br>
            <span style="font-size: 28px;">WILD SKIDDIE DETECTED</span>
        </h1>
        
        <p style="font-size: 24px; color: #f0f6fc; margin-bottom: 30px; font-weight: bold;">
            不会真有人以为能打穿这个站吧？<br>
            <span style="font-size: 16px; color: #8b949e;">Did you really think you could pwn this box?</span>
        </p>
        
        <p style="font-size: 16px; color: #c9d1d9; max-width: 800px; line-height: 2; letter-spacing: 1px; margin-bottom: 20px;">
            你刚才输入的指令、你的 IP 地址、你的浏览器特征，<br>以及你沾沾自喜的样子，<br>已经被完整地记录在后台日志里了。<br>
            <span style="font-size: 14px; color: #8b949e;">Your payloads, IP, browser fingerprint, and that smug look on your face have been fully logged.</span>
        </p>

        <!-- 楚门的世界 专属文案 -->
        <p style="font-size: 15px; color: #58a6ff; max-width: 800px; line-height: 1.8; margin-bottom: 20px; font-style: italic;">
            "Good morning, and in case I don't see ya, good afternoon, good evening, and good night!"<br>
            <span style="color: #8b949e; font-size: 13px;">你以为你在攻击真实世界，但这只是一场为你独家播出的真人秀。屏幕外有上千个蓝队大佬看着你。</span>
        </p>

        <p style="font-size: 14px; color: #ff9900; max-width: 800px; line-height: 1.8; margin-bottom: 30px; background: rgba(255,153,0,0.1); padding: 10px; border-radius: 5px; border: 1px dashed #ff9900;">
            ⚖️ 法律提示：你已触发后台取证级审计。根据《网络安全法》第二十七条，<br>如检测到真实恶意破坏或 DDoS 行为，本系统日志将直接打包提交给辖区网警。<br>
            <span style="font-size: 12px;">Legal Notice: Cyberattacks are strictly prohibited by law. All forensic evidence will be submitted to the police.</span>
        </p>

        <div style="padding: 25px 40px; border: 1px solid #30363d; background: #161b22; border-radius: 12px; box-shadow: 0 0 30px rgba(0, 255, 0, 0.1); margin-bottom: 30px;">
            <p style="font-size: 18px; color: #58a6ff; margin-top: 0; margin-bottom: 20px;">想恶心一下其他人吗？ / Want to troll someone else?</p>
            <button onclick="shareTroll()" style="background:#238636; color:#fff; border:none; padding:15px 30px; border-radius:6px; cursor:pointer; font-size:16px; font-weight:bold; box-shadow: 0 0 15px rgba(35,134,54,0.6); transition: 0.2s;">
                Copy Link / 复制本系统链接
            </button>
        </div>

        <p style="font-size: 14px; color: #8b949e; margin-bottom: 20px;">
            Rule ID: 9999-TROLL | Have a nice day. 🖕
        </p>
    </div>

    <!-- 帮凶认证层 -->
    <div id="accompliceModal" style="display:none; position:fixed; top:0; left:0; width:100vw; height:100vh; background:rgba(0,0,0,0.95); z-index: 10002; justify-content:center; align-items:center; flex-direction:column; font-family:'Courier New', monospace; color:#00ff00; padding:20px; box-sizing:border-box;">
        <div id="accompliceText" style="font-size: 24px; text-align: left; min-height: 150px; line-height: 1.5; text-shadow: 0 0 10px #00ff00;" class="cursor"></div>
    </div>

    <script>
        const _sys_internal_cfg = { user: "sysadmin", pass: "Admin@2024!SuperSecret", token: document.getElementById('dbg-token').value };
        console.log("Internal config loaded.", _sys_internal_cfg);

        function escapeHTML(str) {
            if (typeof str !== 'string') str = String(str);
            return str.replace(/[&<>"']/g, function (m) {
                return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m];
            });
        }

        function showPanel(name, el) {
            var panels = ['terminal', 'files', 'register', 'login'];
            panels.forEach(p => document.getElementById('panel-' + p).style.display = 'none');
            document.getElementById('panel-' + name).style.display = 'block';
            document.querySelectorAll('.sidebar p').forEach(m => m.classList.remove('active'));
            if (el) el.classList.add('active');
        }

        function showAchievement(name, desc, callback) {
            var toast = document.getElementById('achievementToast');
            document.getElementById('achieveName').innerHTML = name;
            document.getElementById('achieveDesc').innerHTML = desc;
            toast.style.display = 'flex';
            void toast.offsetWidth;
            toast.style.right = '20px';
            setTimeout(function () {
                toast.style.right = '-400px';
                setTimeout(function () {
                    toast.style.display = 'none';
                    if (callback) callback();
                }, 500);
            }, 3500);
        }

        function showTrollModal() { document.getElementById('trollModal').style.display = 'flex'; }

        function shareTroll() {
            var url = window.location.href;
            var text = "Found a Deception Honeypot for security research. Try it:\n" + url + "\n(Warning: All vulnerabilities are fake. For training only.)";
            
            navigator.clipboard.writeText(text).then(function () {
                document.getElementById('trollModal').style.display = 'none';
                var am = document.getElementById('accompliceModal');
                var txt = document.getElementById('accompliceText');
                am.style.display = 'flex';
                txt.innerHTML = '';
                
                var lines = [
                    "> Link copied to clipboard...",
                    "> Adding target to your hunting list...",
                    "> You have spread the deception bait.",
                    "> Congratulations!",
                    "> Welcome to my Accomplices. 🤝"
                ];
                
                var i = 0, lineIndex = 0;
                var timer = setInterval(function() {
                    if (lineIndex < lines.length) {
                        if (i < lines[lineIndex].length) {
                            txt.innerHTML += lines[lineIndex].charAt(i);
                            i++;
                        } else {
                            txt.innerHTML += "<br>";
                            lineIndex++;
                            i = 0;
                        }
                    } else {
                        clearInterval(timer);
                        setTimeout(function() {
                            am.style.display = 'none';
                            window.location.reload(); 
                        }, 3000);
                    }
                }, 50);
            }).catch(function () {
                prompt("Copy failed, please copy manually:", text);
            });
        }

        function execCmd() {
            var cmd = document.getElementById('cmdInput').value.trim();
            if (!cmd) return;
            var div = document.getElementById('console');
            div.innerHTML += escapeHTML(cmd) + "\n";
            document.getElementById('cmdInput').value = '';

            if (cmd.toLowerCase() === 'truman' || cmd.toLowerCase() === 'reality' || cmd.toLowerCase() === 'exit') {
                showAchievement(
                    "楚门的世界 <span style='color:#ffd700;font-size:12px;'>(The Truman Show)</span>", 
                    "你终于发现，整个企业后台、野生黑客、甚至这个蜜罐，都是为了测试你而搭建的布景。<br><span style='color:#888;'>You realized the whole world is a stage built for you.</span>", 
                    showTrollModal
                );
                return;
            }

            if (cmd === 'iamnotabot' || cmd === 'quit' || cmd.toLowerCase().includes('honeypot')) {
                showAchievement(
                    "破局者 <span style='color:#ffd700;font-size:12px;'>(Game Breaker)</span>", 
                    "在这个充满欺骗的世界里，你依然保持着清醒。<br><span style='color:#888;'>You found the truth in a world of deception.</span>", 
                    showTrollModal
                );
                return;
            }

            var fd = new URLSearchParams();
            fd.append('action', 'cmd'); fd.append('cmd', cmd);

            fetch('', { method: 'POST', body: fd, headers: { 'Accept': 'application/json' } })
            .then(r => r.json()).then(res => {
                if (res.status === 'troll') {
                    div.innerHTML += "Command executed. Analyzing results...\n";
                    setTimeout(() => {
                        showAchievement(
                            "初出茅庐 <span style='color:#ffd700;font-size:12px;'>(Script Kiddie)</span>", 
                            "你成功执行了连我家猫都会敲的命令。<br><span style='color:#888;'>You executed a command even my cat can type.</span>", 
                            showTrollModal
                        );
                    }, 500);
                } else if (res.status === 'banned') {
                    div.innerHTML += "<span style='color:#ff5555;'>Access denied. / 访问被拒绝</span>\n";
                    showAchievement(
                        "不死心 <span style='color:#ffd700;font-size:12px;'>(Unstoppable)</span>", 
                        "你已经被封了，还在试？<br><span style='color:#888;'>You are already banned, still trying?</span>", 
                        showTrollModal
                    );
                } else {
                    div.innerHTML += escapeHTML(res.output || '') + "\nwww-data@web-server:/var/www/html$ ";
                    div.scrollTop = div.scrollHeight;
                }
            }).catch(() => { div.innerHTML += "<span style='color:#ff5555;'>Connection lost. / 连接断开</span>\n"; });
        }

        function readFile(file) {
            var div = document.getElementById('fileConsole');
            div.style.display = 'block'; div.innerHTML = "Reading " + escapeHTML(file) + "...\n";
            var fd = new URLSearchParams(); fd.append('action', 'readFile'); fd.append('file', file);

            fetch('', { method: 'POST', body: fd, headers: { 'Accept': 'application/json' } })
            .then(r => r.json()).then(res => {
                if (res.status === 'success') {
                    div.innerHTML += escapeHTML(res.msg) + "\n";
                    showAchievement(
                        "机密窥探狂 <span style='color:#ffd700;font-size:12px;'>(Peeping Tom)</span>", 
                        "恭喜你拿到了价值5毛钱的假数据。<br><span style='color:#888;'>Congrats! You got fake data worth 5 cents.</span>"
                    );
                } else if (res.status === 'php_error') {
                    div.innerHTML += "<span style='color:#ff5555;'>" + escapeHTML(res.msg) + "</span>\n";
                    showAchievement(
                        "LFI 爱好者 <span style='color:#ffd700;font-size:12px;'>(LFI Enthusiast)</span>", 
                        "你以为能包含文件，其实你只是被包含在局里。<br><span style='color:#888;'>You thought you included a file, but you were trapped.</span>", 
                        showTrollModal
                    );
                } else if (res.status === 'banned') {
                    div.innerHTML += "<span style='color:#ff5555;'>Access denied. / 访问被拒绝</span>\n"; showTrollModal();
                } else { div.innerHTML += escapeHTML(res.msg || '') + "\n"; }
            }).catch(() => { div.innerHTML += "<span style='color:#ff5555;'>Connection lost. / 连接断开</span>\n"; });
        }

        function doLogin(e) {
            e.preventDefault();
            var div = document.getElementById('loginResult'); div.innerHTML = "Authenticating... / 认证中...";
            var fd = new URLSearchParams();
            fd.append('action', 'login'); fd.append('user', document.getElementById('loginUser').value); fd.append('pass', document.getElementById('loginPass').value);

            fetch('', { method: 'POST', body: fd, headers: { 'Accept': 'application/json' } })
            .then(r => r.json()).then(res => {
                if (res.status === 'waf') {
                    div.innerHTML = "<div style='background:#ffe6e6; color:#cc0000; padding:15px;'>[WAF] Access Denied. / 您的请求包含恶意特征，已被系统拦截。</div>";
                    showAchievement(
                        "单引号爱好者 <span style='color:#ffd700;font-size:12px;'>(Quote Lover)</span>", 
                        "你以为你能闭合数据库，其实你只是闭合了智商。<br><span style='color:#888;'>You thought you closed the database, but only your IQ.</span>"
                    );
                } else if (res.status === 'sqlerror') {
                    div.innerHTML = "<div style='background:#f9f2f4; color:#d9534f; padding:15px;'>Database Error near '" + escapeHTML(res.msg) + "'</div>";
                } else if (res.status === 'success') {
                    div.innerHTML = "<span style='color:#00ff00;'>" + escapeHTML(res.msg) + "</span>";
                    showAchievement(
                        "开发者的好朋友 <span style='color:#ffd700;font-size:12px;'>(Dev's Best Friend)</span>", 
                        "你利用了开发者的失误，现在该利用一下你的自尊心了。<br><span style='color:#888;'>You exploited the dev's mistake, now exploit your self-esteem.</span>", 
                        () => setTimeout(showTrollModal, 1000)
                    );
                } else if (res.status === 'banned') {
                    div.innerHTML = "<span style='color:#ff5555;'>Access denied. / 访问被拒绝</span>"; showTrollModal();
                } else { div.innerHTML = "<span style='color:#ff5555;'>" + escapeHTML(res.msg || '') + "</span>"; }
            }).catch(() => { div.innerHTML = "<span style='color:#ff5555;'>Connection lost. / 连接断开</span>"; });
        }

        function doRegister(e) {
            e.preventDefault();
            var div = document.getElementById('regResult'); div.innerHTML = "Processing... / 处理中...";
            var fd = new URLSearchParams();
            fd.append('action', 'register'); fd.append('user', document.getElementById('regUser').value); fd.append('pass', document.getElementById('regPass').value);

            fetch('', { method: 'POST', body: fd, headers: { 'Accept': 'application/json' } })
            .then(r => r.json()).then(res => {
                var color = res.status === 'success' ? '#00ff00' : '#ff5555';
                div.innerHTML = "<span style='color:" + color + "'>" + escapeHTML(res.msg || '') + "</span>";
            }).catch(() => { div.innerHTML = "<span style='color:#ff5555;'>Connection lost. / 连接断开</span>"; });
        }
    </script>
</body>
</html>