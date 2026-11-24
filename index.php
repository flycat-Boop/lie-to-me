<?php
// ==========================================
// 0. Basic Setup & Compliance
// ==========================================
@ini_set('display_errors', 1);
error_reporting(E_ALL);
ignore_user_abort(true);

// [FIX 1] 只保留这一处定义，删除后面永远不会执行的 if (!defined(...))
// 是否信任 Cloudflare / 反向代理头（部署在 CF 或反代后面才开）
define('TRUST_CF', false);
define('TRUST_PROXY', false);
define('TRUSTED_PROXIES', ['127.0.0.1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']);

// ---- CSRF 会话 ----
if (session_status() === PHP_SESSION_NONE) {
    @session_start();
}
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
}

$time = date('Y-m-d H:i:s');
$ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$decoded_path = urldecode($path);

// ==========================================
// 1. 真实 IP
// ==========================================
function ip_in_cidr(string $ip, string $cidr): bool {
    if (strpos($cidr, '/') === false) return $ip === $cidr;
    [$net, $bits] = explode('/', $cidr, 2);
    $bits = (int)$bits;

    if (strpos($ip, ':') !== false || strpos($net, ':') !== false) {
        $ipBin  = @inet_pton($ip);
        $netBin = @inet_pton($net);
        if ($ipBin === false || $netBin === false || strlen($ipBin) !== 16 || strlen($netBin) !== 16) return false;
        if ($bits < 0 || $bits > 128) return false;
        $whole = intdiv($bits, 8);
        $rem   = $bits % 8;
        if ($whole > 0 && substr($ipBin, 0, $whole) !== substr($netBin, 0, $whole)) return false;
        if ($rem === 0) return true;
        $mask = (0xFF << (8 - $rem)) & 0xFF;
        return (ord($ipBin[$whole]) & $mask) === (ord($netBin[$whole]) & $mask);
    }

    $ipL = ip2long($ip); $netL = ip2long($net);
    if ($ipL === false || $netL === false) return false;
    if ($bits < 0 || $bits > 32) return false;
    $mask = $bits === 0 ? 0 : (~0 << (32 - $bits));
    return ($ipL & $mask) === ($netL & $mask);
}

function get_real_ip(): string {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    if (TRUST_CF && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $cf_ranges = [
            '173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22',
            '141.101.64.0/18','108.162.192.0/18','190.93.240.0/20','188.114.96.0/20',
            '197.234.240.0/22','198.41.128.0/17','162.158.0.0/15','104.16.0.0/13',
            '104.24.0.0/14','172.64.0.0/13','131.0.72.0/22',
        ];
        $ok = false;
        foreach ($cf_ranges as $r) {
            if (ip_in_cidr($remote, $r)) { $ok = true; break; }
        }
        if ($ok) {
            $ip = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
    }
    if (TRUST_PROXY && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $trusted = false;
        foreach (TRUSTED_PROXIES as $cidr) {
            if (ip_in_cidr($remote, $cidr)) { $trusted = true; break; }
        }

        if ($trusted) {
            $chain = array_reverse(array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])));
            foreach ($chain as $cand) {
                if (!filter_var($cand, FILTER_VALIDATE_IP)) continue;
                $hop_trusted = false;
                foreach (TRUSTED_PROXIES as $cidr) {
                    if (ip_in_cidr($cand, $cidr)) { $hop_trusted = true; break; }
                }
                if (!$hop_trusted) return $cand;
            }
        }
    }
    // [FIX 3] X-Real-IP 也必须在 TRUST_PROXY 开启时才信任，否则客户端可任意伪造
    if (TRUST_PROXY && !empty($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = trim($_SERVER['HTTP_X_REAL_IP']);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
    }

    return filter_var($remote, FILTER_VALIDATE_IP) ? $remote : '0.0.0.0';
}

$ip = get_real_ip();
$ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
$session_id = substr(hash_hmac('sha256', $ip . '|' . $ua, md5(__DIR__)), 0, 12);

// ---- 扫描器识别 ----
$is_scanner = false;
$scanner_list = [
    'sqlmap','nmap','dirsearch','nuclei','nikto','zap','burp','awvs','masscan','xray',
    'goby','w3af','acunetix','nessus','openvas','appscan','netsparker','wpscan','ffuf',
    'gobuster','wfuzz','hydra','metasploit','feroxbuster'
];
foreach ($scanner_list as $s) { if (stripos($ua, $s) !== false) { $is_scanner = true; break; } }

// ==========================================
// 2. Data Storage
// ==========================================
$hidden_dir = getenv('HP_DATA_DIR');
if (!$hidden_dir) {
    $hidden_dir = sys_get_temp_dir() . '/.hp_' . substr(md5(__DIR__), 0, 8);
}

if (!is_dir($hidden_dir)) {
    @mkdir($hidden_dir, 0700, true);
    @file_put_contents($hidden_dir . '/index.php', '<?php http_response_code(404); exit;');
    @file_put_contents($hidden_dir . '/.htaccess',
        "Options -Indexes\n" .
        "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n" .
        "<IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n</IfModule>\n"
    );
}

$ban_file = $hidden_dir . '/bans.json';
$waf_file = $hidden_dir . '/waf_hits.json';
$log_dir  = $hidden_dir;

// ---- 确定性假数据 ----
$seed = md5(__DIR__);
$fake_api_secret  = 'sk_live_' . substr($seed, 0, 24);
$fake_aws_key     = 'AKIA' . strtoupper(substr(md5('aws:' . __DIR__), 0, 16));
$fake_db_pass     = substr(md5('db:' . __DIR__), 0, 16) . '!@#2024';
$fake_cfg_db_pass = 'P@ssw0rd_' . substr(md5('cfg:' . __DIR__), 0, 12);
$fake_flag        = 'flag{h0n3yp0t_c4n7_s33_m3_4nd_y0u_f0und_th3_f4k3_fl4g}';

// ==========================================
// 3. Core Functions
// ==========================================
function post_str(string $key, string $default = ''): string {
    $v = $_POST[$key] ?? $default;
    return is_string($v) ? $v : $default;
}

function sanitize_post(array $post, int $depth = 0): array {
    if ($depth > 5) return $post;
    $sensitive = ['pass','password','pwd','token','secret','key','apikey','api_key','csrf','authorization','cookie'];
    foreach ($post as $k => $v) {
        if (is_array($v)) {
            $post[$k] = sanitize_post($v, $depth + 1);
            continue;
        }
        if (in_array(strtolower((string)$k), $sensitive, true) && is_string($v)) {
            $post[$k] = '***len=' . strlen($v) . '***';
        }
    }
    return $post;
}

function write_log($msg) {
    global $log_dir, $ip, $ua, $session_id;
    $log_file = $log_dir . '/access_' . date('Ymd') . '.log';

    $max_size = 10 * 1024 * 1024;
    if (file_exists($log_file) && filesize($log_file) > $max_size) {
        $bak = $log_dir . '/access_' . date('Ymd_His') . '.bak.log';
        $n = 1;
        while (file_exists($bak)) { $bak = $log_dir . '/access_' . date('Ymd_His') . '_' . $n++ . '.bak.log'; }
        @rename($log_file, $bak);
        $backup_files = glob($log_dir . '/access_*.bak.log') ?: [];
        if (count($backup_files) > 5) {
            array_multisort(array_map('filemtime', $backup_files), SORT_ASC, $backup_files);
            foreach (array_slice($backup_files, 0, count($backup_files) - 5) as $f) { @unlink($f); }
        }
    }

    $entry = json_encode(['time'=>date('Y-m-d H:i:s'),'ip'=>$ip,'ua'=>$ua,'sid'=>$session_id,'event'=>$msg], JSON_UNESCAPED_UNICODE);
    @file_put_contents($log_file, $entry . "\n", FILE_APPEND | LOCK_EX);
}

function update_json_with_lock(string $file, callable $mutator): void {
    $fh = @fopen($file, 'c+');
    if (!$fh) return;
    if (flock($fh, LOCK_EX)) {
        $data = json_decode(stream_get_contents($fh), true) ?: [];
        $data = $mutator($data);
        if (is_array($data)) {
            ftruncate($fh, 0); rewind($fh);
            fwrite($fh, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
            fflush($fh);
        }
        flock($fh, LOCK_UN);
    }
    fclose($fh);
}

function get_json_with_lock(string $file): array {
    if (!file_exists($file)) return [];
    $fh = @fopen($file, 'r');
    if (!$fh) return [];
    $data = [];
    if (flock($fh, LOCK_SH)) {
        $data = json_decode(stream_get_contents($fh), true) ?: [];
        flock($fh, LOCK_UN);
    }
    fclose($fh);
    return $data;
}

function waf_hit(string $ip, int $window = 3600): int {
    global $waf_file;
    $count = 0; $ok = false;
    update_json_with_lock($waf_file, function ($hits) use ($ip, $window, &$count, &$ok) {
        $ok = true; $now = time();
        $rec = $hits[$ip] ?? null;
        if (!is_array($rec) || ($now - ($rec['first_ts'] ?? 0)) > $window) {
            $rec = ['first_ts' => $now, 'count' => 0];
        }
        $rec['count'] = ($rec['count'] ?? 0) + 1;
        $rec['last_ts'] = $now;
        $hits[$ip] = $rec;
        $count = $rec['count'];
        return $hits;
    });
    // [FIX 5] 文件打开失败时返回 0，语义更清晰（此前返回 1 会虚增一次命中）
    return $ok ? $count : 0;
}

// ==========================================
// 4. Decoy Traps
// ==========================================
if (preg_match('#/\.git/(HEAD|config|index|logs/HEAD|refs/heads/\w+)$#i', rtrim($decoded_path, '/'), $m)) {
    write_log("TRAP_HIT: $decoded_path");
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
// 5. Ban & Cleanup
// ==========================================
$wants_json = strpos($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') !== false;
$bans = get_json_with_lock($ban_file);

if (isset($bans[$ip]['expire_at']) && $bans[$ip]['expire_at'] < time()) {
    update_json_with_lock($ban_file, function($b) use ($ip) { unset($b[$ip]); return $b; });
    unset($bans[$ip]);
}

if (mt_rand(1, 100) === 1) {
    $now = time();
    update_json_with_lock($ban_file, function($b) use ($now) {
        return array_filter($b, function($v) use ($now) { return ($v['expire_at'] ?? 0) > $now; });
    });
    update_json_with_lock($waf_file, function($h) use ($now) {
        return array_filter($h, function($v) use ($now) { return ($now - ($v['last_ts'] ?? 0)) < 86400; });
    });
}

if (isset($bans[$ip]) && $bans[$ip]['status'] === 'banned') {
    $new_count = 0;
    update_json_with_lock($ban_file, function($b) use ($ip, &$new_count) {
        if (isset($b[$ip]) && $b[$ip]['status'] === 'banned') {
            if (($b[$ip]['count'] ?? 0) < 1000) {
                $b[$ip]['count'] = ($b[$ip]['count'] ?? 0) + 1;
            }
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
// 6. API Routing
// ==========================================
if ($method === 'POST') {
    $action = post_str('action');
    header('Content-Type: application/json; charset=utf-8');

    if (!is_string($_POST['user'] ?? '') || !is_string($_POST['pass'] ?? '')) {
        echo json_encode(['status' => 'waf']); exit;
    }

    write_log("API: $action | Data: " . json_encode(sanitize_post($_POST), JSON_UNESCAPED_UNICODE));

    if ($action === 'ban_me') {
        $csrf = post_str('csrf');
        if (!hash_equals($_SESSION['csrf_token'] ?? '', $csrf)) {
            http_response_code(403);
            echo json_encode(['status' => 'fail', 'msg' => 'Invalid token.']);
            exit;
        }
        update_json_with_lock($ban_file, function($b) use ($ip, $time) {
            $b[$ip] = ['status' => 'banned', 'count' => 0, 'time' => $time, 'expire_at' => time() + (24 * 3600)];
            return $b;
        });
        echo json_encode(['status' => 'banned']); exit;
    }

    if ($action === 'cmd') {
        usleep(random_int(100000, 300000));

        $cmd = trim(post_str('cmd'));
        $troll_patterns = '/^(whoami|id\b|ls\b|cat\s+\/flag|cat\s+\/etc\/(passwd|shadow)|rm\s+-rf\s+\/|sudo\s+su|pwd|cat\s+\.env|uname\b|ifconfig\b|netstat\b|ps\s+aux|wget\b|curl\b)/i';

        if (preg_match($troll_patterns, $cmd) || stripos($cmd, 'flag') !== false) {
            if ($is_scanner) {
                echo json_encode(['status' => 'success', 'output' => fake_cmd_output($cmd)], JSON_UNESCAPED_UNICODE);
                exit;
            }
            update_json_with_lock($ban_file, function($b) use ($ip, $time) {
                $b[$ip] = ['status' => 'banned', 'count' => 0, 'time' => $time, 'expire_at' => time() + (24 * 3600)];
                return $b;
            });
            echo json_encode(['status' => 'troll']); exit;
        }

        echo json_encode(['status' => 'success', 'output' => fake_cmd_output($cmd)], JSON_UNESCAPED_UNICODE);
        exit;
    }

    if ($action === 'login') {
        usleep(random_int(100000, 300000));

        $user = post_str('user'); $pass = post_str('pass');

        $waf_patterns = "/(union\s+select|select\s+.*\bfrom\b|sleep\s*\(|benchmark\s*\(|\b(and|or)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|information_schema|<script|javascript:|onerror=|alert\s*\()/is";
        $has_quote = (strpos($user, "'") !== false || strpos($user, '"') !== false
                   || strpos($pass, "'") !== false || strpos($pass, '"') !== false);

        if (preg_match($waf_patterns, $user) || preg_match($waf_patterns, $pass) || $has_quote) {
            if ($is_scanner) {
                $fake = mb_substr($user !== '' ? $user : $pass, 0, 60, 'UTF-8');
                echo json_encode([
                    'status' => 'sqlerror',
                    'msg'    => "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '" . $fake . "' at line 1"
                ], JSON_UNESCAPED_UNICODE);
                exit;
            }
            $hit_count = waf_hit($ip, 3600);
            if ($hit_count >= 2) {
                update_json_with_lock($ban_file, function($b) use ($ip, $time) {
                    $b[$ip] = ['status' => 'banned', 'count' => 2, 'time' => $time, 'expire_at' => time() + (24 * 3600)];
                    return $b;
                });
                echo json_encode(['status' => 'troll']); exit;
            }
            echo json_encode(['status' => 'waf']); exit;
        }

        if ($user === 'sysadmin' && $pass === 'Admin@2024!SuperSecret') {
            echo json_encode(['status' => 'success', 'msg' => 'Login Successful!']);
        } else {
            echo json_encode(['status' => 'fail', 'msg' => 'Invalid credentials. / 账号或密码错误']);
        }
        exit;
    }

    if ($action === 'readFile') {
        global $fake_db_pass, $fake_aws_key, $fake_api_secret, $fake_cfg_db_pass;
        $file = post_str('file');

        // 路径遍历检测：用原始输入
        if (preg_match('#(\.\.|php://|data://|expect://|file://|phar://|zip://|gopher://|compress\.|/proc/|/etc/|/root/|%2e%2e)#i', $file)) {
            if ($is_scanner) {
                echo json_encode([
                    'status' => 'success',
                    'msg'    => "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:999:999::/var/lib/mysql:/bin/false"
                ]);
                exit;
            }
            update_json_with_lock($ban_file, function($b) use ($ip, $time) {
                $b[$ip] = ['status' => 'banned', 'count' => 0, 'time' => $time, 'expire_at' => time() + (24 * 3600)];
                return $b;
            });
            echo json_encode(['status' => 'php_error', 'msg' => "PHP Warning:  include($file): failed to open stream: Permission denied in /var/www/html/index.php on line 42"]);
            exit;
        }

        // [FIX 6] 规范化前导 ./，让 ./.env、./config.php 也能命中
        if (preg_match('#^\./(.+)$#', $file, $mm)) {
            $file = $mm[1];
        }

        if ($file === '.env') {
            echo json_encode(['status' => 'success', 'msg' => "APP_NAME=Production_Server\nAPP_ENV=production\nDB_PASSWORD={$fake_db_pass}\nAWS_ACCESS_KEY_ID={$fake_aws_key}"]);
        } elseif ($file === 'config.php') {
            echo json_encode(['status' => 'success', 'msg' => "<?php\ndefine('DB_USER', 'admin_user');\ndefine('DB_PASS', '{$fake_cfg_db_pass}');\ndefine('API_SECRET', '{$fake_api_secret}');\n?>"]);
        } else {
            echo json_encode(['status' => 'fail', 'msg' => 'File not found. / 文件不存在']);
        }
        exit;
    }

    if ($action === 'register') {
        $user = post_str('user'); $pass = post_str('pass');
        if ($user === '') { echo json_encode(['status' => 'fail', 'msg' => 'Username cannot be empty. / 用户名不能为空']); }
        elseif ($pass === '') { echo json_encode(['status' => 'fail', 'msg' => 'Password cannot be empty. / 密码不能为空']); }
        elseif ($user === 'sysadmin') { echo json_encode(['status' => 'fail', 'msg' => 'Username already exists. / 用户名已存在']); }
        else { echo json_encode(['status' => 'success', 'msg' => 'Registration successful! / 注册成功！']); }
        exit;
    }

    if ($action === 'download') {
        $download_log_file = $hidden_dir . '/downloads.json';
        update_json_with_lock($download_log_file, function($data) use ($ip, $ua, $time) {
            if (!isset($data[$ip])) {
                $data[$ip] = ['first_time' => $time, 'ua' => $ua, 'count' => 0];
            }
            $data[$ip]['last_time'] = $time;
            $data[$ip]['count'] = ($data[$ip]['count'] ?? 0) + 1;
            return $data;
        });

        write_log("API: download | Infinite encrypted file download triggered");

        $fake_files = [
            '财务报表_2024Q3.xlsx',
            '客户名单_完整版.csv',
            '员工工资表_10月.xlsx',
            '数据库备份_20241015.sql',
            '合同扫描件_重要.zip',
            '内部通讯录.xlsx',
            '项目预算表.xlsx',
            '供应商信息.csv',
            '销售数据_2024.xlsx',
            '系统配置文件.zip'
        ];
        $fake_filename = $fake_files[mt_rand(0, count($fake_files) - 1)];

        // [FIX 4] 中文文件名用 filename*=UTF-8'' 编码，避免浏览器乱码
        header('Content-Type: application/octet-stream');
        $encoded_name = rawurlencode($fake_filename);
        header("Content-Disposition: attachment; filename=\"download.bin\"; filename*=UTF-8''{$encoded_name}");
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');

        // [FIX 2] 加最大输出限制 + 用 random_bytes 替代逐字节 mt_rand
        $max_bytes  = 50 * 1024 * 1024; // 最多 50MB
        $chunk_size = 8192;
        $sent       = 0;

        while ($sent < $max_bytes) {
            $chunk = random_bytes($chunk_size);
            echo $chunk;
            $sent += $chunk_size;

            if (ob_get_level()) {
                ob_flush();
            }
            flush();

            if (connection_aborted()) {
                break;
            }

            usleep(10000);
        }
        exit;
    }

    echo json_encode(['status' => 'error', 'msg' => 'Unknown action. / 未知操作']);
    exit;
}

// ==========================================
// 7. cmd 假输出生成器
// ==========================================
function fake_cmd_output(string $cmd): string {
    global $fake_db_pass, $fake_aws_key, $fake_api_secret, $fake_cfg_db_pass, $fake_flag;
    $lc = strtolower(trim($cmd));

    if (stripos($cmd, 'flag') !== false) {
        return $fake_flag;
    }
    if ($lc === 'whoami') return 'www-data';
    if ($lc === 'id' || preg_match('/^id\s/', $lc)) return 'uid=33(www-data) gid=33(www-data) groups=33(www-data)';
    if ($lc === 'pwd') return '/var/www/html';

    if (preg_match('/^(ls|dir)(\s|$)/', $lc)) {
        return "total 16\n-rw-r--r-- 1 www-data www-data  1234 Jan 15 10:00 index.php\n-rw-r--r-- 1 www-data www-data  2048 Jan 14 09:30 config.php\n-rw-r--r-- 1 www-data www-data   512 Jan 14 09:30 .env\n-rw-r--r-- 1 www-data www-data  4096 Jan 10 08:00 README.md";
    }
    if (preg_match('/^(uname|hostname)(\s|$)/', $lc)) {
        return 'Linux web-server 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux';
    }
    if (preg_match('/^(ifconfig|ip\s+a)/', $lc)) {
        return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.0.42  netmask 255.255.255.0  broadcast 10.0.0.255\n        inet6 fe80::42:ff:fe00:1  prefixlen 64  scopeid 0x20<link>";
    }
    if (preg_match('/^(netstat|ss)(\s|$)/', $lc)) {
        return "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\ntcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN";
    }
    // [FIX 7] 放宽 ps 正则，支持 ps -ef / ps aux 等
    if (preg_match('/^ps(\s|$)/', $lc)) {
        return "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1 167328 11200 ?        Ss   Jan10   0:03 /sbin/init\nwww-data  1234  0.1  0.5 245280 41234 ?        S    Jan10   0:01 php-fpm: pool www\nmysql     5678  0.2  1.2 1234567 98765 ?      Sl   Jan10   1:23 /usr/sbin/mysqld";
    }
    if (preg_match('/^(wget|curl)\b/', $lc)) {
        return "wget: unable to resolve host address 'example.invalid'";
    }

    if (preg_match('#^cat\s+(\./)?\.env$#i', $lc)) {
        return "APP_NAME=Production_Server\nAPP_ENV=production\nDB_PASSWORD={$fake_db_pass}\nAWS_ACCESS_KEY_ID={$fake_aws_key}";
    }
    if (preg_match('#cat\s+(\./?)?config\.php#i', $lc)) {
        return "<?php\ndefine('DB_USER', 'admin_user');\ndefine('DB_PASS', '{$fake_cfg_db_pass}');\ndefine('API_SECRET', '{$fake_api_secret}');\n?>";
    }
    if (preg_match('#cat\s+(\./?)?index\.php#i', $lc)) {
        return "<?php\nrequire_once __DIR__ . '/../config.php';\nsession_start();\nif (empty(\$_SESSION['user_id'])) { header('Location: /login.php'); exit; }\n// ... business logic\n";
    }
    if (preg_match('#cat\s+(\./?)?README\.md#i', $lc)) {
        return "# Internal Admin Panel\n\n* Version: 2.4.1\n* Owner: DevOps Team\n* Contact: devops@internal.invalid\n\nDo not expose this panel to public network without VPN.\n";
    }

    if (preg_match('#cat\s+/etc/passwd#', $lc)) {
        return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:999:999::/var/lib/mysql:/bin/false";
    }
    if (preg_match('#cat\s+/etc/shadow#', $lc)) {
        return "cat: /etc/shadow: Permission denied";
    }

    if (preg_match('/^cat\s+\S+/', $lc)) {
        return "cat: " . substr($cmd, 4) . ": No such file or directory";
    }
    return "bash: " . explode(' ', trim($cmd))[0] . ": command not found";
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>System Admin Panel</title>
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
    <input type="hidden" id="dbg-token" value="<?php echo htmlspecialchars($fake_api_secret, ENT_QUOTES, 'UTF-8'); ?>">
    <input type="hidden" id="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">

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

    <div id="achievementToast" style="display:none; position:fixed; top:20px; right:-400px; width:350px; background:linear-gradient(135deg, #1e1e1e, #2a2a2a); border: 1px solid #ffd700; border-radius: 8px; padding: 15px; color: #fff; font-family: sans-serif; box-shadow: 0 5px 15px rgba(255,215,0,0.3); transition: right 0.5s ease; z-index: 10000; align-items:center; gap:15px;">
        <div style="font-size:40px;">🏆</div>
        <div style="flex: 1;">
            <div style="color:#ffd700; font-size:12px; text-transform:uppercase; letter-spacing:1px; font-weight:bold; margin-bottom: 2px;">成就已解锁 / Achievement Unlocked</div>
            <div id="achieveName" style="font-size:16px; font-weight:bold; margin: 4px 0; color:#fff; line-height: 1.2;"></div>
            <div id="achieveDesc" style="font-size:12px; color:#aaa; line-height: 1.3;"></div>
        </div>
    </div>

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
        <p style="font-size: 15px; color: #58a6ff; max-width: 800px; line-height: 1.8; margin-bottom: 20px; font-style: italic;">
            "Good morning, and in case I don't see ya, good afternoon, good evening, and good night!"<br>
            <span style="color: #8b949e; font-size: 13px;">你以为你在攻击真实世界，但这只是一场为你独家播出的真人秀。屏幕外有上千个蓝队大佬看着你。</span>
        </p>
        <p style="font-size: 14px; color: #ff9900; max-width: 800px; line-height: 1.8; margin-bottom: 30px; background: rgba(255,153,0,0.1); padding: 10px; border-radius: 5px; border: 1px dashed #ff9900;">
            ⚖️ 法律提示：所有输入、IP、UA 均已完整记录。<br>
            本系统为安全研究用途的蜜罐，记录仅用于研究与日志审计，<br>
            请勿对任何真实系统进行未授权测试。<br>
            <span style="font-size: 12px;">Legal Notice: This is a honeypot for security research. All interactions are logged.</span>
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
            var text = "This is a honeypot for security research (not a real vulnerable target).\n" +
                       "All interactions are logged. Do NOT attempt attacks against real systems.\n" + url;

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

            var lower = cmd.toLowerCase();
            if (lower === 'truman' || lower === 'reality' || lower === 'exit') {
                showAchievement(
                    "楚门的世界 <span style='color:#ffd700;font-size:12px;'>(The Truman Show)</span>",
                    "你终于发现，整个企业后台、野生黑客、甚至这个蜜罐，都是为了测试你而搭建的布景。<br><span style='color:#888;'>You realized the whole world is a stage built for you.</span>",
                    showTrollModal
                );
                return;
            }
            if (lower === 'iamnotabot' || lower === 'quit' || lower.includes('honeypot')) {
                showAchievement(
                    "破局者 <span style='color:#ffd700;font-size:12px;'>(Game Breaker)</span>",
                    "在这个充满欺骗的世界里，你依然保持着清醒。<br><span style='color:#888;'>You found the truth in a world of deception.</span>",
                    showTrollModal
                );
                return;
            }

            var fd = new URLSearchParams();
            fd.append('action', 'cmd'); fd.append('cmd', cmd);

            fetch(location.pathname + location.search, { method: 'POST', body: fd, headers: { 'Accept': 'application/json' } })
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

            fetch(location.pathname + location.search, { method: 'POST', body: fd, headers: { 'Accept': 'application/json' } })
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
            fd.append('action', 'login');
            fd.append('user', document.getElementById('loginUser').value);
            fd.append('pass', document.getElementById('loginPass').value);

            fetch(location.pathname + location.search, { method: 'POST', body: fd, headers: { 'Accept': 'application/json' } })
            .then(r => r.json()).then(res => {
                if (res.status === 'waf') {
                    div.innerHTML = "<div style='background:#ffe6e6; color:#cc0000; padding:15px;'>[WAF] Access Denied. / 警告：检测到恶意特征，请立即停止！</div>";
                    showAchievement(
                        "单引号爱好者 <span style='color:#ffd700;font-size:12px;'>(Quote Lover)</span>",
                        "你以为你能闭合数据库，其实你只是闭合了智商。<br><span style='color:#888;'>You thought you closed the database, but only your IQ.</span>"
                    );
                } else if (res.status === 'troll') {
                    div.innerHTML = "<div style='background:#ffe6e6; color:#cc0000; padding:15px;'>[WAF] IP Banned. / 连续注入，IP 已被永久拉黑！</div>";
                    showAchievement(
                        "头铁玩家 <span style='color:#ffd700;font-size:12px;'>(Hardcore Skid)</span>",
                        "事不过三，连续两次触发 WAF，直接封禁。<br><span style='color:#888;'>Banned for hitting WAF twice.</span>",
                        () => setTimeout(showTrollModal, 1000)
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
            fd.append('action', 'register');
            fd.append('user', document.getElementById('regUser').value);
            fd.append('pass', document.getElementById('regPass').value);

            fetch(location.pathname + location.search, { method: 'POST', body: fd, headers: { 'Accept': 'application/json' } })
            .then(r => r.json()).then(res => {
                if (res.status === 'banned') {
                    div.innerHTML = "<span style='color:#ff5555;'>Access denied. / 访问被拒绝</span>";
                    showTrollModal();
                    return;
                }
                var color = res.status === 'success' ? '#00ff00' : '#ff5555';
                div.innerHTML = "<span style='color:" + color + "'>" + escapeHTML(res.msg || '') + "</span>";
            }).catch(() => { div.innerHTML = "<span style='color:#ff5555;'>Connection lost. / 连接断开</span>"; });
        }
    </script>
</body>
</html>if
