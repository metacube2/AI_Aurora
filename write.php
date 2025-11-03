<?php
/**
 * ═══════════════════════════════════════════════════════════
 * SECURE PRIVATE CHAT SYSTEM - VOLLSCHUTZ VERSION
 * ═══════════════════════════════════════════════════════════
 * Features:
 * - Altersverifikation (U18/Ü18 Trennung)
 * - User-ID System (Max#1234)
 * - Keyword-Filter (Treffen, Adressen, etc.)
 * - Rate-Limiting (Spam-Schutz)
 * - Wortfilter (Schimpfwörter)
 * - Link-Blockierung
 * - Report-System
 * - Block-Funktion
 * - Admin-Panel
 * - Auto-Flagging
 * - Log-System
 * - AGB/Disclaimer
 * - Server-Sent Events (Echtzeit)
 * ═══════════════════════════════════════════════════════════
 */

// ═══════════════════════════════════════════════════════════
// KONFIGURATION
// ═══════════════════════════════════════════════════════════

define('DB_FILE', __DIR__ . '/chat_secure.db');
define('MESSAGE_RETENTION_HOURS', 24);
define('LOG_RETENTION_MONTHS', 6);
define('ONLINE_TIMEOUT_SECONDS', 30);
define('SSE_RETRY_MS', 500);
define('MAX_MESSAGES_PER_FETCH', 200);

// Rate Limiting
define('MAX_MESSAGES_PER_MINUTE', 10);
define('MAX_MESSAGES_PER_HOUR', 100);
define('MAX_MESSAGES_PER_DAY_U18', 50);
define('UPLOAD_DIR', __DIR__ . '/uploads');
define('MAX_ATTACHMENT_SIZE', 200 * 1024); // 200 KB

// Upload-Verzeichnis erstellen
if (!is_dir(UPLOAD_DIR)) {
    mkdir(UPLOAD_DIR, 0755, true);
}

// Admin Credentials (BITTE ÄNDERN!)
define('ADMIN_USERNAME', 'admin');
define('ADMIN_PASSWORD', password_hash('SecureAdmin2025!', PASSWORD_BCRYPT));

// Keyword Blacklist (Treffen, Adressen, etc.)
$KEYWORD_BLACKLIST = [
    // Deutsch
    'treffen', 'meet', 'date', 'treff', 'sehen', 'besuchen',
    'adresse', 'wohnung', 'haus', 'straße', 'strasse',
    'telefon', 'nummer', 'handy', 'whatsapp', 'snapchat', 'instagram',
    'facebook', 'telegram', 'tiktok', 'discord',
    'foto', 'bild', 'selfie', 'nackt', 'video',
    'wo wohnst', 'wie alt', 'alter', 'geburtstag',
    'schule', 'klasse', 'lehrer',
    // Englisch
    'address', 'phone', 'number', 'picture', 'pic', 'naked',
    'where do you live', 'how old', 'school',
];

// Wortfilter (Schimpfwörter - TOP 50)
$PROFANITY_FILTER = [
    // Deutsch (Beispiele - erweitere selbst)
    'arsch', 'scheisse', 'scheiße', 'fick', 'hurensohn',
    'wichser', 'fotze', 'schlampe', 'bastard', 'idiot',
    'vollidiot', 'depp', 'trottel', 'schwachkopf',
    // Englisch
    'fuck', 'shit', 'ass', 'bitch', 'bastard',
    'damn', 'crap', 'dick', 'pussy', 'cock',
];

// ═══════════════════════════════════════════════════════════
// DATENBANK SETUP
// ═══════════════════════════════════════════════════════════

function getDB() {
    $db = new SQLite3(DB_FILE);
    $db->busyTimeout(5000);
    
    // Users Table (mit Geburtsdatum und User-ID)
    $db->exec('
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            user_id TEXT UNIQUE NOT NULL,
            birthdate DATE NOT NULL,
            age_group TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_banned INTEGER DEFAULT 0,
            ban_reason TEXT
        )
    ');
    
 


    // Messages Table
$db->exec('
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user_id INTEGER NOT NULL,
        to_user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_read INTEGER DEFAULT 0,
        is_flagged INTEGER DEFAULT 0,
        flag_reason TEXT,
        attachment_path TEXT,
        attachment_type TEXT,
        attachment_size INTEGER,
        FOREIGN KEY (from_user_id) REFERENCES users(id),
        FOREIGN KEY (to_user_id) REFERENCES users(id)
    )
');

    
    // Online Status Table
    $db->exec('
        CREATE TABLE IF NOT EXISTS online_status (
            user_id INTEGER PRIMARY KEY,
            last_ping DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ');

    // User Sessions Table
    $db->exec('
        CREATE TABLE IF NOT EXISTS user_sessions (
            user_id INTEGER PRIMARY KEY,
            session_token TEXT NOT NULL,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ');

    // Reports Table
    $db->exec('
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_id INTEGER NOT NULL,
            reported_user_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            message_id INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT "pending",
            FOREIGN KEY (reporter_id) REFERENCES users(id),
            FOREIGN KEY (reported_user_id) REFERENCES users(id),
            FOREIGN KEY (message_id) REFERENCES messages(id)
        )
    ');
    
    // Blocks Table
    $db->exec('
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            blocker_id INTEGER NOT NULL,
            blocked_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (blocker_id) REFERENCES users(id),
            FOREIGN KEY (blocked_id) REFERENCES users(id),
            UNIQUE(blocker_id, blocked_id)
        )
    ');
    
    // Rate Limiting Table
    $db->exec('
        CREATE TABLE IF NOT EXISTS rate_limits (
            user_id INTEGER NOT NULL,
            action_type TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ');
    
    // Logs Table (für Behörden)
    $db->exec('
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ');
    
    // Admin Table
    $db->exec('
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ');
    
    // Create default admin if not exists
   // Admin-Account erstellen (nur einmal!)
$stmt = $db->prepare('SELECT COUNT(*) as count FROM admins WHERE username = :username');
$stmt->bindValue(':username', ADMIN_USERNAME, SQLITE3_TEXT);
$result = $stmt->execute();
$row = $result->fetchArray(SQLITE3_ASSOC);

if ($row['count'] == 0) {
    $stmt = $db->prepare('INSERT INTO admins (username, password_hash) VALUES (:username, :password)');
    $stmt->bindValue(':username', ADMIN_USERNAME, SQLITE3_TEXT);
    $stmt->bindValue(':password', ADMIN_PASSWORD, SQLITE3_TEXT);
    $stmt->execute();
}


 

        // Create indexes
        $db->exec('CREATE INDEX IF NOT EXISTS idx_messages_users ON messages(from_user_id, to_user_id)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_users_age_group ON users(age_group)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_blocks ON blocks(blocker_id, blocked_id)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_user_sessions_last_seen ON user_sessions(last_seen)');

        $initialized = true;
    }
    
    // Create indexes
    $db->exec('CREATE INDEX IF NOT EXISTS idx_messages_users ON messages(from_user_id, to_user_id)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_users_age_group ON users(age_group)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_blocks ON blocks(blocker_id, blocked_id)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_user_sessions_last_seen ON user_sessions(last_seen)');

    return $db;
}

// ═══════════════════════════════════════════════════════════
// SECURITY FUNCTIONS
// ═══════════════════════════════════════════════════════════

function generateUserId() {
    return str_pad(mt_rand(1000, 9999), 4, '0', STR_PAD_LEFT);
}

function calculateAge($birthdate) {
    $birth = new DateTime($birthdate);
    $today = new DateTime();
    return $birth->diff($today)->y;
}

function getAgeGroup($birthdate) {
    $age = calculateAge($birthdate);
    return $age < 18 ? 'U18' : 'O18';
}

function checkKeywordBlacklist($message) {
    global $KEYWORD_BLACKLIST;
    
    $message_lower = mb_strtolower($message, 'UTF-8');
    
    foreach ($KEYWORD_BLACKLIST as $keyword) {
        if (stripos($message_lower, $keyword) !== false) {
            return ['blocked' => true, 'keyword' => $keyword];
        }
    }
    
    return ['blocked' => false];
}

function checkProfanityFilter($message) {
    global $PROFANITY_FILTER;
    
    $message_lower = mb_strtolower($message, 'UTF-8');
    
    foreach ($PROFANITY_FILTER as $word) {
        if (stripos($message_lower, $word) !== false) {
            return ['blocked' => true, 'word' => $word];
        }
    }
    
    return ['blocked' => false];
}

function checkLinkFilter($message) {
    $patterns = [
        '/https?:\/\//i',
        '/www\./i',
        '/[a-z0-9-]+\.(com|de|ch|net|org|info)/i'
    ];
    
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $message)) {
            return ['blocked' => true];
        }
    }
    
    return ['blocked' => false];
}

function checkRateLimit($userId, $ageGroup) {
    $db = getDB();
    
    // Check messages per minute
    $stmt = $db->prepare("
        SELECT COUNT(*) as count 
        FROM rate_limits 
        WHERE user_id = :user_id 
        AND action_type = 'message' 
        AND timestamp > datetime('now', '-1 minute')
    ");
    $stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    
    if ($row['count'] >= MAX_MESSAGES_PER_MINUTE) {
        return ['allowed' => false, 'reason' => 'Zu viele Nachrichten pro Minute (max ' . MAX_MESSAGES_PER_MINUTE . ')'];
    }
    
    // Check messages per hour
    $stmt = $db->prepare("
        SELECT COUNT(*) as count 
        FROM rate_limits 
        WHERE user_id = :user_id 
        AND action_type = 'message' 
        AND timestamp > datetime('now', '-1 hour')
    ");
    $stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    
    if ($row['count'] >= MAX_MESSAGES_PER_HOUR) {
        return ['allowed' => false, 'reason' => 'Zu viele Nachrichten pro Stunde (max ' . MAX_MESSAGES_PER_HOUR . ')'];
    }
    
    // Check messages per day for U18
    if ($ageGroup === 'U18') {
        $stmt = $db->prepare("
            SELECT COUNT(*) as count 
            FROM rate_limits 
            WHERE user_id = :user_id 
            AND action_type = 'message' 
            AND timestamp > datetime('now', '-1 day')
        ");
        $stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);
        
        if ($row['count'] >= MAX_MESSAGES_PER_DAY_U18) {
            return ['allowed' => false, 'reason' => 'Tages-Limit erreicht (max ' . MAX_MESSAGES_PER_DAY_U18 . ' für U18)'];
        }
    }
    
    return ['allowed' => true];
}

function logRateLimit($userId) {
    $db = getDB();
    $stmt = $db->prepare("INSERT INTO rate_limits (user_id, action_type) VALUES (:user_id, 'message')");
    $stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
    $stmt->execute();
}

function logSecurityEvent($userId, $action, $details = '') {
    $db = getDB();
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    
    $stmt = $db->prepare('
        INSERT INTO security_logs (user_id, action, details, ip_address)
        VALUES (:user_id, :action, :details, :ip)
    ');
    $stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
    $stmt->bindValue(':action', $action, SQLITE3_TEXT);
    $stmt->bindValue(':details', $details, SQLITE3_TEXT);
    $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
    $stmt->execute();
}

function canUsersChatByAge($ageGroupA, $ageGroupB) {
    if (!$ageGroupA || !$ageGroupB) {
        return false;
    }

    // Wenn einer minderjährig ist, müssen beide minderjährig sein
    if ($ageGroupA === 'U18' || $ageGroupB === 'U18') {
        return $ageGroupA === 'U18' && $ageGroupB === 'U18';
    }

    // Volljährige dürfen miteinander chatten
    return true;
}

function isBlocked($userId, $otherUserId) {
    $db = getDB();
    $stmt = $db->prepare('
        SELECT COUNT(*) as count 
        FROM blocks 
        WHERE (blocker_id = :user1 AND blocked_id = :user2)
        OR (blocker_id = :user2 AND blocked_id = :user1)
    ');
    $stmt->bindValue(':user1', $userId, SQLITE3_INTEGER);
    $stmt->bindValue(':user2', $otherUserId, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    
    return $row['count'] > 0;
}

function cleanupOldData() {
    $db = getDB();

    // Delete old messages
    $hours = MESSAGE_RETENTION_HOURS;
    $attachmentResult = $db->query("SELECT attachment_path FROM messages WHERE attachment_path IS NOT NULL AND timestamp < datetime('now', '-{$hours} hours')");
    while ($attachmentRow = $attachmentResult->fetchArray(SQLITE3_ASSOC)) {
        $relativePath = $attachmentRow['attachment_path'] ?? '';
        if (!$relativePath) {
            continue;
        }

        $normalizedPath = str_replace('\\', '/', $relativePath);
        if (strpos($normalizedPath, 'uploads/') !== 0) {
            continue;
        }

        $fullPath = __DIR__ . '/' . $normalizedPath;
        if (is_file($fullPath)) {
            @unlink($fullPath);
        }
    }

    $db->exec("DELETE FROM messages WHERE timestamp < datetime('now', '-{$hours} hours')");
    
    // Delete old rate limits
    $db->exec("DELETE FROM rate_limits WHERE timestamp < datetime('now', '-1 day')");
    
    // Delete old logs (keep 6 months)
    $months = LOG_RETENTION_MONTHS;
    $db->exec("DELETE FROM security_logs WHERE timestamp < datetime('now', '-{$months} months')");

    // Remove stale session placeholders
    $db->exec("DELETE FROM user_sessions WHERE last_seen < datetime('now', '-5 minutes')");
}

// ═══════════════════════════════════════════════════════════
// SESSION & AUTH
// ═══════════════════════════════════════════════════════════

session_start();
$isAdminPage = isset($_GET['admin']);

function isLoggedIn() {
    return isset($_SESSION['user_id']) && isset($_SESSION['username']);
}

function isAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true;
}

function getCurrentUserId() {
    return $_SESSION['user_id'] ?? null;
}

function getCurrentUsername() {
    return $_SESSION['username'] ?? null;
}

function getCurrentUserDisplayName() {
    if (!isLoggedIn()) return null;
    return $_SESSION['username'] . '#' . $_SESSION['user_display_id'];
}

function getCurrentAgeGroup() {
    return $_SESSION['age_group'] ?? null;
}

function updateOnlineStatus($userId) {
    $db = getDB();
    $stmt = $db->prepare('
        INSERT OR REPLACE INTO online_status (user_id, last_ping)
        VALUES (:user_id, CURRENT_TIMESTAMP)
    ');
    $stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
    $stmt->execute();

    $stmt = $db->prepare('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = :user_id');
    $stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
    $stmt->execute();

    touchUserSession($userId);
}

function generateSessionToken() {
    return bin2hex(random_bytes(32));
}

function startUserSession($userId) {
    if (!$userId) {
        return ['allowed' => false, 'error' => 'Ungültige Benutzer-ID'];
    }

    $db = getDB();
    $stmt = $db->prepare('SELECT session_token, last_seen FROM user_sessions WHERE user_id = :user_id');
    $stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $existing = $result->fetchArray(SQLITE3_ASSOC);

    if ($existing && !empty($existing['last_seen'])) {
        $secondsSinceLastSeen = time() - strtotime($existing['last_seen']);

        if ($secondsSinceLastSeen < ONLINE_TIMEOUT_SECONDS) {
            return [
                'allowed' => false,
                'error' => 'Du bist bereits auf einem anderen Gerät eingeloggt. Bitte dort zuerst ausloggen oder kurz warten.'
            ];
        }
    }

    $token = generateSessionToken();

    $stmt = $db->prepare('
        INSERT OR REPLACE INTO user_sessions (user_id, session_token, last_seen)
        VALUES (:user_id, :token, CURRENT_TIMESTAMP)
    ');
    $stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
    $stmt->bindValue(':token', $token, SQLITE3_TEXT);
    $stmt->execute();

    $_SESSION['session_token'] = $token;

    return ['allowed' => true, 'token' => $token];
}

function touchUserSession($userId) {
    if (!$userId || empty($_SESSION['session_token'])) {
        return;
    }

    $db = getDB();
    $stmt = $db->prepare('
        UPDATE user_sessions
        SET last_seen = CURRENT_TIMESTAMP
        WHERE user_id = :user_id AND session_token = :token
    ');
    $stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
    $stmt->bindValue(':token', $_SESSION['session_token'], SQLITE3_TEXT);
    $stmt->execute();
}

function clearUserSession($userId) {
    if (!$userId) {
        return;
    }

    $db = getDB();
    $stmt = $db->prepare('DELETE FROM user_sessions WHERE user_id = :user_id');
    $stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
    $stmt->execute();

    unset($_SESSION['session_token']);
}

function validateActiveSession() {
    if (!isLoggedIn()) {
        return false;
    }

    $token = $_SESSION['session_token'] ?? null;
    if (!$token) {
        return false;
    }

    $db = getDB();
    $stmt = $db->prepare('SELECT session_token, last_seen FROM user_sessions WHERE user_id = :user_id');
    $stmt->bindValue(':user_id', getCurrentUserId(), SQLITE3_INTEGER);
    $result = $stmt->execute();
    $session = $result->fetchArray(SQLITE3_ASSOC);

    if (!$session) {
        return false;
    }

    if (!hash_equals($session['session_token'], $token)) {
        return false;
    }

    if (!empty($session['last_seen'])) {
        $secondsSinceLastSeen = time() - strtotime($session['last_seen']);

        if ($secondsSinceLastSeen > ONLINE_TIMEOUT_SECONDS * 3) {
            return false;
        }
    }

    return true;
}

// ═══════════════════════════════════════════════════════════
// AJAX API HANDLER
// ═══════════════════════════════════════════════════════════

if (isset($_POST['action']) || isset($_GET['action'])) {
    header('Content-Type: application/json');
    
    $action = $_POST['action'] ?? $_GET['action'];
    
    // ───────────────────────────────────────────────────────
    // REGISTER
    // ───────────────────────────────────────────────────────
    if ($action === 'register') {
        $username = trim($_POST['username'] ?? '');
        $birthdate = trim($_POST['birthdate'] ?? '');
        $agreed_terms = isset($_POST['agreed_terms']) && $_POST['agreed_terms'] === 'true';

        // Validierung
        if (empty($username) || empty($birthdate)) {
            echo json_encode(['success' => false, 'error' => 'Username und Geburtsdatum erforderlich']);
            exit;
        }
        
        if (!$agreed_terms) {
            echo json_encode(['success' => false, 'error' => 'Bitte akzeptiere die Nutzungsbedingungen']);
            exit;
        }
        
        if (strlen($username) < 3 || strlen($username) > 15) {
            echo json_encode(['success' => false, 'error' => 'Username muss 3-15 Zeichen lang sein']);
            exit;
        }
        
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            echo json_encode(['success' => false, 'error' => 'Nur Buchstaben, Zahlen und _ erlaubt']);
            exit;
        }
        
        // Verbotene Usernamen
        $forbidden = ['admin', 'moderator', 'support', 'system', 'root'];
        if (in_array(strtolower($username), $forbidden)) {
            echo json_encode(['success' => false, 'error' => 'Dieser Username ist nicht erlaubt']);
            exit;
        }
        
        // Alter prüfen
        $age = calculateAge($birthdate);
        if ($age < 13) {
            echo json_encode(['success' => false, 'error' => 'Du musst mindestens 13 Jahre alt sein']);
            logSecurityEvent(null, 'REGISTER_UNDERAGE', "Username: $username, Age: $age");
            exit;
        }
        
        $ageGroup = getAgeGroup($birthdate);
        
        $db = getDB();
        
        // Generate unique user_id
        $userId = generateUserId();
        $attempts = 0;
        while ($attempts < 10) {
            $stmt = $db->prepare('SELECT COUNT(*) as count FROM users WHERE user_id = :user_id');
            $stmt->bindValue(':user_id', $userId, SQLITE3_TEXT);
            $result = $stmt->execute();
            $row = $result->fetchArray(SQLITE3_ASSOC);
            
            if ($row['count'] == 0) break;
            
            $userId = generateUserId();
            $attempts++;
        }
        
        // Create user
        $stmt = $db->prepare('
            INSERT INTO users (username, user_id, birthdate, age_group)
            VALUES (:username, :user_id, :birthdate, :age_group)
        ');
        $stmt->bindValue(':username', $username, SQLITE3_TEXT);
        $stmt->bindValue(':user_id', $userId, SQLITE3_TEXT);
        $stmt->bindValue(':birthdate', $birthdate, SQLITE3_TEXT);
        $stmt->bindValue(':age_group', $ageGroup, SQLITE3_TEXT);
        $stmt->execute();

        $dbUserId = $db->lastInsertRowID();

        $sessionResult = startUserSession($dbUserId);
        if (!$sessionResult['allowed']) {
            logSecurityEvent($dbUserId, 'LOGIN_BLOCKED_DUPLICATE_SESSION', 'REGISTER');
            echo json_encode([
                'success' => false,
                'error' => $sessionResult['error']
            ]);
            exit;
        }

        $_SESSION['user_id'] = $dbUserId;
        $_SESSION['username'] = $username;
        $_SESSION['user_display_id'] = $userId;
        $_SESSION['age_group'] = $ageGroup;
        $_SESSION['birthdate'] = $birthdate;
        
        updateOnlineStatus($dbUserId);
        logSecurityEvent($dbUserId, 'REGISTER', "Age group: $ageGroup");
        
        echo json_encode([
            'success' => true,
            'user_id' => $dbUserId,
            'username' => $username,
            'display_name' => $username . '#' . $userId,
            'age_group' => $ageGroup
        ]);
        exit;
    }

    // ───────────────────────────────────────────────────────
    // LOGIN
    // ───────────────────────────────────────────────────────
    if ($action === 'login') {
        $username = trim($_POST['username'] ?? '');
        $birthdate = trim($_POST['birthdate'] ?? '');
        $forceLogin = in_array(($_POST['force_login'] ?? '0'), ['1', 'true', 'TRUE'], true);

        if ($username === '' || $birthdate === '') {
            echo json_encode(['success' => false, 'error' => 'Bitte gib Username und Geburtsdatum ein.']);
            exit;
        }

        $db = getDB();
        $stmt = $db->prepare('
            SELECT id, username, user_id as display_id, birthdate, age_group, is_banned, ban_reason
            FROM users
            WHERE LOWER(username) = LOWER(:username)
            LIMIT 1
        ');
        $stmt->bindValue(':username', $username, SQLITE3_TEXT);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);

        if (!$user) {
            echo json_encode(['success' => false, 'error' => 'Account wurde nicht gefunden.']);
            exit;
        }

        if ((int)$user['is_banned'] === 1) {
            $reason = $user['ban_reason'] ? (string)$user['ban_reason'] : 'Verstoß gegen Regeln';
            echo json_encode(['success' => false, 'error' => 'Dein Account ist gesperrt: ' . $reason]);
            exit;
        }

        if ($user['birthdate'] !== $birthdate) {
            logSecurityEvent($user['id'], 'LOGIN_FAILED', 'Falsches Geburtsdatum');
            echo json_encode(['success' => false, 'error' => 'Daten stimmen nicht überein.']);
            exit;
        }

        $sessionResult = startUserSession($user['id'], $forceLogin);
        if (!$sessionResult['allowed']) {
            $response = [
                'success' => false,
                'error' => $sessionResult['error'] ?? 'Anmeldung nicht möglich.'
            ];

            if (!empty($sessionResult['can_force'])) {
                $response['can_force'] = true;
            }

            echo json_encode($response);
            exit;
        }

        if ($forceLogin) {
            logSecurityEvent($user['id'], 'LOGIN_FORCE', 'Sitzung übernommen');
        }

        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['user_display_id'] = $user['display_id'];
        $_SESSION['age_group'] = $user['age_group'];
        $_SESSION['birthdate'] = $user['birthdate'];

        updateOnlineStatus($user['id']);
        logSecurityEvent($user['id'], 'LOGIN', 'Erfolgreiche Anmeldung');

        echo json_encode([
            'success' => true,
            'user_id' => $user['id'],
            'display_name' => $user['username'] . '#' . $user['display_id'],
            'age_group' => $user['age_group']
        ]);
        exit;
    }

    // ───────────────────────────────────────────────────────
    // ADMIN LOGIN
    // ───────────────────────────────────────────────────────
    if ($action === 'admin_login') {
        $username = trim($_POST['username'] ?? '');
        $password = trim($_POST['password'] ?? '');
        
        $db = getDB();
        $stmt = $db->prepare('SELECT * FROM admins WHERE username = :username');
        $stmt->bindValue(':username', $username, SQLITE3_TEXT);
        $result = $stmt->execute();
        $admin = $result->fetchArray(SQLITE3_ASSOC);
        
        if ($admin && password_verify($password, $admin['password_hash'])) {
            $_SESSION['is_admin'] = true;
            $_SESSION['admin_id'] = $admin['id'];
            $_SESSION['admin_username'] = $admin['username'];
            
            logSecurityEvent(null, 'ADMIN_LOGIN', "Admin: $username");
            
            echo json_encode(['success' => true]);
        } else {
            logSecurityEvent(null, 'ADMIN_LOGIN_FAILED', "Username: $username");
            echo json_encode(['success' => false, 'error' => 'Ungültige Zugangsdaten']);
        }
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // LOGOUT
    // ───────────────────────────────────────────────────────
    if ($action === 'logout') {
        if (isLoggedIn()) {
            $currentUserId = getCurrentUserId();
            logSecurityEvent($currentUserId, 'LOGOUT', '');
            clearUserSession($currentUserId);
        }
        session_destroy();
        echo json_encode(['success' => true]);
        exit;
    }

    // All other actions require login
    if (!isLoggedIn() && !isAdmin()) {
        echo json_encode(['success' => false, 'error' => 'Nicht eingeloggt']);
        exit;
    }

    if (isLoggedIn() && !isAdmin() && !validateActiveSession()) {
        $userId = getCurrentUserId();
        clearUserSession($userId);
        session_destroy();
        echo json_encode(['success' => false, 'error' => 'Deine Sitzung ist nicht mehr gültig. Bitte erneut einloggen.']);
        exit;
    }

    if (isLoggedIn() && !isAdmin()) {
        touchUserSession(getCurrentUserId());
    }
    
    // ───────────────────────────────────────────────────────
    // PING (UPDATE ONLINE STATUS)
    // ───────────────────────────────────────────────────────
    if ($action === 'ping') {
        updateOnlineStatus(getCurrentUserId());
        cleanupOldData();
        echo json_encode(['success' => true]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // GET USERS
    // ───────────────────────────────────────────────────────
    if ($action === 'get_users') {
        $db = getDB();
        $currentUserId = getCurrentUserId();
        $currentAgeGroup = getCurrentAgeGroup();
        
        $query = '
            SELECT
                u.id,
                u.username,
                u.user_id as display_id,
                u.age_group,
                u.last_seen,
                CASE
                    WHEN os.last_ping IS NOT NULL
                    AND (julianday("now") - julianday(os.last_ping)) * 86400 < ' . ONLINE_TIMEOUT_SECONDS . '
                    THEN 1
                    ELSE 0
                END as is_online,
                (
                    SELECT COUNT(*)
                    FROM messages
                    WHERE from_user_id = u.id
                    AND to_user_id = :current_user_id
                    AND is_read = 0
                ) as unread_count,
                (
                    SELECT COUNT(*)
                    FROM blocks
                    WHERE blocker_id = :current_user_id
                    AND blocked_id = u.id
                ) as is_blocked_by_me,
                (
                    SELECT COUNT(*)
                    FROM blocks
                    WHERE blocker_id = u.id
                    AND blocked_id = :current_user_id
                ) as has_blocked_me
            FROM users u
            LEFT JOIN online_status os ON u.id = os.user_id
            WHERE u.id != :current_user_id
            AND u.is_banned = 0
        ';

        if ($currentAgeGroup === 'U18') {
            $query .= ' AND u.age_group = :allowed_group';
        } else {
            $query .= ' AND u.age_group != :blocked_group';
        }

        $query .= ' ORDER BY is_online DESC, u.username ASC';

        $stmt = $db->prepare($query);
        $stmt->bindValue(':current_user_id', $currentUserId, SQLITE3_INTEGER);

        if ($currentAgeGroup === 'U18') {
            $stmt->bindValue(':allowed_group', 'U18', SQLITE3_TEXT);
        } else {
            $stmt->bindValue(':blocked_group', 'U18', SQLITE3_TEXT);
        }
        $result = $stmt->execute();
        
        $users = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            // Don't show users who blocked me or I blocked
            if ($row['is_blocked_by_me'] > 0 || $row['has_blocked_me'] > 0) {
                continue;
            }
            
            $users[] = [
                'id' => $row['id'],
                'username' => $row['username'],
                'display_id' => $row['display_id'],
                'display_name' => $row['username'] . '#' . $row['display_id'],
                'age_group' => $row['age_group'],
                'is_online' => $row['is_online'],
                'unread_count' => $row['unread_count']
            ];
        }
        
        echo json_encode(['success' => true, 'users' => $users]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // GET MESSAGES
    // ───────────────────────────────────────────────────────
    if ($action === 'get_messages') {
        $otherUserId = intval($_GET['user_id'] ?? 0);

        if ($otherUserId <= 0) {
            echo json_encode(['success' => false, 'error' => 'Ungültige User-ID']);
            exit;
        }

        // Check if blocked
        if (isBlocked(getCurrentUserId(), $otherUserId)) {
            echo json_encode(['success' => false, 'error' => 'Chat nicht verfügbar']);
            exit;
        }

        $db = getDB();
        $currentUserId = getCurrentUserId();
        $currentAgeGroup = getCurrentAgeGroup();

        $stmt = $db->prepare('SELECT age_group FROM users WHERE id = :user_id AND is_banned = 0');
        $stmt->bindValue(':user_id', $otherUserId, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $otherUser = $result->fetchArray(SQLITE3_ASSOC);

        if (!$otherUser) {
            echo json_encode(['success' => false, 'error' => 'Benutzer nicht gefunden']);
            exit;
        }

        if (!canUsersChatByAge($currentAgeGroup, $otherUser['age_group'])) {
            logSecurityEvent($currentUserId, 'AGE_RESTRICTION_BLOCKED', "GET_MESSAGES -> User $otherUserId");
            echo json_encode(['success' => false, 'error' => 'Chat zwischen Altersgruppen nicht erlaubt']);
            exit;
        }

        $query = '
            SELECT * FROM (
                SELECT
                    m.id,
                    m.from_user_id,
                    m.to_user_id,
                    m.message,
                    m.timestamp,
                    m.is_read,
                    m.is_flagged,
                    u.username as from_username,
                    u.user_id as from_display_id
                FROM messages m
                JOIN users u ON m.from_user_id = u.id
                WHERE
                    (m.from_user_id = :current_user_id AND m.to_user_id = :other_user_id)
                    OR
                    (m.from_user_id = :other_user_id AND m.to_user_id = :current_user_id)
                ORDER BY m.id DESC
                LIMIT :limit
            )
            ORDER BY id ASC
        ';

        $stmt = $db->prepare($query);
        $stmt->bindValue(':current_user_id', $currentUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':other_user_id', $otherUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':limit', MAX_MESSAGES_PER_FETCH, SQLITE3_INTEGER);
        $result = $stmt->execute();
        
        $messages = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $messages[] = [
                'id' => $row['id'],
                'from_user_id' => $row['from_user_id'],
                'to_user_id' => $row['to_user_id'],
                'message' => $row['message'],
                'timestamp' => $row['timestamp'],
                'is_read' => $row['is_read'],
                'is_flagged' => $row['is_flagged'],
                'attachment_url' => $row['attachment_path'] ?: null,
                'attachment_type' => $row['attachment_type'] ?: null,
                'attachment_size' => $row['attachment_size'] !== null ? (int)$row['attachment_size'] : null,
                'from_username' => $row['from_username'],
                'from_display_name' => $row['from_username'] . '#' . $row['from_display_id']
            ];
        }
        
        echo json_encode(['success' => true, 'messages' => $messages]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // SEND MESSAGE
    // ───────────────────────────────────────────────────────
    if ($action === 'send_message') {
        $toUserId = intval($_POST['to_user_id'] ?? 0);
        $message = trim($_POST['message'] ?? '');
        $hasAttachment = isset($_FILES['attachment']) && ($_FILES['attachment']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE;

        if ($toUserId <= 0) {
            echo json_encode(['success' => false, 'error' => 'Ungültige User-ID']);
            exit;
        }

        if (!$hasAttachment && $message === '') {
            echo json_encode(['success' => false, 'error' => 'Nachricht oder Bild erforderlich']);
            exit;
        }

        if (strlen($message) > 1000) {
            echo json_encode(['success' => false, 'error' => 'Nachricht zu lang (max 1000 Zeichen)']);
            exit;
        }

        $attachmentFile = $hasAttachment ? $_FILES['attachment'] : null;
        $attachmentMime = null;
        $attachmentSize = null;

        if ($hasAttachment && $attachmentFile) {
            if (!is_uploaded_file($attachmentFile['tmp_name'])) {
                echo json_encode(['success' => false, 'error' => 'Ungültiger Datei-Upload']);
                exit;
            }

            if ($attachmentFile['error'] !== UPLOAD_ERR_OK) {
                echo json_encode(['success' => false, 'error' => 'Bild konnte nicht hochgeladen werden']);
                exit;
            }

            if ($attachmentFile['size'] > MAX_ATTACHMENT_SIZE) {
                echo json_encode(['success' => false, 'error' => 'Bild ist zu groß (max. 200 KB)']);
                exit;
            }

            $attachmentSize = (int)$attachmentFile['size'];

            $mime = null;
            if (function_exists('finfo_open')) {
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                if ($finfo) {
                    $mime = finfo_file($finfo, $attachmentFile['tmp_name']);
                    finfo_close($finfo);
                }
            }
            if (!$mime && function_exists('mime_content_type')) {
                $mime = mime_content_type($attachmentFile['tmp_name']);
            }
            if (!$mime && isset($attachmentFile['type'])) {
                $mime = $attachmentFile['type'];
            }

            $mime = strtolower((string)$mime);
            if (!in_array($mime, ['image/jpeg', 'image/pjpeg', 'image/jpg'], true)) {
                echo json_encode(['success' => false, 'error' => 'Nur JPG-Bilder sind erlaubt']);
                exit;
            }

            $imageInfo = @getimagesize($attachmentFile['tmp_name']);
            if ($imageInfo === false || !in_array($imageInfo[2], [IMAGETYPE_JPEG], true)) {
                echo json_encode(['success' => false, 'error' => 'Bilddatei konnte nicht verifiziert werden']);
                exit;
            }

            $attachmentMime = 'image/jpeg';
        }

        // Check if blocked
        if (isBlocked(getCurrentUserId(), $toUserId)) {
            echo json_encode(['success' => false, 'error' => 'Nachricht kann nicht gesendet werden']);
            exit;
        }

        $db = getDB();
        $currentUserId = getCurrentUserId();
        $currentAgeGroup = getCurrentAgeGroup();

        $stmt = $db->prepare('SELECT age_group FROM users WHERE id = :user_id AND is_banned = 0');
        $stmt->bindValue(':user_id', $toUserId, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $targetUser = $result->fetchArray(SQLITE3_ASSOC);

        if (!$targetUser) {
            echo json_encode(['success' => false, 'error' => 'Empfänger nicht gefunden']);
            exit;
        }

        if (!canUsersChatByAge($currentAgeGroup, $targetUser['age_group'])) {
            logSecurityEvent($currentUserId, 'AGE_RESTRICTION_BLOCKED', "SEND_MESSAGE -> User $toUserId");
            echo json_encode(['success' => false, 'error' => 'Nachrichten zwischen Altersgruppen nicht erlaubt']);
            exit;
        }

        // Rate Limiting
        $rateLimitCheck = checkRateLimit($currentUserId, $currentAgeGroup);
        if (!$rateLimitCheck['allowed']) {
            logSecurityEvent($currentUserId, 'RATE_LIMIT_EXCEEDED', $rateLimitCheck['reason']);
            echo json_encode(['success' => false, 'error' => $rateLimitCheck['reason']]);
            exit;
        }

        if ($message !== '') {
            // Keyword Blacklist
            $keywordCheck = checkKeywordBlacklist($message);
            if ($keywordCheck['blocked']) {
                logSecurityEvent($currentUserId, 'KEYWORD_BLOCKED', "Keyword: {$keywordCheck['keyword']}");
                echo json_encode([
                    'success' => false,
                    'error' => 'Deine Nachricht enthält nicht erlaubte Inhalte',
                    'details' => 'Verbotenes Wort erkannt: ' . $keywordCheck['keyword']
                ]);
                exit;
            }

            // Profanity Filter
            $profanityCheck = checkProfanityFilter($message);
            if ($profanityCheck['blocked']) {
                logSecurityEvent($currentUserId, 'PROFANITY_BLOCKED', "Word: {$profanityCheck['word']}");
                echo json_encode([
                    'success' => false,
                    'error' => 'Deine Nachricht enthält Schimpfwörter',
                    'details' => 'Bitte verwende eine angemessene Sprache'
                ]);
                exit;
            }

            // Link Filter
            $linkCheck = checkLinkFilter($message);
            if ($linkCheck['blocked']) {
                logSecurityEvent($currentUserId, 'LINK_BLOCKED', "Message: $message");
                echo json_encode([
                    'success' => false,
                    'error' => 'Links sind nicht erlaubt',
                    'details' => 'Aus Sicherheitsgründen können keine URLs gesendet werden'
                ]);
                exit;
            }
        }

        // Auto-Flagging (verdächtige Muster)
        $isFlagged = 0;
        $flagReason = '';

        if ($message !== '') {
            if (preg_match('/(.)\1{5,}/', $message)) {
                $isFlagged = 1;
                $flagReason = 'Repeated characters';
            }

            if (strlen($message) > 20 && $message === strtoupper($message)) {
                $isFlagged = 1;
                $flagReason = 'All caps';
            }

            $emojiCount = preg_match_all('/[\x{1F600}-\x{1F64F}]/u', $message);
            if ($emojiCount > 10) {
                $isFlagged = 1;
                $flagReason = 'Excessive emojis';
            }
        }

        $attachmentPath = null;
        if ($hasAttachment && $attachmentFile) {
            $randomName = bin2hex(random_bytes(16)) . '.jpg';
            $destination = rtrim(UPLOAD_DIR, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $randomName;

            if (!move_uploaded_file($attachmentFile['tmp_name'], $destination)) {
                echo json_encode(['success' => false, 'error' => 'Bild konnte nicht gespeichert werden']);
                exit;
            }

            $attachmentPath = 'uploads/' . $randomName;
        }

        // Insert message
        $stmt = $db->prepare('
            INSERT INTO messages (from_user_id, to_user_id, message, is_flagged, flag_reason, attachment_path, attachment_type, attachment_size)
            VALUES (:from_user_id, :to_user_id, :message, :is_flagged, :flag_reason, :attachment_path, :attachment_type, :attachment_size)
        ');
        $stmt->bindValue(':from_user_id', $currentUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':to_user_id', $toUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':message', $message, SQLITE3_TEXT);
        $stmt->bindValue(':is_flagged', $isFlagged, SQLITE3_INTEGER);
        $stmt->bindValue(':flag_reason', $flagReason, SQLITE3_TEXT);
        if ($attachmentPath) {
            $stmt->bindValue(':attachment_path', $attachmentPath, SQLITE3_TEXT);
            $stmt->bindValue(':attachment_type', $attachmentMime, SQLITE3_TEXT);
            $stmt->bindValue(':attachment_size', $attachmentSize, SQLITE3_INTEGER);
        } else {
            $stmt->bindValue(':attachment_path', null, SQLITE3_NULL);
            $stmt->bindValue(':attachment_type', null, SQLITE3_NULL);
            $stmt->bindValue(':attachment_size', null, SQLITE3_NULL);
        }
        $stmt->execute();

        $messageId = $db->lastInsertRowID();

        // Log rate limit
        logRateLimit($currentUserId);

        if ($isFlagged) {
            logSecurityEvent($currentUserId, 'MESSAGE_FLAGGED', "Reason: $flagReason, Message ID: $messageId");
        }

        if ($attachmentPath) {
            logSecurityEvent($currentUserId, 'ATTACHMENT_UPLOADED', "Message ID: $messageId, Size: $attachmentSize");
        }

        echo json_encode([
            'success' => true,
            'message_id' => $messageId,
            'timestamp' => date('Y-m-d H:i:s'),
            'attachment_url' => $attachmentPath
        ]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // MARK AS READ
    // ───────────────────────────────────────────────────────
    if ($action === 'mark_read') {
        $otherUserId = intval($_POST['user_id'] ?? 0);
        
        if ($otherUserId <= 0) {
            echo json_encode(['success' => false, 'error' => 'Ungültige User-ID']);
            exit;
        }

        $db = getDB();
        $currentUserId = getCurrentUserId();
        $currentAgeGroup = getCurrentAgeGroup();

        $stmt = $db->prepare('SELECT age_group FROM users WHERE id = :user_id AND is_banned = 0');
        $stmt->bindValue(':user_id', $otherUserId, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $otherUser = $result->fetchArray(SQLITE3_ASSOC);

        if (!$otherUser) {
            echo json_encode(['success' => false, 'error' => 'Benutzer nicht gefunden']);
            exit;
        }

        if (!canUsersChatByAge($currentAgeGroup, $otherUser['age_group'])) {
            logSecurityEvent($currentUserId, 'AGE_RESTRICTION_BLOCKED', "MARK_READ -> User $otherUserId");
            echo json_encode(['success' => false, 'error' => 'Aktion zwischen Altersgruppen nicht erlaubt']);
            exit;
        }

        $stmt = $db->prepare('
            UPDATE messages
            SET is_read = 1
            WHERE from_user_id = :other_user_id
            AND to_user_id = :current_user_id 
            AND is_read = 0
        ');
        $stmt->bindValue(':other_user_id', $otherUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':current_user_id', $currentUserId, SQLITE3_INTEGER);
        $stmt->execute();
        
        echo json_encode(['success' => true]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // BLOCK USER
    // ───────────────────────────────────────────────────────
    if ($action === 'block_user') {
        $blockedUserId = intval($_POST['user_id'] ?? 0);
        
        if ($blockedUserId <= 0) {
            echo json_encode(['success' => false, 'error' => 'Ungültige User-ID']);
            exit;
        }
        
        $db = getDB();
        $currentUserId = getCurrentUserId();
        
        $stmt = $db->prepare('
            INSERT OR IGNORE INTO blocks (blocker_id, blocked_id)
            VALUES (:blocker_id, :blocked_id)
        ');
        $stmt->bindValue(':blocker_id', $currentUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':blocked_id', $blockedUserId, SQLITE3_INTEGER);
        $stmt->execute();
        
        logSecurityEvent($currentUserId, 'USER_BLOCKED', "Blocked user ID: $blockedUserId");
        
        echo json_encode(['success' => true]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // UNBLOCK USER
    // ───────────────────────────────────────────────────────
    if ($action === 'unblock_user') {
        $blockedUserId = intval($_POST['user_id'] ?? 0);
        
        if ($blockedUserId <= 0) {
            echo json_encode(['success' => false, 'error' => 'Ungültige User-ID']);
            exit;
        }
        
        $db = getDB();
        $currentUserId = getCurrentUserId();
        
        $stmt = $db->prepare('
            DELETE FROM blocks 
            WHERE blocker_id = :blocker_id 
            AND blocked_id = :blocked_id
        ');
        $stmt->bindValue(':blocker_id', $currentUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':blocked_id', $blockedUserId, SQLITE3_INTEGER);
        $stmt->execute();
        
        logSecurityEvent($currentUserId, 'USER_UNBLOCKED', "Unblocked user ID: $blockedUserId");
        
        echo json_encode(['success' => true]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // REPORT USER
    // ───────────────────────────────────────────────────────
    if ($action === 'report_user') {
        $reportedUserId = intval($_POST['user_id'] ?? 0);
        $reason = trim($_POST['reason'] ?? '');
        $messageId = intval($_POST['message_id'] ?? 0);
        
        if ($reportedUserId <= 0) {
            echo json_encode(['success' => false, 'error' => 'Ungültige User-ID']);
            exit;
        }
        
        if (empty($reason)) {
            echo json_encode(['success' => false, 'error' => 'Bitte gib einen Grund an']);
            exit;
        }
        
        $db = getDB();
        $currentUserId = getCurrentUserId();
        
        $stmt = $db->prepare('
            INSERT INTO reports (reporter_id, reported_user_id, reason, message_id)
            VALUES (:reporter_id, :reported_user_id, :reason, :message_id)
        ');
        $stmt->bindValue(':reporter_id', $currentUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':reported_user_id', $reportedUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':reason', $reason, SQLITE3_TEXT);
        $stmt->bindValue(':message_id', $messageId > 0 ? $messageId : null, SQLITE3_INTEGER);
        $stmt->execute();
        
        logSecurityEvent($currentUserId, 'USER_REPORTED', "Reported user ID: $reportedUserId, Reason: $reason");
        
        echo json_encode(['success' => true, 'message' => 'Meldung wurde erfolgreich gesendet']);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // GET BLOCKED USERS
    // ───────────────────────────────────────────────────────
    if ($action === 'get_blocked_users') {
        $db = getDB();
        $currentUserId = getCurrentUserId();
        
        $query = '
            SELECT 
                u.id,
                u.username,
                u.user_id as display_id,
                b.timestamp as blocked_at
            FROM blocks b
            JOIN users u ON b.blocked_id = u.id
            WHERE b.blocker_id = :current_user_id
            ORDER BY b.timestamp DESC
        ';
        
        $stmt = $db->prepare($query);
        $stmt->bindValue(':current_user_id', $currentUserId, SQLITE3_INTEGER);
        $result = $stmt->execute();
        
        $blockedUsers = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $blockedUsers[] = [
                'id' => $row['id'],
                'display_name' => $row['username'] . '#' . $row['display_id'],
                'blocked_at' => $row['blocked_at']
            ];
        }
        
        echo json_encode(['success' => true, 'blocked_users' => $blockedUsers]);
        exit;
    }
    
    // ═══════════════════════════════════════════════════════════
    // ADMIN ACTIONS
    // ═══════════════════════════════════════════════════════════
    
    if (!isAdmin()) {
        echo json_encode(['success' => false, 'error' => 'Admin-Rechte erforderlich']);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // ADMIN: GET REPORTS
    // ───────────────────────────────────────────────────────
    if ($action === 'admin_get_reports') {
        $db = getDB();
        
        $query = '
            SELECT 
                r.id,
                r.reason,
                r.timestamp,
                r.status,
                r.message_id,
                reporter.username as reporter_name,
                reporter.user_id as reporter_display_id,
                reported.username as reported_name,
                reported.user_id as reported_display_id,
                reported.id as reported_user_id,
                m.message as message_content
            FROM reports r
            JOIN users reporter ON r.reporter_id = reporter.id
            JOIN users reported ON r.reported_user_id = reported.id
            LEFT JOIN messages m ON r.message_id = m.id
            WHERE r.status = "pending"
            ORDER BY r.timestamp DESC
            LIMIT 50
        ';
        
        $result = $db->query($query);
        
        $reports = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $reports[] = [
                'id' => $row['id'],
                'reporter' => $row['reporter_name'] . '#' . $row['reporter_display_id'],
                'reported' => $row['reported_name'] . '#' . $row['reported_display_id'],
                'reported_user_id' => $row['reported_user_id'],
                'reason' => $row['reason'],
                'message' => $row['message_content'],
                'timestamp' => $row['timestamp'],
                'status' => $row['status']
            ];
        }
        
        echo json_encode(['success' => true, 'reports' => $reports]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // ADMIN: GET FLAGGED MESSAGES
    // ───────────────────────────────────────────────────────
    if ($action === 'admin_get_flagged') {
        $db = getDB();
        
        $query = '
            SELECT 
                m.id,
                m.message,
                m.flag_reason,
                m.timestamp,
                u.username,
                u.user_id as display_id,
                u.id as user_db_id
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.is_flagged = 1
            ORDER BY m.timestamp DESC
            LIMIT 50
        ';
        
        $result = $db->query($query);
        
        $flagged = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $flagged[] = [
                'id' => $row['id'],
                'user' => $row['username'] . '#' . $row['display_id'],
                'user_id' => $row['user_db_id'],
                'message' => $row['message'],
                'reason' => $row['flag_reason'],
                'timestamp' => $row['timestamp']
            ];
        }
        
        echo json_encode(['success' => true, 'flagged' => $flagged]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // ADMIN: GET STATISTICS
    // ───────────────────────────────────────────────────────
    if ($action === 'admin_get_stats') {
        $db = getDB();
        
        // Total users
        $result = $db->query('SELECT COUNT(*) as count FROM users WHERE is_banned = 0');
        $totalUsers = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        // U18 users
        $result = $db->query('SELECT COUNT(*) as count FROM users WHERE age_group = "U18" AND is_banned = 0');
        $u18Users = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        // O18 users
        $result = $db->query('SELECT COUNT(*) as count FROM users WHERE age_group = "O18" AND is_banned = 0');
        $o18Users = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        // Online users
        $result = $db->query('
            SELECT COUNT(*) as count 
            FROM online_status 
            WHERE (julianday("now") - julianday(last_ping)) * 86400 < ' . ONLINE_TIMEOUT_SECONDS
        );
        $onlineUsers = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        // Total messages (24h)
        $result = $db->query('SELECT COUNT(*) as count FROM messages');
        $totalMessages = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        // Flagged messages
        $result = $db->query('SELECT COUNT(*) as count FROM messages WHERE is_flagged = 1');
        $flaggedMessages = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        // Pending reports
        $result = $db->query('SELECT COUNT(*) as count FROM reports WHERE status = "pending"');
        $pendingReports = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        // Banned users
        $result = $db->query('SELECT COUNT(*) as count FROM users WHERE is_banned = 1');
        $bannedUsers = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        echo json_encode([
            'success' => true,
            'stats' => [
                'total_users' => $totalUsers,
                'u18_users' => $u18Users,
                'o18_users' => $o18Users,
                'online_users' => $onlineUsers,
                'total_messages' => $totalMessages,
                'flagged_messages' => $flaggedMessages,
                'pending_reports' => $pendingReports,
                'banned_users' => $bannedUsers
            ]
        ]);
        exit;
    }

    if ($action === 'admin_get_banned_users') {
        $db = getDB();

        $result = $db->query('
            SELECT id, username, user_id as display_id, ban_reason, last_seen
            FROM users
            WHERE is_banned = 1
            ORDER BY last_seen DESC
            LIMIT 100
        ');

        $banned = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $banned[] = [
                'id' => $row['id'],
                'display_name' => $row['username'] . '#' . $row['display_id'],
                'reason' => $row['ban_reason'] ?? 'keine Angabe',
                'last_seen' => $row['last_seen']
            ];
        }

        echo json_encode(['success' => true, 'banned' => $banned]);
        exit;
    }

    // ───────────────────────────────────────────────────────
    // ADMIN: BAN USER
    // ───────────────────────────────────────────────────────
    if ($action === 'admin_ban_user') {
        $userId = intval($_POST['user_id'] ?? 0);
        $reason = trim($_POST['reason'] ?? 'Verstoß gegen Nutzungsbedingungen');
        
        if ($userId <= 0) {
            echo json_encode(['success' => false, 'error' => 'Ungültige User-ID']);
            exit;
        }
        
        $db = getDB();
        $stmt = $db->prepare('
            UPDATE users 
            SET is_banned = 1, ban_reason = :reason 
            WHERE id = :user_id
        ');
        $stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
        $stmt->bindValue(':reason', $reason, SQLITE3_TEXT);
        $stmt->execute();
        
        logSecurityEvent(null, 'ADMIN_BAN_USER', "User ID: $userId, Reason: $reason");
        
        echo json_encode(['success' => true, 'message' => 'User wurde gesperrt']);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // ADMIN: UNBAN USER
    // ───────────────────────────────────────────────────────
    if ($action === 'admin_unban_user') {
        $userId = intval($_POST['user_id'] ?? 0);
        
        if ($userId <= 0) {
            echo json_encode(['success' => false, 'error' => 'Ungültige User-ID']);
            exit;
        }
        
        $db = getDB();
        $stmt = $db->prepare('
            UPDATE users 
            SET is_banned = 0, ban_reason = NULL 
            WHERE id = :user_id
        ');
        $stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
        $stmt->execute();
        
        logSecurityEvent(null, 'ADMIN_UNBAN_USER', "User ID: $userId");
        
        echo json_encode(['success' => true, 'message' => 'Sperre wurde aufgehoben']);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // ADMIN: RESOLVE REPORT
    // ───────────────────────────────────────────────────────
    if ($action === 'admin_resolve_report') {
        $reportId = intval($_POST['report_id'] ?? 0);
        $action_taken = trim($_POST['action_taken'] ?? 'resolved');
        
        if ($reportId <= 0) {
            echo json_encode(['success' => false, 'error' => 'Ungültige Report-ID']);
            exit;
        }
        
        $db = getDB();
        $stmt = $db->prepare('
            UPDATE reports 
            SET status = :status 
            WHERE id = :report_id
        ');
        $stmt->bindValue(':report_id', $reportId, SQLITE3_INTEGER);
        $stmt->bindValue(':status', $action_taken, SQLITE3_TEXT);
        $stmt->execute();
        
        logSecurityEvent(null, 'ADMIN_RESOLVE_REPORT', "Report ID: $reportId, Action: $action_taken");
        
        echo json_encode(['success' => true, 'message' => 'Report wurde bearbeitet']);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // ADMIN: DELETE MESSAGE
    // ───────────────────────────────────────────────────────
    if ($action === 'admin_delete_message') {
        $messageId = intval($_POST['message_id'] ?? 0);

        if ($messageId <= 0) {
            echo json_encode(['success' => false, 'error' => 'Ungültige Message-ID']);
            exit;
        }

        $db = getDB();
        $stmt = $db->prepare('DELETE FROM messages WHERE id = :message_id');
        $stmt->bindValue(':message_id', $messageId, SQLITE3_INTEGER);
        $stmt->execute();

        logSecurityEvent(null, 'ADMIN_DELETE_MESSAGE', "Message ID: $messageId");

        echo json_encode(['success' => true, 'message' => 'Nachricht wurde gelöscht']);
        exit;
    }

    if ($action === 'poll_updates') {
        if (!isLoggedIn()) {
            echo json_encode(['success' => false, 'error' => 'Nicht angemeldet']);
            exit;
        }

        if (!validateActiveSession()) {
            echo json_encode(['success' => false, 'error' => 'Sitzung ungültig']);
            exit;
        }

        $lastMessageId = intval($_POST['last_message_id'] ?? $_GET['last_message_id'] ?? 0);

        $db = getDB();
        $currentUserId = getCurrentUserId();
        $currentAgeGroup = getCurrentAgeGroup();

        touchUserSession($currentUserId);

        $stmt = $db->prepare('
            SELECT
                m.id,
                m.from_user_id,
                m.to_user_id,
                m.message,
                m.timestamp,
                m.attachment_path,
                m.attachment_type,
                m.attachment_size,
                uf.username as from_username,
                uf.user_id as from_display_id,
                uf.age_group as from_age_group,
                ut.age_group as to_age_group
            FROM messages m
            JOIN users uf ON m.from_user_id = uf.id
            JOIN users ut ON m.to_user_id = ut.id
            WHERE m.id > :last_message_id
            AND (m.to_user_id = :current_user_id OR m.from_user_id = :current_user_id)
            AND NOT EXISTS (
                SELECT 1 FROM blocks
                WHERE (blocker_id = :current_user_id AND blocked_id = m.from_user_id)
                OR (blocker_id = m.from_user_id AND blocked_id = :current_user_id)
            )
            ORDER BY m.id ASC
        ');
        $stmt->bindValue(':last_message_id', $lastMessageId, SQLITE3_INTEGER);
        $stmt->bindValue(':current_user_id', $currentUserId, SQLITE3_INTEGER);
        $result = $stmt->execute();

        $messages = [];
        $maxId = $lastMessageId;

        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $otherAgeGroup = $row['from_user_id'] === $currentUserId ? $row['to_age_group'] : $row['from_age_group'];

            if (!canUsersChatByAge($currentAgeGroup, $otherAgeGroup)) {
                continue;
            }

            $maxId = max($maxId, (int)$row['id']);

            $messages[] = [
                'id' => $row['id'],
                'from_user_id' => $row['from_user_id'],
                'to_user_id' => $row['to_user_id'],
                'message' => $row['message'],
                'timestamp' => $row['timestamp'],
                'attachment_url' => $row['attachment_path'] ?: null,
                'attachment_type' => $row['attachment_type'] ?: null,
                'attachment_size' => $row['attachment_size'] !== null ? (int)$row['attachment_size'] : null,
                'from_username' => $row['from_username'],
                'from_display_name' => $row['from_username'] . '#' . $row['from_display_id']
            ];
        }

        echo json_encode([
            'success' => true,
            'messages' => $messages,
            'last_message_id' => $maxId
        ]);
        exit;
    }

    echo json_encode(['success' => false, 'error' => 'Unbekannte Aktion']);
    exit;
}

// ═══════════════════════════════════════════════════════════
// SSE STREAM (ECHTZEIT)
// ═══════════════════════════════════════════════════════════

if (isset($_GET['stream']) && $_GET['stream'] === 'events') {
    if (!isLoggedIn()) {
        exit;
    }

    if (!validateActiveSession()) {
        exit;
    }

    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('Connection: keep-alive');
    header('X-Accel-Buffering: no');

    $currentUserId = getCurrentUserId();
    $currentAgeGroup = getCurrentAgeGroup();
    $lastMessageId = intval($_GET['last_message_id'] ?? 0);

    touchUserSession($currentUserId);

    set_time_limit(0);
    ob_implicit_flush(true);
    while (ob_get_level() > 0) {
        @ob_end_flush();
    }

    echo ": connected\n\n";
    echo "retry: " . SSE_RETRY_MS . "\n\n";
    flush();
    
    $lastPingTime = time();
    
    // ✅ ENDLOSSCHLEIFE HINZUFÜGEN!
    while (true) {
        if (connection_aborted()) {
            break;
        }
        
        $db = getDB();
        
        $stmt = $db->prepare('
            SELECT
                m.id,
                m.from_user_id,
                m.to_user_id,
                m.message,
                m.timestamp,
                m.attachment_path,
                m.attachment_type,
                m.attachment_size,
                uf.username as from_username,
                uf.user_id as from_display_id,
                uf.age_group as from_age_group,
                ut.age_group as to_age_group
            FROM messages m
            JOIN users uf ON m.from_user_id = uf.id
            JOIN users ut ON m.to_user_id = ut.id
            WHERE m.id > :last_message_id
            AND (m.to_user_id = :current_user_id OR m.from_user_id = :current_user_id)
            AND NOT EXISTS (
                SELECT 1 FROM blocks
                WHERE (blocker_id = :current_user_id AND blocked_id = m.from_user_id)
                OR (blocker_id = m.from_user_id AND blocked_id = :current_user_id)
            )
            ORDER BY m.id ASC
        ');
        $stmt->bindValue(':last_message_id', $lastMessageId, SQLITE3_INTEGER);
        $stmt->bindValue(':current_user_id', $currentUserId, SQLITE3_INTEGER);
        $result = $stmt->execute();
        
        $messages = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $otherAgeGroup = $row['from_user_id'] === $currentUserId ? $row['to_age_group'] : $row['from_age_group'];

            if (!canUsersChatByAge($currentAgeGroup, $otherAgeGroup)) {
                continue;
            }

            $messages[] = [
                'id' => $row['id'],
                'from_user_id' => $row['from_user_id'],
                'to_user_id' => $row['to_user_id'],
                'message' => $row['message'],
                'timestamp' => $row['timestamp'],
                'attachment_url' => $row['attachment_path'] ?: null,
                'attachment_type' => $row['attachment_type'] ?: null,
                'attachment_size' => $row['attachment_size'] !== null ? (int)$row['attachment_size'] : null,
                'from_username' => $row['from_username'],
                'from_display_name' => $row['from_username'] . '#' . $row['from_display_id']
            ];
            
            $lastMessageId = max($lastMessageId, (int)$row['id']);
        }
        
        if (!empty($messages)) {
            echo "data: " . json_encode(['type' => 'messages', 'messages' => $messages]) . "\n\n";
            flush();
        }
        
        // Ping alle 15 Sekunden
        if (time() - $lastPingTime >= 15) {
            echo "data: " . json_encode(['type' => 'ping']) . "\n\n";
            flush();
            $lastPingTime = time();
            touchUserSession($currentUserId);
        }
        
        // Kurze Pause, um CPU zu schonen
        usleep(500000); // 0.5 Sekunden
    }
    
    exit;
}


// ═══════════════════════════════════════════════════════════
// HTML OUTPUT
// ═══════════════════════════════════════════════════════════
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#f59e0b">
    <title>💬 Secure Private Chat</title>
    
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --sun-50: #fff9db;
            --sun-100: #fef3c7;
            --sun-200: #fde68a;
            --sun-300: #fcd34d;
            --sun-400: #fbbf24;
            --sun-500: #f59e0b;
            --sun-600: #d97706;
            --sun-700: #b45309;
            --sun-800: #92400e;
            --sun-900: #78350f;
            --text-dark: #3d2c00;
            --text-muted: rgba(61, 44, 0, 0.7);
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: linear-gradient(135deg, #fef08a 0%, #f97316 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: var(--text-dark);
        }
        
        /* ═══════════════════════════════════════════════════════════ */
        /* LOGIN/REGISTER SCREEN */
        /* ═══════════════════════════════════════════════════════════ */
        
        .auth-container {
            background: #fff9db;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%;
        }
        
        .auth-container h1 {
            color: #d97706;
            margin-bottom: 10px;
            font-size: 32px;
            text-align: center;
        }
        
        .auth-container .subtitle {
            color: #7c4a03;
            margin-bottom: 30px;
            text-align: center;
            font-size: 14px;
        }
        
        .auth-container .warning-box {
            background: #fef3c7;
            border: 2px solid #fbbf24;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
        }
        
        .auth-container .warning-box h3 {
            color: #a16207;
            margin-bottom: 10px;
            font-size: 16px;
        }
        
        .auth-container .warning-box ul {
            color: #a16207;
            margin-left: 20px;
            font-size: 13px;
            line-height: 1.6;
        }
        
        .auth-container .form-group {
            margin-bottom: 20px;
        }
        
        .auth-container label {
            display: block;
            color: #7c4a03;
            font-weight: 600;
            margin-bottom: 8px;
            font-size: 14px;
        }
        
        .auth-container input[type="text"],
        .auth-container input[type="date"],
        .auth-container input[type="password"] {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #fde68a;
            border-radius: 10px;
            font-size: 15px;
            transition: border-color 0.3s, box-shadow 0.3s;
        }
        
        .auth-container input:focus {
            outline: none;
            border-color: #f59e0b;
            box-shadow: 0 0 0 3px rgba(245, 158, 11, 0.25);
        }
        
        .auth-container .checkbox-group {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            margin-bottom: 20px;
        }
        
        .auth-container .checkbox-group input[type="checkbox"] {
            margin-top: 4px;
            width: 18px;
            height: 18px;
            cursor: pointer;
        }
        
        .auth-container .checkbox-group label {
            margin: 0;
            font-weight: normal;
            font-size: 13px;
            cursor: pointer;
        }
        
        .auth-container .terms-text {
            font-size: 12px;
            color: #7c4a03;
            line-height: 1.6;
            margin-top: 10px;
            padding: 10px;
            background: #fff4cc;
            border-radius: 5px;
            max-height: 150px;
            overflow-y: auto;
        }
        
        .auth-container button {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #fbbf24 0%, #f97316 100%);
            color: #3d2c00;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .auth-container button:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 24px rgba(249, 115, 22, 0.25);
        }
        
        .auth-container button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        /* ═══════════════════════════════════════════════════════════ */
        /* ADMIN VIEWS */
        /* ═══════════════════════════════════════════════════════════ */

        .admin-login-container {
            background: var(--sun-50);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(120, 53, 15, 0.25);
            width: 100%;
            max-width: 450px;
            color: var(--text-dark);
        }

        .admin-login-container h1 {
            text-align: center;
            font-size: 28px;
            margin-bottom: 10px;
            color: var(--sun-800);
        }

        .admin-login-container p {
            text-align: center;
            color: var(--text-muted);
            margin-bottom: 25px;
        }

        .admin-login-container .form-group {
            margin-bottom: 20px;
        }

        .admin-login-container label {
            display: block;
            margin-bottom: 6px;
            font-weight: 600;
            color: var(--sun-800);
        }

        .admin-login-container input {
            width: 100%;
            padding: 12px 14px;
            border-radius: 10px;
            border: 2px solid var(--sun-200);
            font-size: 15px;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }

        .admin-login-container input:focus {
            outline: none;
            border-color: var(--sun-600);
            box-shadow: 0 0 0 3px rgba(217, 119, 6, 0.2);
        }

        .admin-login-container button {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 10px;
            background: linear-gradient(135deg, var(--sun-400) 0%, var(--sun-600) 100%);
            color: var(--text-dark);
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .admin-login-container button:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 24px rgba(217, 119, 6, 0.28);
        }

        .admin-login-container .back-link {
            margin-top: 20px;
            text-align: center;
        }

        .admin-login-container .back-link a {
            color: var(--sun-700);
            text-decoration: none;
            font-weight: 600;
        }

        .admin-login-container .back-link a:hover {
            text-decoration: underline;
        }

        .admin-dashboard {
            width: 95%;
            max-width: 1400px;
            background: var(--sun-50);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(120, 53, 15, 0.25);
            padding: 30px;
            display: flex;
            flex-direction: column;
            gap: 30px;
            color: var(--text-dark);
        }

        .admin-dashboard-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 20px;
        }

        .admin-dashboard-header h1 {
            font-size: 26px;
            color: var(--sun-800);
        }

        .admin-dashboard-header button {
            padding: 10px 18px;
            border: none;
            border-radius: 8px;
            background: linear-gradient(135deg, #f87171 0%, #ef4444 100%);
            color: white;
            font-weight: 600;
            cursor: pointer;
            box-shadow: 0 10px 24px rgba(239, 68, 68, 0.35);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .admin-dashboard-header button:hover {
            transform: translateY(-1px);
            box-shadow: 0 12px 28px rgba(220, 38, 38, 0.4);
        }

        .admin-stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
        }

        .admin-stat-card {
            padding: 20px;
            border-radius: 16px;
            background: linear-gradient(135deg, var(--sun-400) 0%, var(--sun-700) 100%);
            color: var(--text-dark);
            display: flex;
            flex-direction: column;
            gap: 6px;
            box-shadow: 0 12px 30px rgba(250, 204, 21, 0.35);
        }

        .admin-stat-card span {
            font-size: 13px;
            opacity: 0.85;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .admin-stat-card strong {
            font-size: 28px;
        }

        .admin-sections {
            display: grid;
            gap: 30px;
        }

        .admin-section {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 16px;
            padding: 20px;
            border: 1px solid rgba(180, 83, 9, 0.2);
            box-shadow: inset 0 0 0 1px rgba(255, 200, 92, 0.25);
        }

        .admin-section h2 {
            font-size: 18px;
            margin-bottom: 15px;
            color: var(--sun-700);
        }

        .admin-table-wrapper {
            overflow-x: auto;
        }

        .admin-table {
            width: 100%;
            border-collapse: collapse;
        }

        .admin-table th,
        .admin-table td {
            text-align: left;
            padding: 12px 10px;
            border-bottom: 1px solid #e5e7eb;
            vertical-align: top;
        }

        .admin-table th {
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--sun-700);
        }

        .admin-action-buttons {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .admin-action-buttons button {
            border: none;
            border-radius: 6px;
            padding: 6px 10px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
        }

        .btn-danger {
            background: #ef4444;
            color: white;
        }

        .btn-danger:hover {
            background: #dc2626;
        }

        .btn-secondary {
            background: #e5e7eb;
            color: #111827;
        }

        .btn-secondary:hover {
            background: #d1d5db;
        }

        .btn-success {
            background: #10b981;
            color: white;
        }

        .btn-success:hover {
            background: #059669;
        }

        .admin-empty-state {
            text-align: center;
            padding: 20px;
            color: #6b7280;
            font-size: 14px;
        }

        .admin-error-message {
            margin-bottom: 15px;
            color: #dc2626;
            text-align: center;
            display: none;
        }

        .error-message {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
            font-size: 14px;
        }

        .auth-toggle {
            display: flex;
            gap: 8px;
            margin-bottom: 18px;
            background: rgba(255, 221, 87, 0.2);
            padding: 6px;
            border-radius: 999px;
        }

        .auth-toggle button {
            flex: 1;
            border: none;
            border-radius: 999px;
            padding: 10px 12px;
            font-weight: 600;
            cursor: pointer;
            background: transparent;
            color: #92400e;
            transition: background 0.2s ease, color 0.2s ease;
        }

        .auth-toggle button.active {
            background: linear-gradient(135deg, var(--sun-400), var(--sun-500));
            color: #ffffff;
            box-shadow: 0 8px 16px rgba(188, 118, 0, 0.25);
        }

        .auth-form.hidden {
            display: none;
        }

        .form-helper {
            font-size: 13px;
            color: #92400e;
            margin-top: -8px;
            margin-bottom: 16px;
        }

        .force-login-box {
            background: #fff7ed;
            border: 1px solid rgba(217, 119, 6, 0.25);
            border-radius: 12px;
            padding: 12px;
            margin-bottom: 16px;
            display: none;
        }

        .force-login-box p {
            margin: 0 0 12px;
            font-size: 13px;
            color: #92400e;
        }

        .force-login-box button {
            background: var(--sun-500);
            color: #fff;
            border: none;
            padding: 10px 16px;
            border-radius: 10px;
            font-weight: 600;
            cursor: pointer;
        }

        .success-message {
            background: #d4edda;
            color: #155724;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
            font-size: 14px;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--sun-500) 0%, var(--sun-700) 100%);
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 12px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            box-shadow: 0 12px 24px rgba(188, 118, 0, 0.35);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .btn-primary:hover {
            transform: translateY(-1px);
            box-shadow: 0 16px 30px rgba(188, 118, 0, 0.4);
        }

        .btn-primary:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            box-shadow: none;
        }

        .admin-link {
            text-align: center;
            margin-top: 20px;
            font-size: 13px;
        }
        
        .admin-link a {
            color: var(--sun-700);
            text-decoration: none;
        }

        .admin-link a:hover {
            color: var(--sun-900);
            text-decoration: underline;
        }
        
        /* ═══════════════════════════════════════════════════════════ */
        /* CHAT CONTAINER */
        /* ═══════════════════════════════════════════════════════════ */
        
        .chat-container {
            display: none;
            width: 95%;
            max-width: 1400px;
            height: 90vh;
            background: var(--sun-50);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(60, 42, 0, 0.25);
            overflow: hidden;
            grid-template-columns: 350px 1fr;
            grid-template-rows: 70px 1fr;
        }

        .chat-header {
            grid-column: 1 / -1;
            background: linear-gradient(135deg, var(--sun-500) 0%, var(--sun-900) 100%);
            color: white;
            padding: 0 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .chat-header h1 {
            font-size: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .chat-header .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .chat-header .username {
            font-weight: bold;
            font-size: 14px;
        }
        
        .chat-header .age-badge {
            background: rgba(255,255,255,0.28);
            padding: 4px 12px;
            border-radius: 16px;
            font-size: 12px;
            letter-spacing: 0.02em;
        }

        .chat-header button {
            background: rgba(255,255,255,0.25);
            color: white;
            border: none;
            padding: 8px 18px;
            border-radius: 18px;
            cursor: pointer;
            transition: background 0.2s ease, transform 0.2s ease;
            font-size: 13px;
            font-weight: 600;
        }

        .chat-header button:hover {
            background: rgba(255,255,255,0.35);
            transform: translateY(-1px);
        }
        
        /* SIDEBAR */
        .sidebar {
            background: rgba(255,255,255,0.92);
            border-right: 1px solid rgba(188, 118, 0, 0.18);
            display: flex;
            flex-direction: column;
        }

        .sidebar-search {
            padding: 15px;
            background: var(--sun-50);
            border-bottom: 1px solid rgba(188, 118, 0, 0.15);
        }

        .sidebar-search input {
            width: 100%;
            padding: 10px 15px;
            border: 1px solid rgba(188, 118, 0, 0.3);
            border-radius: 20px;
            font-size: 14px;
            background: white;
            color: var(--text-dark);
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }

        .sidebar-search input:focus {
            outline: none;
            border-color: var(--sun-600);
            box-shadow: 0 0 0 3px rgba(240, 180, 0, 0.25);
        }

        .user-list {
            flex: 1;
            overflow-y: auto;
            background: transparent;
        }

        .user-item {
            padding: 15px 20px;
            border: none;
            border-bottom: 1px solid rgba(188, 118, 0, 0.12);
            cursor: pointer;
            transition: background 0.2s ease, transform 0.2s ease;
            display: flex;
            align-items: center;
            gap: 12px;
            position: relative;
            width: 100%;
            text-align: left;
            background: transparent;
            font: inherit;
        }

        .user-item:hover,
        .user-item:focus-visible {
            background: rgba(255, 208, 70, 0.18);
            outline: none;
        }

        .user-item.active {
            background: rgba(255, 208, 70, 0.32);
            color: var(--text-dark);
            box-shadow: inset 0 0 0 1px rgba(240, 180, 0, 0.35);
        }

        .user-avatar {
            width: 45px;
            height: 45px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--sun-500) 0%, var(--sun-700) 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 700;
            font-size: 16px;
            flex-shrink: 0;
            position: relative;
            box-shadow: 0 6px 14px rgba(188, 118, 0, 0.3);
        }

        .user-item.active .user-avatar {
            background: white;
            color: var(--sun-700);
            box-shadow: 0 0 0 2px rgba(240, 180, 0, 0.45);
        }

        .online-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #3ac57a;
            border: 2px solid white;
            position: absolute;
            bottom: 0;
            right: 0;
        }

        .offline-indicator {
            background: #b5b5b5;
        }

        .user-info-text {
            flex: 1;
            min-width: 0;
        }

        .user-name {
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 2px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .user-status {
            font-size: 12px;
            color: rgba(60, 42, 0, 0.55);
        }

        .user-item.active .user-status {
            color: rgba(60, 42, 0, 0.75);
        }
        
        .unread-badge {
            background: var(--sun-700);
            color: white;
            border-radius: 12px;
            padding: 2px 8px;
            font-size: 11px;
            font-weight: bold;
            min-width: 20px;
            text-align: center;
        }

        /* CHAT AREA */
        .chat-area {
            display: flex;
            flex-direction: column;
            background: var(--sun-50);
        }

        .chat-welcome {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            color: rgba(60, 42, 0, 0.55);
            font-size: 18px;
            text-align: center;
            padding: 0 30px;
        }

        .chat-welcome-icon {
            font-size: 80px;
            margin-bottom: 20px;
        }

        .chat-messages-container {
            display: none;
            flex-direction: column;
            height: 100%;
            background: rgba(255,255,255,0.6);
        }
        
        .chat-messages-header {
            background: white;
            padding: 15px 20px;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .message {
            max-width: 65%;
            padding: 12px 16px;
            border-radius: 14px;
            word-wrap: break-word;
            animation: slideIn 0.3s ease;
            box-shadow: 0 6px 16px rgba(60, 42, 0, 0.08);
        }

        @keyframes slideIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .message-received {
            align-self: flex-start;
            background: white;
            border: 1px solid rgba(188, 118, 0, 0.12);
            border-bottom-left-radius: 4px;
        }

        .message-sent {
            align-self: flex-end;
            background: var(--sun-200);
            color: var(--text-dark);
            border-bottom-right-radius: 4px;
        }

        .message-text {
            margin-bottom: 6px;
            line-height: 1.5;
        }

        .message-time {
            font-size: 11px;
            color: rgba(60, 42, 0, 0.55);
            text-align: right;
        }

        /* Chat Input */
        .chat-input-container {
            background: rgba(255,255,255,0.92);
            padding: 16px 24px;
            border-top: 1px solid rgba(188, 118, 0, 0.18);
            display: flex;
            gap: 12px;
            align-items: flex-end;
            flex-wrap: wrap;
        }

        .chat-input {
            flex: 1 1 auto;
            padding: 12px 16px;
            border: 1px solid rgba(188, 118, 0, 0.28);
            border-radius: 28px;
            font-size: 15px;
            resize: none;
            max-height: 120px;
            background: white;
            color: var(--text-dark);
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }

        .chat-input:focus {
            outline: none;
            border-color: var(--sun-600);
            box-shadow: 0 0 0 3px rgba(240, 180, 0, 0.18);
        }

        .chat-input-tools {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .attach-button {
            background: white;
            border: 1px dashed rgba(240, 180, 0, 0.6);
            color: var(--sun-700);
            padding: 10px 16px;
            border-radius: 24px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
        }

        .attach-button:hover {
            transform: translateY(-1px);
            border-color: var(--sun-700);
            box-shadow: 0 10px 18px rgba(240, 180, 0, 0.18);
        }

        .attachment-info {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(251, 191, 36, 0.18);
            border: 1px solid rgba(240, 180, 0, 0.35);
            border-radius: 20px;
            padding: 6px 12px;
            font-size: 13px;
            color: var(--sun-800);
        }

        .attachment-remove {
            background: none;
            border: none;
            color: #b91c1c;
            font-size: 14px;
            cursor: pointer;
            padding: 0;
        }

        .attachment-remove:hover {
            color: #7f1d1d;
        }

        .send-button {
            background: linear-gradient(135deg, var(--sun-500) 0%, var(--sun-700) 100%);
            color: white;
            border: none;
            padding: 12px 28px;
            border-radius: 28px;
            cursor: pointer;
            font-weight: 600;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            box-shadow: 0 12px 24px rgba(188, 118, 0, 0.35);
        }

        .send-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 16px 28px rgba(188, 118, 0, 0.4);
        }

        .send-button:disabled {
            opacity: 0.55;
            cursor: not-allowed;
            box-shadow: none;
        }

        .attachment-warning {
            margin: 0 24px 12px;
            color: #b91c1c;
            font-size: 13px;
        }

        .message-attachment {
            margin-top: 6px;
        }

        .message-attachment a {
            display: inline-block;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 6px 18px rgba(60, 42, 0, 0.22);
            background: rgba(255, 255, 255, 0.85);
        }

        .message-attachment img {
            display: block;
            max-width: 220px;
            height: auto;
        }

        .empty-user-list,
        .empty-messages,
        .loading-state,
        .error-state,
        .chat-state-message {
            text-align: center;
            padding: 30px 20px;
            color: rgba(60, 42, 0, 0.6);
            font-size: 14px;
        }

        .empty-user-list {
            padding: 40px 20px;
        }

        .loading-state {
            font-style: italic;
        }

        .error-state {
            color: #c2410c;
        }

        .chat-state-message.hidden {
            display: none;
        }

        .chat-state-message.loading-state {
            font-style: italic;
        }

        .chat-state-message.error-state {
            color: #c2410c;
        }

        .hidden {
            display: none !important;
        }
    </style>
</head>
<body>

<?php if (isAdmin()): ?>
    <div class="admin-dashboard">
        <div class="admin-dashboard-header">
            <h1>🔐 Admin-Dashboard</h1>
            <button id="adminLogoutBtn">Logout</button>
        </div>

        <div class="admin-stats-grid" id="adminStatsGrid">
            <!-- Stats injected via JS -->
        </div>

        <div class="admin-sections">
            <div class="admin-section">
                <div class="admin-section-header">
                    <h2>🚨 Offene Meldungen</h2>
                </div>
                <div id="adminReportsContainer" class="admin-table-wrapper">
                    <div class="admin-empty-state">Lade Meldungen…</div>
                </div>
            </div>

            <div class="admin-section">
                <h2>🚩 Markierte Nachrichten</h2>
                <div id="adminFlaggedContainer" class="admin-table-wrapper">
                    <div class="admin-empty-state">Lade Nachrichten…</div>
                </div>
            </div>

            <div class="admin-section">
                <h2>🚫 Gesperrte Nutzer</h2>
                <div id="adminBannedContainer" class="admin-table-wrapper">
                    <div class="admin-empty-state">Lade Nutzer…</div>
                </div>
            </div>
        </div>
    </div>

<?php elseif ($isAdminPage): ?>
    <div class="admin-login-container">
        <h1>🔐 Admin-Login</h1>
        <p>Zugriff nur für autorisierte Moderatoren.</p>

        <div class="admin-error-message" id="adminError"></div>

        <form id="adminLoginForm">
            <div class="form-group">
                <label for="adminUsername">Benutzername</label>
                <input type="text" id="adminUsername" autocomplete="username" required>
            </div>

            <div class="form-group">
                <label for="adminPassword">Passwort</label>
                <input type="password" id="adminPassword" autocomplete="current-password" required>
            </div>

            <button type="submit">Anmelden</button>
        </form>

        <div class="back-link">
            <a href="?">Zurück zum Chat</a>
        </div>
    </div>

<?php elseif (!isLoggedIn()): ?>
    <!-- REGISTRATION FORM -->
    <div class="auth-container">
        <h1>💬 Secure Private Chat</h1>
        <p class="subtitle">Sicherer Chat mit Altersverifikation</p>

        <div class="auth-toggle">
            <button type="button" class="auth-toggle-button active" data-target="register">Registrieren</button>
            <button type="button" class="auth-toggle-button" data-target="login">Einloggen</button>
        </div>

        <div class="error-message" id="registerError"></div>
        <div class="error-message" id="loginError"></div>

        <form id="registerForm" class="auth-form">
            <div class="form-group">
                <label>Username (3-15 Zeichen)</label>
                <input type="text" id="username" maxlength="15" required>
            </div>

            <div class="form-group">
                <label>Geburtsdatum</label>
                <input type="date" id="birthdate" required>
            </div>

            <div class="terms-box">
                <h3>⚠️ Wichtige Regeln</h3>
                <ul>
                    <li><strong>Gib NIEMALS persönliche Daten weiter</strong> (Adresse, Telefon, etc.)</li>
                    <li><strong>Treffe dich NICHT mit Fremden</strong></li>
                    <li>Bleibe respektvoll und freundlich</li>
                    <li>Keine Links oder externe Kontakte teilen</li>
                    <li>Bei verdächtigem Verhalten: Melde den User!</li>
                </ul>
            </div>
            
            <div class="checkbox-group">
                <input type="checkbox" id="agreeTerms" required>
                <label for="agreeTerms">Ich akzeptiere die Nutzungsbedingungen</label>
            </div>

            <button type="submit" class="btn-primary">Chat beitreten</button>
        </form>

        <form id="loginForm" class="auth-form hidden">
            <div class="form-group">
                <label>Username</label>
                <input type="text" id="loginUsername" maxlength="15" autocomplete="username" required>
            </div>

            <div class="form-group">
                <label>Geburtsdatum</label>
                <input type="date" id="loginBirthdate" autocomplete="bday" required>
            </div>

            <p class="form-helper">Nutze dein registriertes Geburtsdatum zur Bestätigung deiner Identität.</p>

            <div class="force-login-box" id="loginTakeoverBox">
                <p>Deine vorige Sitzung scheint noch aktiv zu sein. Du kannst sie hier übernehmen, falls du sicher bist, dass du ausgeloggt bist.</p>
                <button type="button" id="loginTakeoverBtn">Sitzung übernehmen</button>
            </div>

            <button type="submit" class="btn-primary">Einloggen</button>
        </form>

        <div class="admin-link">
            <a href="?admin=1">Admin-Login</a>
        </div>
    </div>

<?php else: ?>
    <!-- CHAT INTERFACE -->
    <div class="chat-container" style="display: grid;">
        <!-- Header -->
        <div class="chat-header">
            <h1>💬 Secure Private Chat</h1>
            <div class="user-info">
                <span class="username"><?php echo getCurrentUserDisplayName(); ?></span>
                <span class="age-badge"><?php echo getCurrentAgeGroup(); ?></span>
                <button id="logoutBtn">Logout</button>
            </div>
        </div>
        
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="sidebar-search">
                <input type="text" id="userSearch" placeholder="🔍 Benutzer suchen...">
            </div>
            <div class="user-list" id="userList">
                <!-- Users loaded via JS -->
            </div>
        </div>
        
        <!-- Chat Area -->
        <div class="chat-area">
            <div class="chat-welcome" id="chatWelcome">
                <div class="chat-welcome-icon">💬</div>
                <div>Wähle einen Benutzer aus der Liste</div>
            </div>
            
            <div class="chat-messages-container" id="chatMessagesContainer">
                <div class="chat-messages-header" id="chatMessagesHeader">
                    <!-- Populated via JS -->
                </div>
                
                <div class="chat-state-message hidden" id="chatStateMessage"></div>
                <div class="chat-messages" id="chatMessages">
                    <!-- Messages loaded via JS -->
                </div>
                
                <div class="chat-input-container">
                    <div class="chat-input-tools">
                        <button type="button" class="attach-button" id="attachmentButton" title="Bild anhängen">📎 Bild</button>
                        <input type="file" id="attachmentInput" accept="image/jpeg" class="hidden" />
                        <div class="attachment-info hidden" id="attachmentInfo">
                            <span id="attachmentFileName"></span>
                            <button type="button" class="attachment-remove" id="attachmentClearBtn" aria-label="Anhang entfernen">✕</button>
                        </div>
                    </div>
                    <textarea class="chat-input" id="chatInput" placeholder="Nachricht schreiben..." rows="1" maxlength="1000"></textarea>
                    <button class="send-button" id="sendButton">Senden</button>
                </div>
                <div class="attachment-warning hidden" id="attachmentWarning"></div>
            </div>
        </div>
    </div>
<?php endif; ?>

<script>
// ═══════════════════════════════════════════════════════════
// JAVASCRIPT
// ═══════════════════════════════════════════════════════════

const currentUrl = new URL(window.location.href);
const basePath = currentUrl.pathname;
const baseParams = new URLSearchParams(currentUrl.search);
const postTarget = `${currentUrl.origin}${basePath}${baseParams.toString() ? `?${baseParams.toString()}` : ''}`;

function buildUrl(params = {}) {
    const url = new URL(basePath, window.location.origin);
    baseParams.forEach((value, key) => {
        if (!Object.prototype.hasOwnProperty.call(params, key)) {
            url.searchParams.set(key, value);
        }
    });

    Object.entries(params).forEach(([key, value]) => {
        if (value === null || value === undefined) {
            return;
        }
        url.searchParams.set(key, value);
    });

    return url.toString();
}

function postFormData(formData) {
    return fetch(postTarget, {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
    });
}

<?php if (isAdmin()): ?>
// ADMIN DASHBOARD
const adminStatsGrid = document.getElementById('adminStatsGrid');
const adminReportsContainer = document.getElementById('adminReportsContainer');
const adminFlaggedContainer = document.getElementById('adminFlaggedContainer');
const adminBannedContainer = document.getElementById('adminBannedContainer');

function adminEscapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text ?? '';
    return div.innerHTML;
}

function adminFormatDate(value) {
    if (!value) return '-';
    try {
        return new Date(value).toLocaleString('de-DE');
    } catch (e) {
        return value;
    }
}

async function adminFetch(action, payload = {}) {
    const formData = new FormData();
    formData.append('action', action);
    Object.entries(payload).forEach(([key, val]) => formData.append(key, val));

    const response = await postFormData(formData);
    return response.json();
}

function renderAdminStats(stats) {
    if (!stats) {
        adminStatsGrid.innerHTML = '<div class="admin-empty-state">Keine Statistiken verfügbar.</div>';
        return;
    }

    const statItems = [
        ['Registrierte Nutzer', stats.total_users],
        ['U18 Nutzer', stats.u18_users],
        ['Ü18 Nutzer', stats.o18_users],
        ['Aktiv online', stats.online_users],
        ['Nachrichten gesamt', stats.total_messages],
        ['Markierte Nachrichten', stats.flagged_messages],
        ['Offene Meldungen', stats.pending_reports],
        ['Gesperrte Nutzer', stats.banned_users]
    ];

    adminStatsGrid.innerHTML = statItems.map(([label, value]) => `
        <div class="admin-stat-card">
            <span>${adminEscapeHtml(label)}</span>
            <strong>${Number(value) || 0}</strong>
        </div>
    `).join('');
}

function renderReports(reports) {
    if (!reports || reports.length === 0) {
        adminReportsContainer.innerHTML = '<div class="admin-empty-state">Aktuell liegen keine offenen Meldungen vor.</div>';
        return;
    }

    const rows = reports.map(report => `
        <tr data-report-id="${report.id}" data-user-id="${report.reported_user_id}">
            <td>${adminEscapeHtml(report.reporter)}</td>
            <td>${adminEscapeHtml(report.reported)}</td>
            <td>
                <strong>${adminEscapeHtml(report.reason)}</strong>
                ${report.message ? `<div>${adminEscapeHtml(report.message)}</div>` : ''}
            </td>
            <td>${adminEscapeHtml(adminFormatDate(report.timestamp))}</td>
            <td>
                <div class="admin-action-buttons">
                    <button class="btn-danger" data-action="ban" data-user="${report.reported_user_id}">Sperren</button>
                    <button class="btn-success" data-action="resolve" data-report="${report.id}">Erledigt</button>
                </div>
            </td>
        </tr>
    `).join('');

    adminReportsContainer.innerHTML = `
        <table class="admin-table">
            <thead>
                <tr>
                    <th>Melder</th>
                    <th>Gemeldeter</th>
                    <th>Grund &amp; Nachricht</th>
                    <th>Zeitpunkt</th>
                    <th>Aktionen</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
    `;

    adminReportsContainer.querySelectorAll('button[data-action="ban"]').forEach(btn => {
        btn.addEventListener('click', () => adminBanUser(btn.dataset.user));
    });

    adminReportsContainer.querySelectorAll('button[data-action="resolve"]').forEach(btn => {
        btn.addEventListener('click', () => adminResolveReport(btn.dataset.report));
    });
}

function renderFlagged(flagged) {
    if (!flagged || flagged.length === 0) {
        adminFlaggedContainer.innerHTML = '<div class="admin-empty-state">Keine markierten Nachrichten vorhanden.</div>';
        return;
    }

    const rows = flagged.map(item => `
        <tr data-message-id="${item.id}" data-user-id="${item.user_id}">
            <td>${adminEscapeHtml(item.user)}</td>
            <td>${adminEscapeHtml(item.message)}</td>
            <td>${adminEscapeHtml(item.reason)}</td>
            <td>${adminEscapeHtml(adminFormatDate(item.timestamp))}</td>
            <td>
                <div class="admin-action-buttons">
                    <button class="btn-danger" data-action="ban" data-user="${item.user_id}">Sperren</button>
                    <button class="btn-secondary" data-action="delete" data-message="${item.id}">Löschen</button>
                </div>
            </td>
        </tr>
    `).join('');

    adminFlaggedContainer.innerHTML = `
        <table class="admin-table">
            <thead>
                <tr>
                    <th>Nutzer</th>
                    <th>Nachricht</th>
                    <th>Grund</th>
                    <th>Zeitpunkt</th>
                    <th>Aktionen</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
    `;

    adminFlaggedContainer.querySelectorAll('button[data-action="ban"]').forEach(btn => {
        btn.addEventListener('click', () => adminBanUser(btn.dataset.user));
    });

    adminFlaggedContainer.querySelectorAll('button[data-action="delete"]').forEach(btn => {
        btn.addEventListener('click', () => adminDeleteMessage(btn.dataset.message));
    });
}

function renderBanned(banned) {
    if (!banned || banned.length === 0) {
        adminBannedContainer.innerHTML = '<div class="admin-empty-state">Keine Nutzer gesperrt.</div>';
        return;
    }

    const rows = banned.map(user => `
        <tr data-user-id="${user.id}">
            <td>${adminEscapeHtml(user.display_name)}</td>
            <td>${adminEscapeHtml(user.reason)}</td>
            <td>${adminEscapeHtml(adminFormatDate(user.last_seen))}</td>
            <td>
                <div class="admin-action-buttons">
                    <button class="btn-success" data-action="unban" data-user="${user.id}">Entsperren</button>
                </div>
            </td>
        </tr>
    `).join('');

    adminBannedContainer.innerHTML = `
        <table class="admin-table">
            <thead>
                <tr>
                    <th>Nutzer</th>
                    <th>Grund</th>
                    <th>Zuletzt aktiv</th>
                    <th>Aktionen</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
    `;

    adminBannedContainer.querySelectorAll('button[data-action="unban"]').forEach(btn => {
        btn.addEventListener('click', () => adminUnbanUser(btn.dataset.user));
    });
}

async function loadAdminStats() {
    const response = await fetch(buildUrl({ action: 'admin_get_stats' }), { credentials: 'same-origin' });
    const result = await response.json();
    if (result.success) {
        renderAdminStats(result.stats);
    }
}

async function loadAdminReports() {
    const response = await fetch(buildUrl({ action: 'admin_get_reports' }), { credentials: 'same-origin' });
    const result = await response.json();
    if (result.success) {
        renderReports(result.reports);
    }
}

async function loadAdminFlagged() {
    const response = await fetch(buildUrl({ action: 'admin_get_flagged' }), { credentials: 'same-origin' });
    const result = await response.json();
    if (result.success) {
        renderFlagged(result.flagged);
    }
}

async function loadAdminBanned() {
    const result = await fetch(buildUrl({ action: 'admin_get_banned_users' }), { credentials: 'same-origin' });
    const data = await result.json();
    if (data.success) {
        renderBanned(data.banned);
    }
}

async function adminBanUser(userId) {
    const reason = prompt('Grund für die Sperre eingeben:', 'Verstoß gegen Nutzungsbedingungen');
    if (reason === null) return;

    const result = await adminFetch('admin_ban_user', { user_id: userId, reason });
    if (!result.success) {
        alert(result.error || 'Aktion fehlgeschlagen');
        return;
    }
    await refreshAdminData();
}

async function adminResolveReport(reportId) {
    const actionTaken = prompt('Status für Report festlegen (z.B. resolved, dismissed):', 'resolved');
    if (actionTaken === null) return;

    const result = await adminFetch('admin_resolve_report', { report_id: reportId, action_taken: actionTaken });
    if (!result.success) {
        alert(result.error || 'Aktion fehlgeschlagen');
        return;
    }
    await refreshAdminData();
}

async function adminDeleteMessage(messageId) {
    if (!confirm('Markierte Nachricht wirklich löschen?')) return;

    const result = await adminFetch('admin_delete_message', { message_id: messageId });
    if (!result.success) {
        alert(result.error || 'Aktion fehlgeschlagen');
        return;
    }
    await refreshAdminData();
}

async function adminUnbanUser(userId) {
    const result = await adminFetch('admin_unban_user', { user_id: userId });
    if (!result.success) {
        alert(result.error || 'Aktion fehlgeschlagen');
        return;
    }
    await refreshAdminData();
}

async function refreshAdminData() {
    await Promise.all([
        loadAdminStats(),
        loadAdminReports(),
        loadAdminFlagged(),
        loadAdminBanned()
    ]);
}

document.getElementById('adminLogoutBtn').addEventListener('click', async () => {
    await adminFetch('logout');
    window.location.href = '?';
});

refreshAdminData();
setInterval(refreshAdminData, 30000);

<?php elseif ($isAdminPage): ?>
// ADMIN LOGIN
const adminLoginForm = document.getElementById('adminLoginForm');
const adminError = document.getElementById('adminError');

adminLoginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    adminError.style.display = 'none';

    const formData = new FormData();
    formData.append('action', 'admin_login');
    formData.append('username', document.getElementById('adminUsername').value.trim());
    formData.append('password', document.getElementById('adminPassword').value);

    try {
        const response = await postFormData(formData);
        const result = await response.json();

        if (result.success) {
            window.location.href = '?admin=1';
        } else {
            adminError.textContent = result.error || 'Anmeldung fehlgeschlagen';
            adminError.style.display = 'block';
        }
    } catch (error) {
        adminError.textContent = 'Server nicht erreichbar';
        adminError.style.display = 'block';
    }
});

<?php elseif (!isLoggedIn()): ?>
// AUTH FORMS
const authToggleButtons = document.querySelectorAll('.auth-toggle-button');
const registerForm = document.getElementById('registerForm');
const loginForm = document.getElementById('loginForm');
const registerErrorEl = document.getElementById('registerError');
const loginErrorEl = document.getElementById('loginError');
const loginTakeoverBox = document.getElementById('loginTakeoverBox');
const loginTakeoverBtn = document.getElementById('loginTakeoverBtn');
let lastLoginCredentials = null;
let isSubmittingLogin = false;

function hideElement(el) {
    if (!el) return;
    el.style.display = 'none';
    el.textContent = '';
}

function showAuthView(view) {
    if (view === 'login') {
        registerForm?.classList.add('hidden');
        loginForm?.classList.remove('hidden');
        hideElement(registerErrorEl);
    } else {
        loginForm?.classList.add('hidden');
        registerForm?.classList.remove('hidden');
        hideElement(loginErrorEl);
        if (loginTakeoverBox) {
            loginTakeoverBox.style.display = 'none';
        }
    }
}

authToggleButtons.forEach(button => {
    button.addEventListener('click', () => {
        authToggleButtons.forEach(btn => btn.classList.toggle('active', btn === button));
        showAuthView(button.dataset.target === 'login' ? 'login' : 'register');
    });
});

registerForm?.addEventListener('submit', async (e) => {
    e.preventDefault();

    hideElement(registerErrorEl);

    const username = document.getElementById('username').value.trim();
    const birthdate = document.getElementById('birthdate').value;
    const agreedTerms = document.getElementById('agreeTerms').checked;

    const formData = new FormData();
    formData.append('action', 'register');
    formData.append('username', username);
    formData.append('birthdate', birthdate);
    formData.append('agreed_terms', agreedTerms ? 'true' : 'false');

    try {
        const response = await postFormData(formData);
        const result = await response.json();

        if (result.success) {
            window.location.reload();
        } else if (registerErrorEl) {
            registerErrorEl.textContent = result.error || 'Registrierung fehlgeschlagen.';
            registerErrorEl.style.display = 'block';
        }
    } catch (error) {
        if (registerErrorEl) {
            registerErrorEl.textContent = 'Verbindungsfehler';
            registerErrorEl.style.display = 'block';
        }
    }
});

async function submitLogin(force = false) {
    if (!lastLoginCredentials || isSubmittingLogin) {
        return;
    }

    isSubmittingLogin = true;

    if (loginErrorEl) {
        loginErrorEl.textContent = '';
        loginErrorEl.style.display = 'none';
    }

    if (loginTakeoverBox) {
        loginTakeoverBox.style.display = 'none';
    }

    const formData = new FormData();
    formData.append('action', 'login');
    formData.append('username', lastLoginCredentials.username);
    formData.append('birthdate', lastLoginCredentials.birthdate);
    formData.append('force_login', force ? '1' : '0');

    try {
        const response = await postFormData(formData);
        const result = await response.json();

        if (result.success) {
            window.location.reload();
            return;
        }

        if (loginErrorEl) {
            loginErrorEl.textContent = result.error || 'Anmeldung fehlgeschlagen.';
            loginErrorEl.style.display = 'block';
        }

        if (result.can_force && loginTakeoverBox) {
            loginTakeoverBox.style.display = 'block';
        }
    } catch (error) {
        if (loginErrorEl) {
            loginErrorEl.textContent = 'Verbindungsfehler';
            loginErrorEl.style.display = 'block';
        }
    } finally {
        isSubmittingLogin = false;
    }
}

loginForm?.addEventListener('submit', async (e) => {
    e.preventDefault();

    if (loginErrorEl) {
        loginErrorEl.textContent = '';
        loginErrorEl.style.display = 'none';
    }

    if (loginTakeoverBox) {
        loginTakeoverBox.style.display = 'none';
    }

    lastLoginCredentials = {
        username: document.getElementById('loginUsername').value.trim(),
        birthdate: document.getElementById('loginBirthdate').value
    };

    await submitLogin(false);
});

loginTakeoverBtn?.addEventListener('click', async () => {
    await submitLogin(true);
});

<?php else: ?>
// CHAT INTERFACE
const state = {
    currentUserId: <?php echo getCurrentUserId(); ?>,
    currentUsername: '<?php echo addslashes(getCurrentUsername()); ?>',
    selectedUserId: null,
    users: [],
    messages: [],
    lastMessageId: 0,
    eventSource: null,
    isLoadingUsers: false,
    isLoadingMessages: false,
    connectionErrorShown: false
};

const userListEl = document.getElementById('userList');
const userSearchInput = document.getElementById('userSearch');
const chatWelcomeEl = document.getElementById('chatWelcome');
const chatMessagesContainerEl = document.getElementById('chatMessagesContainer');
const chatMessagesEl = document.getElementById('chatMessages');
const chatStateMessageEl = document.getElementById('chatStateMessage');
const chatMessagesHeaderEl = document.getElementById('chatMessagesHeader');
const chatInputEl = document.getElementById('chatInput');
const sendButtonEl = document.getElementById('sendButton');

async function loadUsers() {
    if (!userListEl) {
        return;
    }

    state.isLoadingUsers = true;
    renderUserList();

    try {
        const response = await fetch('?action=get_users');
        if (!response.ok) {
            throw new Error('NETZWERK_FEHLER');
        }

        const result = await response.json();

        if (result.success) {
            state.users = Array.isArray(result.users) ? result.users : [];
        } else {
            throw new Error(result.error || 'Nutzerliste konnte nicht geladen werden.');
        }

        state.isLoadingUsers = false;
        renderUserList();
    } catch (error) {
        console.error('Nutzerliste konnte nicht geladen werden:', error);
        state.isLoadingUsers = false;
        if (userListEl) {
            userListEl.innerHTML = '<div class="error-state">Nutzerliste konnte nicht geladen werden.</div>';
        }
    }
}

function renderUserList() {
    if (!userListEl) {
        return;
    }

    const searchTerm = (userSearchInput?.value || '').toLowerCase();
    const users = Array.isArray(state.users) ? state.users : [];

    if (state.isLoadingUsers && users.length === 0) {
        userListEl.innerHTML = '<div class="loading-state">Nutzer werden geladen…</div>';
        return;
    }

    if (users.length === 0) {
        userListEl.innerHTML = '<div class="empty-user-list">Noch keine passenden Kontakte verfügbar.</div>';
        return;
    }

    const filtered = users.filter(user => user.display_name.toLowerCase().includes(searchTerm));

    if (filtered.length === 0) {
        userListEl.innerHTML = '<div class="empty-user-list">Keine Treffer für deine Suche.</div>';
        return;
    }

    const fragment = document.createDocumentFragment();

    filtered.forEach(user => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'user-item' + (Number(user.id) === Number(state.selectedUserId) ? ' active' : '');
        item.dataset.userId = String(user.id);
        item.dataset.displayName = user.display_name;

        const avatar = document.createElement('div');
        avatar.className = 'user-avatar';
        avatar.textContent = (user.username || '?').charAt(0).toUpperCase();

        const indicator = document.createElement('div');
        indicator.className = 'online-indicator' + (user.is_online ? '' : ' offline-indicator');
        avatar.appendChild(indicator);

        const infoWrapper = document.createElement('div');
        infoWrapper.className = 'user-info-text';

        const name = document.createElement('div');
        name.className = 'user-name';
        name.textContent = user.display_name;

        const status = document.createElement('div');
        status.className = 'user-status';
        status.textContent = user.is_online ? 'Online' : 'Offline';

        infoWrapper.appendChild(name);
        infoWrapper.appendChild(status);

        item.appendChild(avatar);
        item.appendChild(infoWrapper);

        if (Number(user.unread_count) > 0) {
            const unread = document.createElement('div');
            unread.className = 'unread-badge';
            unread.textContent = String(user.unread_count);
            item.appendChild(unread);
        }

        item.addEventListener('click', () => {
            selectUser(Number(user.id), user.display_name);
        });

        fragment.appendChild(item);
    });

    userListEl.innerHTML = '';
    userListEl.appendChild(fragment);
}

function renderChatHeader(displayName) {
    if (!chatMessagesHeaderEl) {
        return;
    }

    chatMessagesHeaderEl.innerHTML = '';

    const avatar = document.createElement('div');
    avatar.className = 'user-avatar';
    const initial = (displayName?.trim() || '?').charAt(0).toUpperCase();
    avatar.textContent = initial || '?';

    const info = document.createElement('div');
    const name = document.createElement('div');
    name.className = 'user-name';
    name.textContent = displayName;
    info.appendChild(name);

    chatMessagesHeaderEl.appendChild(avatar);
    chatMessagesHeaderEl.appendChild(info);
}

function updateChatState(type, message = '') {
    if (!chatStateMessageEl || !chatMessagesEl) {
        return;
    }

    chatStateMessageEl.className = 'chat-state-message';

    if (!type) {
        chatStateMessageEl.textContent = '';
        chatStateMessageEl.classList.add('hidden');
        chatMessagesEl.classList.remove('hidden');
        return;
    }

    chatStateMessageEl.textContent = message;
    chatStateMessageEl.classList.remove('hidden');

    if (type === 'loading') {
        chatStateMessageEl.classList.add('loading-state');
    } else if (type === 'error') {
        chatStateMessageEl.classList.add('error-state');
    } else if (type === 'empty') {
        chatStateMessageEl.classList.add('empty-messages');
    }

    const hideMessages = type === 'loading' || type === 'error' || type === 'empty';
    chatMessagesEl.classList.toggle('hidden', hideMessages);
}

function selectUser(userId, displayName) {
    state.selectedUserId = userId;
    state.messages = [];

    if (chatWelcomeEl) {
        chatWelcomeEl.style.display = 'none';
    }

    if (chatMessagesContainerEl) {
        chatMessagesContainerEl.style.display = 'flex';
    }

    if (chatMessagesEl) {
        chatMessagesEl.innerHTML = '';
        chatMessagesEl.classList.add('hidden');
    }

    renderChatHeader(displayName);
    updateChatState('loading', 'Nachrichten werden geladen…');
    renderUserList();
    loadMessages(userId);
}
async function loadMessages(userId) {
    if (!userId) {
        return;
    }

    state.isLoadingMessages = true;
    updateChatState('loading', 'Nachrichten werden geladen…');

    try {
        const response = await fetch(buildUrl({ action: 'get_messages', user_id: userId }));
        
        if (!response.ok) {
            throw new Error('NETZWERK_FEHLER');
        }

        const text = await response.text();
        if (!text || text.trim() === '') {
            throw new Error('Leere Antwort vom Server');
        }

        const result = JSON.parse(text);

        if (!result.success) {
            throw new Error(result.error || 'Nachrichten konnten nicht geladen werden.');
        }

        state.messages = Array.isArray(result.messages) ? result.messages : [];

        if (state.messages.length > 0) {
            renderMessages();
            markAsRead(userId);
            const newLastMessageId = Math.max(...state.messages.map(m => Number(m.id))); 
            state.lastMessageId = Math.max(state.lastMessageId, newLastMessageId);
        } else {
            if (chatMessagesEl) {
                chatMessagesEl.innerHTML = '';
            }
            updateChatState('empty', 'Noch keine Nachrichten. Starte das Gespräch!');
        }
    } catch (error) {
        console.error('Nachrichten konnten nicht geladen werden:', error);
        state.messages = [];
        if (chatMessagesEl) {
            chatMessagesEl.innerHTML = '';
        }
        const errorMessage = (error && error.message && error.message !== 'NETZWERK_FEHLER')
            ? error.message
            : 'Nachrichten konnten nicht geladen werden. Bitte versuche es erneut.';
        updateChatState('error', errorMessage);
    } finally {
        state.isLoadingMessages = false;
    }
}


function renderMessages() {
    const container = chatMessagesEl;

    if (!container) {
        return;
    }

    if (!Array.isArray(state.messages) || state.messages.length === 0) {
        container.innerHTML = '';
        return;
    }

    container.innerHTML = state.messages.map(msg => {
        const isSent = msg.from_user_id === state.currentUserId;
        const time = new Date(msg.timestamp).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
        const hasText = typeof msg.message === 'string' && msg.message.trim() !== '';
        const attachmentUrl = msg.attachment_url;

        const textHtml = hasText ? `<div class="message-text">${escapeHtml(msg.message)}</div>` : '';
        const attachmentHtml = attachmentUrl
            ? `<div class="message-attachment"><a href="${escapeAttribute(attachmentUrl)}" target="_blank" rel="noopener"><img src="${escapeAttribute(attachmentUrl)}" alt="Gesendetes Bild"></a></div>`
            : '';

        return `
            <div class="message ${isSent ? 'message-sent' : 'message-received'}">
                ${attachmentHtml}
                ${textHtml}
                <div class="message-time">${time}</div>
            </div>
        `;
    }).join('');

    container.classList.remove('hidden');
    container.scrollTop = container.scrollHeight;
    updateChatState(null);
}



let attachmentFile = null;
const ATTACHMENT_MAX_SIZE = 200 * 1024; // 200 KB

const attachmentButton = document.getElementById('attachmentButton');
const attachmentInput = document.getElementById('attachmentInput');
const attachmentInfo = document.getElementById('attachmentInfo');
const attachmentFileName = document.getElementById('attachmentFileName');
const attachmentClearBtn = document.getElementById('attachmentClearBtn');
const attachmentWarning = document.getElementById('attachmentWarning');

function escapeAttribute(text) {
    const div = document.createElement('div');
    div.textContent = text ?? '';
    return div.innerHTML.replace(/"/g, '&quot;');
}

function showAttachmentWarning(message) {
    if (attachmentWarning) {
        attachmentWarning.textContent = message;
        attachmentWarning.classList.remove('hidden');
    }
}

function clearAttachmentWarning() {
    if (attachmentWarning) {
        attachmentWarning.textContent = '';
        attachmentWarning.classList.add('hidden');
    }
}

function clearAttachmentSelection() {
    attachmentFile = null;
    if (attachmentInput) attachmentInput.value = '';
    if (attachmentInfo) attachmentInfo.classList.add('hidden');
    if (attachmentFileName) attachmentFileName.textContent = '';
    clearAttachmentWarning();
}

attachmentButton?.addEventListener('click', () => {
    attachmentInput?.click();
});

attachmentInput?.addEventListener('change', (e) => {
    const file = e.target.files?.[0];
    if (!file) {
        clearAttachmentSelection();
        return;
    }
    
    const fileType = (file.type || '').toLowerCase();
    const fileName = file.name || '';
    const isJpeg = /^image\/jpe?g$/.test(fileType) || /\.jpe?g$/i.test(fileName);
    
    if (!isJpeg) {
        showAttachmentWarning('Nur JPG-Bilder sind erlaubt.');
        clearAttachmentSelection();
        return;
    }
    
    if (file.size > ATTACHMENT_MAX_SIZE) {
        showAttachmentWarning('Bild ist zu groß (max. 200 KB).');
        clearAttachmentSelection();
        return;
    }
    
    attachmentFile = file;
    if (attachmentFileName) {
        attachmentFileName.textContent = fileName;
    }
    if (attachmentInfo) {
        attachmentInfo.classList.remove('hidden');
    }
    clearAttachmentWarning();
});

attachmentClearBtn?.addEventListener('click', clearAttachmentSelection);


async function sendMessage() {
    if (!chatInputEl) return;
    
    const message = chatInputEl.value.trim();
    
    if (!message && !attachmentFile) {
        return;
    }
    
    if (!state.selectedUserId) {
        alert('Bitte wähle einen Chat-Partner aus');
        return;
    }
    
    const formData = new FormData();
    formData.append('action', 'send_message');
    formData.append('to_user_id', state.selectedUserId);
    formData.append('message', message);
    
    if (attachmentFile) {
        formData.append('attachment', attachmentFile);
    }
    
    try {
        const response = await postFormData(formData);
        const result = await response.json();
        
        if (result.success) {
            chatInputEl.value = '';
            chatInputEl.style.height = 'auto';
            clearAttachmentSelection();
            // Nachricht wird via SSE empfangen
        } else {
            alert(result.error || 'Nachricht konnte nicht gesendet werden');
        }
    } catch (error) {
        alert('Verbindungsfehler beim Senden');
    }
}


async function markAsRead(userId) {
    const formData = new FormData();
    formData.append('action', 'mark_read');
    formData.append('user_id', userId);

    await postFormData(formData);
    loadUsers();
}
function startSSE() {
    if (state.eventSource) {
        state.eventSource.close();
    }

    const url = buildUrl({
        stream: 'events',
        last_message_id: state.lastMessageId
    });
    
    state.eventSource = new EventSource(url);

    state.eventSource.onopen = () => {
        state.connectionErrorShown = false;
    };

    state.eventSource.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === 'messages' && Array.isArray(data.messages)) {
                data.messages.forEach(msg => {
                    const messageId = Number(msg.id);
                    
                    if (messageId > state.lastMessageId) {
                        state.lastMessageId = messageId;
                        
                        const isRelevant = state.selectedUserId && (
                            (msg.from_user_id === state.selectedUserId && msg.to_user_id === state.currentUserId) ||
                            (msg.from_user_id === state.currentUserId && msg.to_user_id === state.selectedUserId)
                        );
                        
                        if (isRelevant) {
                            const exists = state.messages.some(m => Number(m.id) === messageId);
                            if (!exists) {
                                state.messages.push(msg);
                                renderMessages();
                                
                                if (msg.to_user_id === state.currentUserId) {
                                    markAsRead(msg.from_user_id);
                                }
                            }
                        }
                    }
                });
                
                loadUsers(); // Aktualisiere Nutzerliste
            }
        } catch (error) {
            console.warn('SSE-Daten konnten nicht verarbeitet werden:', error);
        }
    };

    state.eventSource.onerror = () => {
        if (!state.connectionErrorShown) {
            state.connectionErrorShown = true;
            console.warn('SSE-Verbindung unterbrochen');
        }
        
        if (state.eventSource) {
            state.eventSource.close();
        }
        
        setTimeout(startSSE, 2000);
    };
}


function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text ?? '';
    return div.innerHTML;
}

sendButtonEl?.addEventListener('click', sendMessage);

chatInputEl?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});

userSearchInput?.addEventListener('input', () => renderUserList());

document.getElementById('logoutBtn')?.addEventListener('click', async () => {
    const formData = new FormData();
    formData.append('action', 'logout');
    await postFormData(formData);
    window.location.reload();
});

chatInputEl?.addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 100) + 'px';
});

setInterval(async () => {
    const formData = new FormData();
    formData.append('action', 'ping');
    await postFormData(formData);
}, 10000);

loadUsers();
startSSE();
setInterval(loadUsers, 30000);

<?php endif; ?>
</script>
</body>
</html>
