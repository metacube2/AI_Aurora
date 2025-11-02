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
define('SSE_RETRY_MS', 1000);

// Rate Limiting
define('MAX_MESSAGES_PER_MINUTE', 10);
define('MAX_MESSAGES_PER_HOUR', 100);
define('MAX_MESSAGES_PER_DAY_U18', 50);

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
    $db->exec("DELETE FROM messages WHERE timestamp < datetime('now', '-{$hours} hours')");
    
    // Delete old rate limits
    $db->exec("DELETE FROM rate_limits WHERE timestamp < datetime('now', '-1 day')");
    
    // Delete old logs (keep 6 months)
    $months = LOG_RETENTION_MONTHS;
    $db->exec("DELETE FROM security_logs WHERE timestamp < datetime('now', '-{$months} months')");
}

// ═══════════════════════════════════════════════════════════
// SESSION & AUTH
// ═══════════════════════════════════════════════════════════

session_start();

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
            logSecurityEvent(getCurrentUserId(), 'LOGOUT', '');
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
            AND u.age_group = :age_group
            ORDER BY is_online DESC, u.username ASC
        ';
        
        $stmt = $db->prepare($query);
        $stmt->bindValue(':current_user_id', $currentUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':age_group', $currentAgeGroup, SQLITE3_TEXT);
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
        
        $query = '
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
            ORDER BY m.timestamp ASC
        ';
        
        $stmt = $db->prepare($query);
        $stmt->bindValue(':current_user_id', $currentUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':other_user_id', $otherUserId, SQLITE3_INTEGER);
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
        
        if ($toUserId <= 0) {
            echo json_encode(['success' => false, 'error' => 'Ungültige User-ID']);
            exit;
        }
        
        if (empty($message)) {
            echo json_encode(['success' => false, 'error' => 'Nachricht darf nicht leer sein']);
            exit;
        }
        
        if (strlen($message) > 1000) {
            echo json_encode(['success' => false, 'error' => 'Nachricht zu lang (max 1000 Zeichen)']);
            exit;
        }
        
        // Check if blocked
        if (isBlocked(getCurrentUserId(), $toUserId)) {
            echo json_encode(['success' => false, 'error' => 'Nachricht kann nicht gesendet werden']);
            exit;
        }
        
        $db = getDB();
        $currentUserId = getCurrentUserId();
        $currentAgeGroup = getCurrentAgeGroup();
        
        // Rate Limiting
        $rateLimitCheck = checkRateLimit($currentUserId, $currentAgeGroup);
        if (!$rateLimitCheck['allowed']) {
            logSecurityEvent($currentUserId, 'RATE_LIMIT_EXCEEDED', $rateLimitCheck['reason']);
            echo json_encode(['success' => false, 'error' => $rateLimitCheck['reason']]);
            exit;
        }
        
        // Keyword Blacklist
        $keywordCheck = checkKeywordBlacklist($message);
        if ($keywordCheck['blocked']) {
            logSecurityEvent($currentUserId, 'KEYWORD_BLOCKED', "Keyword: {$keywordCheck['keyword']}");
            echo
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
        
        // Auto-Flagging (verdächtige Muster)
        $isFlagged = 0;
        $flagReason = '';
        
        // Check for repeated characters (AAAAAAA)
        if (preg_match('/(.)\1{5,}/', $message)) {
            $isFlagged = 1;
            $flagReason = 'Repeated characters';
        }
        
        // Check for all caps (min 20 chars)
        if (strlen($message) > 20 && $message === strtoupper($message)) {
            $isFlagged = 1;
            $flagReason = 'All caps';
        }
        
        // Check for excessive emojis
        $emojiCount = preg_match_all('/[\x{1F600}-\x{1F64F}]/u', $message);
        if ($emojiCount > 10) {
            $isFlagged = 1;
            $flagReason = 'Excessive emojis';
        }
        
        // Insert message
        $stmt = $db->prepare('
            INSERT INTO messages (from_user_id, to_user_id, message, is_flagged, flag_reason)
            VALUES (:from_user_id, :to_user_id, :message, :is_flagged, :flag_reason)
        ');
        $stmt->bindValue(':from_user_id', $currentUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':to_user_id', $toUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':message', $message, SQLITE3_TEXT);
        $stmt->bindValue(':is_flagged', $isFlagged, SQLITE3_INTEGER);
        $stmt->bindValue(':flag_reason', $flagReason, SQLITE3_TEXT);
        $stmt->execute();
        
        $messageId = $db->lastInsertRowID();
        
        // Log rate limit
        logRateLimit($currentUserId);
        
        if ($isFlagged) {
            logSecurityEvent($currentUserId, 'MESSAGE_FLAGGED', "Reason: $flagReason, Message ID: $messageId");
        }
        
        echo json_encode([
            'success' => true,
            'message_id' => $messageId,
            'timestamp' => date('Y-m-d H:i:s')
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
    
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('Connection: keep-alive');
    header('X-Accel-Buffering: no');
    
    $currentUserId = getCurrentUserId();
    $lastMessageId = intval($_GET['last_message_id'] ?? 0);
    
    set_time_limit(0);
    ob_implicit_flush(true);
    ob_end_flush();
    
    $db = getDB();
    
    $stmt = $db->prepare('
        SELECT 
            m.id,
            m.from_user_id,
            m.to_user_id,
            m.message,
            m.timestamp,
            u.username as from_username,
            u.user_id as from_display_id
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
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
        $messages[] = [
            'id' => $row['id'],
            'from_user_id' => $row['from_user_id'],
            'to_user_id' => $row['to_user_id'],
            'message' => $row['message'],
            'timestamp' => $row['timestamp'],
            'from_username' => $row['from_username'],
            'from_display_name' => $row['from_username'] . '#' . $row['from_display_id']
        ];
    }
    
    if (!empty($messages)) {
        echo "data: " . json_encode(['type' => 'messages', 'messages' => $messages]) . "\n\n";
        flush();
    } else {
        echo "data: " . json_encode(['type' => 'ping']) . "\n\n";
        flush();
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
    <title>🔒 Sicherer Private Chat</title>
            echo json_encode([
                'success' => false, 
                'error' => 'Diese Nachricht enthält nicht erlaubte Inhalte: "' . $keywordCheck['keyword'] . '"',
                'blocked_keyword' => true
            ]);
            exit;
        }
        
        // Profanity Filter
        $profanityCheck = checkProfanityFilter($message);
        if ($profanityCheck['blocked']) {
            logSecurityEvent($currentUserId, 'PROFANITY_BLOCKED', "Word: {$profanityCheck['word']}");
            echo json_encode([
                'success' => false, 
                'error' => 'Bitte verwende keine Schimpfwörter',
                'blocked_profanity' => true
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
                'blocked_link' => true
            ]);
            exit;
        }
        
        // Insert message
        $stmt = $db->prepare('
            INSERT INTO messages (from_user_id, to_user_id, message)
            VALUES (:from_user_id, :to_user_id, :message)
        ');
        $stmt->bindValue(':from_user_id', $currentUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':to_user_id', $toUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':message', $message, SQLITE3_TEXT);
        $stmt->execute();
        
        $messageId = $db->lastInsertRowID();
        
        // Log rate limit
        logRateLimit($currentUserId);
        
        echo json_encode([
            'success' => true,
            'message_id' => $messageId,
            'timestamp' => date('Y-m-d H:i:s')
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
        $blockUserId = intval($_POST['user_id'] ?? 0);
        
        if ($blockUserId <= 0) {
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
        $stmt->bindValue(':blocked_id', $blockUserId, SQLITE3_INTEGER);
        $stmt->execute();
        
        logSecurityEvent($currentUserId, 'USER_BLOCKED', "Blocked user ID: $blockUserId");
        
        echo json_encode(['success' => true]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // UNBLOCK USER
    // ───────────────────────────────────────────────────────
    if ($action === 'unblock_user') {
        $unblockUserId = intval($_POST['user_id'] ?? 0);
        
        if ($unblockUserId <= 0) {
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
        $stmt->bindValue(':blocked_id', $unblockUserId, SQLITE3_INTEGER);
        $stmt->execute();
        
        logSecurityEvent($currentUserId, 'USER_UNBLOCKED', "Unblocked user ID: $unblockUserId");
        
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
        
        // Flag message if provided
        if ($messageId > 0) {
            $stmt = $db->prepare('
                UPDATE messages 
                SET is_flagged = 1, flag_reason = :reason 
                WHERE id = :message_id
            ');
            $stmt->bindValue(':reason', $reason, SQLITE3_TEXT);
            $stmt->bindValue(':message_id', $messageId, SQLITE3_INTEGER);
            $stmt->execute();
        }
        
        echo json_encode(['success' => true, 'message' => 'Meldung wurde erfasst. Danke!']);
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
        
        $blocked = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $blocked[] = [
                'id' => $row['id'],
                'username' => $row['username'],
                'display_id' => $row['display_id'],
                'display_name' => $row['username'] . '#' . $row['display_id'],
                'blocked_at' => $row['blocked_at']
            ];
        }
        
        echo json_encode(['success' => true, 'blocked' => $blocked]);
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
    // GET ADMIN STATS
    // ───────────────────────────────────────────────────────
    if ($action === 'admin_stats') {
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
        
        // Total messages today
        $result = $db->query('SELECT COUNT(*) as count FROM messages WHERE DATE(timestamp) = DATE("now")');
        $messagesToday = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        // Pending reports
        $result = $db->query('SELECT COUNT(*) as count FROM reports WHERE status = "pending"');
        $pendingReports = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        // Flagged messages
        $result = $db->query('SELECT COUNT(*) as count FROM messages WHERE is_flagged = 1');
        $flaggedMessages = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        // Banned users
        $result = $db->query('SELECT COUNT(*) as count FROM users WHERE is_banned = 1');
        $bannedUsers = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        echo json_encode([
            'success' => true,
            'stats' => [
                'total_users' => $totalUsers,
                'u18_users' => $u18Users,
                'o18_users' => $o18Users,
                'messages_today' => $messagesToday,
                'pending_reports' => $pendingReports,
                'flagged_messages' => $flaggedMessages,
                'banned_users' => $bannedUsers
            ]
        ]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // GET REPORTS
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
            ORDER BY r.timestamp DESC
            LIMIT 50
        ';
        
        $result = $db->query($query);
        
        $reports = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $reports[] = [
                'id' => $row['id'],
                'reason' => $row['reason'],
                'timestamp' => $row['timestamp'],
                'status' => $row['status'],
                'reporter_name' => $row['reporter_name'] . '#' . $row['reporter_display_id'],
                'reported_name' => $row['reported_name'] . '#' . $row['reported_display_id'],
                'reported_user_id' => $row['reported_user_id'],
                'message_content' => $row['message_content']
            ];
        }
        
        echo json_encode(['success' => true, 'reports' => $reports]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // BAN USER
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
        
        echo json_encode(['success' => true]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // UNBAN USER
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
        
        echo json_encode(['success' => true]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // RESOLVE REPORT
    // ───────────────────────────────────────────────────────
    if ($action === 'admin_resolve_report') {
        $reportId = intval($_POST['report_id'] ?? 0);
        $status = $_POST['status'] ?? 'resolved';
        
        if ($reportId <= 0) {
            echo json_encode(['success' => false, 'error' => 'Ungültige Report-ID']);
            exit;
        }
        
        $db = getDB();
        
        $stmt = $db->prepare('UPDATE reports SET status = :status WHERE id = :report_id');
        $stmt->bindValue(':status', $status, SQLITE3_TEXT);
        $stmt->bindValue(':report_id', $reportId, SQLITE3_INTEGER);
        $stmt->execute();
        
        logSecurityEvent(null, 'ADMIN_RESOLVE_REPORT', "Report ID: $reportId, Status: $status");
        
        echo json_encode(['success' => true]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // GET SECURITY LOGS
    // ───────────────────────────────────────────────────────
    if ($action === 'admin_get_logs') {
        $db = getDB();
        
        $query = '
            SELECT 
                l.id,
                l.action,
                l.details,
                l.ip_address,
                l.timestamp,
                u.username,
                u.user_id as display_id
            FROM security_logs l
            LEFT JOIN users u ON l.user_id = u.id
            ORDER BY l.timestamp DESC
            LIMIT 100
        ';
        
        $result = $db->query($query);
        
        $logs = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $logs[] = [
                'id' => $row['id'],
                'action' => $row['action'],
                'details' => $row['details'],
                'ip_address' => $row['ip_address'],
                'timestamp' => $row['timestamp'],
                'username' => $row['username'] ? $row['username'] . '#' . $row['display_id'] : 'System'
            ];
        }
        
        echo json_encode(['success' => true, 'logs' => $logs]);
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
    
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('Connection: keep-alive');
    header('X-Accel-Buffering: no');
    
    $currentUserId = getCurrentUserId();
    $lastMessageId = intval($_GET['last_message_id'] ?? 0);
    
    set_time_limit(0);
    ob_implicit_flush(true);
    ob_end_flush();
    
    $db = getDB();
    
    $stmt = $db->prepare('
        SELECT 
            m.id,
            m.from_user_id,
            m.to_user_id,
            m.message,
            m.timestamp,
            u.username as from_username,
            u.user_id as from_display_id
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.id > :last_message_id
        AND (m.to_user_id = :current_user_id OR m.from_user_id = :current_user_id)
        ORDER BY m.id ASC
    ');
    $stmt->bindValue(':last_message_id', $lastMessageId, SQLITE3_INTEGER);
    $stmt->bindValue(':current_user_id', $currentUserId, SQLITE3_INTEGER);
    $result = $stmt->execute();
    
    $messages = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $messages[] = [
            'id' => $row['id'],
            'from_user_id' => $row['from_user_id'],
            'to_user_id' => $row['to_user_id'],
            'message' => $row['message'],
            'timestamp' => $row['timestamp'],
            'from_username' => $row['from_username'],
            'from_display_id' => $row['from_display_id'],
            'from_display_name' => $row['from_username'] . '#' . $row['from_display_id']
        ];
    }
    
    if (!empty($messages)) {
        echo "data: " . json_encode(['type' => 'messages', 'messages' => $messages]) . "\n\n";
        flush();
    } else {
        echo "data: " . json_encode(['type' => 'ping']) . "\n\n";
        flush();
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
    <title>💬 Secure Private Chat</title>
    
    <style>
        /* ═══════════════════════════════════════════════════════════ */
        /* CSS STYLING */
        /* ═══════════════════════════════════════════════════════════ */
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        /* ───────────────────────────────────────────────────────── */
        /* REGISTRATION SCREEN */
        /* ───────────────────────────────────────────────────────── */
        
        .register-container {
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%;
        }
        
        .register-container h1 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 32px;
            text-align: center;
        }
        
        .register-container .subtitle {
            color: #666;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 600;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .terms-box {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            max-height: 200px;
            overflow-y: auto;
            font-size: 14px;
            line-height: 1.6;
            color: #555;
        }
        
        .terms-box h3 {
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .terms-box ul {
            margin-left: 20px;
        }
        
        .terms-box li {
            margin-bottom: 8px;
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: 20px;
            height: 20px;
            margin-right: 10px;
            cursor: pointer;
        }
        
        .checkbox-group label {
            color: #333;
            cursor: pointer;
        }
        
        .btn-primary {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
        }
        
        .btn-primary:active {
            transform: translateY(0);
        }
        
        .btn-primary:disabled {
            opacity: 0.5;
            cursor: not-allowed;
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
        
        .success-message {
            background: #efe;
            color: #3c3;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
            font-size: 14px;
        }
        
        .info-box {
            background: #e3f2fd;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            color: #1976d2;
        }
        
        .age-warning {
            background: #fff3cd;
            color: #856404;
            padding: 12px;
            border-radius: 8px;
            margin-top: 10px;
            font-size: 13px;
        }
        
        /* ───────────────────────────────────────────────────────── */
        /* ADMIN LOGIN */
        /* ───────────────────────────────────────────────────────── */
        
        .admin-link {
            text-align: center;
            margin-top: 20px;
            font-size: 14px;
        }
        
        .admin-link a {
            color: #667eea;
            text-decoration: none;
        }
        
        .admin-link a:hover {
            text-decoration: underline;
        }
        
        /* ───────────────────────────────────────────────────────── */
        /* CHAT CONTAINER */
        /* ───────────────────────────────────────────────────────── */
        
        .chat-container {
            display: none;
            width: 95%;
            max-width: 1400px;
            height: 90vh;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
            grid-template-columns: 350px 1fr;
            grid-template-rows: 60px 1fr;
        }
        
        .chat-container.show {
            display: grid;
        }
        
        /* Chat Header */
        .chat-header {
            grid-column: 1 / -1;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 0 20px;
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
        }
        
        .chat-header .age-badge {
            background: rgba(255,255,255,0.3);
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
        }
        
        .chat-header button {
            background: rgba(255,255,255,0.2);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            transition: background 0.3s;
        }
        
        .chat-header button:hover {
            background: rgba(255,255,255,0.3);
        }
        
        /* Sidebar */
        .sidebar {
            background: #f5f5f5;
            border-right: 1px solid #e0e0e0;
            display: flex;
            flex-direction: column;
        }
        
        .sidebar-tabs {
            display: flex;
            background: white;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .sidebar-tab {
            flex: 1;
            padding: 12px;
            text-align: center;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }
        
        .sidebar-tab.active {
            border-bottom-color: #667eea;
            color: #667eea;
            font-weight: bold;
        }
        
        .sidebar-search {
            padding: 15px;
            background: white;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .sidebar-search input {
            width: 100%;
            padding: 10px 15px;
            border: 1px solid #e0e0e0;
            border-radius: 20px;
            font-size: 14px;
        }
        
        .sidebar-search input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .user-list {
            flex: 1;
            overflow-y: auto;
        }
        
        .user-item {
            padding: 15px 20px;
            border-bottom: 1px solid #e0e0e0;
            cursor: pointer;
            transition: background 0.2s;
            display: flex;
            align-items: center;
            gap:
                        echo json_encode([
                'success' => false, 
                'error' => 'Diese Nachricht enthält nicht erlaubte Inhalte. Gib niemals persönliche Daten weiter!',
                'blocked_keyword' => $keywordCheck['keyword']
            ]);
            exit;
        }
        
        // Profanity Filter
        $profanityCheck = checkProfanityFilter($message);
        if ($profanityCheck['blocked']) {
            logSecurityEvent($currentUserId, 'PROFANITY_BLOCKED', "Word: {$profanityCheck['word']}");
            echo json_encode([
                'success' => false, 
                'error' => 'Bitte verwende keine Schimpfwörter oder Beleidigungen.'
            ]);
            exit;
        }
        
        // Link Filter
        $linkCheck = checkLinkFilter($message);
        if ($linkCheck['blocked']) {
            logSecurityEvent($currentUserId, 'LINK_BLOCKED', "Message: $message");
            echo json_encode([
                'success' => false, 
                'error' => 'Links und URLs sind nicht erlaubt. Teile keine externen Kontakte!'
            ]);
            exit;
        }
        
        // Insert message
        $stmt = $db->prepare('
            INSERT INTO messages (from_user_id, to_user_id, message)
            VALUES (:from_user_id, :to_user_id, :message)
        ');
        $stmt->bindValue(':from_user_id', $currentUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':to_user_id', $toUserId, SQLITE3_INTEGER);
        $stmt->bindValue(':message', $message, SQLITE3_TEXT);
        $stmt->execute();
        
        $messageId = $db->lastInsertRowID();
        
        // Log rate limit
        logRateLimit($currentUserId);
        
        echo json_encode([
            'success' => true,
            'message_id' => $messageId,
            'timestamp' => date('Y-m-d H:i:s')
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
        
        logSecurityEvent($currentUserId, 'BLOCK_USER', "Blocked user ID: $blockedUserId");
        
        echo json_encode(['success' => true, 'message' => 'User wurde blockiert']);
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
        
        logSecurityEvent($currentUserId, 'UNBLOCK_USER', "Unblocked user ID: $blockedUserId");
        
        echo json_encode(['success' => true, 'message' => 'User wurde entblockt']);
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
        
        logSecurityEvent($currentUserId, 'REPORT_USER', "Reported user ID: $reportedUserId, Reason: $reason");
        
        // Auto-flag if multiple reports
        $stmt = $db->prepare('
            SELECT COUNT(*) as count 
            FROM reports 
            WHERE reported_user_id = :reported_user_id 
            AND status = "pending"
        ');
        $stmt->bindValue(':reported_user_id', $reportedUserId, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);
        
        if ($row['count'] >= 3) {
            // Auto-ban after 3 reports
            $stmt = $db->prepare('
                UPDATE users 
                SET is_banned = 1, ban_reason = "Mehrfache Meldungen" 
                WHERE id = :user_id
            ');
            $stmt->bindValue(':user_id', $reportedUserId, SQLITE3_INTEGER);
            $stmt->execute();
            
            logSecurityEvent($reportedUserId, 'AUTO_BAN', "3+ reports");
        }
        
        echo json_encode(['success' => true, 'message' => 'Meldung wurde gespeichert. Danke!']);
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
        
        $blocked = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $blocked[] = [
                'id' => $row['id'],
                'username' => $row['username'],
                'display_name' => $row['username'] . '#' . $row['display_id'],
                'blocked_at' => $row['blocked_at']
            ];
        }
        
        echo json_encode(['success' => true, 'blocked_users' => $blocked]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // ADMIN: GET REPORTS
    // ───────────────────────────────────────────────────────
    if ($action === 'admin_get_reports') {
        if (!isAdmin()) {
            echo json_encode(['success' => false, 'error' => 'Keine Berechtigung']);
            exit;
        }
        
        $db = getDB();
        
        $query = '
            SELECT 
                r.id,
                r.reason,
                r.timestamp,
                r.status,
                u1.username as reporter_username,
                u1.user_id as reporter_display_id,
                u2.username as reported_username,
                u2.user_id as reported_display_id,
                u2.id as reported_user_id,
                m.message as message_content
            FROM reports r
            JOIN users u1 ON r.reporter_id = u1.id
            JOIN users u2 ON r.reported_user_id = u2.id
            LEFT JOIN messages m ON r.message_id = m.id
            WHERE r.status = "pending"
            ORDER BY r.timestamp DESC
        ';
        
        $result = $db->query($query);
        
        $reports = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $reports[] = [
                'id' => $row['id'],
                'reason' => $row['reason'],
                'timestamp' => $row['timestamp'],
                'reporter' => $row['reporter_username'] . '#' . $row['reporter_display_id'],
                'reported_user' => $row['reported_username'] . '#' . $row['reported_display_id'],
                'reported_user_id' => $row['reported_user_id'],
                'message_content' => $row['message_content']
            ];
        }
        
        echo json_encode(['success' => true, 'reports' => $reports]);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // ADMIN: BAN USER
    // ───────────────────────────────────────────────────────
    if ($action === 'admin_ban_user') {
        if (!isAdmin()) {
            echo json_encode(['success' => false, 'error' => 'Keine Berechtigung']);
            exit;
        }
        
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
        
        logSecurityEvent($userId, 'ADMIN_BAN', "Reason: $reason, Admin: " . $_SESSION['admin_username']);
        
        echo json_encode(['success' => true, 'message' => 'User wurde gesperrt']);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // ADMIN: RESOLVE REPORT
    // ───────────────────────────────────────────────────────
    if ($action === 'admin_resolve_report') {
        if (!isAdmin()) {
            echo json_encode(['success' => false, 'error' => 'Keine Berechtigung']);
            exit;
        }
        
        $reportId = intval($_POST['report_id'] ?? 0);
        
        if ($reportId <= 0) {
            echo json_encode(['success' => false, 'error' => 'Ungültige Report-ID']);
            exit;
        }
        
        $db = getDB();
        
        $stmt = $db->prepare('UPDATE reports SET status = "resolved" WHERE id = :report_id');
        $stmt->bindValue(':report_id', $reportId, SQLITE3_INTEGER);
        $stmt->execute();
        
        echo json_encode(['success' => true, 'message' => 'Meldung wurde bearbeitet']);
        exit;
    }
    
    // ───────────────────────────────────────────────────────
    // ADMIN: GET STATS
    // ───────────────────────────────────────────────────────
    if ($action === 'admin_get_stats') {
        if (!isAdmin()) {
            echo json_encode(['success' => false, 'error' => 'Keine Berechtigung']);
            exit;
        }
        
        $db = getDB();
        
        // Total users
        $result = $db->query('SELECT COUNT(*) as count FROM users');
        $totalUsers = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        // Online users
        $result = $db->query("
            SELECT COUNT(*) as count 
            FROM online_status 
            WHERE (julianday('now') - julianday(last_ping)) * 86400 < " . ONLINE_TIMEOUT_SECONDS
        );
        $onlineUsers = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        // Pending reports
        $result = $db->query('SELECT COUNT(*) as count FROM reports WHERE status = "pending"');
        $pendingReports = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        // Messages today
        $result = $db->query("SELECT COUNT(*) as count FROM messages WHERE timestamp > datetime('now', '-1 day')");
        $messagesToday = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        // Banned users
        $result = $db->query('SELECT COUNT(*) as count FROM users WHERE is_banned = 1');
        $bannedUsers = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        // Blocked keywords today
        $result = $db->query("
            SELECT COUNT(*) as count 
            FROM security_logs 
            WHERE action = 'KEYWORD_BLOCKED' 
            AND timestamp > datetime('now', '-1 day')
        ");
        $blockedKeywords = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        echo json_encode([
            'success' => true,
            'stats' => [
                'total_users' => $totalUsers,
                'online_users' => $onlineUsers,
                'pending_reports' => $pendingReports,
                'messages_today' => $messagesToday,
                'banned_users' => $bannedUsers,
                'blocked_keywords_today' => $blockedKeywords
            ]
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
    
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('Connection: keep-alive');
    header('X-Accel-Buffering: no');
    
    $currentUserId = getCurrentUserId();
    $lastMessageId = intval($_GET['last_message_id'] ?? 0);
    
    set_time_limit(0);
    ob_implicit_flush(true);
    ob_end_flush();
    
    $db = getDB();
    
    $stmt = $db->prepare('
        SELECT 
            m.id,
            m.from_user_id,
            m.to_user_id,
            m.message,
            m.timestamp,
            u.username as from_username,
            u.user_id as from_display_id
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.id > :last_message_id
        AND (m.to_user_id = :current_user_id OR m.from_user_id = :current_user_id)
        ORDER BY m.id ASC
    ');
    $stmt->bindValue(':last_message_id', $lastMessageId, SQLITE3_INTEGER);
    $stmt->bindValue(':current_user_id', $currentUserId, SQLITE3_INTEGER);
    $result = $stmt->execute();
    
    $messages = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $messages[] = $row;
    }
    
    if (!empty($messages)) {
        echo "data: " . json_encode(['type' => 'messages', 'messages' => $messages]) . "\n\n";
        flush();
    } else {
        echo "data: " . json_encode(['type' => 'ping']) . "\n\n";
        flush();
    }
    
    exit;
}

// ═══════════════════════════════════════════════════════════
// HTML STARTS HERE
// ═══════════════════════════════════════════════════════════
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>💬 Secure Private Chat</title>
    
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        /* ═══════════════════════════════════════════════════════════ */
        /* LOGIN/REGISTER SCREEN */
        /* ═══════════════════════════════════════════════════════════ */
        
        .auth-container {
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%;
        }
        
        .auth-container h1 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 32px;
            text-align: center;
        }
        
        .auth-container .subtitle {
            color: #666;
            margin-bottom: 30px;
            text-align: center;
            font-size: 14px;
        }
        
        .auth-container .warning-box {
            background: #fff3cd;
            border: 2px solid #ffc107;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
        }
        
        .auth-container .warning-box h3 {
            color: #856404;
            margin-bottom: 10px;
            font-size: 16px;
        }
        
        .auth-container .warning-box ul {
            color: #856404;
            margin-left: 20px;
            font-size: 13px;
            line-height: 1.6;
        }
        
        .auth-container .form-group {
            margin-bottom: 20px;
        }
        
        .auth-container label {
            display: block;
            color: #333;
            font-weight: 600;
            margin-bottom: 8px;
            font-size: 14px;
        }
        
        .auth-container input[type="text"],
        .auth-container input[type="date"],
        .auth-container input[type="password"] {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 15px;
            transition: border-color 0.3s;
        }
        
        .auth-container input:focus {
            outline: none;
            border-color: #667eea;
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
            color: #666;
            line-height: 1.6;
            margin-top: 10px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
            max-height: 150px;
            overflow-y: auto;
        }
        
        .auth-container button {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .auth-container button:hover {
            transform: translateY(-2px);
        }
        
        .auth-container button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
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
        
        .success-message {
            background: #d4edda;
            color: #155724;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
            font-size: 14px;
        }
        
        .admin-link {
            text-align: center;
            margin-top: 20px;
            font-size: 13px;
        }
        
        .admin-link a {
            color: #667eea;
            text-decoration: none;
        }
        
        .admin-link a:hover {
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
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
            grid-template-columns: 350px 1fr;
            grid-template-rows: 60px 1fr;
        }
        
        .chat-header {
            grid-column: 1 / -1;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 0 20px;
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
            background: rgba(255,255,255,0.3);
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
        }
        
        .chat-header button {
            background: rgba(255,255,255,0.2);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            transition: background 0.3s;
            font-size: 13px;
        }
        
        .chat-header button:hover {
            background: rgba(255,255,255,0.3);
        }
        
        /* SIDEBAR */
        .sidebar {
            background: #f5f5f5;
            border-right: 1px solid #e0e0e0;
            display: flex;
            flex-direction: column;
        }
        
        .sidebar-search {
            padding: 15px;
            background: white;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .sidebar-search input {
            width: 100%;
            padding: 10px 15px;
            border: 1px solid #e0e0e0;
            border-radius: 20px;
            font-size: 14px;
        }
        
        .sidebar-search input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .user-list {
            flex: 1;
            overflow-y: auto;
        }
        
        .user-item {
            padding: 15px 20px;
            border-bottom: 1px solid #e0e0e0;
            cursor: pointer;
            transition: background 0.2s;
            display: flex;
            align-items: center;
            gap: 12px;
            position: relative;
        }
        
        .user-item:hover {
            background: #e8e8e8;
        }
        
        .user-item.active {
            background: #667eea;
            color: white;
        }
        
        .user-avatar {
            width: 45px;
            height: 45px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 16px;
            flex-shrink: 0;
            position: relative;
        }
        
        .user-item.active .user-avatar {
            background: white;
            color: #667eea;
        }
        
        .online-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #4caf50;
            border: 2px solid white;
            position: absolute;
            bottom: 0;
            right: 0;
        }
        
        .offline-indicator {
            background: #999;
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
            color: #999;
        }
        
        .user-item.active .user-status {
            color: rgba(255,255,255,0.8);
        }
        
        .unread-badge {
            background: #f44336;
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
            background: #e5ddd5;
        }
        
        .chat-welcome {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            color: #999;
            font-size: 18px;
        }
        
        .chat-welcome-icon {
            font-size: 80px;
            margin-bottom: 20px;
        }
        
        .chat-messages-container {
            display: none;
            flex-direction: column;
            height: 100%;
        }
        
        .chat-messages-header {
            background: white;
            padding: 15px 20px;
            border-bottom: 1

            echo json_encode([
                'success' => false, 
                'error' => 'Nachricht enthält nicht erlaubte Inhalte',
                'reason' => 'Bitte gib keine persönlichen Daten weiter (Adressen, Telefonnummern, etc.)'
            ]);
            exit;
        }
                    border-bottom: 1px solid #e0e0e0;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        
        .message {
            max-width: 65%;
            padding: 10px 15px;
            border-radius: 10px;
            word-wrap: break-word;
            animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .message-received {
            align-self: flex-start;
            background: white;
            border-bottom-left-radius: 2px;
        }
        
        .message-sent {
            align-self: flex-end;
            background: #dcf8c6;
            border-bottom-right-radius: 2px;
        }
        
        .message-text {
            margin-bottom: 5px;
            line-height: 1.4;
        }
        
        .message-time {
            font-size: 11px;
            color: #999;
            text-align: right;
        }
        
        /* Chat Input */
        .chat-input-container {
            background: white;
            padding: 15px 20px;
            border-top: 1px solid #e0e0e0;
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .chat-input {
            flex: 1;
            padding: 12px 15px;
            border: 1px solid #e0e0e0;
            border-radius: 25px;
            font-size: 15px;
            resize: none;
            max-height: 100px;
        }
        
        .chat-input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .send-button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 25px;
            cursor: pointer;
            font-weight: bold;
            transition: transform 0.2s;
        }
        
        .send-button:hover {
            transform: translateY(-2px);
        }
        
        .send-button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
    </style>
</head>
<body>

<?php if (!isLoggedIn()): ?>
    <!-- REGISTRATION FORM -->
    <div class="register-container">
        <h1>💬 Secure Private Chat</h1>
        <p class="subtitle">Sicherer Chat mit Altersverifikation</p>
        
        <div class="error-message" id="errorMessage"></div>
        
        <form id="registerForm">
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
                
                <div class="chat-messages" id="chatMessages">
                    <!-- Messages loaded via JS -->
                </div>
                
                <div class="chat-input-container">
                    <textarea class="chat-input" id="chatInput" placeholder="Nachricht schreiben..." rows="1" maxlength="1000"></textarea>
                    <button class="send-button" id="sendButton">Senden</button>
                </div>
            </div>
        </div>
    </div>
<?php endif; ?>

<script>
// ═══════════════════════════════════════════════════════════
// JAVASCRIPT
// ═══════════════════════════════════════════════════════════

<?php if (!isLoggedIn()): ?>
// REGISTRATION
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value.trim();
    const birthdate = document.getElementById('birthdate').value;
    const agreedTerms = document.getElementById('agreeTerms').checked;
    
    const formData = new FormData();
    formData.append('action', 'register');
    formData.append('username', username);
    formData.append('birthdate', birthdate);
    formData.append('agreed_terms', agreedTerms);
    
    try {
        const response = await fetch('', { method: 'POST', body: formData });
        const result = await response.json();
        
        if (result.success) {
            window.location.reload();
        } else {
            document.getElementById('errorMessage').textContent = result.error;
            document.getElementById('errorMessage').style.display = 'block';
        }
    } catch (error) {
        document.getElementById('errorMessage').textContent = 'Verbindungsfehler';
        document.getElementById('errorMessage').style.display = 'block';
    }
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
    eventSource: null
};

// Load Users
async function loadUsers() {
    const response = await fetch('?action=get_users');
    const result = await response.json();
    
    if (result.success) {
        state.users = result.users;
        renderUserList();
    }
}

// Render User List
function renderUserList() {
    const userList = document.getElementById('userList');
    const searchTerm = document.getElementById('userSearch').value.toLowerCase();
    
    const filtered = state.users.filter(u => u.display_name.toLowerCase().includes(searchTerm));
    
    userList.innerHTML = filtered.map(user => `
        <div class="user-item ${user.id === state.selectedUserId ? 'active' : ''}" onclick="selectUser(${user.id}, '${user.display_name}')">
            <div class="user-avatar">
                ${user.username.charAt(0).toUpperCase()}
                <div class="online-indicator ${user.is_online ? '' : 'offline-indicator'}"></div>
            </div>
            <div class="user-info-text">
                <div class="user-name">${user.display_name}</div>
                <div class="user-status">${user.is_online ? 'Online' : 'Offline'}</div>
            </div>
            ${user.unread_count > 0 ? `<div class="unread-badge">${user.unread_count}</div>` : ''}
        </div>
    `).join('');
}

// Select User
function selectUser(userId, displayName) {
    state.selectedUserId = userId;
    
    document.getElementById('chatWelcome').style.display = 'none';
    document.getElementById('chatMessagesContainer').style.display = 'flex';
    
    document.getElementById('chatMessagesHeader').innerHTML = `
        <div class="user-avatar">${displayName.charAt(0).toUpperCase()}</div>
        <div><div class="user-name">${displayName}</div></div>
    `;
    
    loadMessages(userId);
    renderUserList();
}

// Load Messages
async function loadMessages(userId) {
    const response = await fetch(`?action=get_messages&user_id=${userId}`);
    const result = await response.json();
    
    if (result.success) {
        state.messages = result.messages;
        renderMessages();
        markAsRead(userId);
        
        if (result.messages.length > 0) {
            state.lastMessageId = Math.max(...result.messages.map(m => m.id));
        }
    }
}

// Render Messages
function renderMessages() {
    const container = document.getElementById('chatMessages');
    
    container.innerHTML = state.messages.map(msg => {
        const isSent = msg.from_user_id === state.currentUserId;
        const time = new Date(msg.timestamp).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
        
        return `
            <div class="message ${isSent ? 'message-sent' : 'message-received'}">
                <div class="message-text">${escapeHtml(msg.message)}</div>
                <div class="message-time">${time}</div>
            </div>
        `;
    }).join('');
    
    container.scrollTop = container.scrollHeight;
}

// Send Message
async function sendMessage() {
    const input = document.getElementById('chatInput');
    const message = input.value.trim();
    
    if (!message || !state.selectedUserId) return;
    
    const formData = new FormData();
    formData.append('action', 'send_message');
    formData.append('to_user_id', state.selectedUserId);
    formData.append('message', message);
    
    const response = await fetch('', { method: 'POST', body: formData });
    const result = await response.json();
    
    if (result.success) {
        input.value = '';
    } else {
        alert(result.error);
    }
}

// Mark as Read
async function markAsRead(userId) {
    const formData = new FormData();
    formData.append('action', 'mark_read');
    formData.append('user_id', userId);
    
    await fetch('', { method: 'POST', body: formData });
    loadUsers();
}

// SSE
function startSSE() {
    state.eventSource = new EventSource(`?stream=events&last_message_id=${state.lastMessageId}`);
    
    state.eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        if (data.type === 'messages' && data.messages) {
            data.messages.forEach(msg => {
                if (msg.id > state.lastMessageId) {
                    state.lastMessageId = msg.id;
                    
                    if (state.selectedUserId && 
                        ((msg.from_user_id === state.selectedUserId && msg.to_user_id === state.currentUserId) ||
                         (msg.from_user_id === state.currentUserId && msg.to_user_id === state.selectedUserId))) {
                        
                        if (!state.messages.find(m => m.id === msg.id)) {
                            state.messages.push(msg);
                            renderMessages();
                            
                            if (msg.to_user_id === state.currentUserId) {
                                markAsRead(msg.from_user_id);
                            }
                        }
                    }
                }
            });
            
            loadUsers();
        }
    };
}

// Utility
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Event Listeners
document.getElementById('sendButton').addEventListener('click', sendMessage);
document.getElementById('chatInput').addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});
document.getElementById('userSearch').addEventListener('input', renderUserList);
document.getElementById('logoutBtn').addEventListener('click', async () => {
    const formData = new FormData();
    formData.append('action', 'logout');
    await fetch('', { method: 'POST', body: formData });
    window.location.reload();
});

// Auto-resize textarea
document.getElementById('chatInput').addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 100) + 'px';
});

// Ping every 10s
setInterval(async () => {
    const formData = new FormData();
    formData.append('action', 'ping');
    await fetch('', { method: 'POST', body: formData });
}, 10000);

// Init
loadUsers();
startSSE();
setInterval(loadUsers, 30000);

<?php endif; ?>
</script>
</body>
</html>
