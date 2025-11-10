<?php
declare(strict_types=1);

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require __DIR__ . '/vendor/autoload.php';

session_start();
error_reporting(E_ALL);
ini_set('display_errors', '1');

const STREAM_SOURCE = 'test_video.m3u8';
const LOGO_PATH = 'logo.png';
const IMAGE_DIR = __DIR__ . '/image';
const UPLOAD_DIR = __DIR__ . '/uploads';
const VIDEO_DIR = __DIR__ . '/videos';
const GALLERY_DIR = __DIR__ . '/gallery';
const COMMENTS_FILE = __DIR__ . '/comments.json';
const GUESTBOOK_FILE = __DIR__ . '/guestbook.json';
const FEEDBACK_FILE = __DIR__ . '/feedbacks.json';

if (!is_dir(IMAGE_DIR)) {
    @mkdir(IMAGE_DIR, 0777, true);
}
if (!is_dir(UPLOAD_DIR)) {
    @mkdir(UPLOAD_DIR, 0777, true);
}
if (!is_dir(VIDEO_DIR)) {
    @mkdir(VIDEO_DIR, 0777, true);
}
if (!is_dir(GALLERY_DIR)) {
    @mkdir(GALLERY_DIR, 0777, true);
}
if (!file_exists(COMMENTS_FILE)) {
    file_put_contents(COMMENTS_FILE, json_encode([]));
}
if (!file_exists(GUESTBOOK_FILE)) {
    file_put_contents(GUESTBOOK_FILE, json_encode([]));
}
if (!file_exists(FEEDBACK_FILE)) {
    file_put_contents(FEEDBACK_FILE, json_encode([]));
}

$oldDomains = [
    'www.aurora-wetter-lifecam.ch',
    'www.aurora-wetter-livecam.ch'
];
$newDomain = 'www.aurora-weather-livecam.com';

if (isset($_SERVER['HTTP_HOST']) && in_array($_SERVER['HTTP_HOST'], $oldDomains, true)) {
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $newUrl = $protocol . '://' . $newDomain . ($_SERVER['REQUEST_URI'] ?? '/');
    header('HTTP/1.1 301 Moved Permanently');
    header('Location: ' . $newUrl);
    exit;
}

function respond_json(array $payload, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

class LanguageManager
{
    private array $translations = [
        'de' => [
            'title' => 'Aurora Weather Livecam',
            'welcome' => 'Willkommen bei der Aurora Live Webcam',
            'subline' => 'Livebilder, Zeitraffer, Archiv & Community – alles in einem sonnigen Dashboard.',
            'live' => 'Live',
            'timelapse' => 'Zeitraffer',
            'archive' => 'Archiv',
            'gallery' => 'Galerie',
            'community' => 'Community',
            'contact' => 'Kontakt',
            'guestbook' => 'Gästebuch',
            'send' => 'Senden',
            'name' => 'Name',
            'email' => 'E-Mail',
            'message' => 'Nachricht',
            'screenshot' => 'Screenshot',
            'clip' => 'Clip aufnehmen',
            'download' => 'Neueste Aufnahme laden',
            'calendar_title' => 'Visueller Wetterkalender',
            'language' => 'Sprache',
            'rating' => 'Bewertung',
            'comment' => 'Kommentar',
            'add_entry' => 'Eintrag hinzufügen',
            'view_all' => 'Alle anzeigen',
            'privacy' => 'Privatsphäre',
            'share' => 'Teilen',
            'pip' => 'Bild-in-Bild',
            'stats' => 'Stream-Status',
            'starlink' => 'Starlink-Verbindung',
            'starlink_caption' => 'Scanne den QR-Code für das Starlink Satelliteninternet.',
            'starlink_alt' => 'Starlink QR-Code',
        ],
        'en' => [
            'title' => 'Aurora Weather Livecam',
            'welcome' => 'Welcome to the Aurora Live Webcam',
            'subline' => 'Live footage, timelapse, archive & community – all in one sunny dashboard.',
            'live' => 'Live',
            'timelapse' => 'Timelapse',
            'archive' => 'Archive',
            'gallery' => 'Gallery',
            'community' => 'Community',
            'contact' => 'Contact',
            'guestbook' => 'Guestbook',
            'send' => 'Send',
            'name' => 'Name',
            'email' => 'Email',
            'message' => 'Message',
            'screenshot' => 'Screenshot',
            'clip' => 'Record clip',
            'download' => 'Download latest capture',
            'calendar_title' => 'Visual Weather Calendar',
            'language' => 'Language',
            'rating' => 'Rating',
            'comment' => 'Comment',
            'add_entry' => 'Add entry',
            'view_all' => 'View all',
            'privacy' => 'Privacy',
            'share' => 'Share',
            'pip' => 'Picture-in-Picture',
            'stats' => 'Stream status',
            'starlink' => 'Starlink Connection',
            'starlink_caption' => 'Scan the QR code to reach Starlink satellite internet.',
            'starlink_alt' => 'Starlink QR code',
        ],
        'fr' => [
            'title' => 'Aurora Weather Livecam',
            'welcome' => 'Bienvenue sur la webcam Aurora',
            'subline' => 'Images en direct, time-lapse, archive et communauté – réunis dans un tableau de bord ensoleillé.',
            'live' => 'Direct',
            'timelapse' => 'Accéléré',
            'archive' => 'Archive',
            'gallery' => 'Galerie',
            'community' => 'Communauté',
            'contact' => 'Contact',
            'guestbook' => 'Livre d’or',
            'send' => 'Envoyer',
            'name' => 'Nom',
            'email' => 'E-mail',
            'message' => 'Message',
            'screenshot' => 'Capture',
            'clip' => 'Enregistrer un clip',
            'download' => 'Télécharger la dernière capture',
            'calendar_title' => 'Calendrier météo visuel',
            'language' => 'Langue',
            'rating' => 'Évaluation',
            'comment' => 'Commentaire',
            'add_entry' => 'Ajouter une entrée',
            'view_all' => 'Tout voir',
            'privacy' => 'Confidentialité',
            'share' => 'Partager',
            'pip' => 'Picture-in-Picture',
            'stats' => 'Statut du flux',
            'starlink' => 'Connexion Starlink',
            'starlink_caption' => 'Scannez le QR code pour accéder à l’internet satellite Starlink.',
            'starlink_alt' => 'QR code Starlink',
        ],
        'it' => [
            'title' => 'Aurora Weather Livecam',
            'welcome' => 'Benvenuti alla webcam Aurora',
            'subline' => 'Live, time-lapse, archivio e community – tutto in un dashboard soleggiato.',
            'live' => 'Live',
            'timelapse' => 'Time-lapse',
            'archive' => 'Archivio',
            'gallery' => 'Galleria',
            'community' => 'Community',
            'contact' => 'Contatto',
            'guestbook' => 'Libro degli ospiti',
            'send' => 'Invia',
            'name' => 'Nome',
            'email' => 'E-mail',
            'message' => 'Messaggio',
            'screenshot' => 'Screenshot',
            'clip' => 'Registra clip',
            'download' => 'Scarica l’ultima registrazione',
            'calendar_title' => 'Calendario Meteo Visivo',
            'language' => 'Lingua',
            'rating' => 'Valutazione',
            'comment' => 'Commento',
            'add_entry' => 'Aggiungi',
            'view_all' => 'Vedi tutto',
            'privacy' => 'Privacy',
            'share' => 'Condividi',
            'pip' => 'Picture-in-Picture',
            'stats' => 'Stato del flusso',
            'starlink' => 'Connessione Starlink',
            'starlink_caption' => 'Scansiona il QR code per accedere a Starlink Internet satellitare.',
            'starlink_alt' => 'QR code Starlink',
        ],
        'zh' => [
            'title' => '极光天气直播摄像头',
            'welcome' => '欢迎来到极光直播摄像头',
            'subline' => '实时画面、延时摄影、档案与社区——尽在阳光活力仪表盘。',
            'live' => '直播',
            'timelapse' => '延时摄影',
            'archive' => '档案',
            'gallery' => '图集',
            'community' => '社区',
            'contact' => '联系',
            'guestbook' => '留言簿',
            'send' => '发送',
            'name' => '姓名',
            'email' => '邮箱',
            'message' => '留言',
            'screenshot' => '截图',
            'clip' => '录制剪辑',
            'download' => '下载最新捕获',
            'calendar_title' => '可视化天气日历',
            'language' => '语言',
            'rating' => '评分',
            'comment' => '评论',
            'add_entry' => '添加条目',
            'view_all' => '查看全部',
            'privacy' => '隐私',
            'share' => '分享',
            'pip' => '画中画',
            'stats' => '流状态',
            'starlink' => 'Starlink 连接',
            'starlink_caption' => '扫描二维码访问 Starlink 高速卫星网络。',
            'starlink_alt' => 'Starlink 二维码',
        ],
    ];

    public function getCurrentLocale(): string
    {
        if (isset($_POST['language'])) {
            $_SESSION['lang'] = $_POST['language'];
        }
        return $_SESSION['lang'] ?? 'de';
    }

    public function get(string $key, ?string $locale = null): string
    {
        $locale = $locale ?? $this->getCurrentLocale();
        $locale = array_key_exists($locale, $this->translations) ? $locale : 'de';
        return $this->translations[$locale][$key] ?? $this->translations['de'][$key] ?? $key;
    }

    public function getAllTranslations(): array
    {
        return $this->translations;
    }
}

class WebcamManager
{
    private string $videoSrc;

    public function __construct(string $videoSrc = STREAM_SOURCE)
    {
        $this->videoSrc = $videoSrc;
    }

    public function getVideoSrc(): string
    {
        return $this->videoSrc;
    }

    public function getImageFiles(): array
    {
        $files = glob(IMAGE_DIR . '/screenshot_*.jpg') ?: [];
        usort($files, static fn(string $a, string $b) => filemtime($b) <=> filemtime($a));
        return array_slice($files, 0, 10);
    }

    public function getLatestVideo(): ?string
    {
        $videos = glob(VIDEO_DIR . '/*.mp4');
        if (!$videos) {
            return null;
        }
        usort($videos, static fn(string $a, string $b) => filemtime($b) <=> filemtime($a));
        return $videos[0];
    }

    public function captureSnapshot(): array
    {
        $outputFile = 'snapshot_' . date('YmdHis') . '.jpg';
        $targetPath = UPLOAD_DIR . '/' . $outputFile;
        $command = sprintf(
            "ffmpeg -y -i %s -i %s -filter_complex 'overlay=main_w-overlay_w-10:10' -frames:v 1 -q:v 2 %s",
            escapeshellarg($this->videoSrc),
            escapeshellarg(LOGO_PATH),
            escapeshellarg($targetPath)
        );
        exec($command, $output, $returnVar);
        if ($returnVar !== 0 || !file_exists($targetPath)) {
            return ['success' => false, 'message' => 'Snapshot konnte nicht erstellt werden.'];
        }
        return ['success' => true, 'file' => basename($targetPath)];
    }

    public function captureClip(int $duration = 10): array
    {
        $outputFile = 'sequence_' . date('YmdHis') . '.mp4';
        $targetPath = UPLOAD_DIR . '/' . $outputFile;
        $command = sprintf(
            "ffmpeg -y -i %s -i %s -filter_complex 'overlay=10:10' -t %d -c:v libx264 -preset fast -crf 23 %s",
            escapeshellarg($this->videoSrc),
            escapeshellarg(LOGO_PATH),
            $duration,
            escapeshellarg($targetPath)
        );
        exec($command, $output, $returnVar);
        if ($returnVar !== 0 || !file_exists($targetPath)) {
            return ['success' => false, 'message' => 'Clip konnte nicht erstellt werden.'];
        }
        return ['success' => true, 'file' => basename($targetPath)];
    }

    public function getStreamStats(): array
    {
        return [
            'bitrate' => rand(4200, 6200),
            'latency' => rand(3, 9),
            'updated' => date('H:i:s'),
        ];
    }

    public function getGallery(): array
    {
        $images = [];
        foreach (glob(GALLERY_DIR . '/*.{jpg,jpeg,png,gif}', GLOB_BRACE) ?: [] as $file) {
            $timestamp = filemtime($file) ?: 0;
            $images[] = [
                'src' => str_replace(__DIR__ . '/', '', $file),
                'date' => date('Y-m-d H:i', $timestamp),
                'timestamp' => $timestamp,
            ];
        }
        usort($images, static fn(array $a, array $b) => $b['timestamp'] <=> $a['timestamp']);
        $images = array_slice($images, 0, 10);
        return array_map(static fn(array $image) => [
            'src' => $image['src'],
            'date' => $image['date'],
        ], $images);
    }
}

class VisualCalendarManager
{
    private array $monthNames = [
        1 => ['de' => 'Januar', 'en' => 'January', 'it' => 'Gennaio', 'fr' => 'Janvier', 'zh' => '一月'],
        2 => ['de' => 'Februar', 'en' => 'February', 'it' => 'Febbraio', 'fr' => 'Février', 'zh' => '二月'],
        3 => ['de' => 'März', 'en' => 'March', 'it' => 'Marzo', 'fr' => 'Mars', 'zh' => '三月'],
        4 => ['de' => 'April', 'en' => 'April', 'it' => 'Aprile', 'fr' => 'Avril', 'zh' => '四月'],
        5 => ['de' => 'Mai', 'en' => 'May', 'it' => 'Maggio', 'fr' => 'Mai', 'zh' => '五月'],
        6 => ['de' => 'Juni', 'en' => 'June', 'it' => 'Giugno', 'fr' => 'Juin', 'zh' => '六月'],
        7 => ['de' => 'Juli', 'en' => 'July', 'it' => 'Luglio', 'fr' => 'Juillet', 'zh' => '七月'],
        8 => ['de' => 'August', 'en' => 'August', 'it' => 'Agosto', 'fr' => 'Août', 'zh' => '八月'],
        9 => ['de' => 'September', 'en' => 'September', 'it' => 'Settembre', 'fr' => 'Septembre', 'zh' => '九月'],
        10 => ['de' => 'Oktober', 'en' => 'October', 'it' => 'Ottobre', 'fr' => 'Octobre', 'zh' => '十月'],
        11 => ['de' => 'November', 'en' => 'November', 'it' => 'Novembre', 'fr' => 'Novembre', 'zh' => '十一月'],
        12 => ['de' => 'Dezember', 'en' => 'December', 'it' => 'Dicembre', 'fr' => 'Décembre', 'zh' => '十二月'],
    ];

    public function getMonthData(int $year, int $month): array
    {
        $firstDay = new DateTimeImmutable(sprintf('%04d-%02d-01', $year, $month));
        $daysInMonth = (int) $firstDay->format('t');
        $days = [];
        for ($day = 1; $day <= $daysInMonth; $day++) {
            $date = sprintf('%04d%02d%02d', $year, $month, $day);
            $pattern = VIDEO_DIR . "/daily_video_{$date}_*.mp4";
            $matches = glob($pattern) ?: [];
            $days[] = [
                'day' => $day,
                'hasVideos' => !empty($matches),
                'count' => count($matches)
            ];
        }
        return [
            'year' => $year,
            'month' => $month,
            'monthName' => $this->monthNames[$month] ?? $this->monthNames[date('n')],
            'days' => $days,
        ];
    }

    public function getVideosForDate(int $year, int $month, int $day): array
    {
        $date = sprintf('%04d%02d%02d', $year, $month, $day);
        $videos = [];
        foreach (glob(VIDEO_DIR . "/daily_video_{$date}_*.mp4") as $file) {
            $videos[] = [
                'file' => basename($file),
                'size' => filesize($file),
                'time' => date('H:i', filemtime($file)),
            ];
        }
        return $videos;
    }
}

class GuestbookManager
{
    private array $entries = [];

    public function __construct()
    {
        $content = json_decode((string) file_get_contents(GUESTBOOK_FILE), true);
        $this->entries = is_array($content) ? $content : [];
    }

    public function addEntry(string $name, string $message, int $rating = 5): array
    {
        $entry = [
            'name' => htmlspecialchars($name, ENT_QUOTES, 'UTF-8'),
            'message' => htmlspecialchars($message, ENT_QUOTES, 'UTF-8'),
            'rating' => max(1, min(5, $rating)),
            'created' => date('Y-m-d H:i:s')
        ];
        $this->entries[] = $entry;
        file_put_contents(GUESTBOOK_FILE, json_encode($this->entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        return $entry;
    }

    public function getEntries(int $limit = 10): array
    {
        return array_slice(array_reverse($this->entries), 0, $limit);
    }
}

class ContactManager
{
    private string $adminEmail = 'metacube@gmail.com';
    private string $gmailUser = 'metacube@gmail.com';
    private string $gmailAppPassword = 'qggk hsxz fdkq jgxa';

    public function handle(string $name, string $email, string $message): array
    {
        if ($name === '' || $email === '' || $message === '') {
            return ['success' => false, 'message' => 'Bitte alle Felder ausfüllen.'];
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'message' => 'Bitte eine gültige E-Mail-Adresse verwenden.'];
        }
        if (mb_strlen($message) < 10) {
            return ['success' => false, 'message' => 'Die Nachricht ist zu kurz.'];
        }

        $payload = [
            'name' => htmlspecialchars(trim($name), ENT_QUOTES, 'UTF-8'),
            'email' => filter_var(trim($email), FILTER_SANITIZE_EMAIL),
            'message' => htmlspecialchars(trim($message), ENT_QUOTES, 'UTF-8'),
            'date' => date('Y-m-d H:i:s'),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        ];

        $existing = json_decode((string) file_get_contents(FEEDBACK_FILE), true);
        $existing = is_array($existing) ? $existing : [];
        $existing[] = $payload;
        file_put_contents(FEEDBACK_FILE, json_encode($existing, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

        $mail = new PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host = 'smtp.gmail.com';
            $mail->SMTPAuth = true;
            $mail->Username = $this->gmailUser;
            $mail->Password = $this->gmailAppPassword;
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = 587;
            $mail->setFrom($this->gmailUser, 'Aurora Livecam');
            $mail->addAddress($this->adminEmail);
            $mail->addReplyTo($payload['email'], $payload['name']);
            $mail->isHTML(true);
            $mail->CharSet = 'UTF-8';
            $mail->Subject = 'Neue Kontaktanfrage von ' . $payload['name'];
            $mail->Body = '<h2>Aurora Kontakt</h2>' .
                '<p><strong>Name:</strong> ' . $payload['name'] . '</p>' .
                '<p><strong>E-Mail:</strong> ' . $payload['email'] . '</p>' .
                '<p><strong>Nachricht:</strong><br>' . nl2br($payload['message']) . '</p>' .
                '<hr><small>Gesendet am ' . $payload['date'] . ' | IP ' . $payload['ip'] . '</small>';
            $mail->send();
        } catch (Exception $e) {
            error_log('Mail error: ' . $mail->ErrorInfo);
            return ['success' => false, 'message' => 'Nachricht gespeichert, E-Mail konnte nicht gesendet werden.'];
        }

        return ['success' => true, 'message' => 'Vielen Dank! Wir melden uns zeitnah.'];
    }
}

class AdminManager
{
    public function isAdmin(): bool
    {
        return isset($_SESSION['admin']) && $_SESSION['admin'] === true;
    }

    public function login(string $username, string $password): bool
    {
        if ($username === 'admin' && $password === 'sonne4000$$$$Q') {
            $_SESSION['admin'] = true;
            return true;
        }
        return false;
    }
}

$languageManager = new LanguageManager();
$locale = $languageManager->getCurrentLocale();
$webcamManager = new WebcamManager();
$calendarManager = new VisualCalendarManager();
$guestbookManager = new GuestbookManager();
$contactManager = new ContactManager();
$adminManager = new AdminManager();

if (isset($_GET['download_video']) && $_GET['download_video'] === 'latest') {
    $latest = $webcamManager->getLatestVideo();
    if ($latest && file_exists($latest)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($latest) . '"');
        header('Content-Length: ' . filesize($latest));
        readfile($latest);
        exit;
    }
    echo 'Kein Video gefunden.';
    exit;
}

if (isset($_GET['api'])) {
    $action = $_GET['api'];
    switch ($action) {
        case 'images':
            respond_json(['images' => array_map(static fn(string $p) => str_replace(__DIR__ . '/', '', $p), $webcamManager->getImageFiles())]);
        case 'gallery':
            respond_json(['gallery' => $webcamManager->getGallery()]);
        case 'calendar':
            $year = isset($_GET['year']) ? (int) $_GET['year'] : (int) date('Y');
            $month = isset($_GET['month']) ? (int) $_GET['month'] : (int) date('n');
            respond_json(['calendar' => $calendarManager->getMonthData($year, $month)]);
        case 'calendar_videos':
            $year = (int) ($_GET['year'] ?? date('Y'));
            $month = (int) ($_GET['month'] ?? date('n'));
            $day = (int) ($_GET['day'] ?? date('j'));
            respond_json(['videos' => $calendarManager->getVideosForDate($year, $month, $day)]);
        case 'guestbook':
            respond_json(['entries' => $guestbookManager->getEntries(50)]);
        case 'stream_stats':
            respond_json(['stats' => $webcamManager->getStreamStats()]);
        default:
            respond_json(['message' => 'Unbekannte API-Anfrage.'], 404);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    switch ($action) {
        case 'capture_snapshot':
            respond_json($webcamManager->captureSnapshot());
        case 'capture_clip':
            $duration = isset($_POST['duration']) ? max(5, min(120, (int) $_POST['duration'])) : 10;
            respond_json($webcamManager->captureClip($duration));
        case 'guestbook_add':
            $name = $_POST['name'] ?? '';
            $message = $_POST['message'] ?? '';
            $rating = isset($_POST['rating']) ? (int) $_POST['rating'] : 5;
            if ($name === '' || $message === '') {
                respond_json(['success' => false, 'message' => 'Name und Nachricht sind erforderlich.'], 422);
            }
            respond_json(['success' => true, 'entry' => $guestbookManager->addEntry($name, $message, $rating)]);
        case 'contact_send':
            $name = $_POST['name'] ?? '';
            $email = $_POST['email'] ?? '';
            $message = $_POST['message'] ?? '';
            respond_json($contactManager->handle($name, $email, $message));
        case 'admin_login':
            $username = $_POST['username'] ?? '';
            $password = $_POST['password'] ?? '';
            respond_json(['success' => $adminManager->login($username, $password)]);
        case 'set_language':
            $_SESSION['lang'] = $_POST['language'] ?? 'de';
            respond_json(['success' => true, 'language' => $_SESSION['lang']]);
        default:
            respond_json(['message' => 'Unbekannte Aktion.'], 400);
    }
}

$translations = $languageManager->getAllTranslations();
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars($locale) ?>">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= htmlspecialchars($languageManager->get('title', $locale)) ?></title>
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/hls.js@1"></script>
    <style>
        :root {
            --sunrise-100: #fff9db;
            --sunrise-200: #ffe782;
            --sunrise-300: #ffcf5c;
            --sunrise-400: #f9b233;
            --sunrise-500: #f2921d;
            --sky-500: #2c7be5;
            --text-primary: #2c2c2c;
            --text-secondary: #4c4c4c;
            --card-bg: rgba(255, 255, 255, 0.85);
            --shadow: 0 25px 45px rgba(255, 204, 0, 0.15);
            --radius-lg: 24px;
            --radius-md: 18px;
            color-scheme: light;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, var(--sunrise-200), var(--sunrise-500));
            min-height: 100vh;
            color: var(--text-primary);
            display: flex;
            flex-direction: column;
        }

        header {
            padding: 48px 5vw 32px;
            text-align: center;
            color: var(--text-primary);
        }

        header h1 {
            font-size: clamp(2.5rem, 5vw, 3.75rem);
            margin: 0;
            letter-spacing: -1px;
            text-shadow: 0 12px 45px rgba(0,0,0,0.2);
        }

        header p {
            margin: 16px auto 0;
            max-width: 640px;
            font-size: 1.1rem;
            color: rgba(40,40,40,0.85);
        }

        main {
            flex: 1;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 32px;
            padding: 0 5vw 80px;
        }

        section {
            background: var(--card-bg);
            backdrop-filter: blur(20px);
            border-radius: var(--radius-lg);
            padding: 24px 28px;
            box-shadow: var(--shadow);
        }

        .hero-section {
            grid-column: 1 / -1;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 24px;
            align-items: start;
        }

        .video-wrapper {
            position: relative;
            background: linear-gradient(135deg, rgba(255,255,255,0.9), rgba(255,255,255,0.6));
            border-radius: var(--radius-lg);
            overflow: hidden;
            box-shadow: 0 30px 60px rgba(255, 165, 0, 0.25);
        }

        #webcamPlayer {
            width: 100%;
            aspect-ratio: 16/9;
            display: block;
            background: #000;
        }

        .player-controls {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-top: 18px;
        }

        .control-btn {
            flex: 1 1 160px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            padding: 14px 18px;
            border-radius: var(--radius-md);
            border: none;
            font-weight: 600;
            letter-spacing: 0.01em;
            color: #1f1f1f;
            cursor: pointer;
            background: linear-gradient(135deg, var(--sunrise-300), var(--sunrise-500));
            box-shadow: 0 16px 35px rgba(242, 146, 29, 0.2);
            transition: transform 0.18s ease, box-shadow 0.18s ease;
        }

        .control-btn.secondary {
            background: rgba(255, 255, 255, 0.95);
            border: 1px solid rgba(0,0,0,0.06);
        }

        .control-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 25px 45px rgba(242, 146, 29, 0.25);
        }

        .meta-info {
            display: grid;
            gap: 16px;
        }

        .meta-card {
            background: rgba(255,255,255,0.95);
            border-radius: var(--radius-md);
            padding: 18px;
            box-shadow: inset 0 0 0 1px rgba(255, 204, 0, 0.2);
        }

        .meta-card h3 {
            margin: 0 0 8px;
            font-size: 1.05rem;
            display: flex;
            justify-content: space-between;
        }

        .qr-wrapper {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 10px;
        }

        .qr-wrapper img {
            width: 160px;
            height: 160px;
            border-radius: 12px;
            box-shadow: 0 12px 24px rgba(0,0,0,0.12);
            background: white;
            padding: 6px;
        }

        .qr-wrapper small {
            text-align: center;
            color: rgba(0,0,0,0.6);
        }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(44, 123, 229, 0.12);
            color: var(--sky-500);
            padding: 6px 12px;
            border-radius: 999px;
            font-size: 0.85rem;
            font-weight: 600;
        }

        .media-grid {
            display: grid;
            gap: 12px;
            grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
        }

        .media-grid img {
            width: 100%;
            border-radius: 14px;
            aspect-ratio: 16/9;
            object-fit: cover;
            box-shadow: 0 12px 22px rgba(0,0,0,0.15);
        }

        .calendar-grid {
            display: grid;
            grid-template-columns: repeat(7, 1fr);
            gap: 10px;
            margin-top: 16px;
        }

        .calendar-day {
            padding: 12px 10px;
            text-align: center;
            border-radius: 16px;
            background: rgba(255, 255, 255, 0.85);
            min-height: 72px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            font-weight: 600;
            transition: transform 0.18s ease, box-shadow 0.18s ease;
            cursor: pointer;
        }

        .calendar-day.has-video {
            background: rgba(255, 255, 255, 0.95);
            box-shadow: inset 0 0 0 2px rgba(242, 146, 29, 0.45);
        }

        .calendar-day.selected {
            background: var(--sunrise-400);
            color: white;
            transform: translateY(-4px);
            box-shadow: 0 12px 24px rgba(242, 146, 29, 0.3);
        }

        .calendar-day .count {
            font-size: 0.75rem;
            color: rgba(0,0,0,0.6);
        }

        form {
            display: grid;
            gap: 12px;
        }

        input, textarea, select {
            border-radius: 14px;
            border: 1px solid rgba(0,0,0,0.08);
            padding: 12px 14px;
            background: rgba(255,255,255,0.95);
            font-size: 1rem;
        }

        textarea {
            min-height: 140px;
            resize: vertical;
        }

        .guestbook-entry {
            padding: 16px 18px;
            border-radius: 18px;
            background: rgba(255,255,255,0.9);
            box-shadow: inset 0 0 0 1px rgba(255, 204, 0, 0.2);
        }

        .language-switch {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .language-switch button {
            border: none;
            background: rgba(255,255,255,0.85);
            padding: 8px 14px;
            border-radius: 999px;
            cursor: pointer;
            font-weight: 600;
            box-shadow: inset 0 0 0 1px rgba(0,0,0,0.08);
        }

        footer {
            text-align: center;
            padding: 32px 5vw 48px;
            color: rgba(0,0,0,0.75);
            font-size: 0.9rem;
        }

        @media (max-width: 768px) {
            header {
                padding-top: 36px;
            }
            .hero-section {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
<header>
    <h1><?= htmlspecialchars($languageManager->get('welcome', $locale)) ?></h1>
    <p><?= htmlspecialchars($languageManager->get('subline', $locale)) ?></p>
</header>

<main>
    <section class="hero-section">
        <div class="video-wrapper">
            <video id="webcamPlayer" playsinline muted></video>
            <div class="player-controls">
                <button class="control-btn" data-action="screenshot">
                    📸 <?= htmlspecialchars($languageManager->get('screenshot', $locale)) ?>
                </button>
                <button class="control-btn" data-action="clip">
                    🎬 <?= htmlspecialchars($languageManager->get('clip', $locale)) ?>
                </button>
                <a class="control-btn secondary" href="?download_video=latest">
                    ⬇️ <?= htmlspecialchars($languageManager->get('download', $locale)) ?>
                </a>
                <button class="control-btn secondary" data-action="pip">
                    📺 <?= htmlspecialchars($languageManager->get('pip', $locale)) ?>
                </button>
                <button class="control-btn secondary" data-action="share">
                    ☀️ <?= htmlspecialchars($languageManager->get('share', $locale)) ?>
                </button>
            </div>
        </div>
        <div class="meta-info">
            <div class="meta-card">
                <h3>
                    <span><?= htmlspecialchars($languageManager->get('stats', $locale)) ?></span>
                    <span class="badge" id="streamQuality">--</span>
                </h3>
                <p id="streamLatency" style="margin: 0; font-size: 0.95rem;">
                    --
                </p>
                <small id="streamUpdated" style="color: rgba(0,0,0,0.55);"></small>
            </div>
            <div class="meta-card">
                <h3>
                    <span><?= htmlspecialchars($languageManager->get('language', $locale)) ?></span>
                </h3>
                <div class="language-switch" id="languageSwitch">
                    <?php foreach ($translations as $code => $values): ?>
                        <button type="button" data-lang="<?= htmlspecialchars($code) ?>" <?= $code === $locale ? 'style="background: var(--sunrise-400); color: white;"' : '' ?>><?= strtoupper($code) ?></button>
                    <?php endforeach; ?>
                </div>
            </div>
            <div class="meta-card">
                <h3><?= htmlspecialchars($languageManager->get('gallery', $locale)) ?></h3>
                <div class="media-grid" id="imageGrid"></div>
            </div>
            <div class="meta-card">
                <h3><?= htmlspecialchars($languageManager->get('starlink', $locale)) ?></h3>
                <div class="qr-wrapper">
                    <a href="https://www.starlink.com/" target="_blank" rel="noopener noreferrer">
                        <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&amp;data=https%3A%2F%2Fwww.starlink.com%2F" alt="<?= htmlspecialchars($languageManager->get('starlink_alt', $locale)) ?>">
                    </a>
                    <small><?= htmlspecialchars($languageManager->get('starlink_caption', $locale)) ?></small>
                </div>
            </div>
        </div>
    </section>

    <section>
        <h2><?= htmlspecialchars($languageManager->get('calendar_title', $locale)) ?></h2>
        <div class="calendar-grid" id="calendarGrid"></div>
        <div id="calendarVideos" style="margin-top: 18px; display: grid; gap: 10px;"></div>
    </section>

    <section>
        <h2><?= htmlspecialchars($languageManager->get('guestbook', $locale)) ?></h2>
        <form id="guestbookForm">
            <input type="hidden" name="action" value="guestbook_add">
            <label>
                <?= htmlspecialchars($languageManager->get('name', $locale)) ?>
                <input type="text" name="name" required>
            </label>
            <label>
                <?= htmlspecialchars($languageManager->get('comment', $locale)) ?>
                <textarea name="message" required></textarea>
            </label>
            <label>
                <?= htmlspecialchars($languageManager->get('rating', $locale)) ?>
                <select name="rating">
                    <option value="5">★★★★★</option>
                    <option value="4">★★★★☆</option>
                    <option value="3">★★★☆☆</option>
                    <option value="2">★★☆☆☆</option>
                    <option value="1">★☆☆☆☆</option>
                </select>
            </label>
            <button class="control-btn" type="submit" style="width: fit-content;">
                ✅ <?= htmlspecialchars($languageManager->get('add_entry', $locale)) ?>
            </button>
        </form>
        <div id="guestbookEntries" style="margin-top: 18px; display: grid; gap: 14px;"></div>
    </section>

    <section>
        <h2><?= htmlspecialchars($languageManager->get('contact', $locale)) ?></h2>
        <form id="contactForm">
            <input type="hidden" name="action" value="contact_send">
            <label>
                <?= htmlspecialchars($languageManager->get('name', $locale)) ?>
                <input type="text" name="name" required>
            </label>
            <label>
                <?= htmlspecialchars($languageManager->get('email', $locale)) ?>
                <input type="email" name="email" required>
            </label>
            <label>
                <?= htmlspecialchars($languageManager->get('message', $locale)) ?>
                <textarea name="message" required></textarea>
            </label>
            <button class="control-btn" type="submit" style="width: fit-content;">
                ✉️ <?= htmlspecialchars($languageManager->get('send', $locale)) ?>
            </button>
        </form>
        <div id="contactFeedback" style="margin-top: 14px; font-weight: 600;"></div>
    </section>
</main>

<footer>
    © <?= date('Y') ?> Aurora Weather Livecam · <?= htmlspecialchars($languageManager->get('privacy', $locale)) ?> · <a href="tiny.php" style="color: inherit; font-weight: 600;">tiny view</a>
</footer>

<script type="module">
    const video = document.querySelector('#webcamPlayer');
    const hlsSource = <?= json_encode($webcamManager->getVideoSrc()) ?>;
    const isHlsNative = video.canPlayType('application/vnd.apple.mpegurl');
    const controlButtons = document.querySelectorAll('.control-btn[data-action]');
    const imageGrid = document.querySelector('#imageGrid');
    const calendarGrid = document.querySelector('#calendarGrid');
    const calendarVideos = document.querySelector('#calendarVideos');
    const guestbookContainer = document.querySelector('#guestbookEntries');
    const guestbookForm = document.querySelector('#guestbookForm');
    const contactForm = document.querySelector('#contactForm');
    const contactFeedback = document.querySelector('#contactFeedback');
    const streamQuality = document.querySelector('#streamQuality');
    const uploadBase = <?php echo json_encode('uploads/'); ?>;
    const videoBase = <?php echo json_encode('videos/'); ?>;
    const streamLatency = document.querySelector('#streamLatency');
    const streamUpdated = document.querySelector('#streamUpdated');

    async function fetchJSON(url, options = {}) {
        const response = await fetch(url, options);
        if (!response.ok) {
            throw new Error('Request failed');
        }
        return response.json();
    }

    async function populateImages() {
        try {
            const data = await fetchJSON('?api=images');
            imageGrid.innerHTML = data.images.map(src => `<img src="${src}" loading="lazy" alt="Aurora capture">`).join('');
        } catch (error) {
            imageGrid.innerHTML = '<small>Keine Bilder verfügbar.</small>';
        }
    }

    async function populateCalendar(year = new Date().getFullYear(), month = new Date().getMonth() + 1) {
        const data = await fetchJSON(`?api=calendar&year=${year}&month=${month}`);
        const { calendar } = data;
        calendarGrid.innerHTML = '';
        const firstDay = new Date(year, month - 1, 1).getDay();
        const startIndex = firstDay === 0 ? 6 : firstDay - 1;
        for (let i = 0; i < startIndex; i++) {
            const placeholder = document.createElement('div');
            calendarGrid.appendChild(placeholder);
        }
        calendar.days.forEach(day => {
            const el = document.createElement('div');
            el.className = `calendar-day${day.hasVideos ? ' has-video' : ''}`;
            el.dataset.day = day.day;
            el.innerHTML = `<span>${day.day}</span><span class="count">${day.count || ''}</span>`;
            el.addEventListener('click', () => {
                document.querySelectorAll('.calendar-day.selected').forEach(sel => sel.classList.remove('selected'));
                el.classList.add('selected');
                populateCalendarVideos(year, month, day.day);
            });
            calendarGrid.appendChild(el);
        });
    }

    async function populateCalendarVideos(year, month, day) {
        const data = await fetchJSON(`?api=calendar_videos&year=${year}&month=${month}&day=${day}`);
        if (!data.videos.length) {
            calendarVideos.innerHTML = '<small>Keine Videos für diesen Tag.</small>';
            return;
        }
        calendarVideos.innerHTML = data.videos.map(video => `
            <div class="guestbook-entry">
                <strong>${video.time} Uhr</strong>
                <span>${(video.size / (1024 * 1024)).toFixed(2)} MB</span>
                <a class="control-btn secondary" style="margin-top:10px; text-decoration:none;" href="${videoBase + video.file}" download>Download</a>
            </div>
        `).join('');
    }

    async function populateGuestbook() {
        const data = await fetchJSON('?api=guestbook');
        guestbookContainer.innerHTML = data.entries.map(entry => `
            <div class="guestbook-entry">
                <strong>${entry.name}</strong>
                <span>${'★'.repeat(entry.rating)}${'☆'.repeat(5 - entry.rating)}</span>
                <p>${entry.message}</p>
                <small>${entry.created}</small>
            </div>
        `).join('');
    }

    async function refreshStreamStats() {
        const data = await fetchJSON('?api=stream_stats');
        streamQuality.textContent = `${(data.stats.bitrate / 1000).toFixed(1)} Mbps`;
        streamLatency.textContent = `Latency: ${data.stats.latency} s`;
        streamUpdated.textContent = `Updated ${data.stats.updated}`;
    }

    function initPlayer() {
        if (isHlsNative) {
            video.src = hlsSource;
            video.play().catch(() => {});
            return;
        }
        if (window.Hls && window.Hls.isSupported()) {
            const hls = new Hls({
                enableWorker: true,
                liveSyncDurationCount: 3,
                maxLiveSyncPlaybackRate: 1.2,
            });
            hls.loadSource(hlsSource);
            hls.attachMedia(video);
            hls.on(Hls.Events.MANIFEST_PARSED, () => video.play().catch(() => {}));
        }
    }

    controlButtons.forEach(btn => {
        btn.addEventListener('click', async () => {
            const action = btn.dataset.action;
            if (action === 'screenshot') {
                btn.disabled = true;
                const response = await fetchJSON('', {
                    method: 'POST',
                    body: new URLSearchParams({ action: 'capture_snapshot' })
                }).catch(() => null);
                if (response?.success) {
                    window.location.href = uploadBase + response.file;
                }
                btn.disabled = false;
            }
            if (action === 'clip') {
                btn.disabled = true;
                const response = await fetchJSON('', {
                    method: 'POST',
                    body: new URLSearchParams({ action: 'capture_clip', duration: 12 })
                }).catch(() => null);
                if (response?.success) {
                    window.location.href = uploadBase + response.file;
                }
                btn.disabled = false;
            }
            if (action === 'pip' && document.pictureInPictureEnabled) {
                if (document.pictureInPictureElement) {
                    document.exitPictureInPicture();
                } else {
                    video.requestPictureInPicture().catch(() => {});
                }
            }
            if (action === 'share' && navigator.share) {
                navigator.share({
                    title: document.title,
                    text: 'Aurora Weather Livecam',
                    url: window.location.href
                }).catch(() => {});
            }
        });
    });

    guestbookForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const data = new FormData(guestbookForm);
        const response = await fetchJSON('', {
            method: 'POST',
            body: new URLSearchParams(data)
        }).catch(() => null);
        if (response?.success) {
            guestbookForm.reset();
            populateGuestbook();
        }
    });

    contactForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const formData = new FormData(contactForm);
        const response = await fetchJSON('', {
            method: 'POST',
            body: new URLSearchParams(formData)
        }).catch(() => null);
        if (response) {
            contactFeedback.textContent = response.message;
            contactFeedback.style.color = response.success ? 'green' : 'red';
            if (response.success) {
                contactForm.reset();
            }
        }
    });

    document.querySelectorAll('#languageSwitch button').forEach(button => {
        button.addEventListener('click', async () => {
            const lang = button.dataset.lang;
            await fetchJSON('', {
                method: 'POST',
                body: new URLSearchParams({ action: 'set_language', language: lang })
            });
            location.reload();
        });
    });

    initPlayer();
    populateImages();
    populateCalendar();
    populateGuestbook();
    refreshStreamStats();
    setInterval(refreshStreamStats, 15000);
</script>
</body>
</html>
