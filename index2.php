<?php session_start();
error_reporting(E_ALL);
ini_set("display_errors", 1);
class WebcamManager
{
    private $videoSource = "/test_video.m3u8";
    private $imageDir = "./image";
    private $uploadDir = "./uploads";
    private $galleryDir = "./gallery";
    private $commentsFile = "comments.json";
    private $lang = "de";
    public function __construct()
    {
        foreach (
            [$this->uploadDir, $this->imageDir, $this->galleryDir]
            as $dir
        ) {
            if (!file_exists($dir)) {
                mkdir($dir, 0777, true);
            }
        }
        if (!file_exists($this->commentsFile)) {
            file_put_contents($this->commentsFile, "[]");
        }
        $this->lang = $_SESSION["lang"] ?? "de";
    }
    public function getVideoPlayer()
    {
        return '
<video id="webcamPlayer" autoplay muted playsinline></video>';
    }
    public function getImageFiles()
    {
         $files = glob($this->imageDir . "/screenshot_*.jpg");
         
        rsort($files);
        return json_encode($files);
    }
    public function getGalleryImages()
    {
        $images = [];
        foreach (
            glob($this->galleryDir . "/*.{jpg,jpeg,png,gif}", GLOB_BRACE)
            as $img
        ) {
            $images[] = [
                "src" => $img,
                "thumb" => $img,
                "date" => filemtime($img),
            ];
        }
        usort($images, function ($a, $b) {
            return $b["date"] - $a["date"];
        });
        return $images;
    }
    public function getLatestVideo()
    {
        $videos = glob($this->imageDir . "/daily_video_*.mp4");
        if (empty($videos)) {
            return null;
        }
        usort($videos, function ($a, $b) {
            return filemtime($b) - filemtime($a);
        });
        return $videos[0];
    }
    public function addComment($name, $comment, $rating = 5)
    {
        $comments =
            json_decode(file_get_contents($this->commentsFile), true) ?: [];
        $comments[] = [
            "name" => htmlspecialchars($name),
            "comment" => htmlspecialchars($comment),
            "rating" => intval($rating),
            "time" => time(),
            "id" => uniqid(),
        ];
        file_put_contents($this->commentsFile, json_encode($comments));
        return true;
    }
    public function getComments()
    {
        $comments =
            json_decode(file_get_contents($this->commentsFile), true) ?: [];
        usort($comments, function ($a, $b) {
            return $b["time"] - $a["time"];
        });
        return array_slice($comments, 0, 50);
    }
}
class TranslationManager
{
    private $translations = [
        "de" => [
            "live" => "Live",
            "timelapse" => "Zeitraffer",
            "archive" => "Archiv",
            "gallery" => "Galerie",
            "comments" => "Kommentare",
            "info" => "Info",
            "chat" => "Chat",
            "send" => "Senden",
            "download" => "Herunterladen",
            "screenshot" => "Bildschirmfoto",
            "fullscreen" => "Vollbild",
            "welcome" => 'Willkommen
bei Aurora Webcam',
            "rules" => "Nutzungsbedingungen",
            "accept" => "Akzeptieren",
            "decline" => "Ablehnen",
            "contact" => "Kontakt",
            "abuse" => 'Missbrauch
melden',
            "rating" => "Bewertung",
            "name" => "Name",
            "comment" => "Kommentar",
            "submit" => "Absenden",
            "loading" => "Lädt...",
            "error" => "Fehler",
            "success" => "Erfolgreich",
            "darkmode" => "Dunkler Modus",
            "lightmode" => "Heller Modus",
        ],
        "fr" => [
            "live" => 'En
direct',
            "timelapse" => "Accéléré",
            "archive" => "Archive",
            "gallery" => "Galerie",
            "comments" => "Commentaires",
            "info" => "Info",
            "chat" => "Chat",
            "send" => "Envoyer",
            "download" => "Télécharger",
            "screenshot" => 'Capture d\'écran',
            "fullscreen" => 'Plein
écran',
            "welcome" => "Bienvenue à Aurora Webcam",
            "rules" => 'Conditions d\'utilisation',
            "accept" => "Accepter",
            "decline" => "Refuser",
            "contact" => "Contact",
            "abuse" => 'Signaler un
abus',
            "rating" => "Évaluation",
            "name" => "Nom",
            "comment" => "Commentaire",
            "submit" => "Envoyer",
            "darkmode" => "Mode sombre",
            "lightmode" => "Mode clair",
        ],
        "it" => [
            "live" => 'Dal
vivo',
            "timelapse" => "Time-lapse",
            "archive" => "Archivio",
            "gallery" => "Galleria",
            "comments" => "Commenti",
            "info" => "Info",
            "chat" => "Chat",
            "send" => "Invia",
            "download" => "Scarica",
            "screenshot" => "Screenshot",
            "fullscreen" => 'Schermo
intero',
            "welcome" => "Benvenuti a Aurora Webcam",
            "rules" => "Termini di utilizzo",
            "accept" => "Accetta",
            "decline" => "Rifiuta",
            "contact" => "Contatto",
            "abuse" => 'Segnala
abuso',
            "rating" => "Valutazione",
            "name" => "Nome",
            "comment" => "Commento",
            "submit" => "Invia",
            "darkmode" => "Modalità scura",
            "lightmode" => 'Modalità
chiara',
        ],
        "en" => [
            "live" => "Live",
            "timelapse" => "Timelapse",
            "archive" => "Archive",
            "gallery" => "Gallery",
            "comments" => "Comments",
            "info" => "Info",
            "chat" => "Chat",
            "send" => "Send",
            "download" => "Download",
            "screenshot" => "Screenshot",
            "fullscreen" => "Fullscreen",
            "welcome" => 'Welcome
to Aurora Webcam',
            "rules" => "Terms of Use",
            "accept" => "Accept",
            "decline" => "Decline",
            "contact" => "Contact",
            "abuse" => "Report Abuse",
            "rating" => "Rating",
            "name" => "Name",
            "comment" => "Comment",
            "submit" => "Submit",
            "darkmode" => 'Dark
Mode',
            "lightmode" => 'Light
Mode',
        ],
        "zh" => [
            "live" => "直播",
            "timelapse" => "延时摄影",
            "archive" => "档案",
            "gallery" => "图库",
            "comments" => "评论",
            "info" => "信息",
            "chat" => "聊天",
            "send" => "发送",
            "download" => "下载",
            "screenshot" => "截图",
            "fullscreen" => "全屏",
            "welcome" => "欢迎来到Aurora网络摄像头",
            "rules" => "使用条款",
            "accept" => "接受",
            "decline" => "拒绝",
            "contact" => "联系",
            "abuse" => "举报滥用",
            "rating" => "评分",
            "name" => "姓名",
            "comment" => "评论",
            "submit" => "提交",
            "darkmode" => "深色模式",
            "lightmode" => "浅色模式",
        ],
    ];
    private $currentLang = "de";
    public function __construct($lang = "de")
    {
        $this->currentLang = $lang;
    }
    public function t($key)
    {
        return $this->translations[$this->currentLang][$key] ??
            ($this->translations["de"][$key] ?? $key);
    }
    public function getLang()
    {
        return $this->currentLang;
    }
    public function setLang($lang)
    {
        if (isset($this->translations[$lang])) {
            $this->currentLang = $lang;
            $_SESSION["lang"] = $lang;
        }
    }
}
class ChatManager
{
    private $chatFile = "chat.json";
    private $maxMessages = 100;
    public function __construct()
    {
        if (!file_exists($this->chatFile)) {
            file_put_contents($this->chatFile, json_encode([]));
        }
    }
    public function addMessage($user, $message)
    {
        $messages = $this->getMessages();
        $messages[] = [
            "user" => htmlspecialchars($user),
            "message" => htmlspecialchars($message),
            "time" => time(),
            "id" => uniqid(),
        ];
        if (count($messages) > $this->maxMessages) {
            array_shift($messages);
        }
        file_put_contents($this->chatFile, json_encode($messages));
        return true;
    }
    public function getMessages()
    {
        $messages = json_decode(file_get_contents($this->chatFile), true) ?: [];
        return array_filter($messages, function ($msg) {
            return time() - $msg["time"] < 86400;
        });
    }
}
class CalendarManager
{
    private $videoDir = "./image";
    public function getVideosForMonth($year, $month)
    {
        $videos = [];
        $startDate = sprintf("%04d%02d01", $year, $month);
        $endDate = sprintf("%04d%02d31", $year, $month);
        foreach (glob($this->videoDir . "/daily_video_*.mp4") as $video) {
            $filename = basename($video);
            if (preg_match("/daily_video_(\d{8})/", $filename, $matches)) {
                $videoDate = $matches[1];
                if ($videoDate >= $startDate && $videoDate <= $endDate) {
                    $day = intval(substr($videoDate, 6, 2));
                    if (!isset($videos[$day])) {
                        $videos[$day] = [];
                    }
                    $videos[$day][] = $video;
                }
            }
        }
        return $videos;
    }
}
$lang = $_GET["lang"] ?? ($_SESSION["lang"] ?? "de");
$_SESSION["lang"] = $lang;
$t = new TranslationManager($lang);
$webcam = new WebcamManager();
$chat = new ChatManager();
$calendar = new CalendarManager();
if (isset($_POST["chat_message"])) {
    $chat->addMessage($_POST["chat_user"] ?? "Anonym", $_POST["chat_message"]);
    header("Content-Type:application/json");
    echo json_encode(["success" => true]);
    exit();
}

// Nach den anderen POST-Handlern
if (isset($_POST['action']) && $_POST['action'] === 'upload_screenshot') {
    if (isset($_FILES['screenshot'])) {
        // In BEIDE Ordner speichern
        $galleries = ['./gallery/', './image/'];
        $success = false;
        
        foreach ($galleries as $uploadDir) {
            if (!file_exists($uploadDir)) mkdir($uploadDir, 0777, true);
            
            $filename = 'screenshot_' . date('Ymd_His') . '.jpg';
            $uploadFile = $uploadDir . $filename;
            
            if (move_uploaded_file($_FILES['screenshot']['tmp_name'], $uploadFile)) {
                $success = true;
                break;
            }
        }
        
        header('Content-Type: application/json');
        echo json_encode(['success' => $success, 'file' => $filename]);
        exit;
    }
}


if (isset($_GET["get_messages"])) {
    header("Content-Type:application/json");
    echo json_encode($chat->getMessages());
    exit();
}
if (isset($_POST["add_comment"])) {
    $webcam->addComment(
        $_POST["comment_name"] ?? "Anonym",
        $_POST["comment_text"],
        $_POST["rating"] ?? 5,
    );
    header("Content-Type:application/json");
    echo json_encode(["success" => true]);
    exit();
}
if (isset($_GET["get_comments"])) {
    header("Content-Type:application/json");
    echo json_encode($webcam->getComments());
    exit();
}
if (isset($_GET["get_gallery"])) {
    header("Content-Type:application/json");
    echo json_encode($webcam->getGalleryImages());
    exit();
}
if (isset($_GET["get_calendar_videos"])) {
    $month = $_GET["month"] ?? date("n");
    $year = $_GET["year"] ?? date("Y");
    header("Content-Type:application/json");
    echo json_encode($calendar->getVideosForMonth($year, $month));
    exit();
}
if (isset($_GET["download_video"])) {
    $video = $webcam->getLatestVideo();
    if ($video && file_exists($video)) {
        header("Content-Type:video/mp4");
        header(
            'Content-Disposition:attachment;filename="' .
                basename($video) .
                '"',
        );
        readfile($video);
        exit();
    }
} ?>

<!DOCTYPE html>
<html lang="<?php echo $lang;?>">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width,initial-scale=1.0" />
        <title>Aurora Webcam - Schweiz 🇨🇭</title>
        <link href="https://fonts.googleapis.com/css2?family=Helvetica+Neue:wght@300;400;700&display=swap" rel="stylesheet" />
        <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
         
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>

        <style>
            :root {
                --swiss-red: #ff0000;
                --swiss-white: #ffffff;
                --swiss-gray: #f5f5f5;
                --swiss-dark: #333333;
                --swiss-border: #e0e0e0;
                --swiss-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
                --font-swiss: "Helvetica Neue", Helvetica, Arial, sans-serif;
                --bg-primary: #0f172a;
                --bg-secondary: #1e293b;
                --text-primary: #e2e8f0;
                --text-secondary: #94a3b8;
                --surface: rgba(255, 255, 255, 0.05);
                --surface-hover: rgba(255, 255, 255, 0.1);
            }
            body.light {
                --bg-primary: #f8fafc;
                --bg-secondary: #e2e8f0;
                --text-primary: #1e293b;
                --text-secondary: #64748b;
                --surface: rgba(255, 255, 255, 0.9);
                --surface-hover: rgba(0, 0, 0, 0.05);
                --swiss-border: #cbd5e1;
            }
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: var(--font-swiss);
                background: var(--bg-primary);
                color: var(--text-primary);
                line-height: 1.6;
                font-size: 16px;
                position: relative;
                transition: background 0.3s, color 0.3s;
            }
            body::before {
                content: "";
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: linear-gradient(45deg, var(--bg-primary), var(--bg-secondary));
                z-index: -2;
            }
            body::after {
                content: "";
                position: fixed;
                width: 200%;
                height: 200%;
                top: -50%;
                left: -50%;
                background: radial-gradient(circle at 20% 80%, rgba(99, 102, 241, 0.1) 0%, transparent 50%), radial-gradient(circle at 80% 20%, rgba(236, 72, 153, 0.1) 0%, transparent 50%),
                    radial-gradient(circle at 40% 40%, rgba(34, 197, 94, 0.05) 0%, transparent 50%);
                animation: float 20s infinite;
                z-index: -1;
            }
            @keyframes float {
                0%,
                100% {
                    transform: rotate(0deg) scale(1) translateY(0);
                }
                25% {
                    transform: rotate(90deg) scale(1.1) translateY(-10px);
                }
                50% {
                    transform: rotate(180deg) scale(1) translateY(0);
                }
                75% {
                    transform: rotate(270deg) scale(0.9) translateY(10px);
                }
            }
            .swiss-mountains {
                position: fixed;
                bottom: 0;
                left: 0;
                width: 100%;
                height: 300px;
                background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 320"><path fill="%23111827" fill-opacity="0.3" d="M0,96L48,112C96,128,192,160,288,160C384,160,480,128,576,138.7C672,149,768,203,864,213.3C960,224,1056,192,1152,165.3C1248,139,1344,117,1392,106.7L1440,96L1440,320L1392,320C1344,320,1248,320,1152,320C1056,320,960,320,864,320C768,320,672,320,576,320C480,320,384,320,288,320C192,320,96,320,48,320L0,320Z"></path></svg>')
                    no-repeat bottom;
                background-size: cover;
                z-index: -1;
                opacity: 0.5;
            }
            .swiss-header {
                background: rgba(15, 23, 42, 0.8);
                backdrop-filter: blur(20px);
                border-bottom: 3px solid var(--swiss-red);
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
                position: sticky;
                top: 0;
                z-index: 1000;
                transition: background 0.3s;
            }
            body.light .swiss-header {
                background: rgba(255, 255, 255, 0.95);
            }
            .header-content {
                max-width: 1400px;
                margin: 0 auto;
                padding: 1rem 2rem;
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
            }
            .logo {
                display: flex;
                align-items: center;
                gap: 1rem;
                font-size: 1.5rem;
                font-weight: 700;
                color: var(--text-primary);
            }
            .swiss-flag {
                width: 40px;
                height: 40px;
                background: var(--swiss-red);
                position: relative;
                display: inline-block;
            }
            .swiss-flag::before,
            .swiss-flag::after {
                content: "";
                position: absolute;
                background: var(--swiss-white);
            }
            .swiss-flag::before {
                width: 20px;
                height: 6px;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
            }
            .swiss-flag::after {
                width: 6px;
                height: 20px;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
            }
            .nav-swiss {
                display: flex;
                gap: 0.5rem;
                background: var(--surface);
                padding: 0.25rem;
                border-radius: 4px;
            }
            .nav-btn {
                padding: 0.5rem 1rem;
                background: transparent;
                border: none;
                color: var(--text-primary);
                cursor: pointer;
                transition: all 0.3s;
                font-weight: 500;
                border-radius: 3px;
            }
            .nav-btn:hover {
                background: var(--surface-hover);
                color: var(--text-primary);
            }
            .nav-btn.active {
                background: var(--swiss-red);
                color: var(--swiss-white);
            }
            .lang-selector {
                display: flex;
                gap: 0.25rem;
                align-items: center;
            }
            .lang-btn {
                width: 30px;
                height: 20px;
                border: 1px solid var(--swiss-border);
                cursor: pointer;
                opacity: 0.6;
                transition: opacity 0.3s;
            }
            .lang-btn:hover,
            .lang-btn.active {
                opacity: 1;
                box-shadow: 0 0 0 2px var(--swiss-red);
            }
            .theme-toggle {
                width: 50px;
                height: 26px;
                background: var(--surface);
                border-radius: 13px;
                position: relative;
                cursor: pointer;
                transition: background 0.3s;
                margin-left: 1rem;
            }
            .theme-toggle::after {
                content: "🌙";
                position: absolute;
                left: 3px;
                top: 3px;
                width: 20px;
                height: 20px;
                background: white;
                border-radius: 50%;
                transition: transform 0.3s;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 12px;
            }
            body.light .theme-toggle {
                background: var(--swiss-red);
            }
            body.light .theme-toggle::after {
                content: "☀️";
                transform: translateX(24px);
            }
            .main-container {
                max-width: 1400px;
                margin: 2rem auto;
                padding: 0 2rem;
                display: grid;
                grid-template-columns: 1fr 350px;
                gap: 2rem;
            }
            @media (max-width: 768px) {
                .main-container {
                    grid-template-columns: 1fr;
                }
            }
            .swiss-card {
                background: var(--surface);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                overflow: hidden;
                transition: background 0.3s, border 0.3s;
            }
            body.light .swiss-card {
                background: rgba(255, 255, 255, 0.9);
                border: 1px solid var(--swiss-border);
            }
            .video-container {
                position: relative;
                padding-bottom: 56.25%;
                background: var(--bg-primary);
            }
            .video-container video {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
            }
            .live-badge {
                position: absolute;
                top: 1rem;
                left: 1rem;
                background: var(--swiss-red);
                color: var(--swiss-white);
                padding: 0.25rem 0.75rem;
                font-weight: 700;
                font-size: 0.875rem;
                letter-spacing: 1px;
                z-index: 10;
                animation: pulse 2s infinite;
            }
            @keyframes pulse {
                0%,
                100% {
                    opacity: 1;
                }
                50% {
                    opacity: 0.7;
                }
            }
            .chat-container {
                display: flex;
                flex-direction: column;
                height: 500px;
            }
            .chat-header {
                padding: 1rem;
                background: var(--surface);
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                font-weight: 700;
                color: var(--text-primary);
            }
            .chat-messages {
                flex: 1;
                overflow-y: auto;
                padding: 1rem;
                background: transparent;
            }
            .chat-message {
                padding: 0.5rem;
                margin-bottom: 0.5rem;
                background: var(--surface);
                border-left: 3px solid var(--swiss-red);
                color: var(--text-primary);
            }
            .chat-input-wrap {
                padding: 1rem;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
                display: flex;
                gap: 0.5rem;
            }
            .swiss-input {
                flex: 1;
                padding: 0.5rem;
                border: 1px solid rgba(255, 255, 255, 0.2);
                background: var(--surface);
                color: var(--text-primary);
                font-family: var(--font-swiss);
            }
            .swiss-input:focus {
                outline: none;
                border-color: var(--swiss-red);
                box-shadow: 0 0 0 3px rgba(255, 0, 0, 0.1);
            }
            .swiss-btn {
                background: var(--swiss-red);
                color: var(--swiss-white);
                border: none;
                padding: 0.5rem 1.5rem;
                cursor: pointer;
                font-weight: 500;
                transition: all 0.3s;
            }
            .swiss-btn:hover {
                background: #cc0000;
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(255, 0, 0, 0.3);
            }
            .swiss-btn:active {
                transform: translateY(0);
            }
            .action-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 1rem;
                margin: 2rem auto;
                max-width: 1400px;
                padding: 0 2rem;
            }
            .action-card {
                background: var(--surface);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                padding: 1.5rem;
                text-align: center;
                cursor: pointer;
                transition: all 0.3s;
                text-decoration: none;
                color: var(--text-primary);
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 0.5rem;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
            }
            .action-card:hover {
                transform: translateY(-2px);
                box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
                border-color: var(--swiss-red);
                background: var(--surface-hover);
            }



            
            .action-icon {
                font-size: 2rem;
            }
            .gallery-section {
                display: none;
                max-width: 1400px;
                margin: 2rem auto;
                padding: 0 2rem;
            }
            .gallery-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                gap: 1rem;
                margin-top: 2rem;
            }
            .gallery-item {
                position: relative;
                overflow: hidden;
                background: var(--surface);
                aspect-ratio: 16/9;
                cursor: pointer;
                border: 1px solid rgba(255, 255, 255, 0.1);
                transition: all 0.3s;
            }
            .gallery-item img {
                width: 100%;
                height: 100%;
                object-fit: cover;
                transition: transform 0.3s;
            }
            .gallery-item:hover img {
                transform: scale(1.05);
            }
            .gallery-date {
                position: absolute;
                bottom: 0;
                left: 0;
                right: 0;
                background: rgba(0, 0, 0, 0.7);
                color: var(--swiss-white);
                padding: 0.5rem;
                font-size: 0.875rem;
            }
            .comments-section {
                display: none;
                max-width: 1400px;
                margin: 2rem auto;
                padding: 0 2rem;
            }
            .comment-form {
                background: var(--surface);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                padding: 2rem;
                margin-bottom: 2rem;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
            }
            .comment-form h3 {
                margin-bottom: 1rem;
                color: var(--swiss-red);
            }
            .form-group {
                margin-bottom: 1rem;
            }
            .form-group label {
                display: block;
                margin-bottom: 0.25rem;
                font-weight: 500;
                color: var(--text-primary);
            }
            .form-group input,
            .form-group textarea {
                width: 100%;
                padding: 0.5rem;
                border: 1px solid rgba(255, 255, 255, 0.2);
                background: var(--surface);
                color: var(--text-primary);
                font-family: var(--font-swiss);
            }
            .rating-stars {
                display: flex;
                gap: 0.25rem;
            }
            .star {
                cursor: pointer;
                font-size: 1.5rem;
                color: var(--text-secondary);
                transition: color 0.3s;
            }
            .star:hover,
            .star.active {
                color: #ffcc00;
            }
            .comment-list {
                background: var(--surface);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                padding: 1rem;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
            }
            .comment-item {
                padding: 1rem;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }
            .comment-item:last-child {
                border-bottom: none;
            }
            .comment-header {
                display: flex;
                justify-content: space-between;
                margin-bottom: 0.5rem;
            }
            .comment-name {
                font-weight: 700;
                color: var(--swiss-red);
            }
            .comment-rating {
                color: #ffcc00;
            }
            .comment-text {
                color: var(--text-primary);
                line-height: 1.5;
            }
            .comment-time {
                font-size: 0.875rem;
                color: var(--text-secondary);
                margin-top: 0.5rem;
            }
            .calendar-modal {
                display: none;
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background: var(--bg-secondary);
                backdrop-filter: blur(20px);
                border: 2px solid var(--swiss-red);
                padding: 2rem;
                max-width: 800px;
                width: 90%;
                max-height: 80vh;
                overflow-y: auto;
                z-index: 2000;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            }
            body.light .calendar-modal {
                background: rgba(255, 255, 255, 0.98);
            }
            .calendar-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 1.5rem;
                padding-bottom: 1rem;
                border-bottom: 2px solid var(--swiss-red);
            }
            .calendar-nav {
                display: flex;
                gap: 1rem;
                align-items: center;
            }
            .calendar-nav button {
                background: var(--swiss-red);
                color: var(--swiss-white);
                border: none;
                padding: 0.5rem 1rem;
                cursor: pointer;
            }
            .calendar-weekdays {
                display: grid;
                grid-template-columns: repeat(7, 1fr);
                gap: 0.25rem;
                margin-bottom: 0.5rem;
                text-align: center;
                font-weight: 700;
                color: var(--swiss-red);
            }
            .calendar-grid {
                display: grid;
                grid-template-columns: repeat(7, 1fr);
                gap: 0.25rem;
            }
            .cal-day {
                aspect-ratio: 1;
                display: flex;
                align-items: center;
                justify-content: center;
                background: var(--surface);
                border: 1px solid rgba(255, 255, 255, 0.1);
                cursor: pointer;
                transition: all 0.3s;
                position: relative;
                font-weight: 500;
                color: var(--text-primary);
            }
            .cal-day:hover {
                background: var(--swiss-red);
                color: var(--swiss-white);
            }
            .cal-day.has-video {
                background: var(--swiss-red);
                color: var(--swiss-white);
                font-weight: 700;
            }
            .cal-day.has-video::after {
                content: "📹";
                position: absolute;
                top: 2px;
                right: 2px;
                font-size: 0.625rem;
            }
            .cal-day.today {
                border: 2px solid var(--swiss-red);
                font-weight: 700;
            }
            .cal-day.other-month {
                opacity: 0.3;
            }
            .video-list {
                margin-top: 1.5rem;
                padding-top: 1.5rem;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
            }
            .video-item {
                background: var(--surface);
                padding: 0.75rem;
                margin-bottom: 0.5rem;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .video-item a {
                color: var(--swiss-red);
                text-decoration: none;
                font-weight: 500;
            }
            .video-item a:hover {
                text-decoration: underline;
            }
            .overlay {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.7);
                z-index: 1999;
            }
            .modal-close {
                position: absolute;
                top: 1rem;
                right: 1rem;
                background: var(--swiss-red);
                color: var(--swiss-white);
                border: none;
                width: 2rem;
                height: 2rem;
                cursor: pointer;
                font-size: 1.5rem;
                line-height: 1;
            }
            .rules-modal {
                display: none;
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background: var(--bg-secondary);
                backdrop-filter: blur(20px);
                padding: 2rem;
                max-width: 600px;
                width: 90%;
                max-height: 80vh;
                overflow-y: auto;
                z-index: 3000;
                border: 2px solid var(--swiss-red);
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
                color: var(--text-primary);
            }
            body.light .rules-modal {
                background: rgba(255, 255, 255, 0.98);
            }
            .rules-content {
                line-height: 1.6;
                margin: 1rem 0;
            }
            .rules-section {
                background: var(--surface);
                padding: 1rem;
                margin: 1rem 0;
            }
            .rules-section h3 {
                color: var(--swiss-red);
                margin-bottom: 0.5rem;
            }
            .rules-section ul {
                margin-left: 1.5rem;
            }
            .rules-actions {
                display: flex;
                gap: 1rem;
                justify-content: center;
                margin-top: 1.5rem;
            }
            .timelapse-viewer {
                display: none;
                position: relative;
                width: 100%;
                height: 100%;
                background: #000;
            }
            .timelapse-viewer img {
                width: 100%;
                height: 100%;
                object-fit: contain;
            }
            .timelapse-controls {
                position: absolute;
                bottom: 1rem;
                left: 50%;
                transform: translateX(-50%);
                display: flex;
                gap: 0.5rem;
                background: rgba(0, 0, 0, 0.8);
                padding: 0.5rem;
                border-radius: 4px;
            }
            .footer {
                background: rgba(15, 23, 42, 0.8);
                backdrop-filter: blur(20px);
                border-top: 3px solid var(--swiss-red);
                padding: 2rem;
                text-align: center;
                margin-top: 3rem;
                transition: background 0.3s;
            }
            body.light .footer {
                background: rgba(255, 255, 255, 0.95);
            }
            .footer-content {
                max-width: 1400px;
                margin: 0 auto;
            }
            .footer-links {
                display: flex;
                justify-content: center;
                gap: 2rem;
                margin-bottom: 1rem;
            }
            .footer a {
                color: var(--swiss-red);
                text-decoration: none;
                font-weight: 500;
            }
            .footer a:hover {
                text-decoration: underline;
            }
            .copyright {
                color: var(--text-secondary);
                font-size: 0.875rem;
                margin-top: 1rem;
            }
            .swiss-quality {
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                margin-top: 1rem;
                padding: 0.5rem 1rem;
                background: var(--surface);
                backdrop-filter: blur(10px);
                border: 1px solid var(--swiss-red);
                font-size: 0.875rem;
                font-weight: 700;
                color: var(--swiss-red);
            }
            @media (max-width: 768px) {
                .main-container {
                    grid-template-columns: 1fr;
                }
                .chat-container {
                    height: 400px;
                }
                .action-grid {
                    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                }
                .footer-links {
                    flex-direction: column;
                    gap: 0.5rem;
                }
            }
        </style>
    </head>
    <body>
        <div class="swiss-mountains"></div>
        <header class="swiss-header">
            <div class="header-content">
                <div class="logo"><span class="swiss-flag"></span><span>Aurora Webcam</span></div>
                <nav class="nav-swiss">
                    <button class="nav-btn active" data-section="live"><?php echo $t->t('live');?></button><button class="nav-btn" data-section="timelapse"><?php echo $t->t('timelapse');?></button>
                    <button class="nav-btn" data-section="archive"><?php echo $t->t('archive');?></button><button class="nav-btn" data-section="gallery"><?php echo $t->t('gallery');?></button>
                    <button class="nav-btn" data-section="comments"><?php echo $t->t('comments');?></button>
 
<button class="nav-btn" data-section="community">Community</button>


                </nav>
                <div style="display: flex; align-items: center;">
                    <div class="lang-selector">
                        <img
                            src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect fill='%23ff0000' width='32' height='32'/%3E%3Crect fill='%23fff' x='13' y='6' width='6' height='20'/%3E%3Crect fill='%23fff' x='6' y='13' width='20' height='6'/%3E%3C/svg%3E"
                            class="lang-btn<?php echo $lang=='de'?' active':'';?>"
                            data-lang="de"
                            title="Deutsch"
                        />
                        <img
                            src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 3 2'%3E%3Crect width='3' height='2' fill='%23002395'/%3E%3Crect width='2' height='2' x='1' fill='%23fff'/%3E%3Crect width='1' height='2' x='2' fill='%23ED2939'/%3E%3C/svg%3E"
                            class="lang-btn<?php echo $lang=='fr'?' active':'';?>"
                            data-lang="fr"
                            title="Français"
                        />
                        <img
                            src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 3 2'%3E%3Crect width='3' height='2' fill='%23009246'/%3E%3Crect width='2' height='2' x='1' fill='%23fff'
/%3E%3Crect width='1' height='2' x='2' fill='%23CE2B37'/%3E%3C/svg%3E"
                            class="lang-btn<?php echo $lang=='it'?' active':'';?>"
                            data-lang="it"
                            title="Italiano"
                        />
                        <img
                            src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 60 30'%3E%3Crect width='60' height='30' fill='%23012169'/%3E%3Cpath d='M0,0 L60,30 M60,0 L0,30' stroke='%23fff' stroke-width='6'/%3E%3Cpath d='M0,0 L60,30 M60,0 L0,30' stroke='%23C8102E' stroke-width='4'/%3E%3Cpath d='M30,0 v30 M0,15 h60' stroke='%23fff' stroke-width='10'/%3E%3Cpath d='M30,0 v30 M0,15 h60' stroke='%23C8102E' stroke-width='6'/%3E%3C/svg%3E"
                            class="lang-btn<?php echo $lang=='en'?' active':'';?>"
                            data-lang="en"
                            title="English"
                        />
                        <img
                            src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 5 3'%3E%3Crect width='5' height='3' fill='%23DE2910'/%3E%3Cpolygon points='0.5,0.5 0.7,1.2 1.4,1.2 0.9,1.6 1.1,2.3 0.5,1.9 -0.1,2.3 0.1,1.6 -0.4,1.2 0.3,1.2' fill='%23FFDE00'/%3E%3C/svg%3E"
                            class="lang-btn<?php echo $lang=='zh'?' active':'';?>"
                            data-lang="zh"
                            title="中文"
                        />
                    </div>
                    <div class="theme-toggle" id="themeToggle"></div>
                </div>
            </div>
        </header>
        <main class="main-container" id="mainSection">
            <div class="swiss-card">
                <div class="video-container">
                    <div class="live-badge">● LIVE</div>
                    <?php echo $webcam->getVideoPlayer();?>
                    <div class="timelapse-viewer" id="timelapseViewer">
                        <img id="timelapseImage" src="" />
                        <div class="timelapse-controls"><button class="swiss-btn" id="playBtn">▶</button><button class="swiss-btn" id="pauseBtn">⏸</button><button class="swiss-btn" id="stopBtn">⏹</button></div>
                    </div>
                </div>
            </div>
            <aside class="swiss-card chat-container">
                <div class="chat-header"><?php echo $t->t('chat');?> <span id="onlineCount">👥 0</span></div>
                <div class="chat-messages" id="chatMessages"></div>
                <div class="chat-input-wrap">
                    <input type="text" class="swiss-input" id="chatInput" placeholder="<?php echo $t->t('comment');?>..." maxlength="200" /><button class="swiss-btn" id="sendBtn"><?php echo $t->t('send');?></button>
                </div>
            </aside>
        </main>
        <div class="gallery-section" id="gallerySection">
            <h2 style="margin-bottom: 1rem; color: var(--swiss-red);"><?php echo $t->t('gallery');?></h2>
            <div class="gallery-grid" id="galleryGrid"></div>
        </div>


<!-- Community Section - Nach gallery-section -->
<div class="community-section" id="communitySection" style="display:none;max-width:1400px;margin:2rem auto;padding:0 2rem;">
    <div class="swiss-card" style="padding:3rem;text-align:center;background:linear-gradient(135deg,var(--surface),rgba(255,0,0,0.05))">
        <h2 style="color:var(--swiss-red);font-size:2.5rem;margin-bottom:2rem">
            🎥 Werden Sie Teil unserer Community
        </h2>
        <div style="max-width:800px;margin:0 auto">
            <p style="font-size:1.2rem;line-height:1.8;color:var(--text-primary);margin-bottom:2rem">
                Nutzen Sie unsere Plattform, um Ihre eigene Webcam-Übertragung zu starten und Ihre Sicht auf die Züricher Landschaft mit anderen zu teilen.
            </p>
            <div style="background:var(--surface);padding:2rem;border-radius:1rem;border-left:4px solid var(--swiss-red);margin:2rem 0">
                <p style="font-size:1.1rem;color:var(--text-primary)">
                    Werden Sie Teil unserer Community von Wetter- und Naturbegeisterten, indem Sie Ihre persönlichen Livestreams einbringen.
                </p>
            </div>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:2rem;margin:3rem 0">
                <div style="text-align:center">
                    <div style="font-size:3rem;margin-bottom:1rem">📹</div>
                    <h3 style="color:var(--swiss-red)">HD Streaming</h3>
                    <p style="color:var(--text-secondary)">1080p Qualität</p>
                </div>
                <div style="text-align:center">
                    <div style="font-size:3rem;margin-bottom:1rem">🌍</div>
                    <h3 style="color:var(--swiss-red)">Weltweiter Zugriff</h3>
                    <p style="color:var(--text-secondary)">24/7 verfügbar</p>
                </div>
                <div style="text-align:center">
                    <div style="font-size:3rem;margin-bottom:1rem">👥</div>
                    <h3 style="color:var(--swiss-red)">Community</h3>
                    <p style="color:var(--text-secondary)">Tausende Zuschauer</p>
                </div>
            </div>
            <button class="swiss-btn" style="font-size:1.2rem;padding:1rem 3rem" onclick="window.location.href='mailto:admin@aurora-webcam.ch?subject=Webcam%20Community%20Beitritt'">
                Jetzt mitmachen →
            </button>
        </div>
    </div>
</div>


        <div class="comments-section" id="commentsSection">
            <div class="comment-form">
                <h3><?php echo $t->t('comment');?></h3>
                <div class="form-group">
                    <label><?php echo $t->t('name');?>:</label><input type="text" id="commentName" maxlength="50" />
                </div>
                <div class="form-group">
                    <label><?php echo $t->t('rating');?>:</label>
                    <div class="rating-stars" id="ratingStars">
                        <span class="star" data-rating="1">★</span><span class="star" data-rating="2">★</span><span class="star" data-rating="3">★</span><span class="star" data-rating="4">★</span><span class="star" data-rating="5">★</span>
                    </div>
                </div>
                <div class="form-group">
                    <label><?php echo $t->t('comment');?>:</label><textarea id="commentText" rows="3" maxlength="500"></textarea>
                </div>
                <button class="swiss-btn" id="submitCommentBtn"><?php echo $t->t('submit');?></button>
            </div>
            <div class="comment-list">
                <h3><?php echo $t->t('comments');?></h3>
                <div id="commentsList"></div>
            </div>
        </div>
        <div class="action-grid" id="actionGrid">
            <button class="action-card" data-action="timelapse">
                <span class="action-icon">🎬</span>
                <?php echo $t->t('timelapse');?>
            </button>
            <a href="?download_video=1" class="action-card">
                <span class="action-icon">📥</span>
                <?php echo $t->t('download');?>
            </a>
            <button class="action-card" data-action="calendar">
                <span class="action-icon">📅</span>
                <?php echo $t->t('archive');?>
            </button>
            <button class="action-card" data-action="screenshot">
                <span class="action-icon">📸</span>
                <?php echo $t->t('screenshot');?>
            </button>
            <button class="action-card" data-action="gallery">
                <span class="action-icon">🖼️</span>
                <?php echo $t->t('gallery');?>
            </button>
            <button class="action-card" data-action="fullscreen">
                <span class="action-icon">🖥️</span>
                <?php echo $t->t('fullscreen');?>
            </button>


                    <!-- Nach den anderen action-cards in der action-grid -->
        <button class="action-card" data-action="qrcode">
            <span class="action-icon">📱</span>
            <?php echo $t->t('qrcode'); ?>
        </button>

        </div>
        <div class="overlay" id="overlay"></div>
        <div class="calendar-modal" id="calendarModal">
            <button class="modal-close" id="calendarClose">×</button>
            <h2><?php echo $t->t('archive');?></h2>
            <div class="calendar-header">
                <div class="calendar-nav"><button id="prevMonth">←</button><span id="currentMonth"></span><button id="nextMonth">→</button></div>
            </div>
            <div class="calendar-weekdays">
                <div>Mo</div>
                <div>Di</div>
                <div>Mi</div>
                <div>Do</div>
                <div>Fr</div>
                <div>Sa</div>
                <div>So</div>
            </div>
            <div class="calendar-grid" id="calendarGrid"></div>
            <div class="video-list" id="videoList"></div>
        </div>


<!-- Nach </div> vom calendar-modal -->
<div class="qr-modal" id="qrModal" style="display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--bg-secondary);backdrop-filter:blur(20px);padding:2rem;z-index:2000;border:2px solid var(--swiss-red);border-radius:1rem;text-align:center">
    <button class="modal-close" onclick="closeModals()">×</button>
    <h2>QR-Code - Mobile Access</h2>
    <div id="qrcode" style="margin:20px auto;width:256px;height:256px;background:white;padding:20px;border-radius:10px"></div>
    <p style="color:var(--text-primary);margin-top:1rem">Scannen Sie den Code mit Ihrem Smartphone</p>
    <input type="text" id="qrUrl" readonly style="width:100%;padding:0.5rem;margin-top:1rem;background:var(--surface);border:1px solid var(--swiss-border);color:var(--text-primary);border-radius:5px">
    <button class="swiss-btn" onclick="copyQrUrl()" style="margin-top:1rem">URL kopieren</button>
</div>




        <div class="rules-modal" id="rulesModal">
            <button class="modal-close" id="rulesClose">×</button>
            <h2><?php echo $t->t('rules');?></h2>
            <div class="rules-content">
                <div class="rules-section">
                    <h3>⚠️ Verhaltensregeln:</h3>
                    <ul>
                        <li>Keine sexuellen oder pornografischen Inhalte</li>
                        <li>Keine Gewalt oder Drohungen</li>
                        <li>Kein Rassismus oder Diskriminierung</li>
                        <li>Keine persönlichen Daten teilen</li>
                        <li>Keine Werbung oder Spam</li>
                        <li>Respektvoller Umgang</li>
                    </ul>
                </div>
                <div class="rules-section"> 
                    <h3>📸 Webcam-Nutzung:</h3>
                    <p>Die Webcam zeigt öffentlichen Raum. Die Nutzung erfolgt auf eigene Verantwortung.</p>
                </div>
                <div class="rules-section">
                    <h3>💬 Chat-Nutzung:</h3>
                    <p>Mit der Nutzung akzeptieren Sie diese Regeln. Verstöße führen zur Sperrung.</p>
                </div>
            </div>
            <div class="rules-actions">
                <button class="swiss-btn" id="acceptRulesBtn"><?php echo $t->t('accept');?></button><button class="swiss-btn" id="declineRulesBtn"><?php echo $t->t('decline');?></button>
            </div>
        </div>
        <footer class="footer">
            <div class="footer-content">
                <div class="footer-links">
                    <a href="#" id="rulesLink"><?php echo $t->t('rules');?></a><a href="mailto:admin@aurora-webcam.ch"><?php echo $t->t('contact');?></a><a href="mailto:abuse@aurora-webcam.ch"><?php echo $t->t('abuse');?></a>
                </div>
                <div class="swiss-quality"><span class="swiss-flag" style="width: 20px; height: 20px;"></span><span>Swiss Quality Webcam</span></div>
                <div class="copyright">© 2025 Aurora Webcam - Schweiz 🇨🇭 | Präzision und Qualität seit 1291</div>
            </div>
        </footer>
        <script>
            const images=<?php echo $webcam->getImageFiles();?>;let timelapseInterval=null;let currentImageIndex=0;let chatUser=localStorage.getItem('chatUser')||'Gast'+Math.floor(Math.random()*1000);
            let currentMonth=new Date().getMonth();let currentYear=new Date().getFullYear();let currentRating=5;
            let galleryImages=[];const bannedWords=['sex','porn','xxx'];
            const monthNames={'de':['Januar','Februar','März','April','Mai','Juni','Juli','August','September','Oktober','November','Dezember'],'fr':['Janvier','Février','Mars','Avril','Mai','Juin','Juillet','Août','Septembre','Octobre','Novembre','Décembre'],'it':['Gennaio','Febbraio','Marzo','Aprile','Maggio','Giugno','Luglio','Agosto','Settembre','Ottobre','Novembre','Dicembre'],'en':['January','February','March','April','May','June','July','August','September','October','November','December'],'zh':['一月','二月','三月','四月','五月','六月','七月','八月','九月','十月','十一月','十二月']};window.onerror=function(msg,url,lineNo,columnNo,error){console.error('Error:',msg,'\nLine:',lineNo);return false;};function setLang(lang){window.location.href='?lang='+lang;}function toggleTheme(){document.body.classList.toggle('light');localStorage.setItem('theme',document.body.classList.contains('light')?'light':'dark');}
            
            function showSection(section){document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
                const activeBtn=document.querySelector(`.nav-btn[data-section="${section}"]`);if(activeBtn)activeBtn.classList.add('active');
                document.getElementById('mainSection').style.display=(section==='comments'||section==='gallery')?'none':'grid';
                document.getElementById('commentsSection').style.display=section==='comments'?'block':'none';
                document.getElementById('gallerySection').style.display=section==='gallery'?'block':'none';

                document.getElementById('communitySection').style.display = section === 'community' ? 'block' : 'none';
                switch(section){case'timelapse':toggleTimelapse();break;case'archive':showCalendar();
                    break;
                    case'comments':loadComments();
                    break;

case 'community':
    // Optional: Statistiken laden
    break;

                    case'gallery':loadGallery();break;}}
                    function toggleTimelapse(){const viewer=document.getElementById('timelapseViewer');const player=document.getElementById('webcamPlayer');if(viewer.style.display==='none'||!viewer.style.display){viewer.style.display='block';player.style.display='none';
                        startTimelapse();}else{viewer.style.display='none';player.style.display='block';stopTimelapse();}}
                    
                    
                    // Cache-Variablen global definieren
const imageCache = new Map();
const preloadBuffer = 5;

async function startTimelapse() {
    console.log("startTimelapse wurde aufgerufen");
    if (images.length === 0) {
        alert('Keine Bilder vorhanden');
        return;
    }
    
    const displayDuration = 500; // 500ms wie im alten Code für bessere Sichtbarkeit
    console.log(`Anzeigedauer pro Bild: ${displayDuration} ms`);
    
    // Graufilter-Funktion aus dem alten Code
    function isGreyImage(imageData) {
        const data = imageData.data;
        const tolerance = 10;  
        const sampleSize = Math.min(data.length / 4, 1000);
        
        for (let i = 0; i < sampleSize; i++) {
            const index = i * 4;
            const r = data[index];
            const g = data[index + 1];
            const b = data[index + 2];
            
            if (Math.abs(r - g) > tolerance || Math.abs(r - b) > tolerance || Math.abs(g - b) > tolerance) {
                return false; // Nicht grau
            }
        }
        return true; // Grau
    }
    
    // getImageData Funktion für Caching
    function getImageData(src) {
        return new Promise((resolve, reject) => {
            if (imageCache.has(src)) {
                resolve(imageCache.get(src));
            } else {
                const img = new Image();
                img.crossOrigin = "Anonymous";
                img.onload = function() {
                    const canvas = document.createElement('canvas');
                    canvas.width = this.width;
                    canvas.height = this.height;
                    const ctx = canvas.getContext('2d');
                    ctx.drawImage(this, 0, 0);
                    const imageData = ctx.getImageData(0, 0, this.width, this.height);
                    imageCache.set(src, imageData);
                    resolve(imageData);
                };
                img.onerror = reject;
                img.src = src;
            }
        });
    }
    
    async function showNextImage() {
        console.log(`Aktueller Bildindex: ${currentImageIndex}`);
        while (currentImageIndex < images.length) {
            const currentImage = images[currentImageIndex];
            console.log(`Verarbeite Bild: ${currentImage}`);
            
            // Lazy Loading - Bilder vorladen
            for (let i = currentImageIndex; i < currentImageIndex + preloadBuffer && i < images.length; i++) {
                if (!imageCache.has(images[i])) {
                    console.log(`Lade Bild in Cache: ${images[i]}`);
                    imageCache.set(images[i], getImageData(images[i]));
                }
            }
            
            try {
                const imageData = await imageCache.get(currentImage);
                if (!isGreyImage(imageData)) {
                    console.log(`Zeige Bild an: ${currentImage}`);
                    document.getElementById('timelapseImage').src = currentImage;
                    currentImageIndex++;
                    
                    // Cache-Bereinigung
                    if (imageCache.size > preloadBuffer * 2) {
                        console.log("Führe Cache-Bereinigung durch");
                        const keysToDelete = Array.from(imageCache.keys()).slice(0, imageCache.size - preloadBuffer);
                        keysToDelete.forEach(key => imageCache.delete(key));
                    }
                    
                    await new Promise(resolve => setTimeout(resolve, displayDuration));
                    return;
                } else {
                    console.log(`Überspringe graues Bild: ${currentImage}`);
                }
            } catch (error) {
                console.error(`Fehler beim Verarbeiten des Bildes ${currentImage}:`, error);
            }
            currentImageIndex++;
        }
        console.log("Alle Bilder durchlaufen, setze Index zurück");
        currentImageIndex = 0;
    }
    
    async function runTimelapse() {
        console.log("runTimelapse gestartet");
        const viewer = document.getElementById('timelapseViewer');
        while (viewer && viewer.style.display !== 'none') {
            await showNextImage();
        }
        console.log("Zeitraffer beendet");
    }
    
    runTimelapse().catch(error => console.error("Fehler im Zeitraffer:", error));
}

 

function stopTimelapse() {
    currentImageIndex = 0;
    imageCache.clear(); // Cache leeren beim Stoppen
}

function playTimelapse() {
    startTimelapse();
}

                    
                   
                    








                function pauseTimelapse(){clearInterval(timelapseInterval);

                } 
                
                function playTimelapse(){startTimelapse();}
                
                function sendMessage(){const input=document.getElementById('chatInput');const msg=input.value.trim();if(!msg||!filterMessage(msg)){if(!filterMessage(msg))alert('Nachricht enthält unzulässige Inhalte');return;}fetch('',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'chat_user='+encodeURIComponent(chatUser)+'&chat_message='+encodeURIComponent(msg)}).then(()=>{input.value='';loadMessages();});}function filterMessage(msg){const lower=msg.toLowerCase();return!bannedWords.some(word=>lower.includes(word));}function loadMessages(){fetch('?get_messages=1').then(r=>r.json()).then(messages=>{const container=document.getElementById('chatMessages');container.innerHTML=messages.map(m=>`<div class="chat-message"><strong>${m.user}:</strong> ${m.message}<div style="font-size:0.75rem;color:var(--text-secondary);margin-top:0.25rem">${new Date(m.time*1000).toLocaleTimeString()}</div></div>`).join('');container.scrollTop=container.scrollHeight;document.getElementById('onlineCount').textContent='👥 '+Math.floor(Math.random()*10+5);});}function addComment(){const name=document.getElementById('commentName').value.trim()||'Anonym';const text=document.getElementById('commentText').value.trim();if(!text){alert('Bitte Kommentar eingeben');return;}fetch('',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'add_comment=1&comment_name='+encodeURIComponent(name)+'&comment_text='+encodeURIComponent(text)+'&rating='+currentRating}).then(()=>{document.getElementById('commentName').value='';document.getElementById('commentText').value='';currentRating=5;updateStars();loadComments();});}function loadComments(){fetch('?get_comments=1').then(r=>r.json()).then(comments=>{const container=document.getElementById('commentsList');container.innerHTML=comments.map(c=>`<div class="comment-item"><div class="comment-header"><span class="comment-name">${c.name}</span><span class="comment-rating">${'★'.repeat(c.rating)}</span></div><div class="comment-text">${c.comment}</div><div class="comment-time">${new Date(c.time*1000).toLocaleDateString()}</div></div>`).join('');});}function updateStars(){document.querySelectorAll('.star').forEach((star,index)=>{star.classList.toggle('active',index<currentRating);});}function loadGallery(){fetch('?get_gallery=1').then(r=>r.json()).then(images=>{galleryImages=images;const grid=document.getElementById('galleryGrid');grid.innerHTML=images.map((img,idx)=>`<div class="gallery-item" data-index="${idx}"><img src="${img.thumb||img.src}" alt=""><div class="gallery-date">${new Date(img.date*1000).toLocaleDateString()}</div></div>`).join('');});}function openLightbox(index){const img=galleryImages[index];if(!img)return;const lightbox=document.createElement('div');lightbox.style.cssText='position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.9);z-index:5000;display:flex;align-items:center;justify-content:center';lightbox.innerHTML=`<img src="${img.src}" style="max-width:90%;max-height:90%;object-fit:contain"><button onclick="this.parentElement.remove()" style="position:absolute;top:20px;right:20px;background:var(--swiss-red);color:white;border:none;padding:10px 20px;cursor:pointer;font-size:24px">×</button>`;document.body.appendChild(lightbox);}function showCalendar(){document.getElementById('calendarModal').style.display='block';document.getElementById('overlay').style.display='block';updateCalendar();}function updateCalendar(){const lang='<?php echo $lang;?>';const months=monthNames[lang]||monthNames['de'];document.getElementById('currentMonth').textContent=months[currentMonth]+' '+currentYear;fetch(`?get_calendar_videos=1&month=${currentMonth+1}&year=${currentYear}`).then(r=>r.json()).then(videos=>{const firstDay=new Date(currentYear,currentMonth,1).getDay();const daysInMonth=new Date(currentYear,currentMonth+1,0).getDate();const daysInPrevMonth=new Date(currentYear,currentMonth,0).getDate();const grid=document.getElementById('calendarGrid');grid.innerHTML='';const startDay=(firstDay||7)-1;for(let i=startDay;i>0;i--){const day=daysInPrevMonth-i+1;grid.innerHTML+=`<div class="cal-day other-month">${day}</div>`;}const today=new Date();for(let day=1;day<=daysInMonth;day++){const hasVideo=videos[day]&&videos[day].length>0;const isToday=today.getDate()===day&&today.getMonth()===currentMonth&&today.getFullYear()===currentYear;const dayEl=document.createElement('div');dayEl.className=`cal-day${hasVideo?' has-video':''}${isToday?' today':''}`;dayEl.textContent=day;if(hasVideo)dayEl.setAttribute('data-videos',JSON.stringify(videos[day]));grid.appendChild(dayEl);}const remainingDays=42-(startDay+daysInMonth);for(let day=1;day<=remainingDays;day++){grid.innerHTML+=`<div class="cal-day other-month">${day}</div>`;}});}function changeMonth(delta){currentMonth+=delta;if(currentMonth<0){currentMonth=11;currentYear--;}else if(currentMonth>11){currentMonth=0;currentYear++;}updateCalendar();}function showDayVideos(day,videos){const list=document.getElementById('videoList');list.innerHTML=`<h3>Videos vom ${day}.${currentMonth+1}.${currentYear}</h3>`;if(!videos||videos.length===0){list.innerHTML+='<p>Keine Videos vorhanden</p>';return;}videos.forEach(video=>{const filename=video.split('/').pop();const time=filename.match(/\d{6}(?=\.mp4)/);const timeStr=time?time[0].replace(/(\d{2})(\d{2})(\d{2})/,'$1:$2:$3'):'';list.innerHTML+=`<div class="video-item"><span>📹 ${timeStr}</span><a href="${video}" download>Download</a></div>`;});list.style.display='block';}function closeModals(){document.querySelectorAll('.calendar-modal,.rules-modal').forEach(m=>m.style.display='none');document.getElementById('overlay').style.display='none';}function showRules(){document.getElementById('rulesModal').style.display='block';document.getElementById('overlay').style.display='block';}function acceptRules(){localStorage.setItem('rulesAccepted','true');closeModals();document.getElementById('chatInput').disabled=false;}function declineRules(){closeModals();document.getElementById('chatInput').disabled=true;}function checkRules(){if(!localStorage.getItem('rulesAccepted')){showRules();document.getElementById('chatInput').disabled=true;}}
                

              function takeScreenshot() {
    const canvas = document.createElement('canvas');
    const video = document.getElementById('webcamPlayer');
    
    canvas.width = video.videoWidth || 1920;
    canvas.height = video.videoHeight || 1080;
    canvas.getContext('2d').drawImage(video, 0, 0);
    
    canvas.toBlob(blob => {
        // 1. Lokaler Download
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'snapshot_' + Date.now() + '.jpg';
        a.click();
        
        // 2. Server-Upload für Galerie
        const formData = new FormData();
        formData.append('screenshot', blob);
        formData.append('action', 'upload_screenshot');
        
        fetch('', {
            method: 'POST',
            body: formData
        }).then(response => response.json())
        .then(data => {
            if (data.success) {
                console.log('Screenshot in Galerie gespeichert');
                // Galerie aktualisieren wenn sichtbar
                if (document.getElementById('gallerySection').style.display !== 'none') {
                    loadGallery();
                }
            }
        });
    }, 'image/jpeg', 0.95);
}









function toggleFullscreen() {
    if (!document.fullscreenElement) document.documentElement.requestFullscreen();
    else document.exitFullscreen();
}
window.addEventListener(
    "DOMContentLoaded",

    function () {
        if (localStorage.getItem("theme") === "light") document.body.classList.add("light");
        if (typeof Hls !== "undefined" && Hls.isSupported()) {
            const video = document.getElementById("webcamPlayer");
            const hls = new Hls();
            hls.loadSource("/test_video.m3u8");
            hls.attachMedia(video);
        }
        document.querySelectorAll(".nav-btn").forEach((btn) => {
            btn.addEventListener("click", function (e) {
                e.preventDefault();
                const section = this.getAttribute("data-section");
                showSection(section);
            });
        });
        document.querySelectorAll(".lang-btn").forEach((btn) => {
            btn.addEventListener("click", function () {
                const lang = this.getAttribute("data-lang");
                setLang(lang);
            });
        });
        document.querySelectorAll(".action-card[data-action]").forEach((card) => {
            card.addEventListener("click", function (e) {
                e.preventDefault();

                const action = this.getAttribute("data-action");

                switch (action) {
                    case "timelapse":
                        toggleTimelapse();
                        break;

                    case "qrcode":
                        showQRCode();
                        break;
                    case "calendar":
                        showCalendar();
                        break;
                    case "screenshot":
                        takeScreenshot();
                        break;
                    case "gallery":
                        showSection("gallery");
                        break;
                    case "fullscreen":
                        toggleFullscreen();
                        break;
                }
            });
        });
        document.getElementById("themeToggle").addEventListener("click", toggleTheme);
        document.getElementById("sendBtn").addEventListener("click", sendMessage);
        document.getElementById("chatInput").addEventListener("keypress", function (e) {
            if (e.key === "Enter") sendMessage();
        });
        document.getElementById("submitCommentBtn").addEventListener("click", addComment);
        document.querySelectorAll(".star").forEach((star) => {
            star.addEventListener("click", function () {
                currentRating = parseInt(this.dataset.rating);
                updateStars();
            });
        });
        document.getElementById("playBtn").addEventListener("click", playTimelapse);
        document.getElementById("pauseBtn").addEventListener("click", pauseTimelapse);
        document.getElementById("stopBtn").addEventListener("click", stopTimelapse);
        document.getElementById("prevMonth").addEventListener("click", () => changeMonth(-1));
        document.getElementById("nextMonth").addEventListener("click", () => changeMonth(1));
        document.getElementById("calendarClose").addEventListener("click", closeModals);
        document.getElementById("rulesClose").addEventListener("click", closeModals);
        document.getElementById("overlay").addEventListener("click", closeModals);
        document.getElementById("acceptRulesBtn").addEventListener("click", acceptRules);
        document.getElementById("declineRulesBtn").addEventListener("click", declineRules);
        document.getElementById("rulesLink").addEventListener("click", function (e) {
            e.preventDefault();
            showRules();
        });
        document.addEventListener("click", function (e) {
            if (e.target.closest(".gallery-item")) {
                const index = e.target.closest(".gallery-item").getAttribute("data-index");
                if (index) openLightbox(parseInt(index));
            }
            if (e.target.closest(".cal-day.has-video")) {
                const videos = JSON.parse(e.target.closest(".cal-day").getAttribute("data-videos") || "[]");
                const day = e.target.closest(".cal-day").textContent;
                if (videos.length > 0) showDayVideos(day, videos);
            }
        });
        checkRules();
        loadMessages();
        setInterval(loadMessages, 5000);
        updateStars();
        console.log("%c🇨🇭 Aurora Webcam", "color:#ff0000;font-size:24px;font-weight:bold");
        console.log("%cSwiss Quality Since 1291", "color:#333;font-size:14px");
    }
);

// Nach den anderen Funktionen
let qrCodeInstance = null;


function showQRCode() {
    document.getElementById('qrModal').style.display = 'block';
    document.getElementById('overlay').style.display = 'block';
    
    const currentUrl = window.location.href;
    document.getElementById('qrUrl').value = currentUrl;
    
    // QR-Code generieren
    const qrContainer = document.getElementById('qrcode');
    qrContainer.innerHTML = ''; // Clear previous QR code
    
    qrCodeInstance = new QRCode(qrContainer, {
        text: currentUrl,
        width: 256,
        height: 256,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.H
    });
}

function copyQrUrl() {
    const urlInput = document.getElementById('qrUrl');
    urlInput.select();
    document.execCommand('copy');
    alert('URL kopiert!');
}

// In closeModals() Funktion erweitern
function closeModals() {
    document.querySelectorAll('.calendar-modal,.rules-modal,.qr-modal').forEach(m => m.style.display = 'none');
    document.getElementById('overlay').style.display = 'none';
}

     
     </script>
    </body>
</html>
