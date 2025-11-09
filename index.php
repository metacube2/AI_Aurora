<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require __DIR__ . '/vendor/autoload.php';

if (isset($_GET['download_video'])) {
    $videoDir = './videos/';
    $latestVideo = null;
    $latestTime = 0;

    // Finde das neueste Video
    foreach (glob($videoDir . '*.mp4') as $video) {
        $mtime = filemtime($video);
        if ($mtime > $latestTime) {
            $latestTime = $mtime;
            $latestVideo = $video;
        }
    }

    if ($latestVideo) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($latestVideo).'"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($latestVideo));
        readfile($latestVideo);
        exit;
    } else {
        echo "Kein Video zum Herunterladen gefunden.";
        exit;
    }
}




// Funktion zur sicheren Umleitung
function safeRedirect($url) {
    if (!headers_sent()) {
        header("HTTP/1.1 301 Moved Permanently");
        header("Location: " . $url);
    } else {
        echo '<script>window.location.href="' . $url . '";</script>';
    }
    exit();
}

// Hauptlogik
$oldDomains = [
    'www.aurora-wetter-lifecam.ch',
    'www.aurora-wetter-livecam.ch'
];
$newDomain = 'www.aurora-weather-livecam.com';

if (in_array($_SERVER['HTTP_HOST'], $oldDomains)) {
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
    $newUrl = $protocol . '://' . $newDomain . $_SERVER['REQUEST_URI'];
    
    // Logging für Debugging
    error_log("Umleitung von {$_SERVER['HTTP_HOST']} nach $newUrl");
    
    if (!headers_sent()) {
        header("HTTP/1.1 301 Moved Permanently");
        header("Location: " . $newUrl);
    } else {
        echo '<script>window.location.href="' . $newUrl . '";</script>';
    }
    exit();
}



 

session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);
$imageDir = "./image"; // Angepasst an das Ausgabeverzeichnis des Bash-Skripts
$imageFiles = glob("$imageDir/screenshot_*.jpg");
rsort($imageFiles); // Sortiert die Dateien in umgekehrter Reihenfolge (neueste zuerst)
$imageFilesJson = json_encode($imageFiles);
 
class WebcamManager {

    private $videoSrc = 'test_video.m3u8';
    private $logoPath = 'logo.png';

 public function displayWebcam() {
    return '<video id="webcam-player" 
            autoplay 
            muted 
            playsinline 
            webkit-playsinline 
            x-webkit-airplay="allow"
            x5-video-player-type="h5"
            x5-video-player-fullscreen="true"
            style="width: 100%; height: 100%; object-fit: contain;">
        </video>';
}

	
	
    public function captureSnapshot() {
									
        $outputFile = 'snapshot_' . date('YmdHis') . '.jpg';
        $command = "ffmpeg -i {$this->videoSrc} -i {$this->logoPath} -filter_complex 'overlay=main_w-overlay_w-10:10' -vframes 1 -q:v 2 {$outputFile}";

        
        exec($command, $output, $returnVar);

        if ($returnVar !== 0) {
            return "Fehler beim Erstellen des Snapshots.";
        }

		// Kopieren des Snapshots in den Uploads-Ordner
        $uploadDir = "uploads/";
        if (!file_exists($uploadDir)) {
            mkdir($uploadDir, 0777, true);
        
        }
    
        $uploadFile = $uploadDir . $outputFile;
        if (copy($outputFile, $uploadFile)) {
            
        } else {
            
        }				   
							   
		 

        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $outputFile . '"');
        readfile($outputFile);
        unlink($outputFile);
        exit;
    }
// public function getImageFiles() {
//     // Nur JPG-Dateien aus uploads/, KEINE MP4-Dateien
//     $imageFiles = glob("uploads/*.{jpg,jpeg,png,gif}", GLOB_BRACE);
    
//     // Filtere unerwünschte Dateien aus
//     $imageFiles = array_filter($imageFiles, function($file) {
//         $basename = basename($file);
//         // Blockiere sequence_*.mp4 und andere unerwünschte Dateien
//         return pathinfo($file, PATHINFO_EXTENSION) !== 'mp4' && 
//                strpos($basename, 'sequence_') !== 0;
//     });
    
//     return json_encode(array_values($imageFiles));
// }
public function getImageFiles() {
    // Screenshots aus dem image/ Ordner holen
    $imageFiles = glob("image/screenshot_*.jpg");
    sort($imageFiles); // Neueste zuerst
    return json_encode($imageFiles);
}




    
    public function captureVideoSequence($duration = 10) {
        $outputFile = 'sequence_' . date('YmdHis') . '.mp4';
        $command = "ffmpeg -i {$this->videoSrc} -i {$this->logoPath} -filter_complex 'overlay=10:10' -t {$duration} -c:v libx264 -preset fast -crf 23 {$outputFile}";
        
        exec($command, $output, $returnVar);

        if ($returnVar !== 0) {
            return "Fehler beim Erstellen der Video-Sequenz.";
        }

						  // Kopieren des Videoclips in den Uploads-Ordner
    $uploadDir = "uploads/";
    if (!file_exists($uploadDir)) {
        mkdir($uploadDir, 0777, true);
        echo "Uploads-Ordner erstellt.<br>";
    }

    $uploadFile = $uploadDir . $outputFile;
    if (copy($outputFile, $uploadFile)) {
      
    } else {
        echo "Fehler beim Kopieren des Videoclips in den Uploads-Ordner.<br>";
    }
							   
		 

        header('Content-Type: video/mp4');
        header('Content-Disposition: attachment; filename="' . $outputFile . '"');
        readfile($outputFile);
        unlink($outputFile);
        exit;
    }
public function getJavaScript() {
    return "
    document.addEventListener('DOMContentLoaded', function () {
        var video = document.getElementById('webcam-player');
        var videoSrc = '{$this->videoSrc}';
        
        // Mobile Detection
        var isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
        var isIOS = /iPhone|iPad|iPod/i.test(navigator.userAgent);
        
        // Controls NUR auf Desktop verstecken
        video.controls = false;
        
        if (isIOS) {
            // iOS native HLS
            video.src = videoSrc;
            video.setAttribute('playsinline', '');
            video.setAttribute('webkit-playsinline', '');
            video.muted = true;
            
            video.addEventListener('loadedmetadata', function() {
                video.play().catch(function(e) {
                    console.log('iOS Autoplay blockiert');
                });
            });
            
        } else if (Hls.isSupported()) {
            var hls = new Hls({
                // Mobile-optimierte Einstellungen
                liveSyncDurationCount: isMobile ? 2 : 3,
                liveMaxLatencyDurationCount: isMobile ? 5 : 10,
                liveDurationInfinity: true,
                enableWorker: !isMobile,
                lowLatencyMode: false,
                backBufferLength: isMobile ? 30 : 90,
                maxBufferLength: isMobile ? 30 : 60,
                maxMaxBufferLength: isMobile ? 60 : 120,
                maxBufferSize: isMobile ? 60*1000*1000 : 120*1000*1000,
                
                // Mobile-spezifische Timeouts
                manifestLoadingTimeOut: isMobile ? 20000 : 10000,
                manifestLoadingMaxRetry: 8,
                levelLoadingTimeOut: isMobile ? 20000 : 10000,
                levelLoadingMaxRetry: 8,
                fragLoadingTimeOut: isMobile ? 20000 : 10000,
                fragLoadingMaxRetry: 8,
                
                // Qualität für Mobile
                startLevel: isMobile ? 0 : -1,
                abrEwmaDefaultEstimate: isMobile ? 500000 : 1000000
            });
            
            hls.loadSource(videoSrc);
            hls.attachMedia(video);
            
            hls.on(Hls.Events.MANIFEST_PARSED, function () {
                console.log('Stream geladen');
                
                if (isMobile) {
                    video.muted = true;
                }
                
                // Live-Position anpassen
                if (hls.liveSyncPosition !== null) {
                    var targetPosition = hls.liveSyncPosition - 60;
                    console.log('Setze Position auf: ' + targetPosition);
                    video.currentTime = targetPosition;
                }
                
                video.play().catch(function(e) {
                    console.log('Autoplay blockiert');
                });
            });
            
            // Fehlerbehandlung
            hls.on(Hls.Events.ERROR, function(event, data) {
                if (data.fatal) {
                    switch(data.type) {
                        case Hls.ErrorTypes.NETWORK_ERROR:
                            console.log('Netzwerkfehler - versuche erneut...');
                            setTimeout(function() {
                                hls.startLoad();
                            }, 3000);
                            break;
                        case Hls.ErrorTypes.MEDIA_ERROR:
                            console.log('Media-Fehler - Recovery...');
                            hls.recoverMediaError();
                            break;
                        default:
                            console.log('Kritischer Fehler - Neustart...');
                            hls.destroy();
                            location.reload();
                            break;
                    }
                }
            });
            
        } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
            // Fallback für andere Browser
            video.src = videoSrc;
            video.muted = true;
            video.addEventListener('loadedmetadata', function () {
                video.currentTime = Math.max(0, video.duration - 60);
                video.play();
            });
        }
    });
    ";
}







    public function setVideoSrc($src) {
        $this->videoSrc = $src;
    }
}










class VisualCalendarManager {
    private $videoDir;
    private $monthNames;
    
    public function __construct($videoDir = './videos/') {
        $this->videoDir = $videoDir;
        $this->monthNames = [
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
            12 => ['de' => 'Dezember', 'en' => 'December', 'it' => 'Dicembre', 'fr' => 'Décembre', 'zh' => '十二月']
        ];
    }
    
    public function getVideosForDate($year, $month, $day) {
        $videos = [];
        $dateStr = sprintf('%04d%02d%02d', $year, $month, $day);
        
        foreach (glob($this->videoDir . "daily_video_{$dateStr}_*.mp4") as $video) {
            $videos[] = [
                'path' => $video,
                'filename' => basename($video),
                'filesize' => filesize($video),
                'time' => date('H:i', filemtime($video))
            ];
        }
        
        return $videos;
    }
    
    public function hasVideosForDate($year, $month, $day) {
        $dateStr = sprintf('%04d%02d%02d', $year, $month, $day);
        $pattern = $this->videoDir . "daily_video_{$dateStr}_*.mp4";
        return count(glob($pattern)) > 0;
    }
    
    public function displayVisualCalendar() {
        $currentYear = isset($_GET['cal_year']) ? intval($_GET['cal_year']) : date('Y');
        $currentMonth = isset($_GET['cal_month']) ? intval($_GET['cal_month']) : date('n');
        $selectedDay = isset($_GET['cal_day']) ? intval($_GET['cal_day']) : null;
        
        $output = '<div class="visual-calendar-container">';
        
        // Navigation
        $output .= '<div class="calendar-navigation">';
        $output .= '<button onclick="changeMonth(' . $currentYear . ',' . ($currentMonth - 1) . ')" class="cal-nav-btn">◀</button>';
        $output .= '<h3>' . $this->monthNames[$currentMonth]['de'] . ' ' . $currentYear . '</h3>';
        $output .= '<button onclick="changeMonth(' . $currentYear . ',' . ($currentMonth + 1) . ')" class="cal-nav-btn">▶</button>';
        $output .= '</div>';
        
        // Kalender-Grid
        $output .= '<div class="calendar-grid">';
        
        // Wochentage Header
        $weekdays = ['Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa', 'So'];
        foreach ($weekdays as $day) {
            $output .= '<div class="calendar-weekday">' . $day . '</div>';
        }
        
        // Tage des Monats
        $firstDay = mktime(0, 0, 0, $currentMonth, 1, $currentYear);
        $daysInMonth = date('t', $firstDay);
        $dayOfWeek = date('N', $firstDay) - 1; // 0 = Montag
        
        // Leere Zellen vor dem ersten Tag
        for ($i = 0; $i < $dayOfWeek; $i++) {
            $output .= '<div class="calendar-day empty"></div>';
        }
        
        // Tage mit Videos markieren
        for ($day = 1; $day <= $daysInMonth; $day++) {
            $hasVideos = $this->hasVideosForDate($currentYear, $currentMonth, $day);
            $isSelected = ($selectedDay == $day);
            $isToday = ($currentYear == date('Y') && $currentMonth == date('n') && $day == date('j'));
            
            $classes = 'calendar-day';
            if ($hasVideos) $classes .= ' has-video';
            if ($isSelected) $classes .= ' selected';
            if ($isToday) $classes .= ' today';
            
            $output .= '<div class="' . $classes . '" onclick="selectDay(' . $currentYear . ',' . $currentMonth . ',' . $day . ')">';
            $output .= '<span class="day-number">' . $day . '</span>';
            if ($hasVideos) {
                $output .= '<span class="video-indicator">📹</span>';
            }
            $output .= '</div>';
        }
        
        $output .= '</div>'; // calendar-grid
        
        // Video-Liste für ausgewählten Tag
        if ($selectedDay) {
            $videos = $this->getVideosForDate($currentYear, $currentMonth, $selectedDay);
            if (!empty($videos)) {
                $output .= '<div class="day-videos">';
                $output .= '<h4>Videos vom ' . sprintf('%02d.%02d.%04d', $selectedDay, $currentMonth, $currentYear) . '</h4>';
                $output .= '<ul class="video-download-list">';
                
                foreach ($videos as $video) {
                    $sizeInMb = round($video['filesize'] / (1024 * 1024), 2);
                    $token = hash_hmac('sha256', $video['path'], session_id());
                    
                    $output .= '<li>';
                    $output .= '<span class="video-time">🕐 ' . $video['time'] . ' Uhr</span>';
                    $output .= '<span class="video-size">' . $sizeInMb . ' MB</span>';
                    $output .= '<a href="?download_specific_video=' . urlencode($video['path']) . '&token=' . $token . '" class="download-link">';
                    $output .= '⬇️ Download';
                    $output .= '</a>';
                    $output .= '</li>';
                }
                
                $output .= '</ul>';
                $output .= '</div>';
            } else {
                $output .= '<div class="no-videos">Keine Videos für diesen Tag verfügbar.</div>';
            }
        }
        
        $output .= '</div>'; // visual-calendar-container
        
        return $output;
    }
}



























class GuestbookManager {
    private $entries = [];
    private $dbFile = 'guestbook.json';

    public function __construct() {
        if (file_exists($this->dbFile)) {
            $this->entries = json_decode(file_get_contents($this->dbFile), true);
        }
    }

    public function handleFormSubmission() {
        if (isset($_POST['guestbook'], $_POST['guest-name'], $_POST['guest-message'])) {
            $this->addEntry($_POST['guest-name'], $_POST['guest-message']);
            $this->saveEntries();
        }
    }

    private function addEntry($name, $message) {
        $this->entries[] = [
            'name' => $name,
            'message' => $message,
            'date' => date('Y-m-d H:i:s')
        ];
    }

    public function deleteEntry($index) {
        if (isset($this->entries[$index])) {
            unset($this->entries[$index]);
            $this->entries = array_values($this->entries); // Re-indizieren des Arrays
            $this->saveEntries();
            return true;
        }
        return false;
    }
    


    private function saveEntries() {
        file_put_contents($this->dbFile, json_encode($this->entries));
    }

    public function displayForm() {
        return '
        <form method="post">
            <input type="hidden" name="guestbook" value="1">

          <label for="guest-name" 
       data-en="Name:" 
       data-de="Name:" 
       data-it="Nome:"   data-zh="姓名：
       data-fr="Nom:">
    Name:
</label>
<input type="text" id="guest-name" name="guest-name" required>
<label for="guest-message" 
       data-en="Message:" 
       data-de="Nachricht:" 
       data-it="Messaggio:" 
       data-fr="Message:">
    Nachricht:
</label>
<textarea id="guest-message" name="guest-message" required></textarea>
<button type="submit" 
        data-en="Add Entry" 
        data-de="Eintrag hinzufügen" 
        data-it="Aggiungi Voce" 
        data-fr="Ajouter une entrée">
    Eintrag hinzufügen
</button>

        </form>';
    }
public function displayEntries($isAdmin = false) {
    $output = '<div id="guestbook-entries">';
    foreach ($this->entries as $index => $entry) {
        $output .= "
        <div class='guestbook-entry'>
            <h4><i class='fas fa-user'></i> {$entry['name']}</h4>
            <p><i class='fas fa-comment'></i> {$entry['message']}</p>
            <small><i class='fas fa-clock'></i> {$entry['date']}</small>";
            if ($isAdmin) {
                $output .= "<form method='post' style='display:inline;'>
                    <input type='hidden' name='action' value='delete_guestbook'>
                    <input type='hidden' name='delete_entry' value='{$index}'>
                    <button type='submit' class='delete-btn'>Löschen</button>
                </form>";
            }
            
    }
    $output .= '</div>';
    return $output;
}

    
}


class ContactManager {
    //private $adminEmail = 'ingo.kohler.zh@gmail.com';  // ← Empfänger
    private $adminEmail = 'metacube@gmail.com';  // ← Empfänger
    private $feedbackFile = 'feedbacks.json';
    private $gmailUser = 'metacube@gmail.com';  // ← DEINE GMAIL-ADRESSE
    private $gmailAppPassword = 'qggk hsxz fdkq jgxa';  // ← APP-PASSWORT VON GMAIL
    
    public function displayForm() {
        return '
        <form method="post" id="contact-form">
            <input type="hidden" name="contact" value="1">
            <label for="name" 
                   data-en="Name:" 
                   data-de="Name:" 
                   data-it="Nome:" 
                   data-fr="Nom:"
                   data-zh="姓名：">
                Name:
            </label>
            <input type="text" id="name" name="name" required minlength="2">
            
            <label for="email" 
                   data-en="E-Mail:" 
                   data-de="E-Mail:" 
                   data-it="Email:" 
                   data-fr="E-mail:"
                   data-zh="电子邮件：">
                E-Mail:
            </label>
            <input type="email" id="email" name="email" required>
            
            <label for="message" 
                   data-en="Message:" 
                   data-de="Nachricht:" 
                   data-it="Messaggio:" 
                   data-fr="Message:"
                   data-zh="消息：">
                Nachricht:
            </label>
            <textarea id="message" name="message" required minlength="10"></textarea>
            
            <button type="submit" 
                    data-en="Send Message" 
                    data-de="Nachricht senden" 
                    data-it="Invia Messaggio" 
                    data-fr="Envoyer le message"
                    data-zh="发送消息">
                Nachricht senden
            </button>
        </form>
        <div id="contact-feedback" style="margin-top: 15px;"></div>';
    }

    public function handleSubmission($name, $email, $message) {
        // Validierung
        if (empty($name) || empty($email) || empty($message)) {
            return [
                'success' => false, 
                'message' => 'Alle Felder sind erforderlich'
            ];
        }
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return [
                'success' => false, 
                'message' => 'Ungültige E-Mail-Adresse'
            ];
        }
        
        if (strlen($message) < 10) {
            return [
                'success' => false, 
                'message' => 'Nachricht zu kurz (mindestens 10 Zeichen)'
            ];
        }
        
        // Sanitize
        $name = htmlspecialchars(trim($name), ENT_QUOTES, 'UTF-8');
        $email = filter_var(trim($email), FILTER_SANITIZE_EMAIL);
        $message = htmlspecialchars(trim($message), ENT_QUOTES, 'UTF-8');
        
        // Feedback speichern
        $feedback = [
            'name' => $name,
            'email' => $email,
            'message' => $message,
            'date' => date('Y-m-d H:i:s'),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ];
        
        $feedbacks = file_exists($this->feedbackFile) 
            ? json_decode(file_get_contents($this->feedbackFile), true) 
            : [];
        
        if (!is_array($feedbacks)) {
            $feedbacks = [];
        }
        
        $feedbacks[] = $feedback;
        file_put_contents($this->feedbackFile, json_encode($feedbacks, JSON_PRETTY_PRINT));
        
        // E-MAIL SENDEN MIT GMAIL SMTP
        $mailSent = $this->sendEmailViaGmail($name, $email, $message, $feedback['date'], $feedback['ip']);
        
        if ($mailSent) {
            return [
                'success' => true, 
                'message' => 'Vielen Dank! Ihre Nachricht wurde gesendet.'
            ];
        } else {
            error_log("Mail-Fehler: Nachricht von {$email} konnte nicht gesendet werden");
            return [
                'success' => false, 
                'message' => 'Nachricht wurde gespeichert, aber E-Mail konnte nicht gesendet werden.'
            ];
        }
    }
    
    private function sendEmailViaGmail($name, $email, $message, $date, $ip) {
        $mail = new PHPMailer(true);
        

    try {
            // DEBUG-MODUS AKTIVIEREN
            $mail->SMTPDebug = 2;
            $mail->Debugoutput = function($str, $level) {
                error_log("PHPMailer Debug: $str");
            };
            
            // SMTP Konfiguration
            $mail->isSMTP();
            $mail->Host = 'smtp.gmail.com';
            $mail->SMTPAuth = true;
            $mail->Username = $this->gmailUser;  // metacube@gmail.com
            $mail->Password = $this->gmailAppPassword;  // qggk hsxz fdkq jgxa
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = 587;


 
            
            // Absender & Empfänger
            $mail->setFrom($this->gmailUser, 'Aurora Livecam');
            $mail->addAddress($this->adminEmail);  // admin@aurora-live-weathercam.com
            $mail->addReplyTo($email, $name);
            
            // Inhalt
            $mail->isHTML(true);
            $mail->CharSet = 'UTF-8';
            $mail->Subject = '🔔 Neue Kontaktanfrage von ' . $name;
            $mail->Body = $this->getEmailTemplate($name, $email, $message, $date, $ip);
            
            $mail->send();
            return true;
        } catch (Exception $e) {
            error_log("PHPMailer Error: {$mail->ErrorInfo}");
            return false;
        }
    }
    
    private function getEmailTemplate($name, $email, $message, $date, $ip) {
        return "
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset='UTF-8'>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    line-height: 1.6; 
                    color: #333;
                    background-color: #f4f4f4;
                    margin: 0;
                    padding: 0;
                }
                .container { 
                    max-width: 600px; 
                    margin: 20px auto; 
                    background: white;
                    border-radius: 10px;
                    overflow: hidden;
                    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                }
                .header { 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    color: white; 
                    padding: 30px 20px; 
                    text-align: center;
                }
                .header h2 {
                    margin: 0;
                    font-size: 24px;
                }
                .content { 
                    padding: 30px 20px;
                }
                .info-box {
                    background: #f9f9f9;
                    border-left: 4px solid #667eea;
                    padding: 15px;
                    margin: 15px 0;
                    border-radius: 5px;
                }
                .info-box strong {
                    color: #667eea;
                    display: block;
                    margin-bottom: 5px;
                }
                .message-box {
                    background: white;
                    border: 1px solid #e0e0e0;
                    padding: 20px;
                    margin: 20px 0;
                    border-radius: 5px;
                    line-height: 1.8;
                }
                .footer { 
                    background: #f9f9f9;
                    padding: 20px; 
                    text-align: center;
                    font-size: 12px; 
                    color: #999;
                    border-top: 1px solid #e0e0e0;
                }
                .button {
                    display: inline-block;
                    padding: 12px 30px;
                    background: #4CAF50;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    margin: 15px 0;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h2>📧 Neue Kontaktanfrage</h2>
                    <p style='margin: 10px 0 0 0; opacity: 0.9;'>Aurora Weather Livecam</p>
                </div>
                
                <div class='content'>
                    <div class='info-box'>
                        <strong>👤 Name:</strong>
                        {$name}
                    </div>
                    
                    <div class='info-box'>
                        <strong>📧 E-Mail:</strong>
                        <a href='mailto:{$email}' style='color: #667eea;'>{$email}</a>
                    </div>
                    
                    <div class='info-box'>
                        <strong>💬 Nachricht:</strong>
                    </div>
                    
                    <div class='message-box'>
                        " . nl2br($message) . "
                    </div>
                    
                    <div style='text-align: center; margin: 30px 0;'>
                        <a href='mailto:{$email}' class='button'>
                            ↩️ Direkt antworten
                        </a>
                    </div>
                </div>
                
                <div class='footer'>
                    <p><strong>📅 Gesendet am:</strong> {$date}</p>
                    <p><strong>🌐 IP-Adresse:</strong> {$ip}</p>
                    <p style='margin-top: 15px;'>
                        Diese E-Mail wurde automatisch vom Kontaktformular auf<br>
                        <a href='https://www.aurora-live-weathercam.com' style='color: #667eea;'>
                            www.aurora-live-weathercam.com
                        </a> generiert.
                    </p>
                </div>
            </div>
        </body>
        </html>
        ";
    }
}

class AdminManager {
    public function isAdmin() {
        return isset($_SESSION['admin']) && $_SESSION['admin'] === true;
    }
    public function handleLogin($username, $password) {
        echo "Login-Versuch: Username = $username, Passwort = $password"; // Debugging
        if ($username === 'admin' && $password === 'sonne4000$$$$Q') {
            $_SESSION['admin'] = true;
            return true;
        }
        return false;
    }
    
    public function handleImageUpload($file) {
        if (!$this->isAdmin()) {
            return false; // Nur Admins dürfen Bilder hochladen
        }
         
        if (!isset($file['tmp_name']) || empty($file['tmp_name'])) {
            echo "Keine Datei hochgeladen.";
            return false;
        }
    
        $target_dir = "uploads/";
        if (!file_exists($target_dir)) {
            mkdir($target_dir, 0777, true);
        }
    
        $target_file = $target_dir . basename($file["name"]);
        $uploadOk = 1;
        $imageFileType = strtolower(pathinfo($target_file,PATHINFO_EXTENSION));
    
      
        $check = @getimagesize($file["tmp_name"]);
        if($check === false) {
            echo "Die Datei ist kein Bild.";
            return false;
        }
    
    
        if ($file["size"] > 5000000) { // 5MB Limit
            echo "Die Datei ist zu groß.";
            return false;
        }
    
        // Erlauben Sie nur bestimmte Dateiformate
        if($imageFileType != "jpg" && $imageFileType != "png" && $imageFileType != "jpeg"
        && $imageFileType != "gif" ) {
            echo "Nur JPG, JPEG, PNG & GIF Dateien sind erlaubt.";
            return false;
        }
    
        // Wenn alles in Ordnung ist, versuchen Sie, die Datei hochzuladen
        if (move_uploaded_file($file["tmp_name"], $target_file)) {
            echo "Die Datei ". basename( $file["name"]). " wurde hochgeladen.";
            return true;
        } else {
            echo "Es gab einen Fehler beim Hochladen der Datei.";
            return false;
        }
    }
    
    
    public function displayLoginForm() {
        return '
        <form id="login-form" method="post">
            <input type="hidden" name="admin-login" value="1">
            <label for="username">Benutzername:</label>
            <input type="text" id="username" name="username" required>
            <label for="password">Passwort:</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Einloggen</button>
        </form>';
    }

    public function displayAdminContent() {
        $feedbacks = json_decode(file_get_contents('feedbacks.json') ?: '[]', true);
        $output = '<h3>Admin-Bereich</h3><div id="message-list">';
        foreach ($feedbacks as $feedback) {
            $output .= "<div>";
            $output .= "<h4>{$feedback['name']} ({$feedback['email']})</h4>";
            $output .= "<p>{$feedback['message']}</p>";
            $output .= "<small>{$feedback['date']}</small>";
            $output .= "</div>";
        }
        $output .= '</div>';

        $output .= '
        <h3>Social Media Links verwalten</h3>
        <form id="social-media-form" method="post">
            <input type="hidden" name="update-social-media" value="1">
            <select name="social-platform" required>
                <option value="facebook">Facebook</option>
                <option value="instagram">Instagram</option>
                <option value="tiktok">TikTok</option>
            </select>
            <input type="url" name="social-url" placeholder="Profil URL" required>
            <button type="submit">Aktualisieren</button>
        </form>';
        $output .= '
        <h3>Bild hochladen</h3>
        <form action="" method="post" enctype="multipart/form-data">
            <input type="file" name="fileToUpload" id="fileToUpload">
            <input type="submit" value="Bild hochladen" name="submit">
        </form>';
        return $output;
    }
    
    public function displayGalleryImages() {
    $output = '<div id="gallery-images">';
    $files = glob("uploads/*.*");
    foreach($files as $file) {
        $filename = basename($file);
        $extension = pathinfo($file, PATHINFO_EXTENSION);
        
        // NUR Bilddateien anzeigen, KEINE Videos
        if (in_array(strtolower($extension), ['jpg', 'jpeg', 'png', 'gif'])) {
            $output .= '<img src="'.$file.'" alt="'.$filename.'" style="width:200px; height:auto; margin:10px; cursor:pointer;">';
        }
    }
    $output .= '</div>';
    return $output;
}




    public function handleSocialMediaUpdate($platform, $url) {
        $socialLinks = json_decode(file_get_contents('social_links.json') ?: '{}', true);
        $socialLinks[$platform] = $url;
        file_put_contents('social_links.json', json_encode($socialLinks));
    }
}



// Weather Bingo Manager
//require_once 'weather_bingo.php';
//$weatherBingo = new WeatherBingo();






// Neue VideoArchiveManager Klasse 


class VideoArchiveManager {
    private $videoDir;
    private $monthNames;
    
    public function __construct($videoDir = './videos/') {
        $this->videoDir = $videoDir;
        $this->monthNames = [
            '01' => 'Januar',
            '02' => 'Februar',
            '03' => 'März',
            '04' => 'April',
            '05' => 'Mai',
            '06' => 'Juni',
            '07' => 'Juli',
            '08' => 'August',
            '09' => 'September',
            '10' => 'Oktober',
            '11' => 'November',
            '12' => 'Dezember'
        ];
    }
    
    public function getVideosGroupedByDate() {
        $videos = [];
        
        foreach (glob($this->videoDir . 'daily_video_*.mp4') as $video) {
            // Dateinamenformat: daily_video_YYYYMMDD_HHMMSS.mp4
            if (preg_match('/daily_video_(\d{8})_\d{6}\.mp4/', basename($video), $matches)) {
                $dateStr = $matches[1]; // YYYYMMDD
                $year = substr($dateStr, 0, 4);
                $month = substr($dateStr, 4, 2);
                $day = substr($dateStr, 6, 2);
                
                // Gruppiere nach Jahr und Monat
                $videos[$year][$month][] = [
                    'path' => $video,
                    'filename' => basename($video),
                    'day' => $day,
                    'filesize' => filesize($video),
                    'modified' => filemtime($video)
                ];
            }
        }
        
        // Nach Tag sortieren
        foreach ($videos as $year => $months) {
            foreach ($months as $month => $days) {
                usort($videos[$year][$month], function($a, $b) {
                    return $b['day'] - $a['day']; // Absteigend sortieren (neueste zuerst)
                });
            }
        }
        
        return $videos;
    }
    
    public function getAvailableYearsAndMonths() {
        $videos = $this->getVideosGroupedByDate();
        $result = [];
        
        foreach ($videos as $year => $months) {
            $result[$year] = array_keys($months);
        }
        
        return $result;
    }
    
    public function getVideosForYearAndMonth($year, $month) {
        $videos = $this->getVideosGroupedByDate();
        return isset($videos[$year][$month]) ? $videos[$year][$month] : [];
    }
    
    public function displayCalendarInterface() {
        $yearsAndMonths = $this->getAvailableYearsAndMonths();
        
        $output = '<div class="calendar-interface">';
        $output .= '<h3 data-en="Video Archive" data-de="Video-Archiv" data-it="Archivio Video" data-fr="Archives Vidéo" data-zh="视频档案">Video-Archiv</h3>';
        
        if (empty($yearsAndMonths)) {
            $output .= '<p data-en="No videos available." data-de="Keine Videos verfügbar." data-it="Nessun video disponibile." data-fr="Aucune vidéo disponible." data-zh="没有可用的视频。">Keine Videos verfügbar.</p>';
        } else {
            $output .= '<div class="calendar-selection">';
            $output .= '<form method="get" action="#archive">';
            
            // Jahr-Auswahl
            $output .= '<label data-en="Year:" data-de="Jahr:" data-it="Anno:" data-fr="Année:" data-zh="年份：">Jahr:</label>';
            $output .= '<select name="calendar_year" id="calendar_year">';
            
            foreach ($yearsAndMonths as $year => $months) {
                $selected = (isset($_GET['calendar_year']) && $_GET['calendar_year'] == $year) ? 'selected' : '';
                $output .= "<option value=\"$year\" $selected>$year</option>";
            }
            
            $output .= '</select>';
            
            // Monats-Auswahl
            $output .= '<label data-en="Month:" data-de="Monat:" data-it="Mese:" data-fr="Mois:" data-zh="月份：">Monat:</label>';
            $output .= '<select name="calendar_month" id="calendar_month">';
            
            // Wenn ein Jahr ausgewählt wurde, zeige die verfügbaren Monate
            if (isset($_GET['calendar_year']) && isset($yearsAndMonths[$_GET['calendar_year']])) {
                foreach ($yearsAndMonths[$_GET['calendar_year']] as $month) {
                    $selected = (isset($_GET['calendar_month']) && $_GET['calendar_month'] == $month) ? 'selected' : '';
                    $output .= "<option value=\"$month\" $selected>{$this->monthNames[$month]}</option>";
                }
            }
            
            $output .= '</select>';
            $output .= '<button type="submit" data-en="Show" data-de="Anzeigen" data-it="Mostra" data-fr="Afficher" data-zh="显示">Anzeigen</button>';
            $output .= '</form>';
            $output .= '</div>';
            
            // Wenn Jahr und Monat ausgewählt wurden, zeige die Videos
            if (isset($_GET['calendar_year']) && isset($_GET['calendar_month'])) {
                $year = $_GET['calendar_year'];
                $month = $_GET['calendar_month'];
                $videos = $this->getVideosForYearAndMonth($year, $month);
                
                if (!empty($videos)) {
                    $output .= '<div class="video-list">';
                    $output .= "<h4>Videos für {$this->monthNames[$month]} $year</h4>";
                    $output .= '<ul>';
                    
                    foreach ($videos as $video) {
                        $sizeInMb = round($video['filesize'] / (1024 * 1024), 2);
                        $date = date('d.m.Y H:i', $video['modified']);
                        
                        // Sicherer Token für die Dateiverfikation
                        $token = hash_hmac('sha256', $video['path'], session_id());
                        
                        $output .= "<li>";
                        $output .= "<a href=\"?download_specific_video=" . urlencode($video['path']) . "&token=" . urlencode($token) . "\">";
                        $output .= "Tag {$video['day']}: {$video['filename']} ($sizeInMb MB - $date)";
                        $output .= "</a>";
                        $output .= "</li>";
                    }
                    
                    $output .= '</ul>';
                    $output .= '</div>';
                } else {
                    $output .= "<p>Keine Videos für {$this->monthNames[$month]} $year gefunden.</p>";
                }
            }
        }
        
        $output .= '</div>';
        return $output;
    }
    
    public function handleSpecificVideoDownload() {
        if (isset($_GET['download_specific_video']) && isset($_GET['token'])) {
            $videoPath = $_GET['download_specific_video'];
            $token = $_GET['token'];
            
            // Token-Validierung
            $expectedToken = hash_hmac('sha256', $videoPath, session_id());
            if (!hash_equals($expectedToken, $token)) {
                echo "Ungültiger Token. Zugriff verweigert.";
                exit;
            }
            
            // Sicherheitsüberprüfung: Stelle sicher, dass das Video im erlaubten Verzeichnis liegt
            $videoDir = realpath($this->videoDir);
            $requestedPath = realpath($videoPath);
            
            if ($requestedPath && strpos($requestedPath, $videoDir) === 0 && file_exists($requestedPath)) {
                // Nur MP4-Dateien erlauben
                $extension = pathinfo($requestedPath, PATHINFO_EXTENSION);
                if (strtolower($extension) !== 'mp4') {
                    echo "Nur MP4-Dateien können heruntergeladen werden.";
                    exit;
                }
                
                header('Content-Description: File Transfer');
                header('Content-Type: video/mp4');
                header('Content-Disposition: attachment; filename="'.basename($requestedPath).'"');
                header('Expires: 0');
                header('Cache-Control: must-revalidate');
                header('Pragma: public');
                header('Content-Length: ' . filesize($requestedPath));
                readfile($requestedPath);
                exit;
            } else {
                echo "Datei nicht gefunden oder ungültiger Dateipfad.";
                exit;
            }
        }
    }
}







$webcamManager = new WebcamManager();
$imageFilesJson = $webcamManager->getImageFiles();
$guestbookManager = new GuestbookManager();
$contactManager = new ContactManager();
$adminManager = new AdminManager();

// Nach den anderen Manager-Instanzen hinzufügen
$videoArchiveManager = new VideoArchiveManager('./videos/');

// Video-Download-Handler nach dem existierenden Download-Handler hinzufügen
$videoArchiveManager->handleSpecificVideoDownload();


if (isset($_GET['action'])) {
    switch ($_GET['action']) {
        case 'snapshot':
            $webcamManager->captureSnapshot();
																		
            break;
        case 'sequence':
            $webcamManager->captureVideoSequence();
																		
            break;
																							 
    }
		 
}


if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_guestbook') {
    if ($adminManager->isAdmin() && isset($_POST['delete_entry'])) {
        $index = $_POST['delete_entry'];
        if ($guestbookManager->deleteEntry($index)) {
            $_SESSION['message'] = "Eintrag erfolgreich gelöscht.";
        } else {
            $_SESSION['error'] = "Fehler beim Löschen des Eintrags.";
        }
        // Umleitung zur gleichen Seite, um Neuladen des Formulars zu verhindern
        header("Location: " . $_SERVER['PHP_SELF'] . "#guestbook");
        exit();
    }
}


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['guestbook'])) {
        $guestbookManager->handleFormSubmission();
   } elseif (isset($_POST['contact'])) {
    $result = $contactManager->handleSubmission($_POST['name'], $_POST['email'], $_POST['message']);
    
    // JSON-Response für AJAX
    if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && 
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        header('Content-Type: application/json');
        echo json_encode($result);
        exit;
    }
    
    // Normale Formular-Submission
    $_SESSION['contact_result'] = $result;
    header('Location: ' . $_SERVER['PHP_SELF'] . '#kontakt');
    exit;

    } elseif (isset($_POST['admin-login'])) {
        $adminManager->handleLogin($_POST['username'], $_POST['password']);
    } elseif (isset($_POST['update-social-media'])) {
        $adminManager->handleSocialMediaUpdate($_POST['social-platform'], $_POST['social-url']);


    } elseif (isset($_FILES["fileToUpload"]) && $adminManager->isAdmin()) {
        $adminManager->handleImageUpload($_FILES["fileToUpload"]);
}}
?>




<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aurora Livecam - Einzigartige Live-Webcam und Wetter></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   <style>
  /* ========== GRUNDLEGENDE STILE ========== */
/* ========== GRUNDLEGENDE STILE ========== */

/* ========== VISUELLER KALENDER ========== */
.visual-calendar-container {
    max-width: 800px;
    margin: 0 auto;
    background: rgba(255, 255, 255, 0.95);
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 5px 20px rgba(0,0,0,0.1);
}



#timelapse-time-overlay {
    position: absolute;
    top: 20px;
    left: 20px;
    background: rgba(0,0,0,0.7);
    color: white;
    padding: 10px 15px;
    border-radius: 5px;
    font-size: 18px;
    font-weight: bold;
    z-index: 100;
    font-family: monospace;
    box-shadow: 0 2px 10px rgba(0,0,0,0.5);
}


.calendar-navigation {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding: 10px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    border-radius: 8px;
    color: white;
}

.cal-nav-btn {
    background: rgba(255,255,255,0.2);
    border: none;
    color: white;
    font-size: 24px;
    padding: 5px 15px;
    border-radius: 5px;
    cursor: pointer;
    transition: all 0.3s;
}

.cal-nav-btn:hover {
    background: rgba(255,255,255,0.3);
    transform: scale(1.1);
}

.calendar-grid {
    display: grid;
    grid-template-columns: repeat(7, 1fr);
    gap: 5px;
    margin-bottom: 20px;
}

.calendar-weekday {
    text-align: center;
    font-weight: bold;
    padding: 10px;
    background: #f0f0f0;
    border-radius: 5px;
    color: #666;
}

.calendar-day {
    aspect-ratio: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    background: white;
    border: 2px solid #e0e0e0;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.3s;
    position: relative;
    min-height: 60px;
}

.calendar-day:hover:not(.empty) {
    transform: scale(1.05);
    box-shadow: 0 3px 10px rgba(0,0,0,0.15);
    border-color: #667eea;
}

.calendar-day.empty {
    background: transparent;
    border: none;
    cursor: default;
}

.calendar-day.has-video {
    background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
    border-color: #2196F3;
    font-weight: bold;
}

.calendar-day.selected {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border-color: #764ba2;
    transform: scale(1.1);
    box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
}

.calendar-day.today {
    border: 3px solid #4CAF50;
    box-shadow: 0 0 10px rgba(76, 175, 80, 0.3);
}

.day-number {
    font-size: 18px;
    font-weight: 600;
}

.video-indicator {
    position: absolute;
    bottom: 2px;
    right: 2px;
    font-size: 12px;
}

.day-videos {
    background: #f9f9f9;
    border-radius: 8px;
    padding: 20px;
    margin-top: 20px;
    animation: slideIn 0.3s ease;
}

@keyframes slideIn {
    from {
        opacity: 0;
        transform: translateY(-10px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}


/* Mobile Video Optimierungen */
@media (max-width: 768px) {
    .video-container {
        position: relative;
        padding-bottom: 56.25%;
        height: 0;
        overflow: hidden;
    }
    
    #webcam-player {
        position: absolute;
        top: 0;
        left: 0;
        width: 100% !important;
        height: 100% !important;
        object-fit: contain;
        -webkit-tap-highlight-color: transparent;
        -webkit-playsinline: true;
    }
}

/* iOS-spezifische Fixes */
@supports (-webkit-touch-callout: none) {
    #webcam-player {
        -webkit-playsinline: true;
        -webkit-video-playable-inline: true;
    }
}





.day-videos h4 {
    color: #333;
    margin-bottom: 15px;
    padding-bottom: 10px;
    border-bottom: 2px solid #667eea;
}

.video-download-list {
    list-style: none;
    padding: 0;
}

.video-download-list li {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px;
    margin-bottom: 10px;
    background: white;
    border-radius: 6px;
    transition: all 0.3s;
}

.video-download-list li:hover {
    background: #e3f2fd;
    transform: translateX(5px);
}

.video-time {
    font-weight: 600;
    color: #666;
}

.video-size {
    color: #999;
    font-size: 14px;
}

.download-link {
    background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
    color: white;
    padding: 8px 16px;
    border-radius: 20px;
    text-decoration: none;
    transition: all 0.3s;
    font-weight: bold;
}

.download-link:hover {
    transform: scale(1.05);
    box-shadow: 0 3px 10px rgba(76, 175, 80, 0.3);
}

.no-videos {
    text-align: center;
    padding: 30px;
    color: #999;
    font-style: italic;
}

/* Mobile Responsive */
@media (max-width: 600px) {
    .calendar-grid {
        gap: 2px;
    }
    
    .calendar-day {
        min-height: 45px;
    }
    
    .day-number {
        font-size: 14px;
    }
    
    .video-download-list li {
        flex-direction: column;
        gap: 10px;
        text-align: center;
    }
}











body {
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 0;
    color: #333;
    line-height: 1.6;
    background-image: url('main.jpg');
    background-size: cover;
    background-position: center;
    background-attachment: fixed;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 20px;
}

.section {
    padding: 80px 0;
    background-color: rgba(255, 255, 255, 0.8);
    margin-bottom: 20px;
    position: relative;
    z-index: 10;
}

.section h2 {
    font-size: 36px;
    margin-bottom: 40px;
    text-align: center;
    color: #333;
}

.page-title {
    font-size: 3rem;
    font-weight: bold;
    text-align: center;
    margin: 20px 0;
    color: #333;
}

/* ========== HEADER & NAVIGATION ========== */
header {
    background-color: rgba(255, 255, 255, 0.95);
    padding: 10px 0;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
    position: sticky;
    top: 0;
    z-index: 100;
}

.logo img {
    height: 50px;
}

nav ul {
    list-style: none;
    padding: 0;
    display: flex;
    justify-content: space-around;
    flex-wrap: wrap;
    margin: 0;
}

nav ul li {
    margin: 5px 10px;
}

nav ul li a {
    text-decoration: none;
    color: #333;
    font-weight: bold;
    padding: 5px 10px;
    transition: color 0.3s;
}

nav ul li a:hover {
    color: #4CAF50;
}

/* ========== BUTTONS & CONTROLS ========== */
.button {
    display: inline-block;
    padding: 10px 20px;
    margin: 10px;
    background-color: #4CAF50;
    color: white;
    text-decoration: none;
    border-radius: 5px;
    transition: background-color 0.3s;
    font-weight: bold;
    text-align: center;
    border: none;
    cursor: pointer;
}

.button:hover {
    background-color: #45a049;
}

button[type="submit"] {
    background-color: #4CAF50;
    color: #fff;
    border: none;
    padding: 10px 20px;
    border-radius: 5px;
    cursor: pointer;
    font-size: 16px;
    transition: background-color 0.3s;
}

button[type="submit"]:hover {
    background-color: #45a049;
}

.delete-btn {
    background-color: #ff4136;
    color: white;
    border: none;
    padding: 5px 10px;
    cursor: pointer;
    font-size: 0.8em;
    margin-left: 10px;
    border-radius: 3px;
}

.delete-btn:hover {
    background-color: #ff1a1a;
}

/* ========== WEBCAM & VIDEO ========== */
.video-container {
    position: relative;
    padding-bottom: 56.25%; /* 16:9 Aspect Ratio */
    height: 0;
    overflow: hidden;
    margin-bottom: 20px;
    background-color: #000;
    border-radius: 8px;
    z-index: 30; /* Erhöht von 5 auf 30 */
}

#webcam-player {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    border-radius: 8px;
}

#timelapse-viewer {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    border-radius: 8px;
}

.webcam-controls {
    text-align: center;
    margin: 20px 0;
}

/* ========== TITLE SECTION ========== */
.title-section {
    text-align: center;
    padding: 50px 0;
    color: #fff;
    text-shadow: 2px 2px 4px rgba(0,0,0,0.7);
    position: relative;
    z-index: 20;
}

.flag-title-container {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 20px;
}

.flag-image {
    width: 50px;
    height: auto;
    box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    border-radius: 3px;
}

.title-section h1 {
    font-size: 2.5em;
    margin-bottom: 10px;
}

.title-section p {
    font-size: 1.2em;
}

/* ========== RECOMMENDATION BANNER ========== */
.recommendation-banner {
    text-align: center;
    padding: 20px;
    background-color: rgba(255, 255, 255, 0.9);
    border-radius: 8px;
    margin-bottom: 20px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.recommendation-banner h2 {
    margin-bottom: 15px;
    color: #333;
}

.sponsor-logos {
    display: flex;
    flex-direction: column;
    align-items: center;
}

.ad-row {
    display: flex;
    justify-content: center;
    flex-wrap: wrap;
    margin-bottom: 10px;
    width: 100%;
}

.ad-item {
    margin: 0 10px 10px;
    text-align: center;
}

.ad-item img {
    max-height: 40px;
    width: auto;
    transition: transform 0.3s;
}

.ad-item img:hover {
    transform: scale(1.1);
}

.ad-item p {
    margin: 5px 0;
    font-size: 14px;
}

/* ========== FORMS ========== */
form {
    display: grid;
    gap: 20px;
    background-color: rgba(255, 255, 255, 0.7);
    padding: 25px;
    border-radius: 8px;
    max-width: 600px;
    margin: 0 auto;
}

input, textarea, select {
    width: 100%;
    padding: 12px;
    border: 1px solid #ddd;
    border-radius: 5px;
    font-size: 16px;
    background-color: white;
}

textarea {
    min-height: 120px;
    resize: vertical;
}

label {
    font-weight: bold;
    margin-bottom: 5px;
    display: block;
}

/* ========== GUESTBOOK ========== */
.guestbook-entry {
    background-color: #f9f9f9;
    border-left: 5px solid #4CAF50;
    margin-bottom: 20px;
    padding: 15px;
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    transition: transform 0.3s ease;
}

.guestbook-entry:hover {
    transform: translateY(-5px);
}

.guestbook-entry h4 {
    color: #333;
    margin-top: 0;
    margin-bottom: 10px;
}

.guestbook-entry p {
    color: #666;
    line-height: 1.6;
    margin: 10px 0;
}

.guestbook-entry small {
    font-size: 0.9em;
    color: #999;
    display: block;
    margin-top: 10px;
}

/* ========== WEATHER BINGO ========== */
.bingo-container {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 30px;
    margin-top: 30px;
}

.daily-challenges {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 25px;
    border-radius: 12px;
    color: white;
}

#challenges-list {
    margin: 20px 0;
}

.challenge-item {
    background: rgba(255,255,255,0.1);
    padding: 15px;
    margin: 10px 0;
    border-radius: 8px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    transition: all 0.3s;
    border: 2px solid transparent;
}

.challenge-item:hover {
    background: rgba(255,255,255,0.2);
    transform: translateX(5px);
}

/* WICHTIG: Selected State */
.challenge-item.selected {
    background: rgba(76, 175, 80, 0.5) !important;
    border: 2px solid #4CAF50 !important;
    transform: scale(1.05);
    box-shadow: 0 0 15px rgba(76, 175, 80, 0.6);
}

.challenge-points {
    background: gold;
    color: #333;
    padding: 5px 10px;
    border-radius: 20px;
    font-weight: bold;
}


/* ========== GALLERY ========== */
#gallery-images {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 15px;
    margin-top: 30px;
}

#gallery-images img {
    width: 200px;
    height: auto;
    border-radius: 5px;
    box-shadow: 0 3px 6px rgba(0,0,0,0.1);
    transition: transform 0.3s, box-shadow 0.3s;
    cursor: pointer;
}

#gallery-images img:hover {
    transform: scale(1.05);
    box-shadow: 0 5px 12px rgba(0,0,0,0.2);
}

/* ========== QR CODE ========== */
#qrcode {
    display: flex;
    justify-content: center;
    margin-top: 20px;
    cursor: pointer;
}

#qrcode img {
    border: 10px solid white;
    border-radius: 5px;
    box-shadow: 0 4px 8px rgba(0,0,0,0.15);
    transition: transform 0.3s;
}

#qrcode img:hover {
    transform: scale(1.05);
}

/* ========== VIDEO ARCHIVE (NEU) ========== */
#archive {
    padding-top: 60px;
    margin-top: 40px;
}

.calendar-interface {
    background-color: rgba(255, 255, 255, 0.95);
    border-radius: 8px;
    padding: 25px;
    margin-bottom: 30px;
    box-shadow: 0 4px 10px rgba(0,0,0,0.1);
    position: relative;
    z-index: 20;
}

.calendar-selection {
    display: flex;
    flex-wrap: wrap;
    gap: 20px;
    margin-bottom: 25px;
    align-items: center;
}

.calendar-selection label {
    font-weight: bold;
    margin: 0;
    min-width: 60px;
}

.calendar-selection select {
    padding: 10px 15px;
    border-radius: 5px;
    border: 1px solid #ddd;
    background-color: white;
    flex: 1;
    min-width: 150px;
    max-width: 200px;
}

.calendar-selection button {
    padding: 10px 25px;
    background-color: #4CAF50;
    color: white;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    transition: background-color 0.3s;
    font-weight: bold;
}

.calendar-selection button:hover {
    background-color: #45a049;
}

.video-list {
    margin-top: 30px;
}

.video-list h4 {
    font-size: 20px;
    margin-bottom: 15px;
    padding-bottom: 10px;
    border-bottom: 2px solid #4CAF50;
    color: #333;
}

.video-list ul {
    list-style-type: none;
    padding: 0;
    max-height: 400px;
    overflow-y: auto;
    background-color: #f9f9f9;
    border-radius: 5px;
    padding: 15px;
    box-shadow: inset 0 0 8px rgba(0,0,0,0.05);
}

.video-list li {
    margin-bottom: 12px;
    padding: 15px;
    background-color: #fff;
    border-radius: 5px;
    transition: all 0.3s ease;
    border-left: 4px solid #4CAF50;
    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
}

.video-list li:hover {
    background-color: #f0f9f0;
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
}

.video-list a {
    text-decoration: none;
    color: #333;
    display: block;
    font-weight: bold;
}

.video-list a:hover {
    color: #4CAF50;
}

/* ========== MODAL ========== */
.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    padding-top: 50px;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    overflow: auto;
    background-color: rgba(0,0,0,0.9);
}

.modal-content {
    margin: auto;
    display: block;
    width: 80%;
    max-width: 700px;
    max-height: 80vh;
    object-fit: contain;
    border-radius: 5px;
}

#caption {
    margin: 15px auto;
    display: block;
    width: 80%;
    max-width: 700px;
    text-align: center;
    color: #ccc;
    padding: 10px 0;
    height: auto;
}

.close {
    position: absolute;
    top: 15px;
    right: 35px;
    color: #f1f1f1;
    font-size: 40px;
    font-weight: bold;
    transition: 0.3s;
    z-index: 1010;
}

.close:hover,
.close:focus {
    color: #bbb;
    text-decoration: none;
    cursor: pointer;
}

.download-btn {
    display: block;
    width: 200px;
    height: 40px;
    margin: 20px auto;
    background-color: #4CAF50;
    color: white;
    text-align: center;
    line-height: 40px;
    text-decoration: none;
    border-radius: 5px;
    font-weight: bold;
    transition: background-color 0.3s;
}

.download-btn:hover {
    background-color: #45a049;
}

/* ========== TIMELAPSE ========== */
.timelapse-container {
    width: 100%;
    max-width: 800px;
    margin: 0 auto;
}

#timelapse {
    width: 100%;
    height: 450px;
    background-color: #000;
    background-size: cover;
    background-position: center;
    border-radius: 8px;
}

.controls {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 15px;
    background-color: rgba(255, 255, 255, 0.9);
    padding: 10px;
    border-radius: 5px;
}

#playPauseButton {
    padding: 5px 10px;
}

#timeSlider {
    flex-grow: 1;
    margin: 0 15px;
    height: 5px;
}

#currentTime {
    font-family: monospace;
    min-width: 150px;
    text-align: right;
}

/* ========== LANGUAGE SWITCH ========== */
#language-switch {
    position: fixed;
    top: 10px;
    right: 10px;
    z-index: 1000;
    background-color: rgba(255, 255, 255, 0.8);
    border-radius: 5px;
    padding: 5px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}

.lang-button {
    background: none;
    border: none;
    cursor: pointer;
    padding: 5px;
    opacity: 0.7;
    transition: opacity 0.3s ease;
    margin: 0 2px;
}

.lang-button:hover, .lang-button.active {
    opacity: 1;
}

.flag-icon {
    width: 30px;
    height: 20px;
    object-fit: cover;
    border-radius: 2px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

/* ========== FOOTER ========== */
footer {
    background-color: rgba(51, 51, 51, 0.9);
    color: #fff;
    padding: 40px 0;
    text-align: center;
    margin-top: 40px;
}

.footer-links {
    margin-bottom: 20px;
}

.footer-links a {
    color: #fff;
    text-decoration: none;
    margin: 0 15px;
    transition: color 0.3s;
}

.footer-links a:hover {
    color: #4CAF50;
    text-decoration: underline;
}

.footer-bottom {
    border-top: 1px solid rgba(255, 255, 255, 0.2);
    padding-top: 20px;
    margin-top: 20px;
}

/* ========== MEDIA QUERIES ========== */
@media (max-width: 768px) {
    .container {
        padding: 0 15px;
    }
    
    .section {
        padding: 40px 0;
    }
    
    nav ul {
        flex-direction: column;
        align-items: center;
    }
    
    nav ul li {
        margin: 8px 0;
    }
    
    .flag-title-container {
        flex-direction: column;
    }
    
    .flag-image {
        width: 30px;
    }
    
    .title-section h1 {
        font-size: 1.8em;
    }
    
    .title-section p {
        font-size: 1em;
    }
    
    #welcome-title {
        font-size: 28px;
    }

    #welcome-subtitle {
        font-size: 18px;
    }

    .calendar-selection {
        flex-direction: column;
        align-items: flex-start;
    }
    
    .calendar-selection select {
        max-width: none;
        width: 100%;
    }
    
    .calendar-selection button {
        width: 100%;
    }
    
    .video-list ul {
        max-height: 300px;
    }
    
    .modal-content {
        width: 95%;
    }
    
    .close {
        right: 15px;
        top: 10px;
    }
}

@media (max-width: 480px) {
    .section h2 {
        font-size: 28px;
    }
    
    .button {
        width: 100%;
        margin: 5px 0;
    }
    
    .webcam-controls {
        display: flex;
        flex-direction: column;
    }
    
    .ad-item {
        margin: 5px;
    }
    
    .ad-item img {
        max-height: 30px;
    }
}


			   
 

</style>
    </style>
    <script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
</head>
<body>
<div id="language-switch">
    <button id="lang-de" class="lang-button" aria-label="Deutsch">
        <img src="images/swiss-flag-new.ico" alt="Schweizer Flagge" class="flag-icon">
    </button>
    <button id="lang-en" class="lang-button" aria-label="English">
        <img src="images/uk-flag.ico" alt="UK Flagge" class="flag-icon">
    </button>
    <button id="lang-it" class="lang-button" aria-label="Italiano">
        <img src="images/italian-flag.ico" alt="Flagge Italien" class="flag-icon">
    </button>
    <button id="lang-fr" class="lang-button" aria-label="Français">
        <img src="images/french-flag.ico" alt="Flagge Frankreich" class="flag-icon">
    </button>
    <button id="lang-zh" class="lang-button" aria-label="中文">
    <img src="images/chinese-flag.ico" alt="中国国旗" class="flag-icon">
</button>

</div>

    <header>
  <link rel="prefetch" href="chat.php">  

    
    
        <div class="container">

        <div class="logo">
                <img src="logo.png" alt="Aurora Wetter Livecam">
            </div>


            <nav>
            <ul>
            <li>
    <a href="#webcams" 
       data-en="Webcam" 
       data-de="Webcam" 
       data-it="Webcam" 
       data-fr="Webcam"
       data-zh="网络摄像头">
        Webcam
    </a>
</li>

<!-- <a href="chat.php" target="_blank" style="color: #667eea; font-weight: bold;">
    💬 Private Chat
</a>
-->



<li>
    <a href="#guestbook" 
       data-en="Guestbook" 
       data-de="Gästebuch" 
       data-it="Libro degli Ospiti"   data-zh="留言簿"
       data-fr="Livre d'or">
      
       Gästebuch
    </a>
</li>
<li>
    <a href="#kontakt" 
       data-en="Contact" 
       data-de="Kontakt" 
       data-it="Contatto" data-zh="联系我们"
       data-fr="Contact">
        Kontakt
    </a>
</li>




<li>
    <a href="#gallery" 
       data-en="Gallery" 
       data-de="Galerie" 
       data-it="Galleria"  data-zh="联系我们"
       data-fr="Galerie">
        Galerie
    </a>
</li>

<li>
    <a href="#archive" 
       data-en="Video Archive" 
       data-de="Videoarchiv (Tagesvideos 12h)" 
       data-it="Archivio Video" 
       data-fr="Archives Vidéo"
       data-zh="视频档案">
        Videoarchiv (Tagesvideos)
    </a>
    </li>

<?php if ($adminManager->isAdmin()): ?>
    <li>
        <a href="#admin" 
           data-en="Admin" 
           data-de="Admin" 
           data-it="Amministratore" 
           data-fr="Admin">
            Admin
        </a>
    </li>






<?php endif; ?>

    </ul>
            </nav>
        </div>
    </header>
    <div class="main-content">
    <section class="title-section">
    <div class="container">
        <div class="flag-title-container">
            <img src="images/swiss.jpg" alt="Schweizer Flagge" class="flag-image">
            <h1
    data-en="Welcome to Aurora Weather Livecam" 
    data-de="Willkommen bei Aurora Wetter Livecam" 
    data-it="Benvenuto su Aurora Weather Livecam" 
    data-fr="Bienvenue sur Aurora Weather Livecam"
    data-zh="欢迎来到极光天气直播摄像头">
    Willkommen bei Aurora Wetter Livecam 
    </h1>


            <img src="local-flag.jpg" alt="Ortsflagge" class="flag-image">
        </div>
        <p 
    data-en="Experience fascinating views of the Zurich region - in real time!" 
    data-de="Erleben Sie faszinierende Ausblicke der Züricher Region - in Echtzeit!"
    data-it="Vivi viste affascinanti della regione di Zurigo - in tempo reale!" data-zh="通过我们的实时网络摄像头体验大自然的美丽。"
    data-fr="Profitez de vues fascinantes de la région de Zurich - en temps réel!">
    Erleben Sie faszinierende Ausblicke der Züricher Region - in Echtzeit!
</p>
 </div>
</section>

    <div class="banner-container">
        <div class="recommendation-banner">
            <h2> <data-de="Unsere Empfehlungen" data-en="our recommendations"> </h2>
            <div class="sponsor-logos">
                <?php
                $advertisements = [
                     
																																
                   ['name' => 'Pizza for You', 'url' => 'https://pizzaforyou.ch//', 'img' => 'pizza.png'],
                   // ['name' => 'Swisscom', 'url' => 'https://www.swisscom.ch/', 'img' => 'images/swisscom.png'],
                  //  ['name' => 'Sunrise Wetteralarm', 'url' => 'https://www.bing.com/ck/nZQ&ntb=1', 'img' => 'images/sunrisealert.png'],
                  //  ['name' => 'Carvolution', 'url' => 'https://www.carvolution.ch/', 'img' => 'images/carvolution.png'],


 
                    ['name' => 'Deine Werbung bei uns', 'url' => 'https://www.aurora-wetter-lifecam.ch/', 'img' => 'werbung.png'],
                    ['name' => 'Deine Werbung bei uns', 'url' => 'https://www.aurora-wetter-lifecam.ch/', 'img' => 'werbung.png'],
                    ['name' => 'Deine Werbung bei uns', 'url' => 'https://www.aurora-wetter-lifecam.ch/', 'img' => 'werbung.png'],
                    ['name' => 'Deine Werbung bei uns', 'url' => 'https://www.aurora-wetter-lifecam.ch/', 'img' => 'werbung.png'],
                    ['name' => 'Deine Werbung bei uns', 'url' => 'https://www.aurora-wetter-lifecam.ch/', 'img' => 'werbung.png'],
                    ['name' => 'Deine Werbung bei uns', 'url' => 'https://www.aurora-wetter-lifecam.ch/', 'img' => 'werbung.png']
				
															  
                ]; 

                $grouped_ads = array_chunk($advertisements, 5);

                foreach ($grouped_ads as $group) {
                    echo '<div class="ad-row">';
                    foreach ($group as $ad) {
                        echo '<div class="ad-item">
                            <a href="' . $ad['url'] . '" target="_blank">
                                <img src="' . $ad['img'] . '" alt="' . $ad['name'] . '">
																		
                            </a>
                        </div>';
                    }
                    echo '</div>';
                }
                ?>
            </div>
			 
			  
        </div>
    </div>
</div>


 




<!-- KORRIGIERTE STRUKTUR -->
<section id="webcams" class="section">
    <div class="container">
        <div class="video-container">
            <?php echo $webcamManager->displayWebcam(); ?>
            <div id="timelapse-viewer" style="display: none; position: absolute; top: 0; left: 0; width: 100%; height: 100%;">
                <img id="timelapse-image" src="" alt="Timelapse Image" style="width: 100%; height: 100%; object-fit: cover;">
            </div>
        </div> <!-- video-container schließen -->
        
        <div class="webcam-controls" style="text-align: left;">
            <a href="?action=snapshot" class="button" 
               data-en="Save Snapshot" 
               data-de="Snapshot speichern"
               data-it="Salva Screenshot" 
               data-fr="Sauvegarder Snapshot"
               data-zh="保存快照">
               Snapshot speichern
            </a>

            <a href="#" class="button" id="timelapse-button" 
               data-en="Week Timelapse" 
               data-de="Wochenzeitraffer"
               data-it="Timelapse Giornaliero" 
               data-fr="Timelapse Quotidien"
               data-zh="每日延时摄影">
               Wochenzeitraffer
            </a>
            <a href="?download_video=1" class="button" 
               data-en="Download Latest Video" 
               data-de="Neuestes Zeitraffervideo herunterladen"
               data-it="Scarica l'ultimo video" 
               data-fr="Télécharger la dernière vidéo"
               data-zh="下载最新视频">
               Neuestes Tageszeitraffervideo herunterladen
            </a>
        </div>
        
        <section class="community-info" style="text-align: center; max-width: 600px; margin: 0 auto;">
            <h2 data-en="Join Our Community" 
                data-de="Werden Sie Teil unserer Community"
                data-it="Unisciti alla nostra comunità"
                data-fr="Rejoignez notre communauté"
                data-zh="加入我们的社区">
                Werden Sie Teil unserer Community
            </h2>
            <p data-en="Use our platform to start your own webcam broadcast and share your view of the Zurich landscape with others."
               data-de="Nutzen Sie unsere Plattform, um Ihre eigene Webcam-Übertragung zu starten und Ihre Sicht auf die Züricher Landschaft mit anderen zu teilen."
               data-it="Usa la nostra piattaforma per avviare la tua trasmissione webcam e condividere la tua vista sul paesaggio di Zurigo con gli altri."
               data-fr="Utilisez notre plateforme pour démarrer votre propre diffusion webcam et partager votre vue sur le paysage zurichois avec d'autres."
               data-zh="使用我们的平台开始您自己的网络摄像头直播，与他人分享您所见的苏黎世风景。">
               Nutzen Sie unsere Plattform, um Ihre eigene Webcam-Übertragung zu starten und Ihre Sicht auf die Züricher Landschaft mit anderen zu teilen.
            </p>
            <p data-en="Become part of our community of weather and nature enthusiasts by contributing your personal livestreams."
               data-de="Werden Sie Teil unserer Community von Wetter- und Naturbegeisterten, indem Sie Ihre persönlichen Livestreams einbringen."
               data-it="Diventa parte della nostra comunità di appassionati di meteo e natura contribuendo con i tuoi livestream personali."
               data-fr="Devenez membre de notre communauté de passionnés de météo et de nature en contribuant avec vos livestreams personnels."
               data-zh="通过贡献您的个人直播，成为我们天气和自然爱好者社区的一员。">
               Werden Sie Teil unserer Community von Wetter- und Naturbegeisterten, indem Sie Ihre persönlichen Livestreams einbringen.
            </p>



    <!-- STARLINK ERGÄNZUNG -->
    <div style="margin-top: 30px; padding: 20px; background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); border-radius: 10px;">
        <h3 style="color: white; margin-bottom: 15px;">
            🛰️ Schnelles Internet für Ihre Livestreams
        </h3>
        <p style="color: white; margin-bottom: 15px;">
            Für hochwertige Webcam-Übertragungen empfehlen wir Starlink - 
            Highspeed-Internet überall verfügbar, perfekt für abgelegene Standorte!
        </p>
        <a href="https://www.starlink.com/" target="_blank" style="display: inline-block;">
            <img src="starlink.png" alt="Starlink - Schnelles Internet überall" 
                 style="max-width: 200px; height: auto; border-radius: 5px; box-shadow: 0 3px 10px rgba(0,0,0,0.3);">
        </a>




        </section>
    </div> <!-- container schließen -->
</section>

<!-- Archive Section AUSSERHALB und NACH der Webcam Section -->
<section id="archive" class="section">
    <div class="container">
        <h2 data-en="Video Archive (Daily Videos 12h)" 
            data-de="Videoarchiv (Tagesvideos 12h)" 
            data-it="Archivio Video" 
            data-fr="Archives Vidéo" 
            data-zh="视频档案">
            Videoarchiv (Tagesvideos)
        </h2>
        <?php 
        $visualCalendar = new VisualCalendarManager('./videos/');
        echo $visualCalendar->displayVisualCalendar();
        ?>
    </div>
</section>



 


</div>
<div class="webcam-controls"  style="text-align: center";>
 
																														 
																															 
																																				
																																					   
 
<a href="?action=snapshot" class="button" 
   data-en="Save Snapshot" 
   data-de="Snapshot speichern"
   data-it="Salva Screenshot" 
   data-fr="Sauvegarder Snapshot" data-zh="开始录制"
   data-zh="保存快照">
   Snapshot speichern
</a>
<a href="?action=sequence" class="button" 
   data-en="Save Video Clip" 
   data-de="Videoclip speichern"
   data-it="Salva Clip Video" data-zh="停止录制"
   data-fr="Sauvegarder Clip Vidéo">
   Videoclip speichern
</a>
<a href="#" class="button" id="timelapse-button" 
   data-en="Week Timelapse" 
   data-de="Wochenzeitraffer"
   data-it="Timelapse Giornaliero" 
   data-fr="Timelapse Quotidien">
   Wochenzeitraffer
</a>

    <!-- Bestehende Buttons hier -->
    <a href="?download_video=1" class="button" 
       data-en="Download Latest Video" 
       data-de="Neuestes Zeitraffervideo herunterladen"
       data-it="Scarica l'ultimo video" 
       data-fr="Télécharger la dernière vidéo">
       Neuestes Tageszeitraffervideo herunterladen
    </a>



</div>
 




        <section class="community-info" style="text-align: center; max-width: 600px; margin: 0 auto;">
            <h2 data-en="Join Our Community" data-zh="加入我们的社" data-de="Werden Sie Teil unserer Community" data-zh="通过贡献您的个人直播，成为我们天气和自然爱好者社区的一员。">Werden Sie Teil unserer Community</h2>
            <p data-en="Use our platform to start your own webcam broadcast and share your view of the Zurich landscape with others."   data-zh="使用我们的平台开始您自己的网络摄像头直播，与他人分享您所见的苏黎世风景。" data-de="Nutzen Sie unsere Plattform, um Ihre eigene Webcam-Übertragung zu starten und Ihre Sicht auf die Züricher Landschaft mit anderen zu teilen.">Nutzen Sie unsere Plattform, um Ihre eigene Webcam-Übertragung zu starten und Ihre Sicht auf die Züricher Landschaft mit anderen zu teilen.</p>
            <p data-en="Become part of our community of weather and nature enthusiasts by contributing your personal livestreams."  data-zh="使用我们的平台开始您自己的网络您自己的网络摄像头直播，与他人分享您所见的苏黎世风景。" data-de="Werden Sie Teil unserer Community von Wetter- und Naturbegeisterten, indem Sie Ihre persönlichen Livestreams einbringen.">Werden Sie Teil unserer Community von Wetter- und Naturbegeisterten, indem Sie Ihre persönlichen Livestreams einbringen.</p>
        </section>



        </div>
    </div>
</section>





<section id="qr-code" class="section">
    <div class="container" style="text-align: center;">

        <h1> 
        
        
        <p 
    data-en="Follow us and copy the code to send it to your friends on TikTok, Facebook, Instagram, etc." 
    data-de="Folge uns und kopiere den Code und sende es deinen Freunden in Tiktok, Facebook, Instagram usw." data-zh="关注我们并复制代码，在抖音、脸书、Instagram等平台与您的朋友分享。"
    data-it="Segui noi e copia il codice da inviare ai tuoi amici su TikTok, Facebook, Instagram, ecc."
    data-fr="Suivez-nous et copiez le code pour l'envoyer à vos amis sur TikTok, Facebook, Instagram, etc.">
    Folge uns und kopiere den Code und sende es deinen Freunden in Tiktok, Facebook, Instagram usw.
</p>
    
        </h1>
        <div id="qrcode" data-url="https://www.aurora-wetter-lifecam.ch/qr.php"></div>
        <p 
    data-en="Click on the QR code to copy the URL" 
    data-de="Klicke auf den QR-Code, um die URL zu kopieren" 
    data-it="Clicca sul QR code per copiare l'URL" data-zh="点击二维码复制网址"
    data-fr="Cliquez sur le QR code pour copier l'URL">
    Klicke auf den QR-Code, um die URL zu kopieren
</p>

    </div>
</section>

<!-- Chat-Regeln Modal -->
<div id="chat-rules-modal" style="display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); max-width: 600px; z-index: 10000; max-height: 80vh; overflow-y: auto;">
    <h2>📋 Nutzungsbedingungen & Chat-Regeln</h2>
    
    <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
        <h3>⚠️ Wichtige Verhaltensregeln:</h3>
        <ul style="line-height: 1.8;">
            <li><strong>Keine sexuellen, pornografischen oder anzüglichen Inhalte</strong></li>
            <li><strong>Keine Gewaltdarstellungen oder -androhungen</strong></li>
            <li><strong>Kein Rassismus, Diskriminierung oder Hassrede</strong></li>
            <li><strong>Keine persönlichen Daten (Telefonnummern, Adressen) teilen</strong></li>
            <li><strong>Keine Werbung oder Spam</strong></li>
            <li><strong>Respektvoller Umgang miteinander</strong></li>
            <li><strong>Keine illegalen Aktivitäten oder Inhalte</strong></li>
        </ul>
    </div>
    
    <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin: 15px 0;">
        <h3>📸 Webcam-Nutzung:</h3>
        <p>Die Webcam zeigt öffentlichen Raum. Es werden keine Personen gezielt aufgenommen. Die Nutzung erfolgt auf eigene Verantwortung.</p>
    </div>
    
    <div style="background: #d1ecf1; padding: 15px; border-radius: 5px; margin: 15px 0;">
        <h3>💬 Chat-Nutzung:</h3>
        <p>Mit der Nutzung des Chats akzeptieren Sie diese Regeln. Verstöße führen zur sofortigen Sperrung. Chat-Nachrichten werden 24 Stunden gespeichert.</p>
    </div>
    
    <div style="background: #f8d7da; padding: 15px; border-radius: 5px; margin: 15px 0;">
        <h3>⚖️ Rechtliches:</h3>
        <p><strong>Haftungsausschluss:</strong> Der Betreiber übernimmt keine Haftung für Inhalte von Nutzern. Jeder Nutzer ist für seine Beiträge selbst verantwortlich.</p>
        <p><strong>Datenschutz:</strong> Es werden nur technisch notwendige Daten gespeichert (IP-Adresse für 24h zur Missbrauchsprävention).</p>
    </div>
    
    <div style="margin-top: 20px; text-align: center;">
        <label style="font-size: 16px;">
            <input type="checkbox" id="accept-rules" style="margin-right: 10px;">
            <strong>Ich akzeptiere die Nutzungsbedingungen</strong>
        </label>
    </div>
    
    <div style="margin-top: 20px; text-align: center;">
        <button onclick="acceptChatRules()" style="background: #4CAF50; color: white; padding: 10px 30px; border: none; border-radius: 5px; font-size: 16px; cursor: pointer;">
            Akzeptieren & Chat nutzen
        </button>
        <button onclick="declineChatRules()" style="background: #f44336; color: white; padding: 10px 30px; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; margin-left: 10px;">
            Ablehnen
        </button>
    </div>
</div>

<!-- Overlay für Modal -->
<div id="modal-overlay" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 9999;"></div>



<!-- CHAT SECTION - PHP AJAX VERSION
<section id="chat" class="section">
    <div class="container">
        <h2 data-en="Live Chat" 
            data-de="Live Chat" 
            data-it="Chat dal Vivo" 
            data-fr="Chat en Direct"
            data-zh="实时聊天">
            Live Chat
        </h2>
        <div id="chat-container" style="background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <div id="chat-messages" style="height: 400px; overflow-y: auto; border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; background: #f9f9f9; border-radius: 5px;">
                Chat-Nachrichten werden hier angezeigt  
            </div>
            <div id="chat-input-container" style="display: flex; gap: 10px;">
                <input type="text" id="chat-username" placeholder="Dein Name" style="flex: 0 0 150px; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
                <input type="text" id="chat-message" placeholder="Nachricht eingeben..." style="flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
                <button id="chat-send" class="button" style="flex: 0 0 100px;">Senden</button>
            </div>
        </div>
    </div>
</section>
 -->





<section id="guestbook" class="section">
    <div class="container">
    <h2 data-en="Guestbook"  data-zh="留言簿" data-de="Gästebuch">Gästebuch</h2>
        <?php 
     if (isset($_SESSION['message'])) {
        echo "<p class='success'>{$_SESSION['message'][$currentLang]}</p>";
        unset($_SESSION['message']);
    }
    if (isset($_SESSION['error'])) {
        echo "<p class='error'>{$_SESSION['error'][$currentLang]}</p>";
        unset($_SESSION['error']);
    }
    
        echo $guestbookManager->displayForm();
        echo $guestbookManager->displayEntries($adminManager->isAdmin());
        ?>
    </div>
</section>


        <section id="kontakt" class="section">
            <div class="container">

                
                
              
    <h2 data-en="Contact" data-de="Kontakt">Kontakt</h2>
    <p data-en="Do you have questions, suggestions, or would you like to support us? We look forward to hearing from you!"   data-zh="您有问题、建议或想要支持我们吗？我们期待收到您的留言！" data-de="Haben Sie Fragen, Anregungen oder möchten uns unterstützen? Wir freuen uns auf Ihre Nachricht!">Haben Sie Fragen, Anregungen oder möchten uns unterstützen? Wir freuen uns auf Ihre Nachricht!</p>
 

                
                
                
                <?php echo $contactManager->displayForm(); ?>
            </div>
        </section>

        <section id="gallery" class="section">
            <div class="container">
            <h2 data-en="Image Gallery" data-de="Bildergalerie"> </h2>

                <div id="gallery-images">
                <?php echo $adminManager->displayGalleryImages(); ?>

        </div>
            </div>
        </section>
        <section id="ueber-uns" class="section">
            
        <div class="container">
        <h2 data-en="About Our Project" data-de="Über unser Projekt" ></h2>

                <div class="about-grid">
                    <div class="about-item">
                    <p 
    data-en="Aurora Weather Livecam is a passion project by weather enthusiasts. We want to bring you closer to the beauty of nature and the fascination of weather." 
    data-de="Aurora Wetter Livecam ist ein Herzensprojekt von Wetterbegeisterten. Wir möchten Ihnen die Schönheit der Natur und Faszination des Wetters näher bringen." data-zh="您有问题、建议或想要支持我们吗？我们期待收到您的留言！"
    data-it="Aurora Weather Livecam è un progetto appassionato di appassionati di meteorologia. Vogliamo avvicinarti alla bellezza della natura e alla fascinazione del clima." 
    data-fr="Aurora Weather Livecam est un projet passionné par des amateurs de météorologie. Nous voulons vous rapprocher de la beauté de la nature et de la fascination pour le climat.">
    Aurora Wetter Livecam ist ein Herzensprojekt von Wetterbegeisterten. Wir möchten Ihnen die Schönheit der Natur und Faszination des Wetters näher bringen.
</p>
<p 
    data-en="For this purpose, we have been operating high-resolution webcams around the clock since 2010. We are particularly proud of unique insights, such as the training flights of the Patrouille Suisse every Monday morning." 
    data-de="Dazu betreiben wir seit 2010 rund um die Uhr hochauflösende Webcams. Besonders stolz sind wir auf einzigartige Einblicke, wie z.B. die Trainingsflüge der Patrouille Suisse jeden Montagmorgen." data-zh="您有问题、建议或想要支持我们吗？我们期待收到您的留言！"
    data-it="Per questo scopo, operiamo webcam ad alta risoluzione 24 ore su 24 dal 2010. Siamo particolarmente orgogliosi di intuizioni uniche, come i voli di addestramento della Patrouille Suisse ogni lunedì mattina." 
    data-fr="À cette fin, nous exploitons des webcams haute résolution 24 heures sur 24 depuis 2010. Nous sommes particulièrement fiers d'avoir des aperçus uniques, tels que les vols d'entraînement de la Patrouille Suisse chaque lundi matin.">
    Dazu betreiben wir seit 2010 rund um die Uhr hochauflösende Webcams. Besonders stolz sind wir auf einzigartige Einblicke, wie z.B. die Trainingsflüge der Patrouille Suisse jeden Montagmorgen.
</p>

              </div>
                </div>



 



                
            </div>
        </section>
        <?php if ($adminManager->isAdmin()): ?>
        <section id="admin" class="section">
            <div class="container">
                <h2>Admin-Bereich</h2>
                <?php echo $adminManager->displayAdminContent(); ?>
            </div>
        </section>
        <?php else: ?>
        <section id="admin-login" class="section">
            <div class="container">
                <h2>Admin Login</h2>
                <?php echo $adminManager->displayLoginForm(); ?>
            </div>
        </section>
        <?php endif; ?>

      


        




    </main>

    <footer>
        <div class="container">
            <div class="footer-links">
                <a href="#webcams">Webcam</a>
                <a href="#guestbook">Gästebuch</a>
                <a href="#kontakt">Kontakt</a>
 
                <a href="#gallery">Galerie</a>
                <a href="#impressum">Impressum</a>

            </div>
            <div class="footer-bottom">
                <p>&copy; 2024 Aurora Wetter Lifecam</p>
            </div>
        </div>
    </footer>



    <script src="https://www.youtube.com/iframe_api"></script>
    <script>
        // Webcam-Player-Logik
        <?php echo $webcamManager->getJavaScript(); ?>

        // Social Media Manager
        function updateSocialMediaLinks() {
            fetch('social_links.json')
                .then(response => response.json())
                .then(data => {
                    const socialLinksContainer = document.getElementById('social-media-links');
                    socialLinksContainer.innerHTML = '';
                    for (const [platform, url] of Object.entries(data)) {
                        const link = document.createElement('a');
                        link.href = url;
                        link.target = '_blank';
                        link.textContent = platform.charAt(0).toUpperCase() + platform.slice(1);
                        socialLinksContainer.appendChild(link);
                    }
                })
                .catch(error => console.error('Error loading social media links:', error));
        }

        // YouTube Audio Player
        var player;
        function onYouTubeIframeAPIReady() {
            player = new YT.Player('audioPlayer', {
                height: '0',
                width: '0',
                videoId: 'WtToep39d2g',
                playerVars: {
                    'autoplay': 1,
                    'controls': 0,
                    'showinfo': 0,
                    'modestbranding': 1,
                    'loop': 1,
                    'playlist': 'WtToep39d2g',
                    'fs': 0,
                    'cc_load_policy': 0,
                    'iv_load_policy': 3,
                    'autohide': 0
                },
                events: {
                    'onReady': onPlayerReady
                }
            });
        }

        // QR-Code Generator
function generateQRCode() {
    var qr = qrcode(0, 'M');
    qr.addData(window.location.href);
    qr.make();
    document.getElementById('qrcode').innerHTML = qr.createImgTag(5);
}

 
        function onPlayerReady(event) {
            event.target.playVideo();
            document.getElementById('playButton').addEventListener('click', function() {
                player.playVideo();
            });
            document.getElementById('pauseButton').addEventListener('click', function() {
                player.pauseVideo();
            });
        }

        // Initialisierung
        document.addEventListener('DOMContentLoaded', function() {
            updateSocialMediaLinks();
            generateQRCode();
        });
    </script>


<script>

document.addEventListener('DOMContentLoaded', function() {
    var modal = document.getElementById('imageModal');
    var modalImg = document.getElementById("modalImage");
    var captionText = document.getElementById("caption");
    var downloadLink = document.getElementById("downloadLink");
    var span = document.getElementsByClassName("close")[0];

    // Fügen Sie einen Klick-Event-Listener zu jedem Bild in der Galerie hinzu
    var images = document.querySelectorAll('#gallery-images img');
    images.forEach(function(img) {
        img.onclick = function() {
            modal.style.display = "block";
            modalImg.src = this.src;
            captionText.innerHTML = this.alt;
            downloadLink.href = this.src;
            downloadLink.download = this.alt || 'download.jpg';
        }
    });

    // Schließen des Modals beim Klick auf (x)
    span.onclick = function() {
        modal.style.display = "none";
    }

    // Schließen des Modals beim Klick außerhalb des Bildes
    window.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = "none";
        }
    }
});
</script>

<script> 
document.addEventListener('DOMContentLoaded', function() {
    var timelapseButton = document.getElementById('timelapse-button');
																				 
    var timelapseViewer = document.getElementById('timelapse-viewer');
    var timelapseImage = document.getElementById('timelapse-image');
    var webcamPlayer = document.getElementById('webcam-player');
    
    var imageFiles = <?php echo $imageFilesJson; ?>;
    var currentImageIndex = 0;
    var timelapseInterval;
							  

    timelapseButton.addEventListener('click', function(e) {
        e.preventDefault();
        toggleTimelapse();
	   

																
						   
							  
    });

    function toggleTimelapse() {
        if (timelapseViewer.style.display === 'none') {
            timelapseViewer.style.display = 'block';
            webcamPlayer.style.display = 'none';
									  
            startTimelapse();
            timelapseButton.textContent = 'Zurück zur Live-Webcam';
																		 
        } else {
            stopTimelapse();
            timelapseViewer.style.display = 'none';
            webcamPlayer.style.display = 'block';
            timelapseButton.textContent = 'Wochenzeitraffer';
																		   
        }
    }

    const imageCache = new Map();
    const preloadBuffer = 5; // Anzahl der im Voraus zu ladenden Bilder


    async function startTimelapse() {
        console.log("startTimelapse wurde aufgerufen");
        if (imageFiles.length === 0) {
            console.log("Keine Bilder gefunden");
            return;
        }
        
        const displayDuration = 20.83; // Millisekunden pro Bild
        console.log(`Anzeigedauer pro Bild: ${displayDuration} ms`);
        
        async function showNextImage() {
            console.log(`Aktueller Bildindex: ${currentImageIndex}`);
            while (currentImageIndex < imageFiles.length) {
                const currentImage = imageFiles[currentImageIndex];
                console.log(`Verarbeite Bild: ${currentImage}`);
                
        const filename = currentImage.split('/').pop();
                const timeMatch = filename.match(/screenshot_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/);
                if (timeMatch) {
                    const [_, year, month, day, hour, minute, second] = timeMatch;
                    const dateStr = `${day}.${month}.${year} ${hour}:${minute}:${second}`;
                    
                    // Zeit-Overlay erstellen oder aktualisieren
                    let timeOverlay = document.getElementById('timelapse-time-overlay');
                    if (!timeOverlay) {
                        timeOverlay = document.createElement('div');
                        timeOverlay.id = 'timelapse-time-overlay';
                        timeOverlay.style.cssText = `
                            position: absolute;
                            top: 20px;
                            left: 20px;
                            background: rgba(0,0,0,0.7);
                            color: white;
                            padding: 10px 15px;
                            border-radius: 5px;
                            font-size: 18px;
                            font-weight: bold;
                            z-index: 100;
                            font-family: monospace;
                        `;
                        document.getElementById('timelapse-viewer').appendChild(timeOverlay);
                    }
                    timeOverlay.textContent = dateStr;
                }


                // Lazy Loading
                for (let i = currentImageIndex; i < currentImageIndex + preloadBuffer && i < imageFiles.length; i++) {
                    if (!imageCache.has(imageFiles[i])) {
                        console.log(`Lade Bild in Cache: ${imageFiles[i]}`);
                        imageCache.set(imageFiles[i], getImageData(imageFiles[i]));
                    }
                }
                
			
                try {
                    const imageData = await imageCache.get(currentImage);
                    if (!isGreyImage(imageData)) {
                        console.log(`Zeige Bild an: ${currentImage}`);
                        timelapseImage.src = currentImage;
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
            while (timelapseViewer.style.display !== 'none') {
                await showNextImage();
            }
            console.log("Zeitraffer beendet");
        }
										  
	 

        runTimelapse().catch(error => console.error("Fehler im Zeitraffer:", error));
    
 
}
	
function updateTimelapseImage() {
    timelapseImage.src = imageFiles[currentImageIndex];
    timelapseSlider.value = currentImageIndex;
    updateTimeDisplay();
}

function updateTimeDisplay() {
    var date = new Date(imageFiles[currentImageIndex].match(/(\d{8}_\d{6})/)[1].replace(/_/g, 'T'));
    timelapseTime.textContent = date.toLocaleString();
}
// Modifizierte getImageData-Funktion für Caching
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


    function stopTimelapse() {
        clearInterval(timelapseInterval);
        currentImageIndex = 0;
    }
 
    function isGreyImage(imageData) {
    const data = imageData.data;
    const tolerance = 10;  
    const sampleSize = Math.min(data.length / 4, 1000); //  Deine Grossmutter

    for (let i = 0; i < sampleSize; i++) {
        const index = i * 4;
        const r = data[index];
        const g = data[index + 1];
        const b = data[index + 2];

        // Prüfen Sie, ob die Farbwerte innerhalb der Toleranz liegen ->  wers glaubt !
        if (Math.abs(r - g) > tolerance || Math.abs(r - b) > tolerance || Math.abs(g - b) > tolerance) {
            return false; // Das Bild ist nicht grau
        }
    }
    return true; // Das Bild ist grau, aber natürlich :)
}
 
function isSunnyImage(imageData) {
    const data = imageData.data;
    const width = imageData.width;
    const height = imageData.height;
   						  
    // Nur den oberen Drittel des Bildes analysieren 
    const searchHeight = Math.floor(height / 3);
    
    // Gopfertamsiech namal !!!!!
    const yellowThreshold = {
        red: 200,
        green: 200,
        blue: 50
    };
    
    // Mindestgröße für die Sonne (in Pixeln)
    const minSunSize = 20;
    
    let sunPixels = 0;
    
    for (let y = 0; y < searchHeight; y++) {
        for (let x = 0; x < width; x++) {
            const index = (y * width + x) * 4;
            const r = data[index];
            const g = data[index + 1];
            const b = data[index + 2];
            
            // Prüfen, ob der Pixel gelb ist
            if (r > yellowThreshold.red && g > yellowThreshold.green && b < yellowThreshold.blue) {
                sunPixels++;
            }
        }
    }
    
    // Als sonnig betrachten, wenn genügend gelbe Pixel gefunden wurden
    return sunPixels > minSunSize * minSunSize;
}
});
    </script>
<script>
document.addEventListener('DOMContentLoaded', function() {
    var qrCodeElement = document.getElementById('qrcode');
    qrCodeElement.addEventListener('click', function() {
    var url = this.getAttribute('data-url');
    navigator.clipboard.writeText(url).then(function() {
        var currentLang = getCurrentLanguage(); // Funktion zum Abrufen der aktuellen Sprache
        var messages = {
            'en': 'QR Code URL has been copied to the clipboard!',
            'de': 'QR-Code-URL wurde in die Zwischenablage kopiert!',
            'it': 'L\'URL del QR Code è stata copiata negli appunti!',
            'fr': 'L\'URL du QR Code a été copiée dans le presse-papiers!'
        };
        alert(messages[currentLang] || messages['en']);
    }, function(err) {
        console.error('Fehler beim Kopieren: ', err);
		   
    });
});

});
</script>
<div id="imageModal" class="modal">
  <span class="close">&times;</span>
  <img class="modal-content" id="modalImage">
  <div id="caption"></div>
  <a id="downloadLink" href="#" download class="download-btn">Download</a>
</div>


<section id="impressum" class="section">
    <div class="container">
    <h2 
    data-en="Imprint" 
    data-de="Impressum" 
    data-it="Impressum"   data-zh="版本说明"
    data-fr="Mentions Légales">
    Impressum
</h2>
<p>Aurora Wetter Livecam</p>
<p>M. Kessler</p>
<p>Dürnten </p>
<p>Schweiz</p>
<p 
    data-en="Inquiries via contact form" 
    data-de="Anfragen per Kontaktformular" 
    data-it="Richieste tramite modulo di contatto"  data-zh="您有问题、建议或想要支持我们吗？我们期待收到您的留言！"
    data-fr="Demandes via formulaire de contact">
    Anfragen per Kontaktformular
</p>
<p 
    data-en="Content responsible: " 
    data-de="Verantwortlich für den Inhalt: " 
    data-it="Responsabile dei contenuti:  " 
    data-fr="Responsable du contenu : ">
    
</p>

    </div>
</section>


<script>
 document.addEventListener('DOMContentLoaded', function() {
    const langButtons = document.querySelectorAll('.lang-button');
    
    langButtons.forEach(button => {
        button.addEventListener('click', function() {
            const lang = this.id.split('-')[1]; // 'de' oder 'en'
            setLanguage(lang);
            
            // Aktiven Button markieren
            langButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
        });
    });
});

function setLanguage(lang) {
    document.querySelectorAll('[data-en], [data-de], [data-it], [data-fr], [data-zh]').forEach(elem => {
        const text = elem.getAttribute(`data-${lang}`);
        if (text) {
            elem.textContent = text;
        }
    });
}



  </script>











<script>
document.addEventListener('DOMContentLoaded', function() {
    const yearSelect = document.getElementById('calendar_year');
    const monthSelect = document.getElementById('calendar_month');
    
    if (yearSelect && monthSelect) {
        yearSelect.addEventListener('change', function() {
            // Formular bei Änderung des Jahres absenden
            this.form.submit();
        });
    }
});
</script>

 <script>
// PHP AJAX Chat (ersetzt WebSocket)
document.addEventListener('DOMContentLoaded', function() {
    const chatMessages = document.getElementById('chat-messages');
    const chatUsername = document.getElementById('chat-username');
    const chatMessage = document.getElementById('chat-message');
    const chatSend = document.getElementById('chat-send');
    
    let lastMessageCount = 0;
    
    // Nachrichten anzeigen
    function displayMessage(data) {
        const messageDiv = document.createElement('div');
        messageDiv.style.marginBottom = '10px';
        messageDiv.style.padding = '8px';
        messageDiv.style.backgroundColor = '#fff';
        messageDiv.style.borderRadius = '5px';
        
        const timestamp = new Date(data.timestamp).toLocaleTimeString('de-CH', {
            hour: '2-digit',
            minute: '2-digit'
        });
        
        messageDiv.innerHTML = `
            <strong>${data.username}:</strong> ${data.message}
            <small style="float: right; color: #999;">${timestamp}</small>
        `;
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
    
    // Nachrichten laden
    function loadMessages() {
        fetch('/chat_ajax.php')
            .then(response => response.json())
            .then(messages => {
                if (messages.length !== lastMessageCount) {
                    chatMessages.innerHTML = '';
                    messages.slice(-50).forEach(msg => displayMessage(msg));
                    lastMessageCount = messages.length;
                }
            })
            .catch(err => console.log('Chat-Fehler:', err));
    }
    
    // Nachricht senden
    function sendMessage() {
        const username = chatUsername.value.trim() || 'Anonym';
        const message = chatMessage.value.trim();
        
        if (message) {
            const formData = new FormData();
            formData.append('username', username);
            formData.append('message', message);
            
            fetch('/chat_ajax.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    chatMessage.value = '';
                    loadMessages(); // Sofort aktualisieren
                }
            });
        }
    }
    
    // Event Listener
    if (chatSend) {
        chatSend.addEventListener('click', sendMessage);
    }
    
    if (chatMessage) {
        chatMessage.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') sendMessage();
        });
    }
    
    // Initial laden und alle 2 Sekunden aktualisieren
    loadMessages();
    setInterval(loadMessages, 2000);
});
</script>


<script>
function changeMonth(year, month) {
    if (month < 1) {
        month = 12;
        year--;
    } else if (month > 12) {
        month = 1;
        year++;
    }
    window.location.href = '?cal_year=' + year + '&cal_month=' + month + '#archive';
}

function selectDay(year, month, day) {
    window.location.href = '?cal_year=' + year + '&cal_month=' + month + '&cal_day=' + day + '#archive';
}









// Weather Bingo JavaScript
const bingoData = {
    challenges: {
        'rainbow': {de: '🌈 Regenbogen', points: 50},
        'fog': {de: '🌫️ Nebel', points: 20},
        'sunrise': {de: '🌅 Sonnenaufgang', points: 30},
        'sunset': {de: '🌆 Sonnenuntergang', points: 30},
        'snow': {de: '❄️ Schnee', points: 40},
        'storm': {de: '⛈️ Gewitter', points: 60},
        'plane': {de: '✈️ Flugzeug', points: 25},
        'patrouille': {de: '🇨🇭 Patrouille Suisse', points: 100},
        'birds': {de: '🦅 Vogelschwarm', points: 15},
        'fullmoon': {de: '🌕 Vollmond', points: 35}
    },
    selectedPredictions: []
};

function loadDailyChallenges() {
    const challenges = ['rainbow', 'fog', 'sunrise', 'plane', 'birds']; // Beispiel
    const container = document.getElementById('challenges-list');
    
    container.innerHTML = challenges.map(key => `
        <div class="challenge-item" data-event="${key}" onclick="toggleChallenge('${key}')">
            <span>${bingoData.challenges[key].de}</span>
            <span class="challenge-points">${bingoData.challenges[key].points} Punkte</span>
        </div>
    `).join('');
}

function toggleChallenge(event) {
    const item = document.querySelector(`[data-event="${event}"]`);
    if (bingoData.selectedPredictions.includes(event)) {
        bingoData.selectedPredictions = bingoData.selectedPredictions.filter(e => e !== event);
        item.classList.remove('selected');
    } else {
        if (bingoData.selectedPredictions.length < 3) {
            bingoData.selectedPredictions.push(event);
            item.classList.add('selected');
        } else {
            alert('Maximal 3 Vorhersagen möglich!');
        }
    }
}

function submitPredictions() {
    const username = document.getElementById('bingo-username').value || 'Anonym';
    
    if (bingoData.selectedPredictions.length === 0) {
        alert('Bitte wähle mindestens eine Vorhersage!');
        return;
    }
    
    fetch('weather_bingo.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `action=submit_prediction&username=${username}&predictions[]=${bingoData.selectedPredictions.join('&predictions[]=')}`
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            alert('Vorhersage gespeichert! Viel Glück!');
            loadLeaderboard();
        }
    });
}

function loadLeaderboard() {
    // Tagesrangliste
    fetch('weather_bingo.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'action=get_leaderboard&period=today'
    })
    .then(r => r.json())
    .then(data => {
        const container = document.getElementById('daily-leaderboard');
        let html = '';
        let rank = 1;
        for (const [username, score] of Object.entries(data)) {
            html += `<div class="leaderboard-entry">
                <span>${rank}. ${username}</span>
                <span>${score} Punkte</span>
            </div>`;
            rank++;
            if (rank > 10) break;
        }
        container.innerHTML = html || '<p>Noch keine Einträge heute</p>';
    });
}

//chat agb
// Chat-Regeln Management
function checkChatRules() {
    if (!localStorage.getItem('chatRulesAccepted')) {
        document.getElementById('chat-rules-modal').style.display = 'block';
        document.getElementById('modal-overlay').style.display = 'block';
        document.getElementById('chat-input').disabled = true;
        document.getElementById('chat-send').disabled = true;
    }
}

function acceptChatRules() {
    if (document.getElementById('accept-rules').checked) {
        localStorage.setItem('chatRulesAccepted', 'true');
        localStorage.setItem('rulesAcceptedDate', new Date().toISOString());
        document.getElementById('chat-rules-modal').style.display = 'none';
        document.getElementById('modal-overlay').style.display = 'none';
        document.getElementById('chat-input').disabled = false;
        document.getElementById('chat-send').disabled = false;
        
        // Willkommensnachricht
        addChatMessage('System', 'Willkommen im Chat! Bitte verhalten Sie sich respektvoll.', true);
    } else {
        alert('Bitte akzeptieren Sie die Nutzungsbedingungen, um den Chat zu nutzen.');
    }
}

function declineChatRules() {
    document.getElementById('chat-rules-modal').style.display = 'none';
    document.getElementById('modal-overlay').style.display = 'none';
    document.getElementById('chat-container').innerHTML = 
        '<div style="padding: 20px; text-align: center; color: #666;">Chat-Nutzung wurde abgelehnt. Bitte laden Sie die Seite neu, wenn Sie den Chat nutzen möchten.</div>';
}

// Beim Laden prüfen
document.addEventListener('DOMContentLoaded', function() {
    checkChatRules();
    
    // Regeln alle 30 Tage erneuern
    const acceptedDate = localStorage.getItem('rulesAcceptedDate');
    if (acceptedDate) {
        const daysSince = (new Date() - new Date(acceptedDate)) / (1000 * 60 * 60 * 24);
        if (daysSince > 30) {
            localStorage.removeItem('chatRulesAccepted');
            localStorage.removeItem('rulesAcceptedDate');
            checkChatRules();
        }
    }
});

// Wort-Filter für unangemessene Inhalte
const bannedWords = ['sex', 'porn', 'xxx', 'nude']; // Erweitern Sie diese Liste

function filterMessage(message) {
    let filtered = message.toLowerCase();
    for (const word of bannedWords) {
        if (filtered.includes(word)) {
            return false; // Nachricht blockieren
        }
    }
    return true;
}

// In der sendMessage Funktion einbauen:
function sendMessage() {
    const input = document.getElementById('chat-input');
    const message = input.value.trim();
    
    if (message && filterMessage(message)) {
        // Nachricht senden
    } else if (!filterMessage(message)) {
        alert('Ihre Nachricht enthält unzulässige Inhalte und wurde blockiert.');
        input.value = '';
    }
}






// Initialisierung
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('challenges-list')) {
        loadDailyChallenges();
        loadLeaderboard();
        setInterval(loadLeaderboard, 30000); // Update alle 30 Sekunden
        
        document.getElementById('submit-predictions')?.addEventListener('click', submitPredictions);
    }
});

















</script>









<div style="text-align: center; padding: 20px; background: #f5f5f5; margin-top: 50px;">
    <a href="#" onclick="document.getElementById('chat-rules-modal').style.display='block'; document.getElementById('modal-overlay').style.display='block'; return false;">
        Nutzungsbedingungen & Chat-Regeln
    </a> | 
    <a href="#" onclick="alert('Kontakt: admin@aurora-webcam.ch'); return false;">Kontakt</a> | 
    <a href="#" onclick="alert('Missbrauch melden: abuse@aurora-webcam.ch'); return false;">Missbrauch melden</a>
</div>





<script>
// Kontaktformular AJAX-Handler
document.addEventListener('DOMContentLoaded', function() {
    const contactForm = document.getElementById('contact-form');
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const feedback = document.getElementById('contact-feedback');
            const submitBtn = this.querySelector('button[type="submit"]');
            
            // Loading State
            submitBtn.disabled = true;
            submitBtn.textContent = '⏳ Wird gesendet...';
            feedback.innerHTML = '<p style="color: #666;">⏳ Nachricht wird gesendet...</p>';
            
            fetch(window.location.href, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    feedback.innerHTML = `<p style="color: #4CAF50; padding: 15px; background: #e8f5e9; border-radius: 5px;">✓ ${data.message}</p>`;
                    contactForm.reset();
                } else {
                    feedback.innerHTML = `<p style="color: #f44336; padding: 15px; background: #ffebee; border-radius: 5px;">✗ ${data.message}</p>`;
                }
            })
            .catch(error => {
                feedback.innerHTML = '<p style="color: #f44336; padding: 15px; background: #ffebee; border-radius: 5px;">✗ Fehler beim Senden. Bitte versuchen Sie es später erneut.</p>';
                console.error('Fehler:', error);
            })
            .finally(() => {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Nachricht senden';
            });
        });
    }
});
</script>





</body>
</html>
