<?php
$recipient = 'meinemail@mail.ch';
$errors = [];
$successMessage = '';

function ensureDirectory(string $path): void
{
    if (!is_dir($path)) {
        mkdir($path, 0775, true);
    }
}

function sanitizeFileName(string $name): string
{
    $name = preg_replace('/[^A-Za-z0-9_.-]/', '_', $name);
    return substr($name, 0, 150);
}

function handleUpload(string $field, string $targetDir, array &$errors): ?array
{
    if (!isset($_FILES[$field]) || $_FILES[$field]['error'] === UPLOAD_ERR_NO_FILE) {
        return null;
    }

    $file = $_FILES[$field];
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $errors[] = 'Beim Hochladen der Datei "' . htmlspecialchars($file['name']) . '" ist ein Fehler aufgetreten.';
        return null;
    }

    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mimeType = $finfo->file($file['tmp_name']);
    $allowedTypes = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/webp' => 'webp',
        'image/gif'  => 'gif'
    ];

    if (!array_key_exists($mimeType, $allowedTypes)) {
        $errors[] = 'Die Datei "' . htmlspecialchars($file['name']) . '" ist kein unterstütztes Bildformat.';
        return null;
    }

    ensureDirectory($targetDir);
    $extension = $allowedTypes[$mimeType];
    $filename = sanitizeFileName(pathinfo($file['name'], PATHINFO_FILENAME));
    if ($filename === '') {
        $filename = 'upload_' . time();
    }
    $destination = rtrim($targetDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $filename . '_' . uniqid() . '.' . $extension;

    if (!move_uploaded_file($file['tmp_name'], $destination)) {
        $errors[] = 'Die Datei "' . htmlspecialchars($file['name']) . '" konnte nicht gespeichert werden.';
        return null;
    }

    return [
        'path' => $destination,
        'original' => $file['name'],
        'type' => $mimeType
    ];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $company = trim($_POST['company'] ?? '');
    $contactEmail = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL) ? $_POST['email'] : '';
    $website = trim($_POST['website'] ?? '');
    $message = trim($_POST['message'] ?? '');
    $bannerLink = trim($_POST['banner_link'] ?? '');

    if ($company === '') {
        $errors[] = 'Bitte geben Sie den Namen Ihres Unternehmens oder Projekts an.';
    }

    if ($contactEmail === '') {
        $errors[] = 'Bitte geben Sie eine gültige E-Mail-Adresse an.';
    }

    if ($bannerLink === '') {
        $errors[] = 'Bitte geben Sie den Link an, der Ihrem Banner zugeordnet werden soll.';
    }

    $uploadedImage = handleUpload('project_image', __DIR__ . '/uploads/images', $errors);
    $uploadedBanner = handleUpload('banner_image', __DIR__ . '/uploads/banners', $errors);

    if (!$errors) {
        $boundary = '=_TinyHome_' . md5((string) microtime(true));
        $headers = [];
        $fromAddress = $contactEmail ?: 'no-reply@tinyhome.local';
        $headers[] = 'From: ' . $fromAddress;
        $headers[] = 'Reply-To: ' . $fromAddress;
        $headers[] = 'MIME-Version: 1.0';
        $headers[] = 'Content-Type: multipart/mixed; boundary="' . $boundary . '"';

        $bodyParts = [];
        $text = "Neue TinyHome-Anfrage\n\n";
        $text .= "Unternehmen/Projekt: $company\n";
        $text .= "Kontakt-E-Mail: $contactEmail\n";
        if ($website !== '') {
            $text .= "Website: $website\n";
        }
        $text .= "Banner-Link: $bannerLink\n\n";
        if ($message !== '') {
            $text .= "Nachricht:\n$message\n\n";
        }
        if ($uploadedImage) {
            $text .= 'Projektbild gespeichert unter: ' . $uploadedImage['path'] . "\n";
        }
        if ($uploadedBanner) {
            $text .= 'Banner gespeichert unter: ' . $uploadedBanner['path'] . "\n";
        }

        $bodyParts[] = '--' . $boundary;
        $bodyParts[] = 'Content-Type: text/plain; charset="UTF-8"';
        $bodyParts[] = 'Content-Transfer-Encoding: 8bit';
        $bodyParts[] = '';
        $bodyParts[] = $text;

        foreach ([$uploadedImage, $uploadedBanner] as $upload) {
            if (!$upload) {
                continue;
            }
            $fileContent = file_get_contents($upload['path']);
            if ($fileContent === false) {
                $errors[] = 'Die Datei "' . htmlspecialchars($upload['original']) . '" konnte nicht für den Mailversand gelesen werden.';
                continue;
            }
            $bodyParts[] = '--' . $boundary;
            $bodyParts[] = 'Content-Type: ' . $upload['type'] . '; name="' . sanitizeFileName($upload['original']) . '"';
            $bodyParts[] = 'Content-Transfer-Encoding: base64';
            $bodyParts[] = 'Content-Disposition: attachment; filename="' . sanitizeFileName($upload['original']) . '"';
            $bodyParts[] = '';
            $bodyParts[] = chunk_split(base64_encode($fileContent));
        }

        $bodyParts[] = '--' . $boundary . '--';
        $body = implode("\r\n", $bodyParts);

        if (!$errors) {
            $mailSent = mail(
                $recipient,
                'Neue TinyHome-Anfrage von ' . $company,
                $body,
                implode("\r\n", $headers)
            );

            if ($mailSent) {
                $successMessage = 'Vielen Dank! Ihre Anfrage wurde erfolgreich übermittelt.';
            } else {
                $errors[] = 'Ihre Anfrage konnte leider nicht versendet werden. Bitte versuchen Sie es später erneut.';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TinyHome Plattform – Natürlich. Minimalistisch. Erschwinglich.</title>
    <style>
        :root {
            --bg: #f5f5f1;
            --accent: #3b755f;
            --accent-dark: #2f5c4b;
            --text: #2b2b28;
            --muted: #6a6a66;
            --card: rgba(255, 255, 255, 0.9);
            font-size: 16px;
        }
        * {
            box-sizing: border-box;
        }
        body {
            margin: 0;
            font-family: 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }
        header {
            background: linear-gradient(135deg, rgba(59,117,95,0.9), rgba(143,170,119,0.85)), url('https://images.unsplash.com/photo-1523419409543-0c1df022bdd7?auto=format&fit=crop&w=1600&q=80') center/cover no-repeat;
            color: #fff;
            padding: 6rem 1.5rem;
            position: relative;
            overflow: hidden;
        }
        header::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(47,92,75,0.45);
        }
        .header-content {
            position: relative;
            max-width: 960px;
            margin: 0 auto;
            text-align: left;
        }
        h1 {
            font-size: clamp(2.5rem, 4vw, 3.5rem);
            margin-bottom: 1rem;
            letter-spacing: 0.05em;
        }
        .subtitle {
            font-size: 1.2rem;
            max-width: 640px;
            margin-bottom: 2.5rem;
            color: rgba(255,255,255,0.9);
        }
        .cta {
            display: inline-flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.9rem 1.6rem;
            background: #fff;
            color: var(--accent);
            font-weight: 600;
            border-radius: 999px;
            text-decoration: none;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        .cta:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 22px rgba(0,0,0,0.18);
        }
        main {
            max-width: 1100px;
            margin: -4rem auto 0;
            padding: 0 1.5rem 4rem;
        }
        .card {
            background: var(--card);
            border-radius: 20px;
            padding: 2.5rem;
            box-shadow: 0 20px 40px rgba(47,92,75,0.12);
            margin-bottom: 3rem;
            backdrop-filter: blur(10px);
        }
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
        }
        .feature {
            background: rgba(255,255,255,0.8);
            border-radius: 18px;
            padding: 1.75rem;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.4);
        }
        .feature h3 {
            margin-top: 0;
            font-size: 1.25rem;
            color: var(--accent);
        }
        .form-grid {
            display: grid;
            gap: 1.5rem;
        }
        .form-group {
            display: flex;
            flex-direction: column;
            gap: 0.6rem;
        }
        label {
            font-weight: 600;
            color: var(--accent-dark);
        }
        input[type="text"],
        input[type="email"],
        input[type="url"],
        textarea,
        input[type="file"] {
            padding: 0.85rem 1rem;
            border: 1px solid rgba(47,92,75,0.2);
            border-radius: 10px;
            background: rgba(255,255,255,0.9);
            font-size: 1rem;
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
        }
        input:focus,
        textarea:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(59,117,95,0.2);
        }
        textarea {
            min-height: 140px;
            resize: vertical;
        }
        .submit-btn {
            align-self: flex-start;
            padding: 0.9rem 2.2rem;
            border: none;
            border-radius: 999px;
            background: var(--accent);
            color: #fff;
            font-size: 1.05rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s ease, transform 0.3s ease;
        }
        .submit-btn:hover {
            background: var(--accent-dark);
            transform: translateY(-2px);
        }
        .notice {
            margin-bottom: 1.5rem;
            padding: 1rem 1.5rem;
            border-radius: 12px;
            background: rgba(47,92,75,0.1);
            color: var(--accent-dark);
        }
        .notice.error {
            background: rgba(180,58,58,0.12);
            color: #8e2a2a;
        }
        footer {
            background: #1f2e27;
            color: rgba(255,255,255,0.85);
            padding: 2.5rem 1.5rem;
        }
        .footer-content {
            max-width: 1100px;
            margin: 0 auto;
            display: grid;
            gap: 1.5rem;
        }
        .agb {
            background: rgba(255,255,255,0.08);
            padding: 1.5rem;
            border-radius: 14px;
        }
        .agb h3 {
            margin-top: 0;
        }
        @media (min-width: 768px) {
            .form-grid {
                grid-template-columns: repeat(2, minmax(0,1fr));
            }
            .form-grid .form-group.full-width {
                grid-column: span 2;
            }
        }
    </style>
</head>
<body>
<header>
    <div class="header-content">
        <h1>TinyHome Plattform</h1>
        <p class="subtitle">Minimalistisches Wohnen im Einklang mit der Natur – wir verbinden Hersteller, Planer:innen und Menschen, die erschwingliche, hochwertige Tiny Houses suchen.</p>
        <a class="cta" href="#kontakt">Jetzt Projekt einreichen</a>
    </div>
</header>
<main>
    <section class="card">
        <h2>Warum TinyHomes?</h2>
        <div class="features">
            <div class="feature">
                <h3>Naturnah leben</h3>
                <p>Unsere Plattform bündelt Anbieter, die nachhaltige Materialien und ökologische Bauweisen priorisieren.</p>
            </div>
            <div class="feature">
                <h3>Minimale Baukosten</h3>
                <p>Smarter Grundriss, effiziente Energie, faire Preise: TinyHomes machen Wohnen wieder erschwinglich.</p>
            </div>
            <div class="feature">
                <h3>Flexibel kombinierbar</h3>
                <p>Vom Wochenend-Retreat bis zum ganzjährigen Zuhause – konfigurieren Sie Ihr TinyHome passend zu Ihrem Lebensstil.</p>
            </div>
            <div class="feature">
                <h3>Direkter Kontakt</h3>
                <p>Sie erhalten maßgeschneiderte Angebote von geprüften Hersteller:innen aus der DACH-Region.</p>
            </div>
        </div>
    </section>

    <section class="card" id="kontakt">
        <h2>Projekt vorstellen &amp; Banner übermitteln</h2>
        <p>Übermitteln Sie uns Ihr TinyHome-Konzept – inklusive Banner-Link, damit wir Bestellungen eindeutig zuordnen können. Wir melden uns persönlich bei Ihnen.</p>

        <?php if ($successMessage !== ''): ?>
            <div class="notice"><?php echo htmlspecialchars($successMessage, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>

        <?php if ($errors): ?>
            <div class="notice error">
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <form method="post" enctype="multipart/form-data" class="form-grid">
            <div class="form-group">
                <label for="company">Unternehmen / Projekt*</label>
                <input type="text" id="company" name="company" value="<?php echo htmlspecialchars($_POST['company'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>
            </div>
            <div class="form-group">
                <label for="email">E-Mail*</label>
                <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($_POST['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>
            </div>
            <div class="form-group">
                <label for="website">Website</label>
                <input type="url" id="website" name="website" placeholder="https://" value="<?php echo htmlspecialchars($_POST['website'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
            </div>
            <div class="form-group">
                <label for="banner_link">Banner-Link (Tracking)*</label>
                <input type="url" id="banner_link" name="banner_link" placeholder="https://ihr-tracking-link" value="<?php echo htmlspecialchars($_POST['banner_link'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>
            </div>
            <div class="form-group">
                <label for="project_image">Projektbild (JPG, PNG, WEBP, GIF)</label>
                <input type="file" id="project_image" name="project_image" accept="image/*">
            </div>
            <div class="form-group">
                <label for="banner_image">Banner (JPG, PNG, WEBP, GIF)</label>
                <input type="file" id="banner_image" name="banner_image" accept="image/*">
            </div>
            <div class="form-group full-width">
                <label for="message">Botschaft an uns</label>
                <textarea id="message" name="message" placeholder="Was macht Ihr TinyHome besonders?"><?php echo htmlspecialchars($_POST['message'] ?? '', ENT_QUOTES, 'UTF-8'); ?></textarea>
            </div>
            <button type="submit" class="submit-btn">Anfrage absenden</button>
        </form>
    </section>
</main>
<footer>
    <div class="footer-content">
        <div>
            <h3>Kontakt</h3>
            <p>TinyHome Plattform<br>Für weitere Fragen: <a href="mailto:meinemail@mail.ch" style="color:#fff; text-decoration: underline;">meinemail@mail.ch</a></p>
        </div>
        <div class="agb">
            <h3>AGB (Schweiz)</h3>
            <p>1. Geltungsbereich: Diese Allgemeinen Geschäftsbedingungen gelten für alle Leistungen der TinyHome Plattform mit Sitz in der Schweiz. Maßgebend ist die jeweils aktuelle Version zum Zeitpunkt des Vertragsschlusses.</p>
            <p>2. Leistungen: Wir vermitteln TinyHome-Hersteller:innen und Interessent:innen. Ein Vertrag über Planung oder Bau kommt ausschließlich zwischen Anbieter:in und Kund:in zustande. Preise verstehen sich in Schweizer Franken (CHF), sofern nicht anders vereinbart.</p>
            <p>3. Haftung: Für Inhalte und Angebote der angeschlossenen Hersteller:innen übernehmen wir keine Haftung. Eigene Haftung wird auf vorsätzliches oder grob fahrlässiges Verhalten beschränkt. Die Plattform haftet nicht für indirekte Schäden, Mangelfolgeschäden oder entgangenen Gewinn.</p>
            <p>4. Datenschutz: Personenbezogene Daten werden gemäß schweizerischem Datenschutzrecht (insbesondere DSG) verarbeitet. Daten werden nur an beteiligte Anbieter:innen weitergegeben, sofern dies für die Vermittlung erforderlich ist.</p>
            <p>5. Zahlungsbedingungen: Vermittlungs- oder Servicegebühren werden gesondert vereinbart und sind binnen 30 Tagen zahlbar. Bei Zahlungsverzug fallen Verzugszinsen in gesetzlicher Höhe sowie Mahngebühren an.</p>
            <p>6. Widerruf &amp; Stornierung: Widerrufs- oder Rücktrittsrechte richten sich nach den individuellen Vereinbarungen zwischen Kund:in und Hersteller:in. Die Plattform bietet Unterstützung bei der Klärung von Streitfällen, übernimmt jedoch keine rechtliche Vertretung.</p>
            <p>7. Gerichtsstand &amp; Recht: Es gilt ausschließlich schweizerisches Recht. Gerichtsstand ist der Sitz der TinyHome Plattform, sofern zwingende gesetzliche Bestimmungen nichts anderes vorsehen.</p>
        </div>
        <p style="font-size:0.9rem; color: rgba(255,255,255,0.7);">© <?php echo date('Y'); ?> TinyHome Plattform. Alle Rechte vorbehalten.</p>
    </div>
</footer>
</body>
</html>
