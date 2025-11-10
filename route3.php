<?php
$host = $_GET['host'] ?? '';
$traceData = [];
$error = '';
$rawOutput = '';

if ($host !== '') {
    $sanitizedHost = preg_replace('/[^A-Za-z0-9\-\.:]/', '', $host);
    if ($sanitizedHost === '') {
        $error = 'Bitte geben Sie einen gültigen Hostnamen oder eine IP-Adresse ein.';
    } else {
        $command = 'traceroute -n ' . escapeshellarg($sanitizedHost) . ' 2>&1';
        $rawOutput = shell_exec($command);
        if ($rawOutput === null) {
            $error = 'Traceroute konnte nicht ausgeführt werden. Ist das Kommando verfügbar?';
        } else {
            $traceData = parseTraceroute($rawOutput);
            if (empty($traceData)) {
                $error = 'Keine Hops gefunden. Prüfen Sie den Hostnamen oder versuchen Sie es später erneut.';
            }
        }
    }
}

if (empty($traceData)) {
    $traceData = getSampleTrace();
    if ($error === '') {
        $error = 'Es werden Beispieldaten angezeigt. Starten Sie eine Abfrage, um echte Traceroute-Daten zu sehen.';
    }
}

$positions = generateHelixLayout(count($traceData));
$traceWithPositions = array_map(function ($hop, $index) use ($positions) {
    return $hop + [
        'position' => $positions[$index] ?? ['x' => 0, 'y' => 0, 'z' => 0],
    ];
}, $traceData, array_keys($traceData));

function parseTraceroute(string $raw): array
{
    $lines = preg_split('/\r?\n/', trim($raw));
    if (!$lines) {
        return [];
    }

    $hops = [];
    foreach ($lines as $line) {
        if (!preg_match('/^\s*(\d+)\s+(.+)/', $line, $parts)) {
            continue;
        }

        $hopNumber = (int) $parts[1];
        $rest = $parts[2];

        preg_match('/([0-9a-fA-F:\.\-]+|\*)/', $rest, $ipMatch);
        $ip = $ipMatch[1] ?? '*';
        $ip = $ip === '*' ? 'Zeitüberschreitung' : $ip;

        preg_match_all('/(\d+\.\d+)\s+ms/', $rest, $latencyMatches);
        $latencies = array_map('floatval', $latencyMatches[1] ?? []);
        $avgLatency = !empty($latencies) ? round(array_sum($latencies) / count($latencies), 2) : null;

        $hops[] = [
            'hop' => $hopNumber,
            'ip' => $ip,
            'avgLatency' => $avgLatency,
            'raw' => trim($line),
        ];
    }

    return $hops;
}

function getSampleTrace(): array
{
    return [
        ['hop' => 1, 'ip' => '192.168.0.1', 'avgLatency' => 1.23, 'raw' => '1  192.168.0.1  1.12 ms  1.20 ms  1.38 ms'],
        ['hop' => 2, 'ip' => '10.12.34.1', 'avgLatency' => 9.87, 'raw' => '2  10.12.34.1  9.44 ms  9.90 ms  10.29 ms'],
        ['hop' => 3, 'ip' => '172.16.5.4', 'avgLatency' => 18.54, 'raw' => '3  172.16.5.4  18.12 ms  18.45 ms  18.71 ms'],
        ['hop' => 4, 'ip' => '198.51.100.12', 'avgLatency' => 27.42, 'raw' => '4  198.51.100.12  27.03 ms  27.54 ms  27.68 ms'],
        ['hop' => 5, 'ip' => '203.0.113.5', 'avgLatency' => 36.18, 'raw' => '5  203.0.113.5  35.82 ms  36.19 ms  36.52 ms'],
        ['hop' => 6, 'ip' => '93.184.216.34', 'avgLatency' => 48.91, 'raw' => '6  93.184.216.34  48.44 ms  48.90 ms  49.39 ms'],
    ];
}

function generateHelixLayout(int $count): array
{
    $positions = [];
    $radius = 160;
    $heightStep = 70;
    $angleStep = pi() / 3;

    for ($i = 0; $i < $count; $i++) {
        $angle = $i * $angleStep;
        $y = ($i - ($count - 1) / 2) * $heightStep;
        $positions[] = [
            'x' => cos($angle) * $radius,
            'y' => $y,
            'z' => sin($angle) * $radius,
        ];
    }

    return $positions;
}
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HyperTracer Canvas Edition</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500&family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            color-scheme: dark;
            --bg: radial-gradient(circle at 20% 20%, rgba(59, 130, 246, 0.22), transparent 55%),
                   radial-gradient(circle at 80% 25%, rgba(147, 51, 234, 0.28), transparent 50%),
                   #020617;
            --panel-bg: rgba(15, 23, 42, 0.88);
            --accent: #38bdf8;
            --accent-strong: #f472b6;
            --text: #e2e8f0;
            --muted: #94a3b8;
            font-size: 16px;
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            grid-template-columns: minmax(320px, 28vw) 1fr;
            grid-template-rows: auto 1fr;
            background: var(--bg);
            font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            color: var(--text);
            overflow: hidden;
        }

        header {
            grid-column: 1 / -1;
            padding: 1.5rem clamp(2rem, 4vw, 5rem);
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            gap: 1.5rem;
            background: linear-gradient(135deg, rgba(2, 132, 199, 0.75), rgba(30, 64, 175, 0.7));
            border-bottom: 1px solid rgba(125, 211, 252, 0.35);
            backdrop-filter: blur(8px);
        }

        header h1 {
            font-family: 'Orbitron', sans-serif;
            margin: 0;
            letter-spacing: 0.14em;
            text-transform: uppercase;
            font-size: clamp(1.5rem, 1vw + 1.8rem, 2.6rem);
        }

        form {
            display: flex;
            flex-wrap: wrap;
            gap: 0.8rem;
            align-items: center;
        }

        form input[type="text"] {
            flex: 1;
            min-width: 240px;
            padding: 0.75rem 1rem;
            border-radius: 999px;
            border: 1px solid rgba(148, 163, 184, 0.25);
            background: rgba(15, 23, 42, 0.55);
            color: var(--text);
            font-size: 1rem;
        }

        form button {
            padding: 0.75rem 1.5rem;
            border-radius: 999px;
            border: none;
            font-weight: 600;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            cursor: pointer;
            background: linear-gradient(135deg, #38bdf8, #3b82f6);
            color: #0f172a;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        form button:hover {
            transform: translateY(-1px);
            box-shadow: 0 12px 30px rgba(14, 165, 233, 0.35);
        }

        .panel {
            grid-row: 2 / -1;
            padding: clamp(1.5rem, 2vw, 2.5rem);
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            background: var(--panel-bg);
            border-right: 1px solid rgba(96, 165, 250, 0.2);
            overflow-y: auto;
        }

        .status {
            padding: 1rem 1.2rem;
            border-radius: 1rem;
            background: rgba(56, 189, 248, 0.08);
            border: 1px solid rgba(56, 189, 248, 0.22);
            font-size: 0.95rem;
            line-height: 1.5;
        }

        .error {
            border-color: rgba(248, 113, 113, 0.45);
            color: #fecaca;
            background: rgba(248, 113, 113, 0.08);
        }

        .controls {
            display: grid;
            gap: 1.25rem;
        }

        .control-group {
            display: grid;
            gap: 0.35rem;
        }

        .control-group label {
            font-size: 0.85rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--muted);
        }

        input[type="range"] {
            width: 100%;
        }

        .hop-list {
            display: grid;
            gap: 0.8rem;
            margin: 0;
            padding: 0;
            list-style: none;
        }

        .hop-item {
            padding: 0.85rem 1rem;
            border-radius: 1rem;
            background: rgba(15, 23, 42, 0.65);
            border: 1px solid transparent;
            display: grid;
            gap: 0.3rem;
            cursor: pointer;
            transition: border-color 0.2s ease, transform 0.2s ease;
        }

        .hop-item:hover {
            border-color: rgba(56, 189, 248, 0.35);
            transform: translateX(4px);
        }

        .hop-item.active {
            border-color: rgba(250, 204, 21, 0.75);
            box-shadow: 0 12px 20px rgba(250, 204, 21, 0.18);
        }

        .hop-meta {
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            color: var(--muted);
        }

        .hop-ip {
            font-family: 'Orbitron', monospace;
            font-size: 1rem;
            color: #bae6fd;
        }

        main {
            position: relative;
            overflow: hidden;
        }

        canvas {
            width: 100%;
            height: 100%;
            display: block;
        }

        .overlay {
            position: absolute;
            inset: 0;
            display: grid;
            place-items: center;
            pointer-events: none;
        }

        .overlay .message {
            padding: 1.5rem 2.5rem;
            border-radius: 1.5rem;
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid rgba(59, 130, 246, 0.3);
            text-align: center;
            max-width: 420px;
            line-height: 1.6;
        }

        .legend {
            display: grid;
            gap: 0.5rem;
            font-size: 0.8rem;
            color: var(--muted);
        }

        .legend span::before {
            content: '';
            display: inline-block;
            width: 10px;
            height: 10px;
            margin-right: 0.5rem;
            border-radius: 50%;
            background: currentColor;
        }

        @media (max-width: 1080px) {
            body {
                grid-template-columns: 1fr;
                grid-template-rows: auto auto 1fr;
            }

            .panel {
                grid-column: 1 / -1;
                grid-row: 2 / 3;
                max-height: 45vh;
            }

            main {
                grid-row: 3 / 4;
                min-height: 55vh;
            }
        }
    </style>
</head>
<body>
<header>
    <h1>HyperTracer — Canvas Flight Deck</h1>
    <form method="get">
        <input type="text" name="host" value="<?= htmlspecialchars($host, ENT_QUOTES) ?>" placeholder="Zielhost oder IP-Adresse" aria-label="Traceroute Host">
        <button type="submit">Traceroute starten</button>
    </form>
</header>

<aside class="panel">
    <div class="status<?= $error ? ' error' : '' ?>">
        <?= htmlspecialchars($error ?: 'Bereit für den Start. Nutzen Sie die Steuerung, um die Route zu erforschen.') ?>
    </div>

    <section class="controls">
        <div class="control-group">
            <label for="yaw">Rotation um Y-Achse</label>
            <input type="range" id="yaw" min="-180" max="180" value="0">
        </div>
        <div class="control-group">
            <label for="pitch">Blickwinkel</label>
            <input type="range" id="pitch" min="-60" max="60" value="-15">
        </div>
        <div class="control-group">
            <label for="speed">Animationsgeschwindigkeit</label>
            <input type="range" id="speed" min="0" max="3" step="0.1" value="1.2">
        </div>
        <div class="legend">
            <span style="color:#facc15">Aktiver Hop</span>
            <span style="color:#38bdf8">Reguläre Hops</span>
            <span style="color:#a855f7">Startrail</span>
        </div>
    </section>

    <ol class="hop-list" id="hopList">
        <?php foreach ($traceWithPositions as $hop): ?>
            <li class="hop-item" data-hop="<?= (int) $hop['hop'] ?>">
                <div class="hop-meta">
                    <span>Hop <?= (int) $hop['hop'] ?></span>
                    <span><?= $hop['avgLatency'] !== null ? $hop['avgLatency'] . ' ms' : '—' ?></span>
                </div>
                <div class="hop-ip"><?= htmlspecialchars($hop['ip']) ?></div>
                <div class="hop-raw"><?= htmlspecialchars($hop['raw']) ?></div>
            </li>
        <?php endforeach; ?>
    </ol>
</aside>

<main>
    <canvas id="galaxyCanvas"></canvas>
    <div class="overlay" id="compatOverlay" hidden>
        <div class="message">
            <h2>Kein WebGL? Kein Problem.</h2>
            <p>Diese Version nutzt ein Canvas-Emulator-Setup, das auch ohne WebGL läuft. Sollte das Canvas dennoch nicht unterstützt sein, aktualisieren Sie Ihren Browser.</p>
        </div>
    </div>
</main>

<script>
(() => {
    const data = <?= json_encode($traceWithPositions, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) ?>;
    const canvas = document.getElementById('galaxyCanvas');
    const ctx = canvas.getContext('2d');
    const overlay = document.getElementById('compatOverlay');

    if (!ctx) {
        overlay.hidden = false;
        return;
    }

    const dpr = window.devicePixelRatio || 1;
    let width = 0;
    let height = 0;

    const state = {
        yaw: 0,
        pitch: -15 * Math.PI / 180,
        rotationVelocity: 0.15,
        autoRotate: true,
        selectedHop: data.length ? data[0].hop : null,
        time: 0,
        speedFactor: 1.2,
    };

    const stars = new Array(240).fill(null).map(() => ({
        x: (Math.random() - 0.5) * 1000,
        y: (Math.random() - 0.5) * 800,
        z: Math.random() * 900 + 200,
        speed: Math.random() * 0.4 + 0.1,
    }));

    const yawControl = document.getElementById('yaw');
    const pitchControl = document.getElementById('pitch');
    const speedControl = document.getElementById('speed');
    const hopList = document.getElementById('hopList');

    yawControl.addEventListener('input', () => {
        state.yaw = yawControl.value * Math.PI / 180;
        state.autoRotate = false;
    });

    pitchControl.addEventListener('input', () => {
        state.pitch = pitchControl.value * Math.PI / 180;
    });

    speedControl.addEventListener('input', () => {
        state.speedFactor = Number(speedControl.value) || 0.1;
    });

    hopList.addEventListener('click', (event) => {
        const item = event.target.closest('.hop-item');
        if (!item) return;
        state.selectedHop = Number(item.dataset.hop);
        state.autoRotate = false;
        highlightListItem();
    });

    function highlightListItem() {
        hopList.querySelectorAll('.hop-item').forEach((item) => {
            const isActive = Number(item.dataset.hop) === state.selectedHop;
            item.classList.toggle('active', isActive);
            if (isActive) {
                item.scrollIntoView({ block: 'center', behavior: 'smooth' });
            }
        });
    }

    function resize() {
        const rect = canvas.getBoundingClientRect();
        width = rect.width * dpr;
        height = rect.height * dpr;
        canvas.width = width;
        canvas.height = height;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    window.addEventListener('resize', resize);
    resize();
    highlightListItem();

    function rotatePoint(point, yaw, pitch) {
        const cosY = Math.cos(yaw);
        const sinY = Math.sin(yaw);
        const cosX = Math.cos(pitch);
        const sinX = Math.sin(pitch);

        // Rotation around Y axis
        const x1 = point.x * cosY - point.z * sinY;
        const z1 = point.x * sinY + point.z * cosY;

        // Rotation around X axis (pitch)
        const y2 = point.y * cosX - z1 * sinX;
        const z2 = point.y * sinX + z1 * cosX;

        return { x: x1, y: y2, z: z2 };
    }

    function project(point) {
        const distance = 900;
        const scale = distance / (distance + point.z);
        return {
            x: point.x * scale,
            y: point.y * scale,
            scale,
        };
    }

    function renderBackground(delta) {
        ctx.fillStyle = 'rgba(4, 6, 24, 0.75)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.save();
        ctx.translate(canvas.width / 2, canvas.height / 2);

        stars.forEach((star) => {
            star.z -= delta * state.speedFactor * star.speed * 40;
            if (star.z < 60) {
                star.z = 900;
            }
            const rotated = rotatePoint(star, state.yaw * 0.3, state.pitch * 0.3);
            const { x, y, scale } = project(rotated);
            const alpha = Math.min(1, 0.2 + (1 - scale) * 1.2);
            const size = Math.max(0.5, 1.5 * (1 - scale));
            ctx.fillStyle = `rgba(148, 163, 184, ${alpha})`;
            ctx.beginPath();
            ctx.arc(x, y, size, 0, Math.PI * 2);
            ctx.fill();
        });

        ctx.restore();
    }

    function renderConnections(points) {
        ctx.save();
        ctx.translate(canvas.width / 2, canvas.height / 2);
        ctx.lineCap = 'round';
        ctx.lineJoin = 'round';

        ctx.beginPath();
        for (let i = 0; i < points.length - 1; i++) {
            const current = points[i];
            const next = points[i + 1];
            ctx.moveTo(current.projected.x, current.projected.y);
            ctx.lineTo(next.projected.x, next.projected.y);
        }
        ctx.lineWidth = 2.5;
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.35)';
        ctx.stroke();

        ctx.beginPath();
        ctx.moveTo(points[0].projected.x, points[0].projected.y);
        for (let i = 1; i < points.length; i++) {
            const p = points[i];
            ctx.lineTo(p.projected.x, p.projected.y);
        }
        ctx.lineWidth = 1;
        ctx.strokeStyle = 'rgba(124, 58, 237, 0.25)';
        ctx.stroke();

        ctx.restore();
    }

    function renderNodes(points, delta) {
        ctx.save();
        ctx.translate(canvas.width / 2, canvas.height / 2);

        points.forEach((point) => {
            const isActive = point.data.hop === state.selectedHop;
            const baseRadius = isActive ? 14 : 8;
            const pulse = Math.sin(state.time * (isActive ? 6 : 3) + point.data.hop) * 0.3 + 1;
            const radius = baseRadius * point.projected.scale * 1.3 * pulse;
            const gradient = ctx.createRadialGradient(
                point.projected.x,
                point.projected.y,
                radius * 0.2,
                point.projected.x,
                point.projected.y,
                radius
            );
            if (isActive) {
                gradient.addColorStop(0, 'rgba(250, 204, 21, 0.9)');
                gradient.addColorStop(1, 'rgba(250, 204, 21, 0.05)');
            } else {
                gradient.addColorStop(0, 'rgba(56, 189, 248, 0.9)');
                gradient.addColorStop(1, 'rgba(56, 189, 248, 0.05)');
            }
            ctx.fillStyle = gradient;
            ctx.beginPath();
            ctx.arc(point.projected.x, point.projected.y, Math.max(radius, 4), 0, Math.PI * 2);
            ctx.fill();

            const label = `#${point.data.hop}`;
            ctx.font = '12px Orbitron';
            ctx.textAlign = 'center';
            ctx.fillStyle = isActive ? 'rgba(250, 204, 21, 0.9)' : 'rgba(191, 219, 254, 0.8)';
            ctx.fillText(label, point.projected.x, point.projected.y - radius - 6);
        });

        ctx.restore();
    }

    function render(delta) {
        state.time += delta * state.speedFactor * 0.001;
        if (state.autoRotate) {
            state.yaw += delta * state.rotationVelocity * 0.0002 * state.speedFactor;
            yawControl.value = ((state.yaw * 180 / Math.PI + 540) % 360) - 180;
        }

        renderBackground(delta);

        const preparedPoints = data.map((hop) => {
            const rotated = rotatePoint(hop.position, state.yaw, state.pitch);
            const projected = project(rotated);
            return { data: hop, rotated, projected };
        }).sort((a, b) => a.rotated.z - b.rotated.z);

        renderConnections(preparedPoints);
        renderNodes(preparedPoints, delta);
        requestAnimationFrame(step);
    }

    let lastTime = performance.now();
    function step(now) {
        const delta = now - lastTime;
        lastTime = now;
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        render(delta);
    }

    canvas.addEventListener('click', (event) => {
        const rect = canvas.getBoundingClientRect();
        const x = (event.clientX - rect.left) * dpr - canvas.width / 2;
        const y = (event.clientY - rect.top) * dpr - canvas.height / 2;
        const threshold = 18 * dpr;

        let closest = null;
        let minDist = Infinity;
        data.forEach((hop) => {
            const rotated = rotatePoint(hop.position, state.yaw, state.pitch);
            const projected = project(rotated);
            const dx = projected.x * dpr - x;
            const dy = projected.y * dpr - y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < minDist && dist < threshold) {
                closest = hop;
                minDist = dist;
            }
        });

        if (closest) {
            state.selectedHop = closest.hop;
            state.autoRotate = false;
            highlightListItem();
        }
    });

    requestAnimationFrame(step);
})();
</script>
</body>
</html>
