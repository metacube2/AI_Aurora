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

function parseTraceroute(string $raw): array
{
    $lines = preg_split('/\r?\n/', trim($raw));
    if (!$lines) {
        return [];
    }

    $hops = [];
    foreach ($lines as $line) {
        if (preg_match('/^\s*\d+\s+/', $line) !== 1) {
            continue;
        }

        preg_match_all('/(\d+\.\d+)\s+ms/', $line, $latencyMatches);
        $latencies = array_map('floatval', $latencyMatches[1] ?? []);
        $avgLatency = !empty($latencies) ? array_sum($latencies) / count($latencies) : null;

        if (preg_match('/^\s*(\d+)\s+([0-9\.\*]+)/', $line, $parts) !== 1) {
            continue;
        }

        $hopNumber = (int) $parts[1];
        $ip = $parts[2];
        if ($ip === '*') {
            $ip = 'Zeitüberschreitung';
        }

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
        ['hop' => 1, 'ip' => '192.168.0.1', 'avgLatency' => 1.2, 'raw' => '1  192.168.0.1  1.123 ms  1.234 ms  1.301 ms'],
        ['hop' => 2, 'ip' => '10.12.34.1', 'avgLatency' => 9.4, 'raw' => '2  10.12.34.1  9.123 ms  9.567 ms  9.400 ms'],
        ['hop' => 3, 'ip' => '172.16.5.4', 'avgLatency' => 18.7, 'raw' => '3  172.16.5.4  18.432 ms  18.913 ms  18.787 ms'],
        ['hop' => 4, 'ip' => '203.0.113.5', 'avgLatency' => 32.9, 'raw' => '4  203.0.113.5  32.113 ms  33.441 ms  33.212 ms'],
        ['hop' => 5, 'ip' => '93.184.216.34', 'avgLatency' => 48.2, 'raw' => '5  93.184.216.34  48.112 ms  48.501 ms  48.032 ms'],
    ];
}

function generatePositions(array $trace): array
{
    $positions = [];
    $radius = 25;
    $spacing = 10;
    foreach ($trace as $index => $hop) {
        $angle = $index * 0.9;
        $positions[] = [
            'x' => cos($angle) * $radius,
            'y' => $index * $spacing,
            'z' => sin($angle) * $radius,
        ];
    }
    return $positions;
}

$positions = generatePositions($traceData);
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>3D Traceroute Visualisierung</title>
    <style>
        body {
            font-family: "Segoe UI", Roboto, sans-serif;
            margin: 0;
            background: #0f172a;
            color: #e2e8f0;
            display: flex;
            flex-direction: column;
            height: 100vh;
        }
        header {
            padding: 1.5rem 2rem;
            background: linear-gradient(135deg, #1d4ed8, #312e81);
            box-shadow: 0 8px 20px rgba(15, 23, 42, 0.6);
            z-index: 10;
        }
        h1 {
            margin: 0;
            font-size: 1.8rem;
        }
        main {
            display: flex;
            flex: 1;
            overflow: hidden;
        }
        #canvas-container {
            flex: 1;
            position: relative;
        }
        #scene {
            width: 100%;
            height: 100%;
            display: block;
        }
        #panel {
            width: 320px;
            background: rgba(15, 23, 42, 0.9);
            border-left: 1px solid rgba(148, 163, 184, 0.2);
            padding: 1.5rem;
            overflow-y: auto;
        }
        form {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
        }
        label {
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #94a3b8;
        }
        input[type="text"] {
            padding: 0.65rem 0.75rem;
            border: 1px solid rgba(148, 163, 184, 0.3);
            border-radius: 0.6rem;
            background: rgba(15, 23, 42, 0.4);
            color: inherit;
        }
        button {
            padding: 0.75rem;
            border: none;
            border-radius: 0.6rem;
            background: linear-gradient(135deg, #22d3ee, #3b82f6);
            color: #0f172a;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 24px rgba(34, 211, 238, 0.3);
        }
        .error {
            padding: 0.75rem 1rem;
            border-radius: 0.6rem;
            background: rgba(248, 113, 113, 0.1);
            border: 1px solid rgba(248, 113, 113, 0.3);
            color: #fecaca;
            margin-bottom: 1.5rem;
        }
        .info-box {
            border-radius: 0.75rem;
            border: 1px solid rgba(94, 234, 212, 0.3);
            padding: 1rem;
            background: rgba(15, 118, 110, 0.15);
            margin-bottom: 1.5rem;
        }
        .hop-list {
            display: grid;
            gap: 0.75rem;
        }
        .hop-card {
            padding: 0.75rem 0.9rem;
            border-radius: 0.75rem;
            border: 1px solid rgba(148, 163, 184, 0.3);
            background: rgba(30, 41, 59, 0.7);
            transition: transform 0.2s ease, border-color 0.2s ease;
        }
        .hop-card.active {
            border-color: rgba(59, 130, 246, 0.8);
            transform: translateX(4px);
        }
        .hop-card h3 {
            margin: 0 0 0.3rem;
            font-size: 1rem;
        }
        .hop-card p {
            margin: 0.2rem 0;
            font-size: 0.85rem;
            color: #cbd5f5;
        }
        #camera-progress {
            width: 100%;
        }
        .slider-label {
            display: flex;
            justify-content: space-between;
            font-size: 0.8rem;
            color: #94a3b8;
            margin-top: -0.25rem;
        }
        .search-wrapper {
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }
        .search-wrapper input {
            flex: 1;
        }
    </style>
</head>
<body>
<header>
    <h1>3D Traceroute Explorer</h1>
    <p>Visualisieren Sie Netzwerkpfade im dreidimensionalen Raum und erkunden Sie die einzelnen Hops.</p>
</header>
<main>
    <div id="canvas-container">
        <canvas id="scene"></canvas>
    </div>
    <aside id="panel">
        <form method="get">
            <div>
                <label for="host">Zielhost</label>
                <input id="host" name="host" type="text" placeholder="z.B. example.com oder 8.8.8.8" value="<?= htmlspecialchars($host, ENT_QUOTES) ?>" />
            </div>
            <button type="submit">Traceroute starten</button>
        </form>
        <?php if ($error !== ''): ?>
            <div class="error"><?= htmlspecialchars($error, ENT_QUOTES) ?></div>
        <?php endif; ?>
        <div class="info-box">
            <strong>Interaktive Steuerung</strong>
            <ul>
                <li>Drehen: Linke Maustaste</li>
                <li>Schwenken: Rechte Maustaste</li>
                <li>Zoom: Mausrad</li>
                <li>Knoten anklicken für Details</li>
            </ul>
        </div>
        <div class="search-wrapper">
            <input type="text" id="search" placeholder="Hop oder IP suchen..." list="node-list" />
            <button type="button" id="search-btn">Suchen</button>
        </div>
        <datalist id="node-list">
            <?php foreach ($traceData as $hop): ?>
                <option value="Hop <?= $hop['hop'] ?>"></option>
                <option value="<?= $hop['ip'] ?>"></option>
            <?php endforeach; ?>
        </datalist>
        <div style="margin: 1.5rem 0 0.5rem;">
            <label for="camera-progress">Pfad erkunden</label>
            <input id="camera-progress" type="range" min="0" max="<?= max(count($traceData) - 1, 1) ?>" step="0.01" value="0" />
            <div class="slider-label">
                <span>Start</span>
                <span>Ende</span>
            </div>
        </div>
        <section class="hop-list" id="hop-list">
            <?php foreach ($traceData as $index => $hop): ?>
                <article class="hop-card" data-hop-index="<?= $index ?>">
                    <h3>Hop <?= $hop['hop'] ?></h3>
                    <p><strong>IP:</strong> <?= htmlspecialchars($hop['ip'], ENT_QUOTES) ?></p>
                    <p><strong>Ø Latenz:</strong> <?= $hop['avgLatency'] !== null ? number_format($hop['avgLatency'], 2) . ' ms' : 'Keine Daten' ?></p>
                    <p class="raw"><?= htmlspecialchars($hop['raw'], ENT_QUOTES) ?></p>
                </article>
            <?php endforeach; ?>
        </section>
    </aside>
</main>
<script>
    const traceData = <?= json_encode($traceData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) ?>;
    const positions = <?= json_encode($positions, JSON_PRETTY_PRINT) ?>;
</script>
<script src="https://cdn.jsdelivr.net/npm/three@0.157.0/build/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/three@0.157.0/examples/js/controls/OrbitControls.js"></script>
<script>
(function() {
    const canvas = document.getElementById('scene');
    const renderer = new THREE.WebGLRenderer({canvas, antialias: true});
    renderer.setPixelRatio(window.devicePixelRatio);
    renderer.setSize(canvas.clientWidth, canvas.clientHeight, false);

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x020617);

    const camera = new THREE.PerspectiveCamera(60, canvas.clientWidth / canvas.clientHeight, 0.1, 1000);
    camera.position.set(60, 60, 60);

    const controls = new THREE.OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;

    const light = new THREE.PointLight(0xffffff, 1.2);
    light.position.set(50, 50, 50);
    scene.add(light);
    scene.add(new THREE.AmbientLight(0x4c566a, 0.6));

    const nodeMaterial = new THREE.MeshStandardMaterial({color: 0x38bdf8, emissive: 0x0f172a});
    const targetMaterial = new THREE.MeshStandardMaterial({color: 0x22d3ee, emissive: 0x164e63});
    const startMaterial = new THREE.MeshStandardMaterial({color: 0x60a5fa, emissive: 0x312e81});

    const nodeGeometry = new THREE.SphereGeometry(1.5, 32, 32);
    const nodes = [];

    const lineMaterial = new THREE.LineBasicMaterial({color: 0x1d4ed8, linewidth: 2});
    const linePoints = [];

    positions.forEach((pos, index) => {
        const material = index === 0 ? startMaterial : (index === positions.length - 1 ? targetMaterial : nodeMaterial);
        const mesh = new THREE.Mesh(nodeGeometry, material.clone());
        mesh.position.set(pos.x, pos.y, pos.z);
        mesh.userData = {...traceData[index], index};
        scene.add(mesh);
        nodes.push(mesh);
        linePoints.push(new THREE.Vector3(pos.x, pos.y, pos.z));
    });

    if (linePoints.length > 1) {
        const lineGeometry = new THREE.BufferGeometry().setFromPoints(linePoints);
        const line = new THREE.Line(lineGeometry, lineMaterial);
        scene.add(line);
    }

    const particleCount = 2000;
    const particleGeometry = new THREE.BufferGeometry();
    const particlePositions = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount; i++) {
        particlePositions[i * 3] = (Math.random() - 0.5) * 400;
        particlePositions[i * 3 + 1] = Math.random() * 400;
        particlePositions[i * 3 + 2] = (Math.random() - 0.5) * 400;
    }
    particleGeometry.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
    const particleMaterial = new THREE.PointsMaterial({color: 0x1e293b, size: 1.2});
    const particles = new THREE.Points(particleGeometry, particleMaterial);
    scene.add(particles);

    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();
    const hopList = document.getElementById('hop-list');

    function resizeRendererToDisplaySize() {
        const width = canvas.clientWidth;
        const height = canvas.clientHeight;
        const needResize = canvas.width !== width || canvas.height !== height;
        if (needResize) {
            renderer.setSize(width, height, false);
            camera.aspect = width / height;
            camera.updateProjectionMatrix();
        }
        return needResize;
    }

    function animate() {
        requestAnimationFrame(animate);
        controls.update();
        resizeRendererToDisplaySize();
        renderer.render(scene, camera);
    }

    animate();

    const infoCards = Array.from(document.querySelectorAll('.hop-card'));

    function setActiveHop(index) {
        infoCards.forEach(card => card.classList.toggle('active', Number(card.dataset.hopIndex) === index));
    }

    function focusOnNode(index) {
        const node = nodes[index];
        if (!node) return;
        const offset = new THREE.Vector3(15, 10, 15);
        const targetPosition = node.position.clone().add(offset);
        camera.position.lerp(targetPosition, 0.3);
        controls.target.copy(node.position);
        setActiveHop(index);
    }

    window.addEventListener('resize', () => resizeRendererToDisplaySize());

    renderer.domElement.addEventListener('click', event => {
        const rect = renderer.domElement.getBoundingClientRect();
        pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
        pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
        raycaster.setFromCamera(pointer, camera);
        const intersects = raycaster.intersectObjects(nodes);
        if (intersects.length > 0) {
            const index = intersects[0].object.userData.index;
            focusOnNode(index);
        }
    });

    infoCards.forEach(card => {
        card.addEventListener('click', () => {
            const index = Number(card.dataset.hopIndex);
            focusOnNode(index);
        });
    });

    const cameraProgress = document.getElementById('camera-progress');
    cameraProgress.addEventListener('input', () => {
        const value = parseFloat(cameraProgress.value);
        const lower = Math.floor(value);
        const upper = Math.ceil(value);
        const alpha = value - lower;
        const startPos = nodes[lower]?.position;
        const endPos = nodes[upper]?.position || startPos;
        if (!startPos || !endPos) return;
        const interpolated = startPos.clone().lerp(endPos, alpha);
        const offset = new THREE.Vector3(12, 8, 12);
        camera.position.copy(interpolated.clone().add(offset));
        controls.target.copy(interpolated);
        setActiveHop(alpha < 0.5 ? lower : upper);
    });

    const searchInput = document.getElementById('search');
    const searchButton = document.getElementById('search-btn');

    function searchNodes() {
        const query = searchInput.value.trim().toLowerCase();
        if (!query) return;
        const foundIndex = traceData.findIndex(hop =>
            `hop ${hop.hop}`.toLowerCase() === query ||
            hop.ip.toLowerCase() === query
        );
        if (foundIndex >= 0) {
            focusOnNode(foundIndex);
            cameraProgress.value = foundIndex;
        } else {
            alert('Kein passender Hop gefunden.');
        }
    }

    searchButton.addEventListener('click', searchNodes);
    searchInput.addEventListener('keydown', event => {
        if (event.key === 'Enter') {
            event.preventDefault();
            searchNodes();
        }
    });
})();
</script>
</body>
</html>
