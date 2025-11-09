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

$positions = generateGalaxyLayout(count($traceData));
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

function generateGalaxyLayout(int $count): array
{
    $positions = [];
    $radiusStep = 28;
    $angleOffset = pi() * (3 - sqrt(5)); // Golden angle
    $heightStep = 12;

    for ($i = 0; $i < $count; $i++) {
        $radius = ($i + 1) * 4 + ($i % 2 === 0 ? $radiusStep : $radiusStep * 0.6);
        $angle = $i * $angleOffset;
        $y = ($i - $count / 2) * $heightStep;

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
    <title>HyperTracer 3D</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600&family=Roboto:wght@300;400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            color-scheme: dark;
            --bg-gradient: radial-gradient(circle at 20% 20%, rgba(56, 189, 248, 0.2), transparent 55%),
                             radial-gradient(circle at 80% 30%, rgba(129, 140, 248, 0.25), transparent 50%),
                             #020617;
            --panel-bg: rgba(15, 23, 42, 0.86);
            --accent: #22d3ee;
            --accent-strong: #38bdf8;
            --warning: #f87171;
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            grid-template-rows: auto 1fr;
            font-family: 'Roboto', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-gradient);
            color: #e2e8f0;
        }

        header {
            position: relative;
            padding: 1.5rem clamp(2rem, 3vw, 4rem);
            background: linear-gradient(135deg, rgba(15, 118, 110, 0.9), rgba(8, 47, 73, 0.85));
            backdrop-filter: blur(6px);
            border-bottom: 1px solid rgba(45, 212, 191, 0.35);
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            gap: 1.25rem;
        }

        header h1 {
            margin: 0;
            font-family: 'Orbitron', sans-serif;
            font-size: clamp(1.6rem, 2vw + 1rem, 2.6rem);
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: #f8fafc;
        }

        header form {
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
            align-items: center;
        }

        header input[type="text"] {
            width: min(320px, 50vw);
            padding: 0.75rem 1rem;
            border-radius: 999px;
            border: 1px solid rgba(56, 189, 248, 0.5);
            background: rgba(15, 23, 42, 0.72);
            color: inherit;
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
        }

        header input[type="text"]:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 4px rgba(34, 211, 238, 0.15);
        }

        header button {
            border: none;
            border-radius: 999px;
            padding: 0.75rem 1.5rem;
            font-size: 0.95rem;
            font-weight: 600;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            background: linear-gradient(135deg, var(--accent-strong), #2563eb);
            color: #0f172a;
            cursor: pointer;
            transition: transform 0.25s ease, box-shadow 0.25s ease;
        }

        header button:hover {
            transform: translateY(-1px);
            box-shadow: 0 12px 24px rgba(37, 99, 235, 0.35);
        }

        main {
            display: grid;
            grid-template-columns: minmax(280px, 400px) 1fr;
            min-height: 0;
            overflow: hidden;
        }

        aside {
            padding: clamp(1.5rem, 2.5vw, 2.75rem);
            border-right: 1px solid rgba(148, 163, 184, 0.2);
            background: var(--panel-bg);
            backdrop-filter: blur(12px);
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            overflow-y: auto;
        }

        aside h2 {
            margin: 0;
            font-size: 1.1rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: rgba(148, 197, 255, 0.95);
        }

        .status {
            padding: 1rem 1.2rem;
            border-radius: 1rem;
            background: rgba(37, 99, 235, 0.15);
            border: 1px solid rgba(37, 99, 235, 0.35);
            line-height: 1.6;
        }

        .status.error {
            background: rgba(248, 113, 113, 0.14);
            border-color: rgba(248, 113, 113, 0.45);
            color: #fecaca;
        }

        .hop-list {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .hop-card {
            padding: 1rem 1.1rem;
            border-radius: 1rem;
            background: rgba(30, 64, 175, 0.2);
            border: 1px solid rgba(56, 189, 248, 0.35);
            display: grid;
            gap: 0.25rem;
            cursor: pointer;
            transition: transform 0.2s ease, border-color 0.2s ease;
        }

        .hop-card:hover, .hop-card.active {
            transform: translateX(4px);
            border-color: var(--accent);
            box-shadow: 0 10px 24px rgba(14, 116, 144, 0.35);
        }

        .hop-card span.label {
            font-size: 0.75rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            opacity: 0.65;
        }

        .hop-card strong {
            font-family: 'Orbitron', sans-serif;
            letter-spacing: 0.08em;
        }

        .legend {
            display: grid;
            gap: 0.75rem;
            padding: 1.2rem 1.35rem;
            border-radius: 1rem;
            background: rgba(15, 23, 42, 0.72);
            border: 1px solid rgba(148, 163, 184, 0.3);
        }

        .legend-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .legend-item::before {
            content: '';
            display: inline-block;
            width: 16px;
            height: 16px;
            border-radius: 999px;
            background: linear-gradient(135deg, var(--accent), rgba(37, 99, 235, 0.8));
            box-shadow: 0 0 12px rgba(45, 212, 191, 0.8);
        }

        .legend-item:nth-child(2)::before {
            background: linear-gradient(135deg, rgba(248, 113, 113, 0.9), rgba(185, 28, 28, 0.6));
            box-shadow: 0 0 12px rgba(248, 113, 113, 0.75);
        }

        .legend-item:nth-child(3)::before {
            width: 40px;
            height: 4px;
            border-radius: 4px;
            background: linear-gradient(90deg, rgba(56, 189, 248, 0), rgba(56, 189, 248, 0.8), rgba(56, 189, 248, 0));
            box-shadow: none;
        }

        .control-deck {
            display: grid;
            gap: 1rem;
            padding: 1.2rem 1.35rem;
            border-radius: 1rem;
            background: rgba(15, 23, 42, 0.7);
            border: 1px solid rgba(56, 189, 248, 0.25);
        }

        .control-deck label {
            font-size: 0.85rem;
            letter-spacing: 0.06em;
            text-transform: uppercase;
        }

        .control-deck input[type="range"] {
            width: 100%;
        }

        .scene-wrapper {
            position: relative;
            background: transparent;
            display: grid;
            overflow: hidden;
        }

        #scene-canvas {
            width: 100%;
            height: 100%;
            display: block;
        }

        .overlay-hud {
            position: absolute;
            inset: 0;
            pointer-events: none;
            display: grid;
        }

        .hud-info {
            align-self: end;
            justify-self: end;
            margin: clamp(1.5rem, 3vw, 3rem);
            padding: 1rem 1.2rem;
            border-radius: 1rem;
            background: rgba(15, 23, 42, 0.55);
            border: 1px solid rgba(56, 189, 248, 0.35);
            font-size: 0.9rem;
            backdrop-filter: blur(6px);
        }

        .hud-info strong {
            font-family: 'Orbitron', sans-serif;
        }

        .webgl-warning {
            position: absolute;
            inset: 0;
            display: none;
            align-items: center;
            justify-content: center;
            background: rgba(15, 23, 42, 0.9);
            backdrop-filter: blur(6px);
            text-align: center;
            font-size: 1rem;
            line-height: 1.6;
            padding: 2rem;
        }

        .webgl-warning.show {
            display: flex;
        }

        @media (max-width: 1080px) {
            main {
                grid-template-columns: 1fr;
                grid-template-rows: auto 1fr;
            }

            aside {
                border-right: none;
                border-bottom: 1px solid rgba(148, 163, 184, 0.2);
            }

            .scene-wrapper {
                min-height: 420px;
            }
        }
    </style>
</head>
<body>
<header>
    <h1>HyperTracer 3D</h1>
    <form method="get">
        <label for="host" class="visually-hidden">Host</label>
        <input type="text" id="host" name="host" placeholder="Hostname oder IP" value="<?php echo htmlspecialchars($host, ENT_QUOTES); ?>">
        <button type="submit">Traceroute starten</button>
    </form>
</header>
<main>
    <aside>
        <section>
            <h2>Status</h2>
            <div class="status <?php echo $error !== '' ? 'error' : ''; ?>">
                <?php echo htmlspecialchars($error !== '' ? $error : 'Bereit für Hypertracing.'); ?>
            </div>
        </section>
        <section>
            <h2>Hops</h2>
            <div class="hop-list" id="hop-list">
                <?php foreach ($traceWithPositions as $hop): ?>
                    <article class="hop-card" data-hop="<?php echo (int) $hop['hop']; ?>">
                        <span class="label">Hop <?php echo (int) $hop['hop']; ?></span>
                        <strong><?php echo htmlspecialchars($hop['ip']); ?></strong>
                        <span><?php echo $hop['avgLatency'] !== null ? htmlspecialchars($hop['avgLatency'] . ' ms') : 'Latenz unbekannt'; ?></span>
                    </article>
                <?php endforeach; ?>
            </div>
        </section>
        <section class="legend">
            <h2>Legende</h2>
            <div class="legend-item">Aktueller Hop</div>
            <div class="legend-item">Paketverlust / Zeitüberschreitung</div>
            <div class="legend-item">Pfadintensität ~ Latenz</div>
        </section>
        <section class="control-deck">
            <h2>Steuerung</h2>
            <label for="timeline">Zeitleiste</label>
            <input type="range" min="0" max="<?php echo max(count($traceWithPositions) - 1, 0); ?>" value="0" id="timeline">
            <label for="speed">Kamerageschwindigkeit</label>
            <input type="range" min="1" max="50" value="14" id="speed">
        </section>
    </aside>
    <section class="scene-wrapper">
        <canvas id="scene-canvas"></canvas>
        <div class="overlay-hud">
            <div class="hud-info" id="hud-info">Hop <strong>1</strong>: <span id="hud-ip"></span></div>
        </div>
        <div class="webgl-warning" id="webgl-warning">
            WebGL konnte nicht initialisiert werden. Bitte verwenden Sie einen modernen Browser oder aktivieren Sie WebGL.
        </div>
    </section>
</main>
<script type="module">
    import * as THREE from 'https://cdn.jsdelivr.net/npm/three@0.160/build/three.module.js';
    import { OrbitControls } from 'https://cdn.jsdelivr.net/npm/three@0.160/examples/jsm/controls/OrbitControls.js';
    import { Line2 } from 'https://cdn.jsdelivr.net/npm/three@0.160/examples/jsm/lines/Line2.js';
    import { LineGeometry } from 'https://cdn.jsdelivr.net/npm/three@0.160/examples/jsm/lines/LineGeometry.js';
    import { LineMaterial } from 'https://cdn.jsdelivr.net/npm/three@0.160/examples/jsm/lines/LineMaterial.js';

    const rawTrace = <?php echo json_encode($traceWithPositions, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); ?>;

    const canvas = document.getElementById('scene-canvas');
    const hudInfo = document.getElementById('hud-info');
    const hudIp = document.getElementById('hud-ip');
    const timeline = document.getElementById('timeline');
    const speed = document.getElementById('speed');
    const hopList = document.getElementById('hop-list');
    const webglWarning = document.getElementById('webgl-warning');

    let renderer, scene, camera, controls;
    let routeCurve, routeMesh, glowMaterial;
    let hopMeshes = [];
    let activeIndex = 0;
    let animationClock = new THREE.Clock();
    let timelineProgress = 0;

    try {
        renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
    } catch (err) {
        webglWarning.classList.add('show');
        throw err;
    }

    if (!renderer.capabilities.isWebGL2 && !renderer.capabilities.isWebGL) {
        webglWarning.classList.add('show');
    }

    const DPR = Math.min(window.devicePixelRatio || 1, 2.5);
    renderer.setPixelRatio(DPR);
    renderer.setSize(canvas.clientWidth, canvas.clientHeight, false);
    renderer.setClearColor(0x020617, 1);

    scene = new THREE.Scene();
    camera = new THREE.PerspectiveCamera(60, canvas.clientWidth / canvas.clientHeight, 0.1, 5000);
    camera.position.set(60, 120, 160);

    controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.08;
    controls.maxDistance = 800;
    controls.minDistance = 20;
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.5;

    const ambient = new THREE.AmbientLight(0x67e8f9, 0.4);
    scene.add(ambient);

    const keyLight = new THREE.SpotLight(0x60a5fa, 1.6, 0, Math.PI / 8, 0.25, 1.5);
    keyLight.position.set(120, 260, 80);
    scene.add(keyLight);

    const fillLight = new THREE.DirectionalLight(0x22d3ee, 0.6);
    fillLight.position.set(-120, -50, -140);
    scene.add(fillLight);

    const fogColor = new THREE.Color('#0b1120');
    scene.fog = new THREE.FogExp2(fogColor, 0.0012);

    // Starfield backdrop
    const starGeometry = new THREE.BufferGeometry();
    const starCount = 3200;
    const starPositions = new Float32Array(starCount * 3);
    for (let i = 0; i < starCount; i++) {
        const radius = THREE.MathUtils.randFloat(260, 2200);
        const theta = THREE.MathUtils.randFloatSpread(360);
        const phi = THREE.MathUtils.randFloatSpread(360);
        const x = radius * Math.sin(theta) * Math.cos(phi);
        const y = radius * Math.sin(theta) * Math.sin(phi);
        const z = radius * Math.cos(theta);
        starPositions.set([x, y, z], i * 3);
    }
    starGeometry.setAttribute('position', new THREE.BufferAttribute(starPositions, 3));
    const starMaterial = new THREE.PointsMaterial({ color: 0x38bdf8, size: 2, sizeAttenuation: true, transparent: true, opacity: 0.65 });
    const starField = new THREE.Points(starGeometry, starMaterial);
    scene.add(starField);

    const glowTexture = new THREE.TextureLoader().load('https://cdn.jsdelivr.net/gh/ykob/sketch-threejs@master/example/img/glow.png');

    const hopPositions = rawTrace.map(hop => new THREE.Vector3(hop.position.x, hop.position.y, hop.position.z));
    routeCurve = new THREE.CatmullRomCurve3(hopPositions, false, 'catmullrom', 0.1);

    const points = routeCurve.getPoints(1024);
    const linePositions = [];
    const colors = [];

    const latencyRange = (() => {
        const latencies = rawTrace.map(h => h.avgLatency ?? 0);
        return { min: Math.min(...latencies), max: Math.max(...latencies) };
    })();

    points.forEach((point, index) => {
        linePositions.push(point.x, point.y, point.z);
        const progress = index / points.length;
        const color = new THREE.Color().setHSL(THREE.MathUtils.lerp(0.55, 0.08, progress), 0.9, 0.55);
        colors.push(color.r, color.g, color.b);
    });

    const lineGeometry = new LineGeometry();
    lineGeometry.setPositions(linePositions);
    lineGeometry.setColors(colors);

    const lineMaterial = new LineMaterial({
        color: 0xffffff,
        linewidth: 0.003,
        vertexColors: true,
        dashed: false,
        transparent: true,
        opacity: 0.9,
        depthWrite: false
    });

    lineMaterial.resolution.set(canvas.clientWidth, canvas.clientHeight);

    routeMesh = new Line2(lineGeometry, lineMaterial);
    scene.add(routeMesh);

    const hopGeometry = new THREE.SphereGeometry(3.2, 32, 32);
    const hopMaterial = new THREE.MeshStandardMaterial({ color: 0x38bdf8, emissive: 0x164e63, metalness: 0.5, roughness: 0.35 });

    const spriteMaterial = new THREE.SpriteMaterial({ map: glowTexture, color: 0x38bdf8, transparent: true, opacity: 0.6, depthWrite: false });

    rawTrace.forEach((hop, index) => {
        const mesh = new THREE.Mesh(hopGeometry, hopMaterial.clone());
        mesh.position.copy(hopPositions[index]);
        mesh.userData = { hop, index };

        const sprite = new THREE.Sprite(spriteMaterial.clone());
        sprite.scale.set(16, 16, 1);
        mesh.add(sprite);

        scene.add(mesh);
        hopMeshes.push(mesh);
    });

    const pulseGeometry = new THREE.SphereGeometry(2, 24, 24);
    glowMaterial = new THREE.ShaderMaterial({
        uniforms: {
            uTime: { value: 0 },
            uColor: { value: new THREE.Color('#22d3ee') }
        },
        vertexShader: `varying float vIntensity;\nvoid main() {\n    vec3 transformed = position;\n    float radius = length(transformed);\n    vIntensity = smoothstep(0.0, 1.0, radius / 2.0);\n    gl_Position = projectionMatrix * modelViewMatrix * vec4(transformed, 1.0);\n}`,
        fragmentShader: `uniform float uTime;\nuniform vec3 uColor;\nvarying float vIntensity;\nvoid main() {\n    float alpha = smoothstep(0.9, 0.0, vIntensity + sin(uTime * 4.0) * 0.2);\n    gl_FragColor = vec4(uColor, alpha);\n}`,
        transparent: true,
        blending: THREE.AdditiveBlending,
        depthWrite: false
    });

    const pulseMesh = new THREE.Mesh(pulseGeometry, glowMaterial);
    scene.add(pulseMesh);

    const gridHelper = new THREE.PolarGridHelper(280, 16, 8, 64, 0x0ea5e9, 0x1e40af);
    gridHelper.material.opacity = 0.3;
    gridHelper.material.transparent = true;
    gridHelper.rotation.x = Math.PI / 2;
    scene.add(gridHelper);

    function resizeRendererToDisplaySize() {
        const width = canvas.clientWidth;
        const height = canvas.clientHeight;
        const needResize = canvas.width !== width * DPR || canvas.height !== height * DPR;
        if (needResize) {
            renderer.setSize(width, height, false);
            camera.aspect = width / height || 1;
            camera.updateProjectionMatrix();
            lineMaterial.resolution.set(width, height);
        }
    }

    function setActiveHop(index, centerCamera = false) {
        activeIndex = THREE.MathUtils.clamp(index, 0, hopMeshes.length - 1);
        hopMeshes.forEach((mesh, idx) => {
            const isActive = idx === activeIndex;
            mesh.material.emissiveIntensity = isActive ? 1.5 : 0.4;
            mesh.scale.setScalar(isActive ? 1.6 : 1);
        });

        const hop = rawTrace[activeIndex];
        hudInfo.querySelector('strong').textContent = hop.hop;
        hudIp.textContent = `${hop.ip} • ${hop.avgLatency !== null ? hop.avgLatency + ' ms' : 'Latenz unbekannt'}`;

        document.querySelectorAll('.hop-card').forEach(card => {
            card.classList.toggle('active', Number(card.dataset.hop) === hop.hop);
        });

        if (centerCamera) {
            const target = hopPositions[activeIndex];
            controls.target.copy(target);
        }
    }

    function animate() {
        requestAnimationFrame(animate);
        resizeRendererToDisplaySize();

        const delta = animationClock.getDelta();
        const elapsed = animationClock.getElapsedTime();

        controls.update();

        starField.rotation.y += delta * 0.01;
        starField.rotation.x += delta * 0.005;

        glowMaterial.uniforms.uTime.value = elapsed;

        const speedValue = Number(speed.value) / 120;
        timelineProgress += delta * speedValue;
        const nextIndex = Math.floor(timelineProgress) % hopMeshes.length;
        if (nextIndex !== activeIndex) {
            setActiveHop(nextIndex);
            timeline.value = nextIndex;
        }

        const currentPoint = routeCurve.getPointAt((timelineProgress % hopMeshes.length) / hopMeshes.length);
        if (currentPoint) {
            pulseMesh.position.copy(currentPoint);
            pulseMesh.scale.setScalar(1 + Math.sin(elapsed * 4) * 0.5 + 0.8);
        }

        renderer.render(scene, camera);
    }

    setActiveHop(0, true);
    animate();

    timeline.addEventListener('input', (event) => {
        timelineProgress = Number(event.target.value);
        setActiveHop(Number(event.target.value), true);
    });

    speed.addEventListener('input', () => {
        // speed adjusts automatically via animate loop
    });

    hopList.addEventListener('click', (event) => {
        const card = event.target.closest('.hop-card');
        if (!card) return;
        const hopNumber = Number(card.dataset.hop);
        const index = rawTrace.findIndex(h => h.hop === hopNumber);
        if (index >= 0) {
            timeline.value = index;
            timelineProgress = index;
            setActiveHop(index, true);
        }
    });

    window.addEventListener('resize', () => {
        renderer.setSize(canvas.clientWidth, canvas.clientHeight, false);
        camera.aspect = canvas.clientWidth / canvas.clientHeight;
        camera.updateProjectionMatrix();
        lineMaterial.resolution.set(canvas.clientWidth, canvas.clientHeight);
    });
</script>
</body>
</html>
