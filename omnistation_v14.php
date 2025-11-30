<?php
// ----------------------------------------------------------------------------
// BACKEND: CRYPTO & DATA LAYER
// ----------------------------------------------------------------------------
$btcPrice = 68500; $trend = 'bullish'; // Fallback defaults
$ctx = stream_context_create(['http' => ['timeout' => 1.5, 'ignore_errors' => true]]);

try {
    $json = @file_get_contents('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd&include_24hr_change=true', false, $ctx);
    if($json) {
        $d = json_decode($json, true);
        $btcPrice = $d['bitcoin']['usd'];
        $trend = ($d['bitcoin']['usd_24h_change'] >= 0) ? 'bullish' : 'bearish';
    }
} catch(Exception $e) {}

$serverData = ['price' => $btcPrice, 'trend' => $trend];
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OMNI-STATION V14 PRO // ADVANCED SAMPLER</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500;900&family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet">

    <style>
        :root {
            --c-accent: #00f3ff;
            --c-warn: #ff0055;
            --c-gold: #ffd700;
            --c-green: #00ff88;
            --bg-dark: #050508;
            --panel: #121216;
        }
        body {
            background: var(--bg-dark);
            color: #ccc;
            font-family: 'Roboto Mono', monospace;
            overflow: hidden;
            user-select: none;
            background-image: radial-gradient(circle at 50% 20%, #1a2030 0%, #000 80%);
        }

        /* PRO SLIDER DESIGN */
        input[type=range] {
            -webkit-appearance: none; width: 100%; background: transparent; height: 24px; cursor: pointer; position: relative; z-index: 10;
        }
        input[type=range]:focus { outline: none; }
        input[type=range]::-webkit-slider-runnable-track {
            width: 100%; height: 6px; background: #222; border: 1px solid #444; border-radius: 2px;
        }
        input[type=range]::-webkit-slider-thumb {
            -webkit-appearance: none; height: 18px; width: 10px; background: var(--c-accent);
            margin-top: -7px; border: 1px solid #fff; box-shadow: 0 0 10px var(--c-accent);
        }

        /* PANELS & UI */
        .cyber-panel {
            background: rgba(18, 18, 22, 0.9);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255,255,255,0.15);
            box-shadow: 0 10px 40px rgba(0,0,0,0.7);
        }
        .tab-btn {
            transition: all 0.2s; border-bottom: 3px solid transparent; opacity: 0.6;
        }
        .tab-btn.active {
            opacity: 1; border-color: var(--c-accent); color: var(--c-accent); background: rgba(0,243,255,0.05);
            text-shadow: 0 0 15px var(--c-accent);
        }

        /* VISUALIZER */
        .scrub-line {
            position: absolute; top: 0; bottom: 0; width: 2px; background: var(--c-warn);
            box-shadow: 0 0 10px var(--c-warn); pointer-events: none; z-index: 20;
        }
        .loop-marker {
            position: absolute; top: 0; bottom: 0; width: 3px; cursor: ew-resize; z-index: 25;
            transition: box-shadow 0.2s;
        }
        .loop-marker:hover {
            box-shadow: 0 0 20px currentColor;
        }
        .loop-region {
            position: absolute; top: 0; bottom: 0; background: rgba(0, 255, 136, 0.1);
            border-left: 2px solid var(--c-green); border-right: 2px solid var(--c-green);
            pointer-events: none; z-index: 15;
        }

        /* KEYBOARD */
        .key {
            background: #eee; border-radius: 0 0 4px 4px; transition: 0.05s;
            box-shadow: inset 0 -5px 10px rgba(0,0,0,0.2);
        }
        .key.black {
            background: #111; color: #fff; z-index:10; height: 60%;
            box-shadow: 3px 3px 5px rgba(0,0,0,0.5);
        }
        .key.active {
            background: var(--c-accent) !important; transform: translateY(2px);
            box-shadow: 0 0 25px var(--c-accent);
        }

        /* TOGGLE SWITCHES */
        .toggle-btn {
            @apply px-3 py-1 text-[10px] font-bold border-2 rounded cursor-pointer transition-all;
        }
        .toggle-btn.on {
            background: var(--c-green); border-color: var(--c-green); color: #000;
            box-shadow: 0 0 15px var(--c-green);
        }
        .toggle-btn.off {
            background: transparent; border-color: #444; color: #666;
        }

        [x-cloak] { display: none !important; }
    </style>
</head>
<body x-data="hybridEngine(<?= htmlspecialchars(json_encode($serverData)) ?>)"
      class="h-screen w-screen flex flex-col p-3 gap-3"
      @keydown.window="handleKey($event, true)"
      @keyup.window="handleKey($event, false)">

    <!-- HEADER -->
    <header class="flex justify-between items-center px-6 py-3 cyber-panel rounded-t-lg z-50">
        <div class="flex items-center gap-6">
            <h1 class="text-3xl font-black font-[Orbitron] italic tracking-widest text-white">
                OMNI<span class="text-[var(--c-accent)]">STATION</span> <span class="text-sm text-gray-500 not-italic">V14 PRO</span>
            </h1>
            <div class="h-8 w-px bg-gray-700"></div>
            <div class="text-[10px] leading-tight font-bold text-gray-400">
                <div>BTC: <span class="text-[var(--c-gold)]">$<span x-text="data.price"></span></span></div>
                <div :class="data.trend==='bullish'?'text-green-500':'text-red-500'" x-text="data.trend.toUpperCase()"></div>
            </div>
        </div>

        <div class="flex items-center gap-6">
            <div class="text-right">
                <div class="text-[9px] text-gray-500 mb-1">OUTPUT LEVEL</div>
                <div class="w-32 h-2 bg-gray-900 rounded overflow-hidden border border-gray-700">
                    <div class="h-full bg-gradient-to-r from-green-500 to-red-500 transition-all duration-75" :style="`width: ${vuMeter}%`"></div>
                </div>
            </div>
            <button @click="toggleSystem()"
                    :class="ready ? 'border-[var(--c-warn)] text-[var(--c-warn)] shadow-[0_0_20px_rgba(255,0,85,0.4)]' : 'border-[var(--c-accent)] text-[var(--c-accent)] animate-pulse'"
                    class="border-2 px-8 py-2 font-bold rounded uppercase tracking-widest hover:bg-white/5 transition-all">
                <span x-text="ready ? 'SHUTDOWN' : 'INITIALIZE'"></span>
            </button>
        </div>
    </header>

    <!-- TAB NAVIGATION -->
    <nav class="flex gap-2 bg-black/30 p-1 rounded cyber-panel z-40">
        <button class="flex-1 py-2 font-bold text-xs tab-btn rounded" :class="tab==='main' && 'active'" @click="tab='main'">1. ADVANCED SAMPLER</button>
        <button class="flex-1 py-2 font-bold text-xs tab-btn rounded" :class="tab==='synth' && 'active'" @click="tab='synth'">2. SYNTH ENGINE</button>
        <button class="flex-1 py-2 font-bold text-xs tab-btn rounded" :class="tab==='fx' && 'active'" @click="tab='fx'">3. FX RACK & MASTER</button>
    </nav>

    <!-- MAIN CONTENT -->
    <main class="flex-1 relative min-h-0 cyber-panel rounded-b-lg overflow-hidden z-30">

        <!-- TAB 1: ADVANCED SAMPLER -->
        <div x-show="tab==='main'" class="absolute inset-0 p-4 grid grid-cols-12 gap-4" x-transition>

            <!-- LEFT: SAMPLER CONTROLS -->
            <div class="col-span-3 flex flex-col gap-3 bg-white/5 p-4 rounded border border-white/10 overflow-y-auto">

                <!-- PLAYBACK MODE -->
                <div class="border-b border-white/10 pb-3">
                    <h3 class="text-[var(--c-green)] font-bold text-xs mb-2">PLAYBACK MODE</h3>
                    <div class="grid grid-cols-2 gap-2">
                        <button @click="p.oneShot = false"
                                :class="!p.oneShot ? 'on' : 'off'"
                                class="toggle-btn">SUSTAINED</button>
                        <button @click="p.oneShot = true"
                                :class="p.oneShot ? 'on' : 'off'"
                                class="toggle-btn">ONE-SHOT</button>
                    </div>
                </div>

                <!-- LOOP CONTROLS -->
                <div class="border-b border-white/10 pb-3">
                    <h3 class="text-[var(--c-green)] font-bold text-xs mb-2">LOOP CONTROLS</h3>
                    <div class="space-y-2">
                        <div class="flex gap-2">
                            <button @click="p.loopEnabled = !p.loopEnabled"
                                    :class="p.loopEnabled ? 'on' : 'off'"
                                    class="toggle-btn flex-1">LOOP</button>
                            <button @click="p.reverse = !p.reverse"
                                    :class="p.reverse ? 'on' : 'off'"
                                    class="toggle-btn flex-1">REVERSE</button>
                        </div>
                        <div>
                            <label class="text-[9px] block">LOOP START</label>
                            <input type="range" min="0" max="1" step="0.001" x-model="p.loopStart" @input="validateLoopPoints()">
                            <div class="text-[8px] text-gray-500" x-text="Math.round(p.loopStart*100)+'%'"></div>
                        </div>
                        <div>
                            <label class="text-[9px] block">LOOP END</label>
                            <input type="range" min="0" max="1" step="0.001" x-model="p.loopEnd" @input="validateLoopPoints()">
                            <div class="text-[8px] text-gray-500" x-text="Math.round(p.loopEnd*100)+'%'"></div>
                        </div>
                    </div>
                </div>

                <!-- ADSR ENVELOPE -->
                <div class="border-b border-white/10 pb-3">
                    <h3 class="text-[var(--c-gold)] font-bold text-xs mb-2">ADSR ENVELOPE</h3>
                    <div class="space-y-2">
                        <div>
                            <label class="text-[9px] flex justify-between"><span>ATTACK</span><span x-text="(p.attack*1000).toFixed(0)+'ms'"></span></label>
                            <input type="range" min="0.001" max="2" step="0.001" x-model="p.attack">
                        </div>
                        <div>
                            <label class="text-[9px] flex justify-between"><span>DECAY</span><span x-text="(p.decay*1000).toFixed(0)+'ms'"></span></label>
                            <input type="range" min="0.001" max="2" step="0.001" x-model="p.decay">
                        </div>
                        <div>
                            <label class="text-[9px] flex justify-between"><span>SUSTAIN</span><span x-text="Math.round(p.sustain*100)+'%'"></span></label>
                            <input type="range" min="0" max="1" step="0.01" x-model="p.sustain">
                        </div>
                        <div>
                            <label class="text-[9px] flex justify-between"><span>RELEASE</span><span x-text="(p.release*1000).toFixed(0)+'ms'"></span></label>
                            <input type="range" min="0.001" max="5" step="0.001" x-model="p.release">
                        </div>
                    </div>
                </div>

                <!-- PITCH & TUNING -->
                <div class="border-b border-white/10 pb-3">
                    <h3 class="text-[var(--c-accent)] font-bold text-xs mb-2">PITCH & TUNING</h3>
                    <div class="space-y-2">
                        <div>
                            <label class="text-[9px] flex justify-between"><span>PITCH</span><span x-text="p.pitch.toFixed(2)+'x'"></span></label>
                            <input type="range" min="0.25" max="4" step="0.01" x-model="p.pitch">
                        </div>
                        <div>
                            <label class="text-[9px] flex justify-between"><span>FINE TUNE</span><span x-text="p.fineTune+' cents'"></span></label>
                            <input type="range" min="-100" max="100" step="1" x-model="p.fineTune">
                        </div>
                        <button @click="p.pitch=1; p.fineTune=0" class="w-full py-1 text-[9px] bg-white/10 hover:bg-white/20 rounded">RESET PITCH</button>
                    </div>
                </div>

                <!-- PAN & STEREO -->
                <div class="border-b border-white/10 pb-3">
                    <h3 class="text-purple-400 font-bold text-xs mb-2">STEREO</h3>
                    <div class="space-y-2">
                        <div>
                            <label class="text-[9px] flex justify-between">
                                <span>PAN</span>
                                <span x-text="p.pan === 0 ? 'CENTER' : (p.pan > 0 ? 'R'+Math.round(p.pan*100) : 'L'+Math.round(Math.abs(p.pan)*100))"></span>
                            </label>
                            <input type="range" min="-1" max="1" step="0.01" x-model="p.pan" @input="updateParams()">
                        </div>
                        <div>
                            <label class="text-[9px] flex justify-between"><span>STEREO WIDTH</span><span x-text="Math.round(p.width*100)+'%'"></span></label>
                            <input type="range" min="0" max="2" step="0.01" x-model="p.width">
                        </div>
                    </div>
                </div>

                <!-- LO-FI / DEGRADATION -->
                <div>
                    <h3 class="text-orange-400 font-bold text-xs mb-2">LO-FI / DEGRADATION</h3>
                    <div class="space-y-2">
                        <div>
                            <label class="text-[9px] flex justify-between"><span>SAMPLE RATE</span><span x-text="Math.round((1-p.bitCrush)*100)+'%'"></span></label>
                            <input type="range" min="0" max="0.95" step="0.01" x-model="p.bitCrush">
                        </div>
                        <div>
                            <label class="text-[9px] flex justify-between"><span>GRAIN CHAOS</span><span x-text="Math.round(p.jitter*100)+'%'"></span></label>
                            <input type="range" min="0" max="0.5" step="0.01" x-model="p.jitter">
                        </div>
                    </div>
                </div>
            </div>

            <!-- CENTER-RIGHT: WAVEFORM & CONTROLS -->
            <div class="col-span-9 flex flex-col gap-4">

                <!-- WAVEFORM DISPLAY -->
                <div class="flex-1 bg-black rounded border border-white/10 relative group overflow-hidden cursor-crosshair"
                     @mousedown="scrubStart($event)" @mousemove="scrubMove($event)" @mouseup="scrubEnd()" @mouseleave="scrubEnd()"
                     @dragover.prevent @drop.prevent="handleDrop($event)">

                    <!-- CANVAS -->
                    <canvas id="wave" class="absolute inset-0 w-full h-full opacity-80"></canvas>

                    <!-- LOOP REGION -->
                    <div x-show="p.loopEnabled && buffer"
                         class="loop-region"
                         :style="`left: ${p.loopStart * 100}%; width: ${(p.loopEnd - p.loopStart) * 100}%`"></div>

                    <!-- LOOP START MARKER -->
                    <div x-show="p.loopEnabled && buffer"
                         class="loop-marker"
                         :style="`left: ${p.loopStart * 100}%; background: var(--c-green); color: var(--c-green)`"
                         @mousedown.stop="dragLoopStart($event)">
                    </div>

                    <!-- LOOP END MARKER -->
                    <div x-show="p.loopEnabled && buffer"
                         class="loop-marker"
                         :style="`left: ${p.loopEnd * 100}%; background: var(--c-green); color: var(--c-green)`"
                         @mousedown.stop="dragLoopEnd($event)">
                    </div>

                    <!-- PLAYHEAD -->
                    <div class="scrub-line" :style="`left: ${p.samplePos * 100}%`"></div>

                    <!-- INFO OVERLAY -->
                    <div class="absolute top-3 left-3 pointer-events-none space-y-1">
                        <div class="text-[11px] font-bold text-[var(--c-accent)]" x-text="fileName || 'NO FILE LOADED - DRAG MP3/WAV HERE'"></div>
                        <div class="text-[9px] text-gray-400" x-show="buffer">
                            <span x-text="(buffer?.duration || 0).toFixed(2)+'s'"></span> ·
                            <span x-text="(buffer?.sampleRate || 0)/1000+'kHz'"></span> ·
                            <span x-text="buffer?.numberOfChannels + ' CH'"></span>
                        </div>
                        <div class="text-[9px] text-[var(--c-warn)] animate-pulse" x-show="isScrubbing">⚡ SCRUBBING</div>
                        <div class="text-[9px] text-[var(--c-green)]" x-show="p.loopEnabled">🔁 LOOP: <span x-text="Math.round(p.loopStart*100)+'% → '+Math.round(p.loopEnd*100)+'%'"></span></div>
                    </div>

                    <!-- FILE INPUT -->
                    <div class="absolute inset-0 flex items-center justify-center pointer-events-none" x-show="!buffer">
                        <div class="text-center">
                            <div class="text-6xl mb-4 opacity-20">📁</div>
                            <div class="text-sm text-gray-500">DRAG & DROP AUDIO FILE</div>
                            <div class="text-xs text-gray-600 mt-2">OR CLICK TO BROWSE</div>
                        </div>
                    </div>
                    <input type="file" accept="audio/*" class="absolute inset-0 opacity-0 cursor-pointer" @change="loadFile($event)" x-show="!buffer">
                </div>

                <!-- BOTTOM CONTROLS -->
                <div class="grid grid-cols-4 gap-3 bg-white/5 p-4 rounded border border-white/10">

                    <!-- VOLUME & MIX -->
                    <div>
                        <h4 class="text-[10px] text-[var(--c-gold)] font-bold mb-2">VOLUME & MIX</h4>
                        <div class="space-y-2">
                            <div>
                                <label class="text-[8px] flex justify-between"><span>SAMPLE VOL</span><span x-text="Math.round(p.sampleVol*100)+'%'"></span></label>
                                <input type="range" min="0" max="1.5" step="0.01" x-model="p.sampleVol">
                            </div>
                            <div>
                                <label class="text-[8px] flex justify-between"><span>SYNTH MIX</span><span x-text="Math.round(p.synthVol*100)+'%'"></span></label>
                                <input type="range" min="0" max="1" step="0.01" x-model="p.synthVol">
                            </div>
                        </div>
                    </div>

                    <!-- FILTER -->
                    <div>
                        <h4 class="text-[10px] text-[var(--c-accent)] font-bold mb-2">FILTER</h4>
                        <div class="space-y-2">
                            <div>
                                <label class="text-[8px] flex justify-between"><span>CUTOFF</span><span x-text="Math.round(p.cutoff*100)+'%'"></span></label>
                                <input type="range" min="0.1" max="1" step="0.01" x-model="p.cutoff" @input="updateParams()">
                            </div>
                            <div>
                                <label class="text-[8px] flex justify-between"><span>RESONANCE</span><span x-text="Math.round(p.reso*100)+'%'"></span></label>
                                <input type="range" min="0" max="1" step="0.01" x-model="p.reso" @input="updateParams()">
                            </div>
                        </div>
                    </div>

                    <!-- LFO WOBBLE -->
                    <div>
                        <h4 class="text-[10px] text-purple-400 font-bold mb-2">LFO MODULATION</h4>
                        <div class="space-y-2">
                            <div>
                                <label class="text-[8px] flex justify-between"><span>WOBBLE AMT</span><span x-text="Math.round(p.wobble*100)+'%'"></span></label>
                                <input type="range" min="0" max="1" step="0.01" x-model="p.wobble" @input="updateParams()">
                            </div>
                            <div>
                                <label class="text-[8px] flex justify-between"><span>LFO SPEED</span><span x-text="p.lfoSpeed.toFixed(1)+'Hz'"></span></label>
                                <input type="range" min="0.1" max="20" step="0.1" x-model="p.lfoSpeed" @input="updateParams()">
                            </div>
                        </div>
                    </div>

                    <!-- ACTIONS -->
                    <div>
                        <h4 class="text-[10px] text-gray-400 font-bold mb-2">ACTIONS</h4>
                        <div class="space-y-1">
                            <button @click="normalizeBuffer()" :disabled="!buffer" class="w-full py-1 text-[9px] bg-blue-500/20 hover:bg-blue-500/40 disabled:opacity-30 disabled:cursor-not-allowed rounded border border-blue-500/50">
                                NORMALIZE
                            </button>
                            <button @click="resetSampler()" class="w-full py-1 text-[9px] bg-red-500/20 hover:bg-red-500/40 rounded border border-red-500/50">
                                RESET ALL
                            </button>
                            <div class="text-[8px] text-gray-600 mt-2">
                                Use A-K keys to play<br>
                                Arrows: Dist/Scrub
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 2: SYNTH ENGINE -->
        <div x-show="tab==='synth'" class="absolute inset-0 p-4 grid grid-cols-3 gap-4" x-transition>
            <div class="bg-white/5 p-4 rounded border border-white/10">
                <h3 class="text-[var(--c-accent)] font-bold text-sm mb-4 border-b border-white/10 pb-2">OSC A (UNISON)</h3>
                <div class="space-y-3">
                    <div>
                        <label class="text-[9px] flex justify-between"><span>SYNTH MIX</span><span x-text="Math.round(p.synthVol*100)+'%'"></span></label>
                        <input type="range" min="0" max="1" step="0.01" x-model="p.synthVol">
                    </div>
                    <div>
                        <label class="text-[9px] flex justify-between"><span>DETUNE</span><span x-text="p.detune+' cents'"></span></label>
                        <input type="range" min="0" max="50" step="1" x-model="p.detune">
                    </div>
                    <div>
                        <label class="text-[9px] flex justify-between"><span>SUB OSC</span><span x-text="Math.round(p.subVol*100)+'%'"></span></label>
                        <input type="range" min="0" max="1" step="0.01" x-model="p.subVol">
                    </div>
                </div>
            </div>

            <div class="bg-white/5 p-4 rounded border border-white/10">
                <h3 class="text-[var(--c-gold)] font-bold text-sm mb-4 border-b border-white/10 pb-2">FILTER</h3>
                <div class="space-y-3">
                    <div>
                        <label class="text-[9px] flex justify-between"><span>CUTOFF</span><span x-text="Math.round(p.cutoff*100)+'%'"></span></label>
                        <input type="range" min="0.1" max="1" step="0.01" x-model="p.cutoff" @input="updateParams()">
                    </div>
                    <div>
                        <label class="text-[9px] flex justify-between"><span>RESONANCE</span><span x-text="Math.round(p.reso*100)+'%'"></span></label>
                        <input type="range" min="0" max="1" step="0.01" x-model="p.reso" @input="updateParams()">
                    </div>
                </div>
            </div>

            <div class="bg-black/30 p-4 rounded text-[10px] text-gray-400 font-mono">
                <div class="text-white font-bold mb-2">SYNTH INFO:</div>
                <div class="space-y-1">
                    <div>• 3x Sawtooth Stack</div>
                    <div>• Unison Detuning</div>
                    <div>• Sub Oscillator</div>
                    <div>• Lowpass Filter</div>
                    <div>• LFO Modulation</div>
                </div>
            </div>
        </div>

        <!-- TAB 3: FX RACK -->
        <div x-show="tab==='fx'" class="absolute inset-0 p-6 grid grid-cols-4 gap-6 bg-black/40" x-cloak>
            <template x-for="mod in ['DISTORTION', 'DELAY', 'REVERB', 'MASTER']">
                <div class="p-5 bg-[#18181c] border border-gray-700 rounded hover:border-[var(--c-accent)] transition-colors">
                    <h3 class="text-white font-bold text-xs mb-4 border-b border-gray-600 pb-2" x-text="mod"></h3>

                    <div x-show="mod==='DISTORTION'" class="space-y-4">
                        <div>
                            <label class="text-[9px] text-[var(--c-warn)] flex justify-between"><span>DRIVE</span><span x-text="Math.round(p.dist*100)+'%'"></span></label>
                            <input type="range" x-model="p.dist" min="0" max="1" step="0.01" @input="updateParams()">
                        </div>
                        <div>
                            <label class="text-[9px] text-[var(--c-warn)] flex justify-between"><span>CRUSH</span><span x-text="Math.round(p.crush*100)+'%'"></span></label>
                            <input type="range" x-model="p.crush" min="0" max="1" step="0.01" @input="updateParams()">
                        </div>
                    </div>

                    <div x-show="mod==='DELAY'" class="space-y-4">
                        <div>
                            <label class="text-[9px] text-green-400 flex justify-between"><span>FEEDBACK</span><span x-text="Math.round(p.delayFb*100)+'%'"></span></label>
                            <input type="range" x-model="p.delayFb" min="0" max="0.95" step="0.01" @input="updateParams()">
                        </div>
                        <div>
                            <label class="text-[9px] text-green-400 flex justify-between"><span>TIME</span><span x-text="(p.delayTime*1000).toFixed(0)+'ms'"></span></label>
                            <input type="range" x-model="p.delayTime" min="0.05" max="2" step="0.01" @input="updateParams()">
                        </div>
                    </div>

                    <div x-show="mod==='REVERB'" class="space-y-4">
                        <div>
                            <label class="text-[9px] text-purple-400 flex justify-between"><span>WET MIX</span><span x-text="Math.round(p.verbMix*100)+'%'"></span></label>
                            <input type="range" x-model="p.verbMix" min="0" max="1" step="0.01" @input="updateParams()">
                        </div>
                    </div>

                    <div x-show="mod==='MASTER'" class="space-y-4">
                        <div>
                            <label class="text-[9px] text-white flex justify-between"><span>MAIN OUTPUT</span><span x-text="Math.round(p.master*100)+'%'"></span></label>
                            <input type="range" x-model="p.master" min="0" max="1.5" step="0.01" @input="updateParams()">
                        </div>
                        <div class="text-[9px] text-gray-500 mt-4">
                            <div class="mb-1">🛡️ LIMITER ACTIVE</div>
                            <div>PEAK: <span class="text-[var(--c-accent)]" x-text="Math.round(vuMeter)+'%'"></span></div>
                        </div>
                    </div>
                </div>
            </template>
        </div>
    </main>

    <!-- KEYBOARD FOOTER -->
    <footer class="h-32 cyber-panel rounded-lg flex px-1 py-1 relative z-50 select-none">
        <template x-for="n in whiteKeys">
            <div class="flex-1 border-r border-gray-400 last:border-0 rounded-b cursor-pointer key relative bg-white text-black"
                 :class="activeNotes.has(n.midi) ? 'active' : ''"
                 @mousedown="play(n.midi)" @mouseup="stop(n.midi)" @mouseleave="stop(n.midi)" @mouseenter="if($event.buttons===1) play(n.midi)">
                 <span class="absolute bottom-2 left-1/2 -translate-x-1/2 text-[10px] font-bold" x-text="n.key"></span>
            </div>
        </template>
        <template x-for="n in blackKeys">
            <div class="absolute w-[6%] rounded-b cursor-pointer key black border-x border-b border-white/20"
                 :style="`left: ${n.pos}%`" :class="activeNotes.has(n.midi) ? 'active' : ''"
                 @mousedown="play(n.midi)" @mouseup="stop(n.midi)" @mouseleave="stop(n.midi)" @mouseenter="if($event.buttons===1) play(n.midi)">
            </div>
        </template>
    </footer>

    <script>
        document.addEventListener('alpine:init', () => {
            Alpine.data('hybridEngine', (server) => ({
                data: server,
                ready: false,
                tab: 'main',
                ctx: null,

                // State
                vuMeter: 0,
                activeNotes: new Set(),
                fileName: '',
                buffer: null,
                originalBuffer: null,

                // Scrubbing & Loop Dragging
                isScrubbing: false,
                isDraggingLoopStart: false,
                isDraggingLoopEnd: false,
                scrubNode: null,
                lastMouseX: 0,

                // Parameters
                p: {
                    master: 0.8,

                    // Synth
                    synthVol: 0.6, subVol: 0.4, detune: 12,

                    // Filter
                    cutoff: 1.0, reso: 0.0,

                    // Sampler Basic
                    sampleVol: 0.8,
                    samplePos: 0.0,
                    pitch: 1.0,
                    fineTune: 0,

                    // Sampler Advanced
                    oneShot: false,
                    loopEnabled: false,
                    loopStart: 0.0,
                    loopEnd: 1.0,
                    reverse: false,

                    // ADSR
                    attack: 0.005,
                    decay: 0.1,
                    sustain: 0.7,
                    release: 0.2,

                    // Stereo
                    pan: 0,
                    width: 1.0,

                    // Lo-Fi
                    bitCrush: 0,
                    jitter: 0.0,

                    // LFO
                    wobble: 0.0,
                    lfoSpeed: 4,

                    // FX
                    dist: 0,
                    crush: 0,
                    delayFb: 0.4,
                    delayTime: 0.3,
                    verbMix: 0.3
                },

                // Keyboard Map
                whiteKeys: [
                    {key:'A',midi:60},{key:'S',midi:62},{key:'D',midi:64},{key:'F',midi:65},
                    {key:'G',midi:67},{key:'H',midi:69},{key:'J',midi:71},{key:'K',midi:72}
                ],
                blackKeys: [
                    {key:'W',midi:61,pos:10.5},{key:'E',midi:63,pos:23},
                    {key:'T',midi:66,pos:48},{key:'Z',midi:68,pos:60.5},{key:'U',midi:70,pos:73}
                ],

                nodes: {}, voices: {}, analyser: null,

                init() {
                    this.loopVis();

                    // Global mouse handlers for loop dragging
                    document.addEventListener('mousemove', (e) => {
                        if(this.isDraggingLoopStart || this.isDraggingLoopEnd) {
                            const canvas = document.getElementById('wave');
                            if(!canvas) return;
                            const rect = canvas.getBoundingClientRect();
                            const pos = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));

                            if(this.isDraggingLoopStart) {
                                this.p.loopStart = Math.min(pos, this.p.loopEnd - 0.01);
                            } else if(this.isDraggingLoopEnd) {
                                this.p.loopEnd = Math.max(pos, this.p.loopStart + 0.01);
                            }
                        }
                    });

                    document.addEventListener('mouseup', () => {
                        this.isDraggingLoopStart = false;
                        this.isDraggingLoopEnd = false;
                    });
                },

                async toggleSystem() {
                    if(!this.ctx) {
                        const AC = window.AudioContext || window.webkitAudioContext;
                        this.ctx = new AC();
                        await this.buildGraph();
                        this.generateFallbackBuffer();
                    }
                    if(this.ctx.state === 'suspended') await this.ctx.resume();
                    this.ready = !this.ready;

                    if(this.p.cutoff < 0.1) this.p.cutoff = 0.8;
                    this.updateParams();

                    this.nodes.master.gain.setTargetAtTime(this.ready ? this.p.master : 0, this.ctx.currentTime, 0.1);
                    if(!this.ready) this.stopAll();
                },

                async buildGraph() {
                    const c = this.ctx;

                    // INPUT & FILTER
                    this.nodes.input = c.createGain();
                    this.nodes.filter = c.createBiquadFilter();
                    this.nodes.filter.type = 'lowpass';
                    this.nodes.filter.frequency.value = 20000;

                    // LFO (Wobble)
                    this.nodes.lfo = c.createOscillator();
                    this.nodes.lfo.frequency.value = 4;
                    this.nodes.lfoGain = c.createGain();
                    this.nodes.lfoGain.gain.value = 0;
                    this.nodes.lfo.connect(this.nodes.lfoGain).connect(this.nodes.filter.frequency);
                    this.nodes.lfo.start();

                    // STEREO PANNER
                    this.nodes.panner = c.createStereoPanner ? c.createStereoPanner() : c.createGain();

                    // FX CHAIN
                    this.nodes.dist = c.createWaveShaper();
                    this.nodes.dist.curve = this.makeCurve(0,0);

                    this.nodes.delay = c.createDelay(5);
                    this.nodes.dfb = c.createGain();
                    this.nodes.delay.connect(this.nodes.dfb).connect(this.nodes.delay);
                    this.nodes.dgain = c.createGain();
                    this.nodes.dgain.gain.value = 0.5;

                    this.nodes.verb = c.createConvolver();
                    await this.makeReverb();
                    this.nodes.vgain = c.createGain();

                    this.nodes.master = c.createGain();
                    this.nodes.analyser = c.createAnalyser();
                    this.nodes.analyser.fftSize = 1024;

                    // ROUTING
                    this.nodes.input.connect(this.nodes.filter);

                    if(this.nodes.panner.pan) {
                        this.nodes.filter.connect(this.nodes.panner);
                        this.nodes.panner.connect(this.nodes.dist);
                    } else {
                        this.nodes.filter.connect(this.nodes.dist);
                    }

                    this.nodes.dist.connect(this.nodes.master);
                    this.nodes.dist.connect(this.nodes.delay);
                    this.nodes.delay.connect(this.nodes.dgain).connect(this.nodes.master);
                    this.nodes.dist.connect(this.nodes.verb);
                    this.nodes.verb.connect(this.nodes.vgain).connect(this.nodes.master);

                    this.nodes.master.connect(this.nodes.analyser);
                    this.nodes.analyser.connect(c.destination);
                },

                // ---------------------------
                // PLAY ENGINE (Advanced Sampler)
                // ---------------------------
                play(midi, velocity = 0.8) {
                    if(!this.ready) return;
                    if(this.activeNotes.has(midi) && !this.p.oneShot) return;
                    this.activeNotes.add(midi);

                    const t = this.ctx.currentTime;
                    const freq = 440 * Math.pow(2, (midi-69)/12);
                    const v = { oscs: [], env: this.ctx.createGain(), midi: midi };

                    // A. SYNTH LAYER
                    if(this.p.synthVol > 0) {
                        for(let i=0; i<3; i++) {
                            const o = this.ctx.createOscillator();
                            o.type = 'sawtooth';
                            o.frequency.value = freq;
                            o.detune.value = (i-1) * this.p.detune;
                            const g = this.ctx.createGain();
                            g.gain.value = (this.p.synthVol / 3) * 0.5 * velocity;
                            o.connect(g).connect(v.env);
                            o.start(t);
                            v.oscs.push(o);
                        }
                    }

                    // Sub Osc
                    if(this.p.subVol > 0) {
                        const s = this.ctx.createOscillator();
                        s.type = 'sine';
                        s.frequency.value = freq/2;
                        const g = this.ctx.createGain();
                        g.gain.value = this.p.subVol * velocity;
                        s.connect(g).connect(v.env);
                        s.start(t);
                        v.oscs.push(s);
                    }

                    // B. ADVANCED SAMPLER LAYER
                    if(this.buffer && this.p.sampleVol > 0) {
                        const s = this.ctx.createBufferSource();

                        // Use reversed buffer if reverse is enabled
                        s.buffer = this.p.reverse ? this.getReverseBuffer() : this.buffer;

                        // Pitch with fine tune
                        const pitchMult = Math.pow(2, this.p.fineTune / 1200);
                        s.playbackRate.value = (freq/261.63) * this.p.pitch * pitchMult;

                        // Loop settings
                        if(this.p.loopEnabled && !this.p.oneShot) {
                            s.loop = true;
                            const dur = s.buffer.duration;
                            s.loopStart = this.p.loopStart * dur;
                            s.loopEnd = this.p.loopEnd * dur;
                        }

                        // Sample rate reduction (bit crush)
                        let sampleNode = s;
                        if(this.p.bitCrush > 0) {
                            const crusher = this.ctx.createWaveShaper();
                            const samples = Math.max(2, Math.floor(256 * (1 - this.p.bitCrush)));
                            crusher.curve = this.makeBitCrushCurve(samples);
                            s.connect(crusher);
                            sampleNode = crusher;
                        }

                        // Granular Start Position
                        let start = this.p.samplePos * s.buffer.duration;
                        start += (Math.random() - 0.5) * this.p.jitter;
                        start = Math.max(0, Math.min(start, s.buffer.duration - 0.01));

                        const g = this.ctx.createGain();
                        g.gain.value = this.p.sampleVol * velocity;

                        if(sampleNode === s) {
                            s.connect(g).connect(v.env);
                        } else {
                            sampleNode.connect(g).connect(v.env);
                        }

                        // Start playback
                        if(this.p.oneShot) {
                            s.start(t, start);
                            // Auto-stop after sample duration
                            const duration = s.buffer.duration - start;
                            setTimeout(() => this.stop(midi), duration * 1000 / s.playbackRate.value);
                        } else {
                            s.start(t, start);
                        }

                        v.oscs.push(s);
                    }

                    // ADSR ENVELOPE
                    const att = this.p.attack;
                    const dec = this.p.decay;
                    const sus = this.p.sustain;

                    v.env.gain.setValueAtTime(0, t);
                    v.env.gain.linearRampToValueAtTime(1.0, t + att);
                    v.env.gain.linearRampToValueAtTime(sus, t + att + dec);

                    v.env.connect(this.nodes.input);
                    this.voices[midi] = v;

                    // Auto-stop for one-shot mode
                    if(this.p.oneShot && this.buffer) {
                        const totalDuration = att + dec + (this.buffer.duration * 0.5);
                        setTimeout(() => this.stop(midi), totalDuration * 1000);
                    }
                },

                stop(midi) {
                    if(!this.voices[midi]) return;
                    this.activeNotes.delete(midi);
                    const v = this.voices[midi];
                    const t = this.ctx.currentTime;

                    // Release phase
                    v.env.gain.cancelScheduledValues(t);
                    v.env.gain.setValueAtTime(v.env.gain.value, t);
                    v.env.gain.linearRampToValueAtTime(0, t + this.p.release);

                    setTimeout(() => {
                        v.oscs.forEach(o => {try{o.stop()}catch(e){}});
                        v.env.disconnect();
                    }, this.p.release * 1000 + 50);

                    delete this.voices[midi];
                },

                stopAll() {
                    Array.from(this.activeNotes).forEach(n => this.stop(n));
                },

                // ---------------------------
                // SCRUBBING & LOOP DRAGGING
                // ---------------------------
                scrubStart(e) {
                    if(!this.buffer || !this.ready) return;
                    this.isScrubbing = true;
                    this.lastMouseX = e.clientX;
                    this.stopAll();

                    if(this.scrubNode) this.scrubNode.stop();
                    this.scrubNode = this.ctx.createBufferSource();
                    this.scrubNode.buffer = this.buffer;
                    this.scrubNode.loop = true;
                    const g = this.ctx.createGain();
                    g.gain.value = this.p.sampleVol;
                    this.scrubNode.connect(g).connect(this.nodes.input);
                    this.scrubNode.start(0, this.p.samplePos * this.buffer.duration);
                    this.scrubNode.playbackRate.value = 0;
                },

                scrubMove(e) {
                    if(!this.isScrubbing) return;
                    const r = e.target.getBoundingClientRect();
                    this.p.samplePos = Math.max(0, Math.min(1, (e.clientX - r.left) / r.width));

                    const delta = e.clientX - this.lastMouseX;
                    this.lastMouseX = e.clientX;
                    if(this.scrubNode) {
                        this.scrubNode.playbackRate.setTargetAtTime(delta * 0.3, this.ctx.currentTime, 0.05);
                    }
                },

                scrubEnd() {
                    this.isScrubbing = false;
                    if(this.scrubNode) {
                        this.scrubNode.stop();
                        this.scrubNode = null;
                    }
                },

                dragLoopStart(e) {
                    e.preventDefault();
                    this.isDraggingLoopStart = true;
                },

                dragLoopEnd(e) {
                    e.preventDefault();
                    this.isDraggingLoopEnd = true;
                },

                validateLoopPoints() {
                    if(this.p.loopStart >= this.p.loopEnd) {
                        this.p.loopEnd = Math.min(1, this.p.loopStart + 0.01);
                    }
                },

                // ---------------------------
                // PARAMS & FX
                // ---------------------------
                updateParams() {
                    if(!this.ready) return;
                    const t = this.ctx.currentTime;

                    this.nodes.master.gain.setTargetAtTime(this.p.master, t, 0.1);

                    const f = Math.pow(this.p.cutoff, 2) * 20000;
                    this.nodes.filter.frequency.setTargetAtTime(Math.max(20, f), t, 0.1);
                    this.nodes.filter.Q.value = this.p.reso * 20;

                    // LFO
                    this.nodes.lfo.frequency.value = this.p.lfoSpeed;
                    this.nodes.lfoGain.gain.setTargetAtTime(this.p.wobble * 2000, t, 0.1);

                    // Panner
                    if(this.nodes.panner.pan) {
                        this.nodes.panner.pan.setTargetAtTime(this.p.pan, t, 0.1);
                    }

                    // Distortion
                    this.nodes.dist.curve = this.makeCurve(this.p.dist, this.p.crush);

                    // Delay
                    this.nodes.dfb.gain.value = this.p.delayFb;
                    this.nodes.delay.delayTime.value = this.p.delayTime;

                    // Reverb
                    this.nodes.vgain.gain.setTargetAtTime(this.p.verbMix, t, 0.1);
                },

                // ---------------------------
                // BUFFER OPERATIONS
                // ---------------------------
                getReverseBuffer() {
                    if(!this.buffer) return null;

                    const reversed = this.ctx.createBuffer(
                        this.buffer.numberOfChannels,
                        this.buffer.length,
                        this.buffer.sampleRate
                    );

                    for(let ch = 0; ch < this.buffer.numberOfChannels; ch++) {
                        const input = this.buffer.getChannelData(ch);
                        const output = reversed.getChannelData(ch);
                        for(let i = 0; i < input.length; i++) {
                            output[i] = input[input.length - 1 - i];
                        }
                    }

                    return reversed;
                },

                normalizeBuffer() {
                    if(!this.buffer) return;

                    // Find peak
                    let peak = 0;
                    for(let ch = 0; ch < this.buffer.numberOfChannels; ch++) {
                        const data = this.buffer.getChannelData(ch);
                        for(let i = 0; i < data.length; i++) {
                            peak = Math.max(peak, Math.abs(data[i]));
                        }
                    }

                    if(peak === 0) return;

                    // Create normalized buffer
                    const normalized = this.ctx.createBuffer(
                        this.buffer.numberOfChannels,
                        this.buffer.length,
                        this.buffer.sampleRate
                    );

                    const ratio = 0.95 / peak; // Leave headroom

                    for(let ch = 0; ch < this.buffer.numberOfChannels; ch++) {
                        const input = this.buffer.getChannelData(ch);
                        const output = normalized.getChannelData(ch);
                        for(let i = 0; i < input.length; i++) {
                            output[i] = input[i] * ratio;
                        }
                    }

                    this.buffer = normalized;
                    this.drawWave();
                },

                resetSampler() {
                    this.p.samplePos = 0;
                    this.p.pitch = 1;
                    this.p.fineTune = 0;
                    this.p.loopStart = 0;
                    this.p.loopEnd = 1;
                    this.p.loopEnabled = false;
                    this.p.reverse = false;
                    this.p.oneShot = false;
                    this.p.pan = 0;
                    this.p.width = 1;
                    this.p.bitCrush = 0;
                    this.p.jitter = 0;
                    this.p.attack = 0.005;
                    this.p.decay = 0.1;
                    this.p.sustain = 0.7;
                    this.p.release = 0.2;
                    this.updateParams();
                },

                // ---------------------------
                // FILES & UTILS
                // ---------------------------
                handleDrop(e) {
                    const f = e.dataTransfer.files[0];
                    if(f) this.loadFile({target:{files:[f]}});
                },

                loadFile(e) {
                    const f = e.target.files[0];
                    if(!f) return;
                    if(!this.ready) this.toggleSystem();

                    this.fileName = f.name.toUpperCase();
                    const r = new FileReader();
                    r.onload = ev => {
                        this.ctx.decodeAudioData(ev.target.result, b => {
                            this.buffer = b;
                            this.originalBuffer = b;
                            this.drawWave();
                        });
                    };
                    r.readAsArrayBuffer(f);
                },

                generateFallbackBuffer() {
                    const sr = this.ctx.sampleRate;
                    const b = this.ctx.createBuffer(2, sr * 2, sr);

                    for(let ch = 0; ch < 2; ch++) {
                        const d = b.getChannelData(ch);
                        for(let i = 0; i < d.length; i++) {
                            d[i] = (Math.random() * 2 - 1) * Math.exp(-i / sr * 2);
                        }
                    }

                    this.buffer = b;
                    this.originalBuffer = b;
                    this.fileName = 'FALLBACK NOISE';
                    this.drawWave();
                },

                makeCurve(amt, crush) {
                    const k = amt * 100;
                    const n = 256;
                    const c = new Float32Array(n);

                    for(let i = 0; i < n; i++) {
                        let x = (i * 2) / n - 1;
                        let y = (3 + k) * x * 20 * (Math.PI / 180) / (Math.PI + k * Math.abs(x));

                        if(crush > 0) {
                            const s = 2 + (1 - crush) * 20;
                            y = Math.round(y * s) / s;
                        }

                        c[i] = y;
                    }

                    return c;
                },

                makeBitCrushCurve(samples) {
                    const curve = new Float32Array(samples);
                    for(let i = 0; i < samples; i++) {
                        curve[i] = (i * 2 / samples) - 1;
                    }
                    return curve;
                },

                async makeReverb() {
                    const l = this.ctx.sampleRate * 3;
                    const b = this.ctx.createBuffer(2, l, this.ctx.sampleRate);

                    for(let ch = 0; ch < 2; ch++) {
                        const d = b.getChannelData(ch);
                        for(let i = 0; i < l; i++) {
                            const decay = Math.pow(1 - i / l, 2);
                            d[i] = (Math.random() * 2 - 1) * decay;
                        }
                    }

                    this.nodes.verb.buffer = b;
                },

                handleKey(e, down) {
                    if(e.repeat) return;

                    // Piano keys
                    const keys = "asdfghjk";
                    const idx = keys.indexOf(e.key.toLowerCase());
                    if(idx > -1) {
                        if(down) this.play(60 + idx);
                        else this.stop(60 + idx);
                    }

                    // Black keys
                    const blackMap = {w:61, e:63, t:66, z:68, u:70};
                    if(blackMap[e.key.toLowerCase()]) {
                        const m = blackMap[e.key.toLowerCase()];
                        if(down) this.play(m);
                        else this.stop(m);
                    }

                    // Arrows for FX/Scrub
                    if(down) {
                        if(e.key === 'ArrowUp') {
                            this.p.dist = Math.min(1, this.p.dist + 0.05);
                            this.updateParams();
                        }
                        if(e.key === 'ArrowDown') {
                            this.p.dist = Math.max(0, this.p.dist - 0.05);
                            this.updateParams();
                        }
                        if(e.key === 'ArrowRight') {
                            this.p.samplePos = Math.min(1, this.p.samplePos + 0.01);
                        }
                        if(e.key === 'ArrowLeft') {
                            this.p.samplePos = Math.max(0, this.p.samplePos - 0.01);
                        }
                        if(e.key === ' ') {
                            e.preventDefault();
                            this.stopAll();
                        }
                    }
                },

                drawWave() {
                    const canvas = document.getElementById('wave');
                    if(!canvas) return;

                    const ctx = canvas.getContext('2d');
                    canvas.width = canvas.clientWidth;
                    canvas.height = canvas.clientHeight;

                    if(!this.buffer) return;

                    const d = this.buffer.getChannelData(0);
                    const step = Math.ceil(d.length / canvas.width);

                    ctx.fillStyle = 'rgba(0, 243, 255, 0.6)';
                    ctx.strokeStyle = 'rgba(0, 243, 255, 0.9)';
                    ctx.lineWidth = 1;
                    ctx.clearRect(0, 0, canvas.width, canvas.height);

                    // Draw waveform
                    ctx.beginPath();
                    for(let i = 0; i < canvas.width; i++) {
                        let min = 0, max = 0;
                        for(let j = 0; j < step; j++) {
                            const val = d[i * step + j] || 0;
                            min = Math.min(min, val);
                            max = Math.max(max, val);
                        }

                        const y1 = ((1 - max) * canvas.height / 2);
                        const y2 = ((1 - min) * canvas.height / 2);

                        ctx.fillRect(i, y1, 1, y2 - y1);
                    }

                    // Draw center line
                    ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
                    ctx.beginPath();
                    ctx.moveTo(0, canvas.height / 2);
                    ctx.lineTo(canvas.width, canvas.height / 2);
                    ctx.stroke();
                },

                loopVis() {
                    requestAnimationFrame(() => this.loopVis());

                    if(!this.nodes.analyser) return;

                    const arr = new Uint8Array(this.nodes.analyser.frequencyBinCount);
                    this.nodes.analyser.getByteFrequencyData(arr);

                    let sum = 0;
                    for(let v of arr) sum += v;

                    this.vuMeter = Math.min(100, (sum / arr.length) * 1.5);
                }
            }))
        });
    </script>
</body>
</html>
