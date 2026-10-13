// QuishGuard Live Camera Scanner Module
let html5QrCode = null;
let currentCameraId = null;
let isScanning = false;

// Web Audio API Beep Generator (No external audio file needed)
function playBeep(freq = 880, duration = 0.15) {
    try {
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = "sine";
        osc.frequency.value = freq;
        gain.gain.setValueAtTime(0.2, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start();
        osc.stop(audioCtx.currentTime + duration);
    } catch (e) {
        console.warn("Audio feedback not supported:", e);
    }
}

async function onScanSuccess(decodedText, decodedResult) {
    if (!isScanning) return;
    isScanning = false;
    
    // Play detection audio feedback
    playBeep(1046, 0.18); // High C tone

    const statusMsg = document.getElementById('camera-status-msg');
    statusMsg.innerHTML = '<span class="text-green"><i class="fa-solid fa-check me-1"></i> QR Detected! Initiating Security Analysis...</span>';

    // Stop camera
    if (html5QrCode) {
        try {
            await html5QrCode.stop();
        } catch (e) {
            console.warn("Error stopping camera:", e);
        }
    }

    // Show scanning progress overlay
    showProgressOverlay("DECODED CAMERA PAYLOAD", "Tracing destination hops and evaluating threat intelligence...");

    try {
        const resp = await fetch('/api/scan/camera', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ payload: decodedText })
        });
        const data = await resp.json();

        if (data.success && data.redirect_url) {
            window.location.href = data.redirect_url;
        } else {
            hideProgressOverlay();
            alert("Analysis failed: " + (data.error || "Unknown server error"));
            resetCameraControls();
        }
    } catch (err) {
        hideProgressOverlay();
        alert("Network communication error: " + err.message);
        resetCameraControls();
    }
}

function onScanFailure(error) {
    // Normal frame scanning failure (no QR in frame yet)
}

function resetCameraControls() {
    isScanning = false;
    document.getElementById('btn-start-camera').style.display = 'inline-block';
    document.getElementById('btn-stop-camera').style.display = 'none';
    document.getElementById('btn-switch-camera').style.display = 'none';
    document.getElementById('camera-overlay').style.display = 'none';
    document.getElementById('camera-status-msg').innerText = 'Camera idle. Click "Start Camera" to activate live viewfinder.';
}

document.addEventListener('DOMContentLoaded', () => {
    const btnStart = document.getElementById('btn-start-camera');
    const btnStop = document.getElementById('btn-stop-camera');
    const btnSwitch = document.getElementById('btn-switch-camera');
    const statusMsg = document.getElementById('camera-status-msg');
    const cameraOverlay = document.getElementById('camera-overlay');

    if (!btnStart) return;

    btnStart.addEventListener('click', async () => {
        statusMsg.innerHTML = '<span class="text-cyan"><i class="fa-solid fa-spinner fa-spin me-1"></i> Initializing camera hardware...</span>';

        if (!html5QrCode) {
            html5QrCode = new Html5Qrcode("qr-reader");
        }

        try {
            const devices = await Html5Qrcode.getCameras();
            if (!devices || devices.length === 0) {
                statusMsg.innerHTML = '<span class="text-red">No camera devices detected on this system.</span>';
                return;
            }

            // Prefer environment / back camera if available
            let selectedCamera = devices[0].id;
            for (let dev of devices) {
                if (dev.label.toLowerCase().includes('back') || dev.label.toLowerCase().includes('environment')) {
                    selectedCamera = dev.id;
                    break;
                }
            }
            currentCameraId = selectedCamera;

            await html5QrCode.start(
                currentCameraId,
                {
                    fps: 15,
                    qrbox: { width: 250, height: 250 },
                    aspectRatio: 1.0
                },
                onScanSuccess,
                onScanFailure
            );

            isScanning = true;
            btnStart.style.display = 'none';
            btnStop.style.display = 'inline-block';
            if (devices.length > 1) {
                btnSwitch.style.display = 'inline-block';
            }
            cameraOverlay.style.display = 'flex';
            statusMsg.innerHTML = '<span class="text-green font-mono">● LIVE SCANNING ACTIVE — Align QR inside reticle</span>';

        } catch (err) {
            statusMsg.innerHTML = `<span class="text-red">Camera access error: ${err}</span>`;
        }
    });

    btnStop.addEventListener('click', async () => {
        if (html5QrCode && isScanning) {
            try {
                await html5QrCode.stop();
            } catch (e) {}
        }
        resetCameraControls();
    });

    // Cleanup camera if user switches tabs
    document.querySelectorAll('#scannerTabs button').forEach(tabBtn => {
        tabBtn.addEventListener('shown.bs.tab', async (e) => {
            if (e.target.id !== 'camera-tab' && isScanning && html5QrCode) {
                try {
                    await html5QrCode.stop();
                } catch (e) {}
                resetCameraControls();
            }
        });
    });
});
