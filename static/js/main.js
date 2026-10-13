// QuishGuard Main Interactive Controls
function showProgressOverlay(title = "PROCESSING FORENSICS...", subtitle = "Running heuristic models and checking threat intelligence...") {
    const overlay = document.getElementById('scan-progress-overlay');
    const titleElem = document.getElementById('scan-status-text');
    const subElem = document.getElementById('scan-substatus-text');
    if (overlay) {
        if (titleElem) titleElem.innerText = title;
        if (subElem) subElem.innerText = subtitle;
        overlay.style.display = 'block';
        overlay.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}

function hideProgressOverlay() {
    const overlay = document.getElementById('scan-progress-overlay');
    if (overlay) overlay.style.display = 'none';
}

document.addEventListener('DOMContentLoaded', () => {

    // --- 1. Image Upload Scanner ---
    const imageDropzone = document.getElementById('image-dropzone');
    const imageInput = document.getElementById('image-file-input');
    const imagePreviewContainer = document.getElementById('image-preview-container');
    const imagePreview = document.getElementById('image-preview');
    const imageDetails = document.getElementById('image-file-details');
    const btnClearImage = document.getElementById('btn-clear-image');
    const btnSubmitImage = document.getElementById('btn-submit-image');
    const uploadForm = document.getElementById('upload-form');

    function handleSelectedImage(file) {
        if (!file || !file.type.startsWith('image/')) {
            alert('Please select a valid image file (PNG, JPG, BMP, WEBP).');
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            imagePreview.src = e.target.result;
            imageDetails.innerText = `${file.name} (${Math.round(file.size / 1024)} KB)`;
            imageDropzone.style.display = 'none';
            imagePreviewContainer.style.display = 'block';
            btnSubmitImage.disabled = false;
        };
        reader.readAsDataURL(file);
    }

    if (imageDropzone && imageInput) {
        ['dragenter', 'dragover'].forEach(eventName => {
            imageDropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                imageDropzone.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            imageDropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                imageDropzone.classList.remove('dragover');
            });
        });

        imageDropzone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                imageInput.files = files;
                handleSelectedImage(files[0]);
            }
        });

        imageInput.addEventListener('change', () => {
            if (imageInput.files.length > 0) {
                handleSelectedImage(imageInput.files[0]);
            }
        });

        btnClearImage.addEventListener('click', () => {
            imageInput.value = '';
            imagePreview.src = '#';
            imagePreviewContainer.style.display = 'none';
            imageDropzone.style.display = 'block';
            btnSubmitImage.disabled = true;
        });

        uploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!imageInput.files.length) return;

            const formData = new FormData();
            formData.append('file', imageInput.files[0]);

            showProgressOverlay("DECODING QR CODE IMAGE...", "Applying multi-strategy filtering (ZXing, OpenCV, CLAHE, Inverted Threshold)...");

            try {
                const resp = await fetch('/api/scan/image', {
                    method: 'POST',
                    body: formData
                });
                const data = await resp.json();

                if (data.success && data.redirect_url) {
                    window.location.href = data.redirect_url;
                } else {
                    hideProgressOverlay();
                    alert("Scan Error: " + (data.error || "Failed to decode QR code."));
                }
            } catch (err) {
                hideProgressOverlay();
                alert("Upload failed: " + err.message);
            }
        });
    }

    // --- 2. PDF Document Scanner ---
    const pdfDropzone = document.getElementById('pdf-dropzone');
    const pdfInput = document.getElementById('pdf-file-input');
    const pdfPreviewContainer = document.getElementById('pdf-preview-container');
    const pdfFilenameBadge = document.getElementById('pdf-filename-badge');
    const btnSubmitPdf = document.getElementById('btn-submit-pdf');
    const pdfForm = document.getElementById('pdf-form');

    function handleSelectedPdf(file) {
        if (!file || !file.name.toLowerCase().endsWith('.pdf')) {
            alert('Please select a PDF document.');
            return;
        }
        pdfFilenameBadge.innerHTML = `<i class="fa-solid fa-file-pdf me-1"></i> ${file.name} (${Math.round(file.size / 1024)} KB)`;
        pdfPreviewContainer.style.display = 'block';
        btnSubmitPdf.disabled = false;
    }

    if (pdfDropzone && pdfInput) {
        ['dragenter', 'dragover'].forEach(evt => pdfDropzone.addEventListener(evt, (e) => { e.preventDefault(); pdfDropzone.classList.add('dragover'); }));
        ['dragleave', 'drop'].forEach(evt => pdfDropzone.addEventListener(evt, (e) => { e.preventDefault(); pdfDropzone.classList.remove('dragover'); }));

        pdfDropzone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                pdfInput.files = files;
                handleSelectedPdf(files[0]);
            }
        });

        pdfInput.addEventListener('change', () => {
            if (pdfInput.files.length > 0) {
                handleSelectedPdf(pdfInput.files[0]);
            }
        });

        pdfForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!pdfInput.files.length) return;

            const formData = new FormData();
            formData.append('file', pdfInput.files[0]);

            showProgressOverlay("PARSING EMBEDDED QR CODES FROM PDF...", "Extracting raster image streams from PDF pages and analyzing findings...");

            try {
                const resp = await fetch('/api/scan/pdf', {
                    method: 'POST',
                    body: formData
                });
                const data = await resp.json();

                if (data.success && data.redirect_url) {
                    window.location.href = data.redirect_url;
                } else {
                    hideProgressOverlay();
                    alert("PDF Scan Error: " + (data.error || "No QR codes found in document."));
                }
            } catch (err) {
                hideProgressOverlay();
                alert("PDF upload failed: " + err.message);
            }
        });
    }

    // --- 3. URL Analyzer & Preset Buttons ---
    const urlInput = document.getElementById('url-input');
    const btnAnalyzeUrl = document.getElementById('btn-analyze-url');

    async function triggerUrlAnalysis(targetUrl) {
        if (!targetUrl) {
            alert('Please enter a target URL or payload.');
            return;
        }

        showProgressOverlay("ANALYZING DESTINATION SECURITY...", "Tracing redirect chains, testing typosquatting, checking IOCs...");

        try {
            const resp = await fetch('/api/scan/url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: targetUrl })
            });
            const data = await resp.json();

            if (data.success && data.redirect_url) {
                window.location.href = data.redirect_url;
            } else {
                hideProgressOverlay();
                alert("URL Analysis failed: " + (data.error || "Invalid response"));
            }
        } catch (err) {
            hideProgressOverlay();
            alert("Analysis request failed: " + err.message);
        }
    }

    if (btnAnalyzeUrl && urlInput) {
        btnAnalyzeUrl.addEventListener('click', () => {
            triggerUrlAnalysis(urlInput.value.trim());
        });

        urlInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                triggerUrlAnalysis(urlInput.value.trim());
            }
        });
    }

    // Quick preset buttons
    document.querySelectorAll('.preset-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const url = this.dataset.url;
            if (urlInput) {
                urlInput.value = url;
                triggerUrlAnalysis(url);
            }
        });
    });

});
