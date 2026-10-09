/**
 * PhishGuard AI - QR Code Threat Scanner Module
 * Decodes QR Codes from Image Files or Live Camera Feed and forwards decoded URLs to PhishGuard AI
 */

class QRScannerManager {
  constructor() {
    this.stream = null;
    this.animFrameId = null;
    this.isScanningCamera = false;
    this.activeTab = 'upload'; // 'upload' | 'camera'
  }

  init() {
    this.createModalDOM();
    this.bindEvents();
  }

  createModalDOM() {
    if (document.getElementById('qrScannerModal')) return;

    const modalHTML = `
    <div class="modal-overlay" id="qrScannerModal">
      <div class="modal-card qr-modal-card">
        <div class="modal-header">
          <div class="modal-title">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="3" width="7" height="7"/>
              <rect x="14" y="3" width="7" height="7"/>
              <rect x="14" y="14" width="7" height="7"/>
              <rect x="3" y="14" width="7" height="7"/>
              <rect x="9" y="9" width="6" height="6"/>
            </svg>
            <span>QR Code Phishing Scanner</span>
          </div>
          <button class="modal-close" id="closeQrModalBtn">&times;</button>
        </div>

        <div class="qr-modal-body">
          <p class="qr-subtitle">Scan suspicious QR codes from images, emails, or physical materials before opening links.</p>

          <!-- Tab Selector -->
          <div class="qr-tabs">
            <button type="button" class="qr-tab-btn active" id="qrTabUpload">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
              Upload QR Image
            </button>
            <button type="button" class="qr-tab-btn" id="qrTabCamera">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
              Live Camera Scanner
            </button>
          </div>

          <!-- Upload View -->
          <div class="qr-view-container active" id="qrUploadView">
            <div class="qr-dropzone" id="qrDropzone">
              <input type="file" id="qrFileInput" accept="image/*" style="display:none;">
              <div class="dropzone-content">
                <div class="qr-icon-wrapper">
                  <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                    <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
                    <rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>
                    <path d="M10 10h4v4h-4z"/>
                  </svg>
                </div>
                <div class="dropzone-text">
                  <strong>Click or Drag & Drop QR Code Image</strong>
                  <span>Supports PNG, JPG, WEBP, GIF (Max 10MB)</span>
                </div>
                <button type="button" class="btn-secondary" id="browseQrFileBtn">
                  Select QR Image File
                </button>
              </div>
              <div class="qr-preview-area" id="qrPreviewArea" style="display: none;">
                <img id="qrPreviewImage" alt="QR Code Preview">
                <div class="qr-scanning-overlay" id="qrScanningOverlay">
                  <div class="scan-laser-line"></div>
                </div>
              </div>
            </div>
          </div>

          <!-- Camera View -->
          <div class="qr-view-container" id="qrCameraView">
            <div class="qr-camera-wrapper">
              <video id="qrVideoFeed" playsinline autoplay muted></video>
              <canvas id="qrCanvas" style="display: none;"></canvas>
              <div class="qr-reticle">
                <div class="reticle-corner top-left"></div>
                <div class="reticle-corner top-right"></div>
                <div class="reticle-corner bottom-left"></div>
                <div class="reticle-corner bottom-right"></div>
                <div class="scan-laser-line"></div>
              </div>
              <div class="camera-placeholder" id="cameraPlaceholder">
                <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
                <span>Click "Start Camera" to scan QR code using your webcam</span>
                <button type="button" class="btn-scan" id="startCamBtn" style="margin-top: 1rem;">Start Camera</button>
              </div>
            </div>
          </div>

          <!-- Decoded Result Status Card -->
          <div class="qr-result-card" id="qrResultCard" style="display: none;">
            <div class="qr-result-header">
              <span class="badge-safe">✓ QR DECODED SUCCESSFULLY</span>
            </div>
            <div class="qr-result-url" id="qrDecodedUrlText">https://example.com</div>
            <div class="qr-result-actions">
              <button type="button" class="btn-scan" id="analyzeQrUrlBtn">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                ANALYZE THIS LINK NOW
              </button>
              <button type="button" class="btn-secondary" id="resetQrBtn">Scan Another</button>
            </div>
          </div>
        </div>
      </div>
    </div>
    `;

    document.body.insertAdjacentHTML('beforeend', modalHTML);
  }

  bindEvents() {
    const modal = document.getElementById('qrScannerModal');
    const closeBtn = document.getElementById('closeQrModalBtn');
    const tabUpload = document.getElementById('qrTabUpload');
    const tabCamera = document.getElementById('qrTabCamera');
    const uploadView = document.getElementById('qrUploadView');
    const cameraView = document.getElementById('qrCameraView');
    const dropzone = document.getElementById('qrDropzone');
    const fileInput = document.getElementById('qrFileInput');
    const browseBtn = document.getElementById('browseQrFileBtn');
    const startCamBtn = document.getElementById('startCamBtn');
    const analyzeQrUrlBtn = document.getElementById('analyzeQrUrlBtn');
    const resetQrBtn = document.getElementById('resetQrBtn');

    // Open/Close
    closeBtn.addEventListener('click', () => this.closeModal());
    modal.addEventListener('click', (e) => {
      if (e.target === modal) this.closeModal();
    });

    // Tab switching
    tabUpload.addEventListener('click', () => {
      tabUpload.classList.add('active');
      tabCamera.classList.remove('active');
      uploadView.classList.add('active');
      cameraView.classList.remove('active');
      this.stopCamera();
      this.activeTab = 'upload';
    });

    tabCamera.addEventListener('click', () => {
      tabCamera.classList.add('active');
      tabUpload.classList.remove('active');
      cameraView.classList.add('active');
      uploadView.classList.remove('active');
      this.activeTab = 'camera';
      this.startCamera();
    });

    // File input trigger
    browseBtn.addEventListener('click', () => fileInput.click());
    dropzone.addEventListener('click', (e) => {
      if (e.target.tagName !== 'BUTTON' && !document.getElementById('qrResultCard').style.display.includes('block')) {
        fileInput.click();
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        this.processFile(e.target.files[0]);
      }
    });

    // Drag & Drop
    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('dragover');
      });
    });

    dropzone.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      if (dt.files && dt.files[0]) {
        this.processFile(dt.files[0]);
      }
    });

    // Camera button
    startCamBtn.addEventListener('click', () => this.startCamera());

    // Actions
    analyzeQrUrlBtn.addEventListener('click', () => {
      const decodedUrl = document.getElementById('qrDecodedUrlText').textContent.trim();
      if (decodedUrl) {
        const urlInput = document.getElementById('urlInput');
        if (urlInput) {
          urlInput.value = decodedUrl;
        }
        this.closeModal();
        // Trigger scan
        const analyzeBtn = document.getElementById('analyzeBtn');
        if (analyzeBtn) {
          analyzeBtn.click();
        }
      }
    });

    resetQrBtn.addEventListener('click', () => {
      this.resetScanner();
    });
  }

  openModal() {
    this.createModalDOM();
    const modal = document.getElementById('qrScannerModal');
    if (modal) {
      modal.classList.add('active');
      this.resetScanner();
    }
  }

  closeModal() {
    const modal = document.getElementById('qrScannerModal');
    if (modal) {
      modal.classList.remove('active');
    }
    this.stopCamera();
  }

  resetScanner() {
    document.getElementById('qrResultCard').style.display = 'none';
    document.getElementById('qrPreviewArea').style.display = 'none';
    document.getElementById('qrDecodedUrlText').textContent = '';
    const fileInput = document.getElementById('qrFileInput');
    if (fileInput) fileInput.value = '';
  }

  processFile(file) {
    if (!file.type.startsWith('image/')) {
      if (window.showToast) showToast('Please select a valid image file', 'warning');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => {
        document.getElementById('qrPreviewImage').src = e.target.result;
        document.getElementById('qrPreviewArea').style.display = 'block';
        this.decodeImage(img);
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  }

  decodeImage(img) {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    canvas.width = img.width;
    canvas.height = img.height;
    ctx.drawImage(img, 0, 0);

    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    if (window.jsQR) {
      const code = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: "dontInvert",
      });

      if (code && code.data) {
        this.onQrFound(code.data);
      } else {
        if (window.showToast) showToast('No valid QR code found in this image. Try another photo.', 'warning');
      }
    } else {
      // Fallback if jsQR library fails to load
      if (window.showToast) showToast('QR processing engine unavailable. Check internet connection.', 'error');
    }
  }

  async startCamera() {
    const video = document.getElementById('qrVideoFeed');
    const placeholder = document.getElementById('cameraPlaceholder');

    try {
      this.stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' }
      });
      video.srcObject = this.stream;
      video.setAttribute('playsinline', true);
      video.style.display = 'block';
      placeholder.style.display = 'none';
      this.isScanningCamera = true;
      requestAnimationFrame(() => this.scanCameraFrame());
    } catch (err) {
      console.warn('Camera access denied or unavailable:', err);
      placeholder.style.display = 'flex';
      video.style.display = 'none';
      placeholder.querySelector('span').textContent = 'Camera permission denied or camera unavailable. Please upload a QR code image instead.';
      if (window.showToast) showToast('Webcam access was not granted.', 'warning');
    }
  }

  scanCameraFrame() {
    if (!this.isScanningCamera) return;

    const video = document.getElementById('qrVideoFeed');
    const canvas = document.getElementById('qrCanvas');
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.height = video.videoHeight;
      canvas.width = video.videoWidth;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      if (window.jsQR) {
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: "dontInvert",
        });

        if (code && code.data) {
          this.onQrFound(code.data);
          this.stopCamera();
          return;
        }
      }
    }

    if (this.isScanningCamera) {
      this.animFrameId = requestAnimationFrame(() => this.scanCameraFrame());
    }
  }

  stopCamera() {
    this.isScanningCamera = false;
    if (this.animFrameId) {
      cancelAnimationFrame(this.animFrameId);
      this.animFrameId = null;
    }
    if (this.stream) {
      this.stream.getTracks().forEach(track => track.stop());
      this.stream = null;
    }
    const video = document.getElementById('qrVideoFeed');
    const placeholder = document.getElementById('cameraPlaceholder');
    if (video) video.style.display = 'none';
    if (placeholder) placeholder.style.display = 'flex';
  }

  onQrFound(decodedText) {
    if (window.sounds && window.sounds.beepStagePass) {
      window.sounds.beepStagePass();
    }
    document.getElementById('qrResultCard').style.display = 'block';
    document.getElementById('qrDecodedUrlText').textContent = decodedText;
    if (window.showToast) showToast('QR Code successfully decoded!', 'success');
  }
}

// Global instance
window.qrScanner = new QRScannerManager();
