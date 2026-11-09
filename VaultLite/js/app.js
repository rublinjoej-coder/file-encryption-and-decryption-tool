/**
 * VaultLite - Main UI & Controller
 * Orchestrates event handling, drag-and-drop, passphrase evaluation,
 * crypto operations, toast notifications, and file downloads.
 */

(function () {
    'use strict';

    // Application State
    const state = {
        currentTab: 'encrypt', // 'encrypt' | 'decrypt'
        encryptFile: null,
        decryptFile: null,
        encryptResultBlob: null,
        encryptResultFilename: '',
        decryptResultBlob: null,
        decryptResultFilename: '',
        activeObjectUrls: []
    };

    // DOM Elements - Tabs
    const tabEncrypt = document.getElementById('tab-encrypt');
    const tabDecrypt = document.getElementById('tab-decrypt');
    const panelEncrypt = document.getElementById('panel-encrypt');
    const panelDecrypt = document.getElementById('panel-decrypt');

    // DOM Elements - Encrypt Tab
    const encryptDropzone = document.getElementById('encrypt-dropzone');
    const encryptFileInput = document.getElementById('encrypt-file-input');
    const encryptFileCard = document.getElementById('encrypt-file-card');
    const encryptFilenameEl = document.getElementById('encrypt-filename');
    const encryptFilesizeEl = document.getElementById('encrypt-filesize');
    const encryptFiletypeEl = document.getElementById('encrypt-filetype');
    const btnRemoveEncryptFile = document.getElementById('btn-remove-encrypt-file');
    const encryptPassphrase = document.getElementById('encrypt-passphrase');
    const encryptPassphraseConfirm = document.getElementById('encrypt-passphrase-confirm');
    const encryptMatchStatus = document.getElementById('encrypt-match-status');
    const strengthBar = document.getElementById('strength-bar');
    const strengthText = document.getElementById('strength-text');
    const btnEncryptSubmit = document.getElementById('btn-encrypt-submit');
    const btnEncryptReset = document.getElementById('btn-encrypt-reset');
    const encryptProgress = document.getElementById('encrypt-progress');
    const encryptProgressMsg = document.getElementById('encrypt-progress-msg');
    const encryptProgressPct = document.getElementById('encrypt-progress-pct');
    const encryptProgressFill = document.getElementById('encrypt-progress-fill');
    const encryptResult = document.getElementById('encrypt-result');
    const resEncName = document.getElementById('res-enc-name');
    const resEncSize = document.getElementById('res-enc-size');
    const btnDownloadSfe = document.getElementById('btn-download-sfe');

    // DOM Elements - Decrypt Tab
    const decryptDropzone = document.getElementById('decrypt-dropzone');
    const decryptFileInput = document.getElementById('decrypt-file-input');
    const decryptFileCard = document.getElementById('decrypt-file-card');
    const decryptFilenameEl = document.getElementById('decrypt-filename');
    const decryptFilesizeEl = document.getElementById('decrypt-filesize');
    const btnRemoveDecryptFile = document.getElementById('btn-remove-decrypt-file');
    const decryptPassphrase = document.getElementById('decrypt-passphrase');
    const btnDecryptSubmit = document.getElementById('btn-decrypt-submit');
    const btnDecryptReset = document.getElementById('btn-decrypt-reset');
    const decryptProgress = document.getElementById('decrypt-progress');
    const decryptProgressMsg = document.getElementById('decrypt-progress-msg');
    const decryptProgressPct = document.getElementById('decrypt-progress-pct');
    const decryptProgressFill = document.getElementById('decrypt-progress-fill');
    const decryptResult = document.getElementById('decrypt-result');
    const resDecName = document.getElementById('res-dec-name');
    const resDecSize = document.getElementById('res-dec-size');
    const resDecType = document.getElementById('res-dec-type');
    const btnDownloadDecrypted = document.getElementById('btn-download-decrypted');

    // DOM Elements - Global & Utilities
    const btnCopySpecs = document.getElementById('btn-copy-specs');
    const copySpecsText = document.getElementById('copy-specs-text');
    const toastContainer = document.getElementById('toast-container');

    // Strength Criteria Elements
    const critLength = document.getElementById('crit-length');
    const critUpper = document.getElementById('crit-upper');
    const critLower = document.getElementById('crit-lower');
    const critNumber = document.getElementById('crit-number');
    const critSpecial = document.getElementById('crit-special');

    /* ==========================================================================
       Utility Functions
       ========================================================================== */

    /**
     * Formats bytes into a human-readable string (B, KB, MB, GB).
     * @param {number} bytes 
     * @returns {string}
     */
    function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    /**
     * Displays a modern toast notification.
     * @param {string} title 
     * @param {string} message 
     * @param {'success'|'error'|'warning'|'info'} type 
     * @param {number} [duration=4500] 
     */
    function showToast(title, message, type = 'info', duration = 4500) {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        const icons = {
            success: `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
            error: `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
            warning: `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
            info: `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`
        };

        toast.innerHTML = `
            ${icons[type] || icons.info}
            <div class="toast-content">
                <div class="toast-title">${escapeHtml(title)}</div>
                <div class="toast-msg">${escapeHtml(message)}</div>
            </div>
            <button class="toast-close" aria-label="Close notification">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
            </button>
        `;

        const closeBtn = toast.querySelector('.toast-close');
        const dismiss = () => {
            toast.classList.add('hiding');
            setTimeout(() => {
                if (toast.parentElement) toast.remove();
            }, 250);
        };

        closeBtn.addEventListener('click', dismiss);
        toastContainer.appendChild(toast);

        if (duration > 0) {
            setTimeout(dismiss, duration);
        }
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    /**
     * Triggers a local browser download from a Blob.
     * @param {Blob} blob 
     * @param {string} filename 
     */
    function triggerDownload(blob, filename) {
        const url = URL.createObjectURL(blob);
        state.activeObjectUrls.push(url);

        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();

        setTimeout(() => {
            a.remove();
            URL.revokeObjectURL(url);
            const index = state.activeObjectUrls.indexOf(url);
            if (index > -1) state.activeObjectUrls.splice(index, 1);
        }, 60000); // 1 minute cleanup window
    }

    /* ==========================================================================
       Tab Navigation
       ========================================================================== */

    function switchTab(tabId) {
        state.currentTab = tabId;
        if (tabId === 'encrypt') {
            tabEncrypt.classList.add('active');
            tabEncrypt.setAttribute('aria-selected', 'true');
            tabDecrypt.classList.remove('active');
            tabDecrypt.setAttribute('aria-selected', 'false');

            panelEncrypt.classList.add('active');
            panelDecrypt.classList.remove('active');
        } else {
            tabDecrypt.classList.add('active');
            tabDecrypt.setAttribute('aria-selected', 'true');
            tabEncrypt.classList.remove('active');
            tabEncrypt.setAttribute('aria-selected', 'false');

            panelDecrypt.classList.add('active');
            panelEncrypt.classList.remove('active');
        }
    }

    tabEncrypt.addEventListener('click', () => switchTab('encrypt'));
    tabDecrypt.addEventListener('click', () => switchTab('decrypt'));

    /* ==========================================================================
       Show / Hide Password Visibility Toggle
       ========================================================================== */

    document.querySelectorAll('.btn-toggle-pw').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            const input = document.getElementById(targetId);
            if (!input) return;

            const isPassword = input.type === 'password';
            input.type = isPassword ? 'text' : 'password';

            // Swap SVG icon between eye and eye-off
            if (isPassword) {
                btn.innerHTML = `
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                        <line x1="1" y1="1" x2="23" y2="23"/>
                    </svg>
                `;
            } else {
                btn.innerHTML = `
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                        <circle cx="12" cy="12" r="3"/>
                    </svg>
                `;
            }
        });
    });

    /* ==========================================================================
       Password Strength Evaluation
       ========================================================================== */

    /**
     * Evaluates password strength based on entropy, length, and character variation.
     * @param {string} password 
     * @returns {Object} score (0-5), label, color, criteria
     */
    function evaluatePasswordStrength(password) {
        if (!password) {
            return {
                score: 0,
                label: 'Empty',
                color: 'var(--text-muted)',
                percent: 0,
                criteria: { length: false, upper: false, lower: false, number: false, special: false }
            };
        }

        const criteria = {
            length: password.length >= 8,
            upper: /[A-Z]/.test(password),
            lower: /[a-z]/.test(password),
            number: /[0-9]/.test(password),
            special: /[^A-Za-z0-9]/.test(password)
        };

        let passedCount = 0;
        if (criteria.length) passedCount++;
        if (criteria.upper) passedCount++;
        if (criteria.lower) passedCount++;
        if (criteria.number) passedCount++;
        if (criteria.special) passedCount++;

        // Bonus for length
        if (password.length >= 14 && passedCount >= 3) {
            passedCount = 5;
        }

        const levels = [
            { score: 1, label: 'Very Weak', color: '#ef4444', percent: 20 },
            { score: 2, label: 'Weak', color: '#f97316', percent: 40 },
            { score: 3, label: 'Fair', color: '#f59e0b', percent: 60 },
            { score: 4, label: 'Strong', color: '#3b82f6', percent: 80 },
            { score: 5, label: 'Very Strong', color: '#10b981', percent: 100 }
        ];

        const index = Math.max(0, Math.min(passedCount - 1, 4));
        const res = levels[index];

        return {
            score: res.score,
            label: res.label,
            color: res.color,
            percent: res.percent,
            criteria
        };
    }

    function updateStrengthMeter(password) {
        const result = evaluatePasswordStrength(password);

        strengthText.textContent = result.label;
        strengthText.style.color = result.color;
        strengthBar.style.width = `${result.percent}%`;
        strengthBar.style.backgroundColor = result.color;

        // Update pills
        critLength.classList.toggle('met', result.criteria.length);
        critUpper.classList.toggle('met', result.criteria.upper);
        critLower.classList.toggle('met', result.criteria.lower);
        critNumber.classList.toggle('met', result.criteria.number);
        critSpecial.classList.toggle('met', result.criteria.special);
    }

    /* ==========================================================================
       Encryption Form Validation & State
       ========================================================================== */

    function validateEncryptInputs() {
        const pw = encryptPassphrase.value;
        const confirm = encryptPassphraseConfirm.value;
        const hasFile = state.encryptFile !== null;

        updateStrengthMeter(pw);

        let passwordsMatch = false;

        if (confirm.length > 0) {
            if (pw === confirm) {
                passwordsMatch = true;
                encryptMatchStatus.innerHTML = `
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                    <span>Passphrases match</span>
                `;
                encryptMatchStatus.className = 'match-status valid';
            } else {
                encryptMatchStatus.innerHTML = `
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                    <span>Passphrases do not match</span>
                `;
                encryptMatchStatus.className = 'match-status invalid';
            }
        } else {
            encryptMatchStatus.textContent = '';
            encryptMatchStatus.className = 'match-status';
        }

        // Enable button only if file is present and passphrases match (and not empty)
        btnEncryptSubmit.disabled = !(hasFile && pw.length > 0 && passwordsMatch);
    }

    encryptPassphrase.addEventListener('input', validateEncryptInputs);
    encryptPassphraseConfirm.addEventListener('input', validateEncryptInputs);

    /* ==========================================================================
       Decryption Form Validation & State
       ========================================================================== */

    function validateDecryptInputs() {
        const pw = decryptPassphrase.value;
        const hasFile = state.decryptFile !== null;
        btnDecryptSubmit.disabled = !(hasFile && pw.length > 0);
    }

    decryptPassphrase.addEventListener('input', validateDecryptInputs);

    /* ==========================================================================
       Drag & Drop Handlers - Encryption
       ========================================================================== */

    function setupDropzone(dropzone, inputEl, onFileSelected) {
        dropzone.addEventListener('click', () => inputEl.click());

        dropzone.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                inputEl.click();
            }
        });

        ['dragenter', 'dragover'].forEach(name => {
            dropzone.addEventListener(name, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(name => {
            dropzone.addEventListener(name, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.remove('dragover');
            });
        });

        dropzone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files && files.length > 0) {
                onFileSelected(files[0]);
            }
        });

        inputEl.addEventListener('change', (e) => {
            if (inputEl.files && inputEl.files.length > 0) {
                onFileSelected(inputEl.files[0]);
            }
        });
    }

    // Encrypt File Selection
    setupDropzone(encryptDropzone, encryptFileInput, (file) => {
        state.encryptFile = file;
        encryptFilenameEl.textContent = file.name;
        encryptFilesizeEl.textContent = formatBytes(file.size);

        // Derive file type badge
        const ext = file.name.split('.').pop().toUpperCase();
        encryptFiletypeEl.textContent = ext ? `${ext}` : (file.type || 'RAW');

        encryptFileCard.classList.add('show');
        encryptResult.classList.remove('show');
        validateEncryptInputs();

        showToast('File Loaded', `Selected "${file.name}" (${formatBytes(file.size)})`, 'info');
    });

    // Remove Encrypt File
    btnRemoveEncryptFile.addEventListener('click', () => {
        state.encryptFile = null;
        encryptFileInput.value = '';
        encryptFileCard.classList.remove('show');
        encryptResult.classList.remove('show');
        validateEncryptInputs();
    });

    // Decrypt File Selection
    setupDropzone(decryptDropzone, decryptFileInput, (file) => {
        if (!file.name.toLowerCase().endsWith('.sfe')) {
            showToast('Invalid File Type', 'Please upload a VaultLite encrypted file with the ".sfe" extension.', 'warning');
            return;
        }

        state.decryptFile = file;
        decryptFilenameEl.textContent = file.name;
        decryptFilesizeEl.textContent = formatBytes(file.size);
        decryptFileCard.classList.add('show');
        decryptResult.classList.remove('show');
        validateDecryptInputs();

        showToast('Encrypted Package Loaded', `Selected "${file.name}" ready for decryption.`, 'info');
    });

    // Remove Decrypt File
    btnRemoveDecryptFile.addEventListener('click', () => {
        state.decryptFile = null;
        decryptFileInput.value = '';
        decryptFileCard.classList.remove('show');
        decryptResult.classList.remove('show');
        validateDecryptInputs();
    });

    /* ==========================================================================
       Reset Handlers
       ========================================================================== */

    function resetEncryptTab() {
        state.encryptFile = null;
        state.encryptResultBlob = null;
        state.encryptResultFilename = '';
        encryptFileInput.value = '';
        encryptPassphrase.value = '';
        encryptPassphraseConfirm.value = '';
        encryptFileCard.classList.remove('show');
        encryptProgress.classList.remove('show');
        encryptResult.classList.remove('show');
        validateEncryptInputs();
        showToast('Reset Complete', 'Encryption workspace cleared.', 'info');
    }

    function resetDecryptTab() {
        state.decryptFile = null;
        state.decryptResultBlob = null;
        state.decryptResultFilename = '';
        decryptFileInput.value = '';
        decryptPassphrase.value = '';
        decryptFileCard.classList.remove('show');
        decryptProgress.classList.remove('show');
        decryptResult.classList.remove('show');
        validateDecryptInputs();
        showToast('Reset Complete', 'Decryption workspace cleared.', 'info');
    }

    btnEncryptReset.addEventListener('click', resetEncryptTab);
    btnDecryptReset.addEventListener('click', resetDecryptTab);

    /* ==========================================================================
       Encryption Action
       ========================================================================== */

    btnEncryptSubmit.addEventListener('click', async () => {
        if (!state.encryptFile) {
            showToast('No File', 'Please select a file to encrypt.', 'warning');
            return;
        }

        const passphrase = encryptPassphrase.value;
        if (!passphrase) {
            showToast('Passphrase Required', 'Please enter a master passphrase.', 'warning');
            return;
        }

        // Lock UI during execution
        btnEncryptSubmit.disabled = true;
        encryptProgress.classList.add('show');
        encryptResult.classList.remove('show');

        const updateProgress = ({ stage, percent, message }) => {
            encryptProgressFill.style.width = `${percent}%`;
            encryptProgressPct.textContent = `${percent}%`;
            encryptProgressMsg.innerHTML = `<span class="spinner"></span><span>${escapeHtml(message)}</span>`;
        };

        try {
            const { sfeBlob, sfeFilename, metadata } = await window.VaultEncryption.encryptFile(
                state.encryptFile,
                passphrase,
                updateProgress
            );

            state.encryptResultBlob = sfeBlob;
            state.encryptResultFilename = sfeFilename;

            // Update result display
            resEncName.textContent = sfeFilename;
            resEncSize.textContent = `${formatBytes(metadata.encryptedSize)} (${metadata.encryptedSize.toLocaleString()} bytes)`;

            // Reveal result card
            encryptProgress.classList.remove('show');
            encryptResult.classList.add('show');

            showToast('Encryption Complete', `Successfully encrypted ${metadata.originalName} into ${sfeFilename}!`, 'success');

            // Auto-trigger download for convenient user experience
            triggerDownload(sfeBlob, sfeFilename);

        } catch (err) {
            console.error('Encryption error:', err);
            encryptProgress.classList.remove('show');
            showToast('Encryption Failed', err.message || 'An error occurred during encryption.', 'error');
        } finally {
            validateEncryptInputs();
        }
    });

    // Manual Download Encrypted File Button
    btnDownloadSfe.addEventListener('click', () => {
        if (state.encryptResultBlob && state.encryptResultFilename) {
            triggerDownload(state.encryptResultBlob, state.encryptResultFilename);
            showToast('Download Started', `Downloading ${state.encryptResultFilename}`, 'info');
        }
    });

    /* ==========================================================================
       Decryption Action
       ========================================================================== */

    btnDecryptSubmit.addEventListener('click', async () => {
        if (!state.decryptFile) {
            showToast('No File', 'Please select an encrypted (.sfe) file.', 'warning');
            return;
        }

        const passphrase = decryptPassphrase.value;
        if (!passphrase) {
            showToast('Passphrase Required', 'Please enter the passphrase.', 'warning');
            return;
        }

        btnDecryptSubmit.disabled = true;
        decryptProgress.classList.add('show');
        decryptResult.classList.remove('show');

        const updateProgress = ({ stage, percent, message }) => {
            decryptProgressFill.style.width = `${percent}%`;
            decryptProgressPct.textContent = `${percent}%`;
            decryptProgressMsg.innerHTML = `<span class="spinner"></span><span>${escapeHtml(message)}</span>`;
        };

        try {
            const { decryptedBlob, originalFilename, originalType, metadata } = await window.VaultDecryption.decryptFile(
                state.decryptFile,
                passphrase,
                updateProgress
            );

            state.decryptResultBlob = decryptedBlob;
            state.decryptResultFilename = originalFilename;

            resDecName.textContent = originalFilename;
            resDecSize.textContent = `${formatBytes(metadata.originalSize)} (${metadata.originalSize.toLocaleString()} bytes)`;
            resDecType.textContent = originalType || 'Unknown binary';

            decryptProgress.classList.remove('show');
            decryptResult.classList.add('show');

            showToast('Decryption Success', `File "${originalFilename}" restored and integrity verified!`, 'success');

            // Auto-trigger download
            triggerDownload(decryptedBlob, originalFilename);

        } catch (err) {
            console.error('Decryption error:', err);
            decryptProgress.classList.remove('show');
            showToast('Decryption Failed', err.message || 'Authentication failed. Check your password or file integrity.', 'error', 6000);
        } finally {
            validateDecryptInputs();
        }
    });

    // Manual Download Decrypted File Button
    btnDownloadDecrypted.addEventListener('click', () => {
        if (state.decryptResultBlob && state.decryptResultFilename) {
            triggerDownload(state.decryptResultBlob, state.decryptResultFilename);
            showToast('Download Started', `Downloading ${state.decryptResultFilename}`, 'info');
        }
    });

    /* ==========================================================================
       Copy Cryptographic Specifications
       ========================================================================== */

    btnCopySpecs.addEventListener('click', async () => {
        const specsText = [
            'VaultLite Cryptographic Specifications:',
            '----------------------------------------',
            'Cipher: AES-256-GCM (Galois/Counter Mode)',
            'Key Size: 256 bits (32 bytes)',
            'Authentication Tag: 128 bits (16 bytes)',
            'Key Derivation: PBKDF2 with HMAC-SHA-256',
            'PBKDF2 Iterations: 300,000 rounds',
            'Salt Length: 16 bytes (128 bits) via crypto.getRandomValues()',
            'IV Length: 12 bytes (96 bits) via crypto.getRandomValues()',
            'File Format: .sfe (Secure File Encryption, binary v1)',
            'Security Architecture: 100% Client-side browser sandbox (zero server storage)'
        ].join('\n');

        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(specsText);
            } else {
                // Fallback for older browsers
                const ta = document.createElement('textarea');
                ta.value = specsText;
                ta.style.position = 'fixed';
                ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                ta.remove();
            }

            copySpecsText.textContent = 'Copied!';
            showToast('Specifications Copied', 'Cryptographic details copied to clipboard.', 'success');
            setTimeout(() => {
                copySpecsText.textContent = 'Copy Specs';
            }, 2500);
        } catch (err) {
            showToast('Copy Failed', 'Unable to access clipboard.', 'warning');
        }
    });

    /* ==========================================================================
       Initial State Initialization
       ========================================================================== */

    validateEncryptInputs();
    validateDecryptInputs();

})();
