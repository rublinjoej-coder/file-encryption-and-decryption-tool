/**
 * VaultLite - Decryption Engine
 * Pure client-side cryptographic module using the standard Web Crypto API.
 * 
 * Cryptographic & Verification Specifications:
 * - Validates file magic header ("VLTE") and format version
 * - Extracts cryptographic metadata (PBKDF2 iteration count, Salt, IV, original filename, original MIME type)
 * - Derives AES-256-GCM key from user passphrase and extracted salt via PBKDF2-HMAC-SHA256
 * - Performs authenticated decryption via AES-256-GCM
 * - Automatically validates the 128-bit authentication tag; detects any tampering, bit flips, or incorrect passphrases
 */

(function (window) {
    'use strict';

    const MAGIC_BYTES = new Uint8Array([0x56, 0x4C, 0x54, 0x45]); // "VLTE"
    const EXPECTED_FORMAT_VERSION = 1;

    const VaultDecryption = {
        MAGIC_BYTES,
        EXPECTED_FORMAT_VERSION,

        /**
         * Validates and parses a raw .sfe binary package into its cryptographic components.
         * @param {ArrayBuffer} sfeBuffer - Raw binary buffer of the .sfe file
         * @returns {Object} Extracted metadata and ciphertext
         */
        parseSfePackage(sfeBuffer) {
            const minHeaderSize = 4 + 1 + 4 + 1 + 16 + 1 + 12 + 2 + 0 + 2 + 0 + 16; // minimum viable size including 16-byte auth tag
            if (!sfeBuffer || sfeBuffer.byteLength < minHeaderSize) {
                throw new Error('File is too small to be a valid VaultLite (.sfe) encrypted package or has been truncated.');
            }

            const view = new DataView(sfeBuffer);
            const uint8View = new Uint8Array(sfeBuffer);
            let offset = 0;

            // 1. Validate magic bytes "VLTE"
            for (let i = 0; i < 4; i++) {
                if (uint8View[offset + i] !== MAGIC_BYTES[i]) {
                    throw new Error('Invalid file format. The selected file is not a valid VaultLite (.sfe) encrypted file.');
                }
            }
            offset += 4;

            // 2. Validate format version
            const version = view.getUint8(offset);
            offset += 1;
            if (version !== EXPECTED_FORMAT_VERSION) {
                throw new Error(`Unsupported format version (${version}). Expected version ${EXPECTED_FORMAT_VERSION}.`);
            }

            // 3. PBKDF2 iterations
            const iterations = view.getUint32(offset, false);
            offset += 4;
            if (iterations < 10000 || iterations > 5000000) {
                throw new Error(`Invalid or suspicious iteration count (${iterations}). File may be corrupted.`);
            }

            // 4. Salt
            const saltLength = view.getUint8(offset);
            offset += 1;
            if (saltLength !== 16) {
                throw new Error(`Invalid salt length (${saltLength} bytes). Expected 16 bytes.`);
            }
            const salt = uint8View.slice(offset, offset + saltLength);
            offset += saltLength;

            // 5. IV
            const ivLength = view.getUint8(offset);
            offset += 1;
            if (ivLength !== 12) {
                throw new Error(`Invalid IV length (${ivLength} bytes). Expected 12 bytes.`);
            }
            const iv = uint8View.slice(offset, offset + ivLength);
            offset += ivLength;

            // 6. Filename
            const filenameLength = view.getUint16(offset, false);
            offset += 2;
            if (offset + filenameLength > sfeBuffer.byteLength) {
                throw new Error('Corrupted header: filename length exceeds file boundary.');
            }
            const decoder = new TextDecoder();
            const filename = decoder.decode(uint8View.slice(offset, offset + filenameLength));
            offset += filenameLength;

            // 7. MIME type
            const mimeLength = view.getUint16(offset, false);
            offset += 2;
            if (offset + mimeLength > sfeBuffer.byteLength) {
                throw new Error('Corrupted header: MIME type length exceeds file boundary.');
            }
            const mimeType = decoder.decode(uint8View.slice(offset, offset + mimeLength));
            offset += mimeLength;

            // 8. Ciphertext + Auth Tag
            const ciphertext = sfeBuffer.slice(offset);
            if (ciphertext.byteLength < 16) {
                throw new Error('Corrupted package: missing or truncated ciphertext / authentication tag.');
            }

            return {
                version,
                iterations,
                salt,
                iv,
                filename: filename || 'decrypted_file',
                mimeType: mimeType || 'application/octet-stream',
                ciphertext,
                headerLength: offset
            };
        },

        /**
         * Derives an AES-GCM 256-bit CryptoKey using PBKDF2-HMAC-SHA256.
         * @param {string} passphrase - User passphrase
         * @param {Uint8Array} salt - 16-byte random salt from header
         * @param {number} iterations - PBKDF2 iterations from header
         * @returns {Promise<CryptoKey>}
         */
        async deriveKey(passphrase, salt, iterations) {
            const encoder = new TextEncoder();
            const passwordBuffer = encoder.encode(passphrase);
            const subtle = (window.crypto || window.msCrypto).subtle;

            const baseKey = await subtle.importKey(
                'raw',
                passwordBuffer,
                { name: 'PBKDF2' },
                false,
                ['deriveKey']
            );

            const derivedKey = await subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: iterations,
                    hash: 'SHA-256'
                },
                baseKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );

            return derivedKey;
        },

        /**
         * Decrypts ciphertext buffer and verifies authentication tag using AES-256-GCM.
         * @param {ArrayBuffer} ciphertext - Ciphertext including 128-bit authentication tag
         * @param {CryptoKey} key - Derived AES-GCM key
         * @param {Uint8Array} iv - 12-byte initialization vector
         * @returns {Promise<ArrayBuffer>} Decrypted plaintext data
         */
        async decryptData(ciphertext, key, iv) {
            const subtle = (window.crypto || window.msCrypto).subtle;
            try {
                return await subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv: iv,
                        tagLength: 128
                    },
                    key,
                    ciphertext
                );
            } catch (err) {
                // In Web Crypto API, AES-GCM throws OperationError if authentication tag fails
                // which occurs when either the passphrase is wrong or the ciphertext was modified.
                throw new Error('Authentication failed. Incorrect passphrase or corrupted/tampered file.');
            }
        },

        /**
         * Complete end-to-end decryption pipeline for an encrypted .sfe File.
         * @param {File} sfeFile - Encrypted .sfe file
         * @param {string} passphrase - Passphrase entered by user
         * @param {Function} [onProgress] - Optional callback to report progress
         * @returns {Promise<{ decryptedBlob: Blob, originalFilename: string, originalType: string, metadata: Object }>}
         */
        async decryptFile(sfeFile, passphrase, onProgress = null) {
            if (!sfeFile) {
                throw new Error('Please select an encrypted (.sfe) file to decrypt.');
            }
            if (!passphrase || passphrase.length === 0) {
                throw new Error('Please enter the decryption passphrase.');
            }

            if (onProgress) onProgress({ stage: 'reading', percent: 15, message: 'Reading encrypted file into memory...' });

            const sfeBuffer = await sfeFile.arrayBuffer();

            if (onProgress) onProgress({ stage: 'parsing', percent: 35, message: 'Validating header & extracting cryptographic metadata...' });

            const parsed = this.parseSfePackage(sfeBuffer);

            if (onProgress) onProgress({ stage: 'deriving_key', percent: 60, message: `Deriving AES-256 key via PBKDF2 (${parsed.iterations.toLocaleString()} iterations)...` });

            const key = await this.deriveKey(passphrase, parsed.salt, parsed.iterations);

            if (onProgress) onProgress({ stage: 'decrypting', percent: 85, message: 'Verifying authentication tag & decrypting payload...' });

            const decryptedBuffer = await this.decryptData(parsed.ciphertext, key, parsed.iv);

            if (onProgress) onProgress({ stage: 'completed', percent: 100, message: 'Decryption and authentication successful!' });

            const decryptedBlob = new Blob([decryptedBuffer], { type: parsed.mimeType });

            return {
                decryptedBlob,
                originalFilename: parsed.filename,
                originalType: parsed.mimeType,
                metadata: {
                    originalName: parsed.filename,
                    originalSize: decryptedBuffer.byteLength,
                    encryptedSize: sfeFile.size,
                    mimeType: parsed.mimeType,
                    iterations: parsed.iterations,
                    saltHex: Array.from(parsed.salt).map(b => b.toString(16).padStart(2, '0')).join(''),
                    ivHex: Array.from(parsed.iv).map(b => b.toString(16).padStart(2, '0')).join(''),
                    cipher: 'AES-256-GCM',
                    kdf: 'PBKDF2-HMAC-SHA256'
                }
            };
        }
    };

    // Export to global scope
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = VaultDecryption;
    } else {
        window.VaultDecryption = VaultDecryption;
    }

})(typeof window !== 'undefined' ? window : globalThis);
