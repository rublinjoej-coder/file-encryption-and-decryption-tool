/**
 * VaultLite - Encryption Engine
 * Pure client-side cryptographic module using the standard Web Crypto API.
 * 
 * Cryptographic Specifications:
 * - Cipher: AES-GCM (Galois/Counter Mode)
 * - Key Size: 256 bits
 * - Key Derivation: PBKDF2 (Password-Based Key Derivation Function 2)
 * - Pseudo-Random Function: HMAC-SHA-256
 * - Salt: 16 bytes (128 bits) cryptographically secure random bytes
 * - IV: 12 bytes (96 bits) cryptographically secure random bytes
 * - Iterations: 300,000 (exceeds OWASP recommendations for HMAC-SHA256)
 * - Authentication Tag: 128 bits (managed automatically by AES-GCM)
 */

(function (window) {
    'use strict';

    // Magic identifier: "VLTE" (4 bytes: 0x56, 0x4C, 0x54, 0x45)
    const MAGIC_BYTES = new Uint8Array([0x56, 0x4C, 0x54, 0x45]);
    const FORMAT_VERSION = 1;
    const DEFAULT_PBKDF2_ITERATIONS = 300000;
    const SALT_BYTE_LENGTH = 16;
    const IV_BYTE_LENGTH = 12;

    const VaultEncryption = {
        MAGIC_BYTES,
        FORMAT_VERSION,
        DEFAULT_PBKDF2_ITERATIONS,
        SALT_BYTE_LENGTH,
        IV_BYTE_LENGTH,

        /**
         * Generates cryptographically secure random bytes.
         * NEVER uses Math.random() for cryptographic operations.
         * @param {number} length Number of random bytes needed
         * @returns {Uint8Array}
         */
        generateRandomBytes(length) {
            const bytes = new Uint8Array(length);
            const cryptoObj = window.crypto || window.msCrypto;
            cryptoObj.getRandomValues(bytes);
            return bytes;
        },

        /**
         * Derives an AES-GCM 256-bit CryptoKey from a passphrase and salt using PBKDF2.
         * @param {string} passphrase - User passphrase
         * @param {Uint8Array} salt - 16-byte random salt
         * @param {number} iterations - Number of PBKDF2 iterations
         * @returns {Promise<CryptoKey>}
         */
        async deriveKey(passphrase, salt, iterations = DEFAULT_PBKDF2_ITERATIONS) {
            const encoder = new TextEncoder();
            const passwordBuffer = encoder.encode(passphrase);
            const subtle = (window.crypto || window.msCrypto).subtle;

            // Import raw password bytes as a base key for PBKDF2
            const baseKey = await subtle.importKey(
                'raw',
                passwordBuffer,
                { name: 'PBKDF2' },
                false, // key is not extractable
                ['deriveKey']
            );

            // Derive the 256-bit AES-GCM encryption key
            const derivedKey = await subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: iterations,
                    hash: 'SHA-256'
                },
                baseKey,
                { name: 'AES-GCM', length: 256 },
                false, // derived key is not extractable from browser memory
                ['encrypt']
            );

            return derivedKey;
        },

        /**
         * Encrypts plaintext file data using AES-256-GCM.
         * @param {ArrayBuffer} plaintextBuffer - Raw file data to encrypt
         * @param {CryptoKey} key - Derived AES-GCM key
         * @param {Uint8Array} iv - 12-byte initialization vector
         * @returns {Promise<ArrayBuffer>} Ciphertext with authentication tag appended
         */
        async encryptData(plaintextBuffer, key, iv) {
            const subtle = (window.crypto || window.msCrypto).subtle;
            return await subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128 // 128-bit authentication tag
                },
                key,
                plaintextBuffer
            );
        },

        /**
         * Serializes metadata and ciphertext into the official .sfe binary package.
         * 
         * Binary Format Specification:
         * [4 bytes] Magic bytes "VLTE"
         * [1 byte]  Format version (0x01)
         * [4 bytes] PBKDF2 Iteration count (Uint32, big-endian)
         * [1 byte]  Salt byte length (16)
         * [16 bytes] Salt
         * [1 byte]  IV byte length (12)
         * [12 bytes] Initialization Vector
         * [2 bytes] Filename byte length (Uint16, big-endian)
         * [N bytes] Original filename (UTF-8)
         * [2 bytes] MIME type byte length (Uint16, big-endian)
         * [M bytes] Original MIME type (UTF-8)
         * [Rest]    Ciphertext with 128-bit auth tag
         * 
         * @param {Object} params
         * @param {ArrayBuffer} params.ciphertext
         * @param {Uint8Array} params.salt
         * @param {Uint8Array} params.iv
         * @param {number} params.iterations
         * @param {string} params.filename
         * @param {string} params.mimeType
         * @returns {Uint8Array} Complete binary .sfe package
         */
        packSfeFile({ ciphertext, salt, iv, iterations, filename, mimeType }) {
            const encoder = new TextEncoder();
            const filenameBytes = encoder.encode(filename || 'unnamed_file');
            const mimeBytes = encoder.encode(mimeType || 'application/octet-stream');

            // Calculate total header size
            // Magic(4) + Version(1) + Iterations(4) + SaltLen(1) + Salt(16) + IvLen(1) + IV(12)
            // + NameLen(2) + NameBytes + MimeLen(2) + MimeBytes
            const headerSize = 4 + 1 + 4 + 1 + salt.length + 1 + iv.length + 2 + filenameBytes.length + 2 + mimeBytes.length;
            const totalSize = headerSize + ciphertext.byteLength;

            const buffer = new ArrayBuffer(totalSize);
            const view = new DataView(buffer);
            const uint8View = new Uint8Array(buffer);

            let offset = 0;

            // 1. Magic bytes "VLTE"
            uint8View.set(MAGIC_BYTES, offset);
            offset += 4;

            // 2. Version (1 byte)
            view.setUint8(offset, FORMAT_VERSION);
            offset += 1;

            // 3. PBKDF2 iterations (4 bytes, Uint32 big-endian)
            view.setUint32(offset, iterations, false);
            offset += 4;

            // 4. Salt length (1 byte) + Salt
            view.setUint8(offset, salt.length);
            offset += 1;
            uint8View.set(salt, offset);
            offset += salt.length;

            // 5. IV length (1 byte) + IV
            view.setUint8(offset, iv.length);
            offset += 1;
            uint8View.set(iv, offset);
            offset += iv.length;

            // 6. Filename length (2 bytes, Uint16 big-endian) + Filename
            view.setUint16(offset, filenameBytes.length, false);
            offset += 2;
            uint8View.set(filenameBytes, offset);
            offset += filenameBytes.length;

            // 7. MIME type length (2 bytes, Uint16 big-endian) + MIME type
            view.setUint16(offset, mimeBytes.length, false);
            offset += 2;
            uint8View.set(mimeBytes, offset);
            offset += mimeBytes.length;

            // 8. Ciphertext + Tag
            uint8View.set(new Uint8Array(ciphertext), offset);

            return uint8View;
        },

        /**
         * Complete end-to-end encryption pipeline for a File object.
         * @param {File} file - Original file to encrypt
         * @param {string} passphrase - Secret passphrase
         * @param {Function} [onProgress] - Optional callback to report progress
         * @returns {Promise<{ sfeBlob: Blob, sfeFilename: string, metadata: Object }>}
         */
        async encryptFile(file, passphrase, onProgress = null) {
            if (!file) {
                throw new Error('Please select a file to encrypt.');
            }
            if (!passphrase || passphrase.length === 0) {
                throw new Error('A valid passphrase is required for encryption.');
            }

            if (onProgress) onProgress({ stage: 'reading', percent: 10, message: 'Reading file into memory...' });

            const fileBuffer = await file.arrayBuffer();

            if (onProgress) onProgress({ stage: 'generating_keys', percent: 30, message: 'Generating random cryptographic Salt & IV...' });

            const salt = this.generateRandomBytes(SALT_BYTE_LENGTH);
            const iv = this.generateRandomBytes(IV_BYTE_LENGTH);
            const iterations = DEFAULT_PBKDF2_ITERATIONS;

            if (onProgress) onProgress({ stage: 'deriving_key', percent: 50, message: `Deriving AES-256 key via PBKDF2 (${iterations.toLocaleString()} iterations)...` });

            const key = await this.deriveKey(passphrase, salt, iterations);

            if (onProgress) onProgress({ stage: 'encrypting', percent: 75, message: 'Encrypting data with AES-256-GCM authenticated cipher...' });

            const ciphertext = await this.encryptData(fileBuffer, key, iv);

            if (onProgress) onProgress({ stage: 'packaging', percent: 90, message: 'Packaging encrypted data into .sfe format...' });

            const sfePackage = this.packSfeFile({
                ciphertext,
                salt,
                iv,
                iterations,
                filename: file.name,
                mimeType: file.type || 'application/octet-stream'
            });

            const sfeBlob = new Blob([sfePackage], { type: 'application/octet-stream' });
            const sfeFilename = `${file.name}.sfe`;

            if (onProgress) onProgress({ stage: 'completed', percent: 100, message: 'Encryption completed successfully!' });

            return {
                sfeBlob,
                sfeFilename,
                metadata: {
                    originalName: file.name,
                    originalSize: file.size,
                    originalType: file.type || 'application/octet-stream',
                    encryptedSize: sfePackage.byteLength,
                    saltHex: Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join(''),
                    ivHex: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''),
                    iterations: iterations,
                    cipher: 'AES-256-GCM',
                    kdf: 'PBKDF2-HMAC-SHA256'
                }
            };
        }
    };

    // Export to global scope
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = VaultEncryption;
    } else {
        window.VaultEncryption = VaultEncryption;
    }

})(typeof window !== 'undefined' ? window : globalThis);
