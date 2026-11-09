/**
 * VaultLite Automated Cryptographic Test Suite
 * Tests all end-to-end encryption & decryption scenarios using Web Crypto standard APIs.
 */

const assert = require('assert');
const crypto = require('crypto');

// Ensure Web Crypto API is globally available
if (!globalThis.crypto) {
    globalThis.crypto = crypto.webcrypto;
}

const VaultEncryption = require('./VaultLite/js/encryption.js');
const VaultDecryption = require('./VaultLite/js/decryption.js');

async function runTests() {
    console.log('====================================================');
    console.log('🛡️  VaultLite Cryptographic Engine Test Suite');
    console.log('====================================================\n');

    let passed = 0;
    let failed = 0;

    async function test(name, fn) {
        try {
            process.stdout.write(`• Testing: ${name}... `);
            await fn();
            console.log('✅ PASSED');
            passed++;
        } catch (err) {
            console.log(`❌ FAILED: ${err.message}`);
            console.error(err);
            failed++;
        }
    }

    // Helper to simulate a File object
    function createMockFile(name, type, buffer) {
        return {
            name,
            type,
            size: buffer.byteLength,
            arrayBuffer: async () => buffer
        };
    }

    // SCENARIO 1 & 2 & 3: Encrypt text file, decrypt, verify byte-for-byte match
    await test('Scenario 1-3: Encrypt & Decrypt text file with byte-for-byte fidelity', async () => {
        const originalText = 'Top Secret Confidential Document: VaultLite Security Protocol 2026!';
        const encoder = new TextEncoder();
        const textBuffer = encoder.encode(originalText).buffer;
        const mockFile = createMockFile('secret_notes.txt', 'text/plain', textBuffer);
        const passphrase = 'SuperSecretCorrectPassword123!#';

        // Encrypt
        const encResult = await VaultEncryption.encryptFile(mockFile, passphrase);
        assert(encResult.sfeFilename === 'secret_notes.txt.sfe');
        assert(encResult.sfeBlob.size > 0);

        // Convert Blob to MockFile for decryption
        const sfeBuffer = await encResult.sfeBlob.arrayBuffer();
        const mockSfeFile = createMockFile('secret_notes.txt.sfe', 'application/octet-stream', sfeBuffer);

        // Decrypt with correct passphrase
        const decResult = await VaultDecryption.decryptFile(mockSfeFile, passphrase);
        assert(decResult.originalFilename === 'secret_notes.txt');
        assert(decResult.originalType === 'text/plain');

        const decBuffer = await decResult.decryptedBlob.arrayBuffer();
        const decoder = new TextDecoder();
        const decryptedText = decoder.decode(decBuffer);
        assert.strictEqual(decryptedText, originalText, 'Decrypted text must match original exactly');
    });

    // SCENARIO 4: Decrypt with incorrect password
    await test('Scenario 4: Rejection of incorrect passphrase', async () => {
        const textBuffer = new TextEncoder().encode('Sensitive Financial Data').buffer;
        const mockFile = createMockFile('finances.csv', 'text/csv', textBuffer);
        const encResult = await VaultEncryption.encryptFile(mockFile, 'PasswordOne!123');

        const sfeBuffer = await encResult.sfeBlob.arrayBuffer();
        const mockSfeFile = createMockFile('finances.csv.sfe', 'application/octet-stream', sfeBuffer);

        let caught = false;
        try {
            await VaultDecryption.decryptFile(mockSfeFile, 'WrongPasswordEntirely!456');
        } catch (err) {
            caught = true;
            assert(err.message.includes('Authentication failed') || err.message.includes('Incorrect passphrase'), `Error should mention auth/passphrase failure: ${err.message}`);
        }
        assert(caught, 'Must throw error when password is wrong');
    });

    // SCENARIO 5: Decrypt corrupted file (tampered ciphertext or tag)
    await test('Scenario 5: Rejection of tampered / corrupted .sfe file', async () => {
        const textBuffer = new TextEncoder().encode('Integrity Critical Data').buffer;
        const mockFile = createMockFile('integrity.txt', 'text/plain', textBuffer);
        const passphrase = 'IntegrityPassword2026!';
        const encResult = await VaultEncryption.encryptFile(mockFile, passphrase);

        const sfeBuffer = await encResult.sfeBlob.arrayBuffer();
        const uint8Array = new Uint8Array(sfeBuffer);

        // Tamper with a byte near the end (ciphertext or auth tag)
        uint8Array[uint8Array.length - 5] ^= 0xFF;

        const corruptedFile = createMockFile('integrity.txt.sfe', 'application/octet-stream', uint8Array.buffer);

        let caught = false;
        try {
            await VaultDecryption.decryptFile(corruptedFile, passphrase);
        } catch (err) {
            caught = true;
            assert(err.message.includes('Authentication failed'), `Tampered file must fail authentication: ${err.message}`);
        }
        assert(caught, 'Must throw error when file is tampered');
    });

    // SCENARIO 6: Non-SFE file header rejection
    await test('Scenario 6: Rejection of non-SFE arbitrary file', async () => {
        const fakeBuffer = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]).buffer;
        const fakeFile = createMockFile('random.sfe', 'application/octet-stream', fakeBuffer);

        let caught = false;
        try {
            await VaultDecryption.decryptFile(fakeFile, 'somePassword');
        } catch (err) {
            caught = true;
            assert(err.message.includes('VaultLite') || err.message.includes('too small') || err.message.includes('Invalid file format'));
        }
        assert(caught, 'Must reject files without valid VLTE header');
    });

    // SCENARIO 7: Empty (0-byte) file handling
    await test('Scenario 7: Encrypt & Decrypt 0-byte empty file', async () => {
        const emptyBuffer = new ArrayBuffer(0);
        const emptyFile = createMockFile('empty.txt', 'text/plain', emptyBuffer);
        const passphrase = 'EmptyFilePassword!999';

        const encResult = await VaultEncryption.encryptFile(emptyFile, passphrase);
        assert(encResult.sfeBlob.size > 0, 'Encrypted package must have header and tag even if payload is 0 bytes');

        const sfeBuffer = await encResult.sfeBlob.arrayBuffer();
        const mockSfeFile = createMockFile('empty.txt.sfe', 'application/octet-stream', sfeBuffer);

        const decResult = await VaultDecryption.decryptFile(mockSfeFile, passphrase);
        assert.strictEqual(decResult.originalFilename, 'empty.txt');
        const decBuffer = await decResult.decryptedBlob.arrayBuffer();
        assert.strictEqual(decBuffer.byteLength, 0, 'Decrypted buffer must be 0 bytes');
    });

    // SCENARIO 8: Arbitrary Binary Data (e.g. simulated PNG or executable)
    await test('Scenario 8: Arbitrary Binary Data (256KB random bytes)', async () => {
        const randomBytes = crypto.randomBytes(256 * 1024); // 256 KB
        const binFile = createMockFile('photo.png', 'image/png', randomBytes.buffer);
        const passphrase = 'BinaryPassword#2026';

        const encResult = await VaultEncryption.encryptFile(binFile, passphrase);
        const sfeBuffer = await encResult.sfeBlob.arrayBuffer();
        const mockSfeFile = createMockFile('photo.png.sfe', 'application/octet-stream', sfeBuffer);

        const decResult = await VaultDecryption.decryptFile(mockSfeFile, passphrase);
        assert.strictEqual(decResult.originalFilename, 'photo.png');
        assert.strictEqual(decResult.originalType, 'image/png');

        const decBuffer = await decResult.decryptedBlob.arrayBuffer();
        assert.strictEqual(decBuffer.byteLength, randomBytes.length);
        const origHash = crypto.createHash('sha256').update(randomBytes).digest('hex');
        const decHash = crypto.createHash('sha256').update(Buffer.from(decBuffer)).digest('hex');
        assert.strictEqual(decHash, origHash, 'SHA-256 hash must match 100%');
    });

    console.log('\n====================================================');
    console.log(`Test Results: ${passed} Passed, ${failed} Failed`);
    console.log('====================================================');

    if (failed > 0) process.exit(1);
}

runTests();
