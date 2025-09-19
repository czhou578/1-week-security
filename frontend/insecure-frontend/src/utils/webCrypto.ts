/**
 * Web Crypto API utilities for client-side encryption
 * EDUCATIONAL: Shows client-side encryption (though backend validation is still needed)
 */

export class WebCryptoUtils {
    private static encoder = new TextEncoder();
    private static decoder = new TextDecoder();

    /**
     * Generate AES-GCM key for symmetric encryption
     */
    static async generateAESKey(): Promise<CryptoKey> {
        return await window.crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true, // extractable
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt data using AES-GCM
     */
    static async encryptData(data: string, key: CryptoKey): Promise<{
        encrypted: string;
        iv: string;
    }> {
        const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
        const encodedData = this.encoder.encode(data);

        const encrypted = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            encodedData
        );

        return {
            encrypted: this.arrayBufferToBase64(encrypted),
            iv: this.arrayBufferToBase64(iv.buffer)
        };
    }

    /**
     * Decrypt data using AES-GCM
     */
    static async decryptData(
        encryptedData: string,
        iv: string,
        key: CryptoKey
    ): Promise<string> {
        const encrypted = this.base64ToArrayBuffer(encryptedData);
        const ivBuffer = this.base64ToArrayBuffer(iv);

        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: new Uint8Array(ivBuffer)
            },
            key,
            encrypted
        );

        return this.decoder.decode(decrypted);
    }

    /**
     * Generate RSA key pair for asymmetric encryption
     */
    static async generateRSAKeyPair(): Promise<CryptoKeyPair> {
        return await window.crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            true, // extractable
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt with RSA public key
     */
    static async encryptWithRSA(data: string, publicKey: CryptoKey): Promise<string> {
        const encodedData = this.encoder.encode(data);
        const encrypted = await window.crypto.subtle.encrypt(
            {
                name: 'RSA-OAEP'
            },
            publicKey,
            encodedData
        );
        return this.arrayBufferToBase64(encrypted);
    }

    /**
     * Hash data using SHA-256
     */
    static async hashData(data: string): Promise<string> {
        const encodedData = this.encoder.encode(data);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', encodedData);
        return this.arrayBufferToBase64(hashBuffer);
    }

    /**
     * Generate secure random token
     */
    static generateSecureToken(length: number = 32): string {
        const array = new Uint8Array(length);
        window.crypto.getRandomValues(array);
        return this.arrayBufferToBase64(array.buffer);
    }

    // Helper functions
    private static arrayBufferToBase64(buffer: ArrayBuffer): string {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    private static base64ToArrayBuffer(base64: string): ArrayBuffer {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * Export key to base64 string
     */
    static async exportKey(key: CryptoKey): Promise<string> {
        const exported = await window.crypto.subtle.exportKey('raw', key);
        return this.arrayBufferToBase64(exported);
    }

    /**
     * Import key from base64 string
     */
    static async importAESKey(keyData: string): Promise<CryptoKey> {
        const keyBuffer = this.base64ToArrayBuffer(keyData);
        return await window.crypto.subtle.importKey(
            'raw',
            keyBuffer,
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt', 'decrypt']
        );
    }
}