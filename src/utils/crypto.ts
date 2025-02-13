// src/utils/crypto.ts

import pkg from 'blakejs';
const { blake2bHex } = pkg;

export function hexToBytes(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) {
        throw new Error("Hex string must have an even length");
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        const hexByte = hex.substring(i, i + 2);
        const byteValue = parseInt(hexByte, 16);
        if (isNaN(byteValue) || byteValue < 0 || byteValue > 255) {
            throw new Error("Invalid hex string");
        }
        bytes[i / 2] = byteValue;
    }
    return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        const hexByte = bytes[i].toString(16).padStart(2, '0');
        hex += hexByte;
    }
    return hex.toLowerCase(); // ensure hex is lowercased
}

export function xorBytes(bytes1: Uint8Array, bytes2: Uint8Array): Uint8Array {
    if (bytes1.length !== bytes2.length) {
        throw new Error("Byte arrays must have the same length for XOR operation");
    }
    const result = new Uint8Array(bytes1.length);
    for (let i = 0; i < bytes1.length; i++) {
        result[i] = bytes1[i] ^ bytes2[i];
    }
    return result;
}

export function generateNonceHex(lengthBytes: number): string {
    const nonceBytes = new Uint8Array(lengthBytes);
    crypto.getRandomValues(nonceBytes);
    return bytesToHex(nonceBytes);
}

export { blake2bHex }; // export blake2bHex