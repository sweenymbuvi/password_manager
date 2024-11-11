"use strict";

/********* External Imports ********/
const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;
const crypto = require('crypto');

/********* Constants ********/
// Number of iterations for PBKDF2 key derivation
const PBKDF2_ITERATIONS = 100000;
// Maximum allowed password length
const MAX_PASSWORD_LENGTH = 64;
// Version identifier for the keychain format
const VERSION = "1.0";

/********* Cryptographic Helper Functions ********/

/**
 * Computes an integrity hash for data verification using HMAC-SHA256
 * @param {CryptoKey} key - The key to use for HMAC
 * @param {Object} data - The data to hash
 * @returns {Promise<string>} Base64 encoded hash
 */
async function computeIntegrityHash(key, data) {
  try {
    // Convert the key to raw format for HMAC
    const rawKey = await subtle.exportKey('raw', key);
    // Create an HMAC key
    const hmacKey = await subtle.importKey(
      'raw',
      rawKey,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    // Convert data to buffer and compute HMAC
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(JSON.stringify(data));
    const hash = await subtle.sign(
      { name: 'HMAC', hash: 'SHA-256' },
      hmacKey,
      dataBuffer
    );

    return encodeBuffer(new Uint8Array(hash));
  } catch (error) {
    throw new Error('Failed to compute integrity hash: ' + error.message);
  }
}

/**
 * Verifies the integrity of data using a provided hash
 * @param {CryptoKey} key - The key used for hash verification
 * @param {Object} data - The data to verify
 * @param {string} providedHash - The hash to verify against
 * @returns {Promise<boolean>} Whether the data is valid
 */
async function verifyIntegrityHash(key, data, providedHash) {
  const computedHash = await computeIntegrityHash(key, data);
  return computedHash === providedHash;
}

/**
 * Encrypts a password using AES-GCM
 * @param {CryptoKey} key - The encryption key
 * @param {string} plaintextPassword - The password to encrypt
 * @returns {Promise<Object>} Object containing IV and encrypted data
 */
async function encryptPassword(key, plaintextPassword) {
  try {
    const iv = getRandomBytes(12); // Generate 12-byte IV for AES-GCM
    const encrypted = await subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      stringToBuffer(plaintextPassword)
    );

    return {
      iv: encodeBuffer(iv),
      ciphertext: encodeBuffer(new Uint8Array(encrypted))
    };
  } catch (error) {
    throw new Error('Encryption failed: ' + error.message);
  }
}

/**
 * Decrypts a password using AES-GCM
 * @param {CryptoKey} key - The decryption key
 * @param {Object} encryptedData - Object containing IV and encrypted data
 * @returns {Promise<string>} The decrypted password
 */
async function decryptPassword(key, encryptedData) {
  try {
    const iv = decodeBuffer(encryptedData.iv);
    const ciphertext = decodeBuffer(encryptedData.ciphertext);
    
    const decrypted = await subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      ciphertext
    );

    return bufferToString(new Uint8Array(decrypted));
  } catch (error) {
    throw new Error('Decryption failed: ' + error.message);
  }
}

/********* Storage Class Implementation ********/
/**
 * Storage class for managing encrypted key-value pairs
 */
class Storage {
  constructor() {
    this.kvs = new Map();
  }

  /**
   * Stores encrypted data for a given domain hash
   * @param {string} domainHash - Hash of the domain name
   * @param {Object} encryptedData - Encrypted password data
   */
  async store(domainHash, encryptedData) {
    this.kvs.set(domainHash, encryptedData);
  }

  /**
   * Retrieves encrypted data for a given domain hash
   * @param {string} domainHash - Hash of the domain name
   * @returns {Object|null} Encrypted data if found, null otherwise
   */
  async retrieve(domainHash) {
    return this.kvs.get(domainHash);
  }

  /**
   * Removes data for a given domain hash
   * @param {string} domainHash - Hash of the domain name
   * @returns {boolean} Whether the removal was successful
   */
  async remove(domainHash) {
    return this.kvs.delete(domainHash);
  }

  /**
   * Serializes the storage to JSON
   * @returns {string} JSON representation of storage
   */
  async serialize() {
    return JSON.stringify({
      kvs: Object.fromEntries(this.kvs),
      version: VERSION
    });
  }

  /**
   * Creates a Storage instance from serialized data
   * @param {string} jsonStr - JSON representation of storage
   * @returns {Storage} New Storage instance
   */
  static async deserialize(jsonStr) {
    const storage = new Storage();
    const parsed = JSON.parse(jsonStr);
    if (!parsed.kvs) {
      throw new Error("Invalid storage format");
    }
    storage.kvs = new Map(Object.entries(parsed.kvs));
    return storage;
  }
}

/********* Keychain Class Implementation ********/
/**
 * Main keychain class for password management
 */
class Keychain {
  constructor() {
    this.storage = new Storage();
    this.secrets = {};
  }

  /**
   * Creates a new keychain with the given master password
   * @param {string} password - Master password for the keychain
   * @returns {Keychain} New keychain instance
   */
  static async init(password) {
    if (password.length > MAX_PASSWORD_LENGTH) {
      throw new Error("Password exceeds maximum length");
    }
    const keychain = new Keychain();
    const salt = getRandomBytes(16);
    keychain.secrets.salt = salt;
    keychain.secrets.key = await keychain.deriveKey(password, salt);
    return keychain;
  }

  /**
   * Derives an encryption key from password and salt using PBKDF2
   * @param {string} password - Password to derive key from
   * @param {Uint8Array} salt - Salt for key derivation
   * @returns {CryptoKey} Derived key
   */
  async deriveKey(password, salt) {
    try {
      const enc = new TextEncoder();
      const keyMaterial = await subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
      );
      return subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: PBKDF2_ITERATIONS,
          hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
    } catch (error) {
      throw new Error("Key derivation failed");
    }
  }

  /**
   * Computes HMAC for domain names
   * @param {string} domain - Domain to compute HMAC for
   * @returns {string} Hex encoded HMAC
   */
  computeHMAC(domain) {
    return crypto.createHmac('sha256', bufferToString(this.secrets.salt))
                .update(domain)
                .digest('hex');
  }

  /**
   * Loads a keychain from serialized data
   * @param {string} password - Master password
   * @param {string} repr - Serialized keychain data
   * @param {string} trustedDataCheck - Integrity check value
   * @returns {Keychain} Loaded keychain instance
   */
  static async load(password, repr, trustedDataCheck) {
    try {
      const keychain = new Keychain();
      const parsedData = JSON.parse(repr);
      
      if (!parsedData.salt || !parsedData.version) {
        throw new Error("Invalid keychain format");
      }

      keychain.secrets.salt = decodeBuffer(parsedData.salt);
      
      try {
        keychain.secrets.key = await keychain.deriveKey(password, keychain.secrets.salt);
      } catch (error) {
        throw new Error("Invalid password");
      }

      if (trustedDataCheck) {
        const computedCheck = await keychain.computeSHA256(repr);
        if (computedCheck !== trustedDataCheck) {
          throw new Error("Data integrity check failed");
        }
      }

      keychain.storage = await Storage.deserialize(repr);
      
      // Verify password by attempting to decrypt an entry
      const entries = Object.entries(parsedData.kvs);
      if (entries.length > 0) {
        try {
          await keychain.decrypt(entries[0][1]);
        } catch (error) {
          throw new Error("Invalid password");
        }
      }
      
      return keychain;
    } catch (error) {
      throw new Error("Failed to load keychain: " + error.message);
    }
  }

  // Wrapper methods for encryption/decryption
  async encrypt(data) {
    return encryptPassword(this.secrets.key, data);
  }

  async decrypt(encryptedData) {
    return decryptPassword(this.secrets.key, encryptedData);
  }

  /**
   * Serializes the keychain and computes integrity check
   * @returns {Array} Array containing serialized data and checksum
   */
  async dump() {
    const dumpData = {
      version: VERSION,
      salt: encodeBuffer(this.secrets.salt),
      kvs: Object.fromEntries(this.storage.kvs)
    };

    const jsonData = JSON.stringify(dumpData);
    const checksum = await this.computeSHA256(jsonData);
    
    return [jsonData, checksum];
  }

  /**
   * Computes SHA-256 hash of data
   * @param {string} data - Data to hash
   * @returns {string} Base64 encoded hash
   */
  async computeSHA256(data) {
    const enc = new TextEncoder();
    const hashBuffer = await subtle.digest("SHA-256", enc.encode(data));
    return bufferToString(new Uint8Array(hashBuffer), 'base64');
  }

  /**
   * Retrieves a password for a given domain
   * @param {string} name - Domain name
   * @returns {Promise<string|null>} Retrieved password or null if not found
   */
  async get(name) {
    const hmacName = this.computeHMAC(name);
    const encryptedData = await this.storage.retrieve(hmacName);
    if (!encryptedData) return null;
    return await this.decrypt(encryptedData);
  }

  /**
   * Stores a password for a given domain
   * @param {string} name - Domain name
   * @param {string} value - Password to store
   */
  async set(name, value) {
    const hmacName = this.computeHMAC(name);
    const encryptedValue = await this.encrypt(value);
    await this.storage.store(hmacName, encryptedValue);
  }

  /**
   * Removes a password for a given domain
   * @param {string} name - Domain name
   * @returns {Promise<boolean>} Whether the removal was successful
   */
  async remove(name) {
    const hmacName = this.computeHMAC(name);
    return await this.storage.remove(hmacName);
  }
}

// Export all required functions and classes
module.exports = {
  Keychain,
  encryptPassword,
  decryptPassword,
  computeIntegrityHash,
  verifyIntegrityHash
};