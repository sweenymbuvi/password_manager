"use strict";

/********* External Imports ********/
const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;
const crypto = require('crypto');

/********* Constants ********/
const PBKDF2_ITERATIONS = 100000;
const MAX_PASSWORD_LENGTH = 64;
const VERSION = "1.0";

/********* Storage Class Implementation ********/
class Storage {
  constructor() {
    this.kvs = new Map();
  }

  async store(domainHash, encryptedData) {
    this.kvs.set(domainHash, {
      iv: encodeBuffer(encryptedData.iv),
      ciphertext: encodeBuffer(encryptedData.ciphertext)
    });
  }

  async retrieve(domainHash) {
    const data = this.kvs.get(domainHash);
    if (!data) return null;
    
    return {
      iv: decodeBuffer(data.iv),
      ciphertext: decodeBuffer(data.ciphertext)
    };
  }

  async remove(domainHash) {
    return this.kvs.delete(domainHash);
  }

  async serialize() {
    const storageObj = {
      kvs: Object.fromEntries(this.kvs),
      version: VERSION
    };
    return JSON.stringify(storageObj);
  }

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
class Keychain {
  constructor() {
    this.storage = new Storage();
    this.secrets = {};
  }

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

  async deriveKey(password, salt) {
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
  }

  computeHMAC(domain) {
    return crypto.createHmac('sha256', bufferToString(this.secrets.salt))
                .update(domain)
                .digest('hex');
  }

  static async load(password, repr, trustedDataCheck) {
    const keychain = new Keychain();
    
    // Verify integrity
    if (trustedDataCheck) {
      const computedCheck = await keychain.computeSHA256(repr);
      if (computedCheck !== trustedDataCheck) {
        throw new Error("Data integrity check failed");
      }
    }

    // Parse the representation
    const parsedData = JSON.parse(repr);
    
    // Validate format
    if (!parsedData.version || !parsedData.salt) {
      throw new Error("Invalid keychain format");
    }

    // Set up encryption materials
    keychain.secrets.salt = Buffer.from(parsedData.salt, 'hex');
    keychain.secrets.key = await keychain.deriveKey(password, keychain.secrets.salt);

    // Restore the storage
    keychain.storage = await Storage.deserialize(repr);

    return keychain;
  }

  async encrypt(data) {
    try {
      const iv = getRandomBytes(12);
      const encodedData = stringToBuffer(data);
      const encryptedContent = await subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        this.secrets.key,
        encodedData
      );

      return {
        iv: iv,
        ciphertext: new Uint8Array(encryptedContent)
      };
    } catch (error) {
      throw new Error("Encryption failed: " + error.message);
    }
  }

  async decrypt(encryptedData) {
    try {
      const decryptedContent = await subtle.decrypt(
        { name: "AES-GCM", iv: encryptedData.iv },
        this.secrets.key,
        encryptedData.ciphertext
      );

      return bufferToString(new Uint8Array(decryptedContent));
    } catch (error) {
      throw new Error("Decryption failed: " + error.message);
    }
  }

  async dump() {
    try {
      // Prepare the full keychain data
      const dumpData = {
        version: VERSION,
        salt: bufferToString(this.secrets.salt, 'hex'),
        kvs: Object.fromEntries(this.storage.kvs)
      };

      const jsonData = JSON.stringify(dumpData);
      const checksum = await this.computeSHA256(jsonData);
      
      return [jsonData, checksum];
    } catch (error) {
      throw new Error("Dump failed: " + error.message);
    }
  }

  async computeSHA256(data) {
    try {
      const enc = new TextEncoder();
      const hashBuffer = await subtle.digest("SHA-256", enc.encode(data));
      return bufferToString(new Uint8Array(hashBuffer));
    } catch (error) {
      throw new Error("SHA-256 computation failed: " + error.message);
    }
  }

  async get(name) {
    try {
      const hmacName = this.computeHMAC(name);
      const encryptedData = await this.storage.retrieve(hmacName);
      if (!encryptedData) return null;
      return await this.decrypt(encryptedData);
    } catch (error) {
      throw new Error("Get failed: " + error.message);
    }
  }

  async set(name, value) {
    try {
      const hmacName = this.computeHMAC(name);
      const encryptedValue = await this.encrypt(value);
      await this.storage.store(hmacName, encryptedValue);
    } catch (error) {
      throw new Error("Set failed: " + error.message);
    }
  }

  async remove(name) {
    try {
      const hmacName = this.computeHMAC(name);
      return await this.storage.remove(hmacName);
    } catch (error) {
      throw new Error("Remove failed: " + error.message);
    }
  }
}

module.exports = { Keychain, Storage };


//Encryption-Decryption with Subtle Crypto 

// Encrypts a password using AES-GCM encryption
async function encryptPassword(key, plaintextPassword) {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // Generate a 12-byte IV for AES-GCM

  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    stringToBuffer(plaintextPassword)
  );

  // Return the IV and ciphertext as Base64 for easy storage
  return {
    iv: encodeBuffer(iv),
    ciphertext: encodeBuffer(new Uint8Array(encrypted))
  };
}

// Decrypts a password using AES-GCM decryption
async function decryptPassword(key, encryptedData) {
  const iv = decodeBuffer(encryptedData.iv); // Decode the IV from Base64
  const ciphertext = decodeBuffer(encryptedData.ciphertext); // Decode ciphertext from Base64

  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    ciphertext
  );

  return bufferToString(new Uint8Array(decrypted)); // Convert decrypted buffer to string
}

// Export the functions using CommonJS
module.exports = {
  encryptPassword,
  decryptPassword,
  computeIntegrityHash,
  verifyIntegrityHash
};


// Adding Integrity functions for Data Verification
// Computes a hash for integrity verification
async function computeIntegrityHash(key, data) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(JSON.stringify(data));

  const hash = await crypto.subtle.sign(
    {
      name: 'HMAC',
      hash: 'SHA-256',
    },
    key,
    dataBuffer
  );

  return encodeBuffer(new Uint8Array(hash));
}

// Verifies the data integrity
async function verifyIntegrityHash(key, data, providedHash) {
  const computedHash = await computeIntegrityHash(key, data);

  if (computedHash !== providedHash) {
    throw new Error('Data integrity check failed. Possible tampering detected.');
  }
}

// Export everything using CommonJS
module.exports = {
  Keychain,
  encryptPassword,
  decryptPassword,
  computeIntegrityHash,
  verifyIntegrityHash
};