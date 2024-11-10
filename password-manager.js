"use strict";

/********* External Imports ********/
const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;
const crypto = require('crypto');

/********* Constants ********/
const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  constructor() {
    this.data = {}; // Public data that won't compromise security
    this.secrets = {}; // Sensitive data that needs encryption
  }

  /**
   * Initializes the Keychain with a derived encryption key from the master password.
   *
   * @param {string} password - The master password.
   * @returns {Keychain} - The initialized Keychain instance.
   */
  static async init(password) {
    if (password.length > MAX_PASSWORD_LENGTH) {
      throw new Error("Password exceeds maximum length");
    }
    const keychain = new Keychain();
    const salt = getRandomBytes(16); // Generate a random salt for PBKDF2
    keychain.secrets.salt = salt;
    keychain.secrets.key = await keychain.deriveKey(password, salt);
    return keychain;
  }

  /**
   * Derives an encryption key from the master password using PBKDF2.
   *
   * @param {string} password - The master password.
   * @param {Buffer} salt - The salt.
   * @returns {CryptoKey} - The derived encryption key.
   */
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

  /**
   * Computes an HMAC for a given domain using the derived key.
   *
   * @param {string} domain - The domain name.
   * @returns {string} - The HMAC of the domain.
   */
  computeHMAC(domain) {
    // It's recommended to use a separate key for HMAC, but for simplicity, we'll use the same key here.
    // In a production system, derive separate keys for different purposes.
    return crypto.createHmac('sha256', this.secrets.key)
                 .update(domain)
                 .digest('hex');
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object). Returns a Keychain object that contains the data
    * from repr. 
    *
    * @param {string} password - The master password.
    * @param {string} repr - The serialized keychain data.
    * @param {string} trustedDataCheck - The SHA-256 checksum.
    * @returns {Keychain} - The loaded Keychain instance.
    */
  static async load(password, repr, trustedDataCheck) {
    const parsedData = JSON.parse(repr);
    const { data, salt } = parsedData;

    const keychain = new Keychain();
    keychain.secrets.salt = Buffer.from(salt, 'hex');
    keychain.secrets.key = await keychain.deriveKey(password, keychain.secrets.salt);

    if (trustedDataCheck) {
      const computedCheck = await keychain.computeSHA256(repr);
      if (computedCheck !== trustedDataCheck) throw new Error("Data integrity check failed");
    }

    keychain.data = data;
    return keychain;
  }

  /**
   * Encrypts the provided data using AES-GCM.
   *
   * @param {string} data - The data to encrypt.
   * @returns {object} - An object containing the IV and encrypted content.
   */
  async encrypt(data) {
    try {
      const iv = getRandomBytes(12); // AES-GCM needs a 12-byte IV
      const encodedData = stringToBuffer(data);

      const encryptedContent = await subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        this.secrets.key,
        encodedData
      );

      return { iv: bufferToString(iv), content: bufferToString(encryptedContent) };
    } catch (error) {
      throw new Error("Encryption failed: " + error.message);
    }
  }

  /**
   * Decrypts the provided encrypted data using AES-GCM.
   *
   * @param {object} encryptedData - The encrypted data containing IV and content.
   * @returns {string} - The decrypted data as a string.
   */
  async decrypt(encryptedData) {
    try {
      const { iv, content } = encryptedData;
      const decryptedContent = await subtle.decrypt(
        { name: "AES-GCM", iv: stringToBuffer(iv) },
        this.secrets.key,
        stringToBuffer(content)
      );
      return bufferToString(decryptedContent);
    } catch (error) {
      throw new Error("Decryption failed: " + error.message);
    }
  }

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * @returns {Promise<Array>} - An array containing the JSON data and its checksum.
    */ 
  async dump() {
    try {
      const jsonData = JSON.stringify(this.data);
      const checksum = await this.computeSHA256(jsonData);
      return [jsonData, checksum];
    } catch (error) {
      throw new Error("Dump failed: " + error.message);
    }
  }

  /**
   * Computes a SHA-256 checksum for the provided data.
   *
   * @param {string} data - The data to checksum.
   * @returns {Promise<string>} - The SHA-256 checksum as a hex string.
   */
  async computeSHA256(data) {
    try {
      const enc = new TextEncoder();
      const hashBuffer = await subtle.digest("SHA-256", enc.encode(data));
      return bufferToString(hashBuffer);
    } catch (error) {
      throw new Error("SHA-256 computation failed: " + error.message);
    }
  }

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * @param {string} name - The domain name.
    * @returns {Promise<string|null>} - The decrypted password or null if not found.
    */
  async get(name) {
    try {
      const hmacName = this.computeHMAC(name);
      const encryptedData = this.data[hmacName];
      if (!encryptedData) return null;
      return await this.decrypt(encryptedData);
    } catch (error) {
      throw new Error("Get failed: " + error.message);
    }
  }

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * @param {string} name - The domain name.
  * @param {string} value - The password to store.
  * @returns {Promise<void>}
  */
  async set(name, value) {
    try {
      const hmacName = this.computeHMAC(name);
      const encryptedValue = await this.encrypt(value);
      this.data[hmacName] = encryptedValue;
    } catch (error) {
      throw new Error("Set failed: " + error.message);
    }
  }

  /**
    * Removes the record with the specified domain name from the password manager.
    * Returns true if the record is removed, false otherwise.
    *
    * @param {string} name - The domain name.
    * @returns {Promise<boolean>} - Whether the removal was successful.
    */
  async remove(name) {
    try {
      const hmacName = this.computeHMAC(name);
      if (this.data[hmacName]) {
        delete this.data[hmacName];
        return true;
      }
      return false;
    } catch (error) {
      throw new Error("Remove failed: " + error.message);
    }
  }
};

module.exports = { Keychain };


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