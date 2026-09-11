import * as openpgp from "openpgp";
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import DecryptPrivateKeyService from "../crypto/decryptPrivateKeyService";
import SignMessageService from "../crypto/signMessageService";
import {
  CRYPTO_SUITE,
  PROTOCOL_VERSION,
  decodeContext,
  encodeBinding,
  encodeContext,
  encodeDeviceLoginTranscript,
  encodeEnrollmentTranscript,
  encodeReleasePackageTranscript,
} from "./cborProtocolV1";
import { base64ToBytes, bytesToBase64, bytesToBase64Url, clearBytes, sha256, sha256Hex } from "./encoding";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export default class KeycloakCryptoEnvelopeService {
  static async create(passphrase, account, start) {
    const kd = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const ks = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const signing = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    if (kd.extractable || signing.privateKey.extractable) {
      throw new Error("Profile-resident private keys must be non-extractable.");
    }
    const publicJwk = await crypto.subtle.exportKey("jwk", signing.publicKey);
    const canonicalPublicJwk = {
      crv: publicJwk.crv,
      ext: true,
      key_ops: ["verify"],
      kty: publicJwk.kty,
      x: publicJwk.x,
      y: publicJwk.y,
    };
    const thumbprintInput = textEncoder.encode(
      JSON.stringify({
        crv: publicJwk.crv,
        kty: publicJwk.kty,
        x: publicJwk.x,
        y: publicJwk.y,
      }),
    );
    const thumbprint = bytesToBase64Url(await sha256(thumbprintInput));
    const context = {
      protocol_version: PROTOCOL_VERSION,
      crypto_suite: CRYPTO_SUITE,
      passbolt_origin: new URL(account.domain).origin,
      user_uuid: account.userId,
      identity_uuid: start.identity_id,
      enrollment_uuid: start.enrollment_id,
      client_enrollment_uuid: crypto.randomUUID(),
      openpgp_fingerprint: account.userKeyFingerprint.toUpperCase(),
      enrollment_public_key_thumbprint: thumbprint,
    };
    const contextBytes = encodeContext(context);
    decodeContext(contextBytes);
    let passphraseBytes;
    let c1;
    let rawKs;
    let privateKey;
    let transferredRawKs = false;
    try {
      passphraseBytes = textEncoder.encode(passphrase);
      const innerIv = crypto.getRandomValues(new Uint8Array(12));
      const outerIv = crypto.getRandomValues(new Uint8Array(12));
      c1 = new Uint8Array(
        await crypto.subtle.encrypt(
          {
            name: "AES-GCM",
            iv: innerIv,
            additionalData: encodeBinding("inner_aad", context),
            tagLength: 128,
          },
          kd,
          passphraseBytes,
        ),
      );
      const c2 = new Uint8Array(
        await crypto.subtle.encrypt(
          {
            name: "AES-GCM",
            iv: outerIv,
            additionalData: encodeBinding("outer_aad", context),
            tagLength: 128,
          },
          ks,
          c1,
        ),
      );
      rawKs = new Uint8Array(await crypto.subtle.exportKey("raw", ks));
      const clientBlobDigest = await sha256Hex(c2);
      const shareDigest = await sha256Hex(rawKs);
      const transcript = encodeEnrollmentTranscript(context, clientBlobDigest, shareDigest);
      privateKey = await DecryptPrivateKeyService.decryptArmoredKey(account.userPrivateArmoredKey, passphrase);
      const message = await openpgp.createCleartextMessage({ text: bytesToBase64Url(transcript) });
      const openpgpSignature = await SignMessageService.signClearMessage(message, [privateKey]);
      transferredRawKs = true;
      return {
        upload: {
          context_cbor: bytesToBase64(contextBytes),
          server_share: bytesToBase64(rawKs),
          client_blob_digest: clientBlobDigest,
          openpgp_fingerprint: context.openpgp_fingerprint,
          client_enrollment_uuid: context.client_enrollment_uuid,
          signing_public_key: JSON.stringify(canonicalPublicJwk),
          signing_key_thumbprint: thumbprint,
          openpgp_transcript_signature: openpgpSignature,
        },
        local: {
          kd,
          signingPrivateKey: signing.privateKey,
          signingPublicKey: signing.publicKey,
          context,
          contextCbor: bytesToBase64(contextBytes),
          c2: bytesToBase64(c2),
          innerIv: bytesToBase64(innerIv),
          outerIv: bytesToBase64(outerIv),
          clientBlobDigest,
          enrollmentId: context.enrollment_uuid,
          clientEnrollmentUuid: context.client_enrollment_uuid,
        },
        rawKs,
      };
    } finally {
      clearBytes(passphraseBytes);
      clearBytes(c1);
      if (!transferredRawKs) {
        clearBytes(rawKs);
      }
      privateKey = null;
    }
  }

  static hpkeSuite() {
    return new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
  }

  static async prepareLogin(local) {
    this.validateLocal(local);
    const contextBytes = base64ToBytes(local.contextCbor);
    const context = decodeContext(contextBytes);
    if (
      !equalObjects(context, local.context) ||
      context.enrollment_uuid !== local.enrollmentId ||
      context.client_enrollment_uuid !== local.clientEnrollmentUuid
    ) {
      throw new Error("The local enrollment metadata has changed.");
    }
    if ((await sha256Hex(base64ToBytes(local.c2))) !== local.clientBlobDigest) {
      throw new Error("The local encrypted enrollment blob has changed.");
    }
    const suite = this.hpkeSuite();
    const hpkeKeyPair = await suite.kem.generateKeyPair();
    const hpkePublicKey = new Uint8Array(await suite.kem.serializePublicKey(hpkeKeyPair.publicKey));
    const clientNonce = crypto.getRandomValues(new Uint8Array(32));
    const transcript = encodeDeviceLoginTranscript(
      context,
      bytesToBase64(clientNonce),
      bytesToBase64(hpkePublicKey),
      local.clientBlobDigest,
    );
    const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, local.signingPrivateKey, transcript);
    return {
      payload: {
        enrollment_id: local.enrollmentId,
        context_cbor: local.contextCbor,
        client_nonce: bytesToBase64(clientNonce),
        hpke_recipient_public_key: bytesToBase64(hpkePublicKey),
        client_blob_digest: local.clientBlobDigest,
        signature: bytesToBase64(signature),
      },
      transient: { suite, hpkePrivateKey: hpkeKeyPair.privateKey, hpkePublicKey, clientNonce, context },
    };
  }

  static async releaseRequest(local, transient, requestId) {
    const transcript = encodeReleasePackageTranscript(
      transient.context,
      bytesToBase64(transient.clientNonce),
      bytesToBase64(transient.hpkePublicKey),
      requestId,
    );
    const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, local.signingPrivateKey, transcript);
    return { request_id: requestId, signature: bytesToBase64(signature) };
  }

  static async recoverPassphrase(local, transient, requestId, releasePackage) {
    const releaseAad = encodeReleasePackageTranscript(
      transient.context,
      bytesToBase64(transient.clientNonce),
      bytesToBase64(transient.hpkePublicKey),
      requestId,
    );
    if (
      releasePackage === null ||
      typeof releasePackage !== "object" ||
      JSON.stringify(Object.keys(releasePackage).sort()) !== JSON.stringify(["ciphertext", "context_hash", "enc"]) ||
      !/^[0-9a-f]{64}$/.test(releasePackage.context_hash) ||
      releasePackage.context_hash !== (await sha256Hex(encodeBinding("context_hash", transient.context)))
    ) {
      throw new Error("The server-share release package is invalid.");
    }
    const encapsulatedKey = base64ToBytes(releasePackage.enc);
    const ciphertext = base64ToBytes(releasePackage.ciphertext);
    if (encapsulatedKey.length !== 65 || ciphertext.length !== 48) {
      throw new Error("The server-share release package has invalid lengths.");
    }
    const recipient = await transient.suite.createRecipientContext({
      recipientKey: transient.hpkePrivateKey,
      enc: encapsulatedKey,
      info: encodeBinding("context_hash", transient.context),
    });
    const rawKs = new Uint8Array(await recipient.open(ciphertext, releaseAad));
    let c1;
    try {
      const ks = await crypto.subtle.importKey("raw", rawKs, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
      c1 = new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: base64ToBytes(local.outerIv),
            additionalData: encodeBinding("outer_aad", transient.context),
            tagLength: 128,
          },
          ks,
          base64ToBytes(local.c2),
        ),
      );
      const passphraseBytes = new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: base64ToBytes(local.innerIv),
            additionalData: encodeBinding("inner_aad", transient.context),
            tagLength: 128,
          },
          local.kd,
          c1,
        ),
      );
      try {
        return textDecoder.decode(passphraseBytes);
      } finally {
        clearBytes(passphraseBytes);
      }
    } finally {
      clearBytes(rawKs);
      clearBytes(c1);
    }
  }

  static validateLocal(local) {
    if (
      !local ||
      local.kd?.type !== "secret" ||
      local.kd.extractable ||
      local.kd.algorithm?.name !== "AES-GCM" ||
      local.kd.algorithm?.length !== 256 ||
      !equalStringArrays(local.kd.usages, ["decrypt", "encrypt"]) ||
      local.signingPrivateKey?.type !== "private" ||
      local.signingPrivateKey.extractable ||
      local.signingPrivateKey.algorithm?.name !== "ECDSA" ||
      local.signingPrivateKey.algorithm?.namedCurve !== "P-256" ||
      !equalStringArrays(local.signingPrivateKey.usages, ["sign"]) ||
      local.signingPublicKey?.type !== "public" ||
      local.signingPublicKey.algorithm?.name !== "ECDSA" ||
      local.signingPublicKey.algorithm?.namedCurve !== "P-256" ||
      !equalStringArrays(local.signingPublicKey.usages, ["verify"]) ||
      local.context?.protocol_version !== PROTOCOL_VERSION ||
      local.context?.crypto_suite !== CRYPTO_SUITE
    ) {
      throw new Error("The browser-profile enrollment is missing or invalid.");
    }
  }
}

function equalObjects(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function equalStringArrays(left, right) {
  return (
    Array.isArray(left) &&
    left.length === right.length &&
    [...left].sort().every((value, index) => value === [...right].sort()[index])
  );
}
