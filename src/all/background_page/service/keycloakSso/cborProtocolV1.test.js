import {
  decodeContext,
  decodeDeviceLoginTranscript,
  decodeEnrollmentTranscript,
  decodeReleasePackageTranscript,
  encodeBinding,
  encodeContext,
  encodeDeviceLoginTranscript,
  encodeEnrollmentTranscript,
  encodeReleasePackageTranscript,
} from "./cborProtocolV1";
import { bytesToBase64, sha256Hex } from "./encoding";
import vectors from "./protocol-v1-vectors.json";

async function expectVector(actual, expected) {
  expect(bytesToBase64(actual)).toBe(expected.base64);
  expect(await sha256Hex(actual)).toBe(expected.sha256);
}

describe("Keycloak cryptographic SSO protocol v1 codec", () => {
  it("matches the frozen PHP context and AAD vectors", async () => {
    const context = encodeContext(vectors.context);
    await expectVector(context, vectors.vectors.context);
    await expectVector(encodeBinding("inner_aad", vectors.context), vectors.vectors.inner_aad);
    await expectVector(encodeBinding("outer_aad", vectors.context), vectors.vectors.outer_aad);
    await expectVector(encodeBinding("context_hash", vectors.context), vectors.vectors.context_hash);
    expect(decodeContext(context)).toEqual(vectors.context);
  });

  it("matches every frozen fixed-transcript vector", async () => {
    const values = vectors.values;
    const enrollment = encodeEnrollmentTranscript(
      vectors.context,
      values.client_blob_digest,
      values.server_share_digest,
    );
    const login = encodeDeviceLoginTranscript(
      vectors.context,
      values.client_nonce,
      values.hpke_recipient_public_key,
      values.client_blob_digest,
    );
    const release = encodeReleasePackageTranscript(
      vectors.context,
      values.client_nonce,
      values.hpke_recipient_public_key,
      values.request_id,
    );
    await expectVector(enrollment, vectors.vectors.enrollment_transcript);
    await expectVector(login, vectors.vectors.device_login_transcript);
    await expectVector(release, vectors.vectors.release_package_transcript);
    expect(decodeEnrollmentTranscript(enrollment).values).toEqual([
      values.client_blob_digest,
      values.server_share_digest,
    ]);
    expect(decodeDeviceLoginTranscript(login).values).toEqual([
      values.client_nonce,
      values.hpke_recipient_public_key,
      values.client_blob_digest,
    ]);
    expect(decodeReleasePackageTranscript(release).values).toEqual([
      values.client_nonce,
      values.hpke_recipient_public_key,
      values.request_id,
    ]);
  });

  it("rejects wrong transcript schemas and trailing bytes", () => {
    const login = encodeDeviceLoginTranscript(
      vectors.context,
      vectors.values.client_nonce,
      vectors.values.hpke_recipient_public_key,
      vectors.values.client_blob_digest,
    );
    expect(() => decodeEnrollmentTranscript(login)).toThrow();
    expect(() => decodeDeviceLoginTranscript(new Uint8Array([...login, 0]))).toThrow();
  });
});
