# Attestation trust roots (Cloud Mode)

This directory holds the bundled, trusted root and intermediate certificates the
Cloud Mode remote-attestation verifiers use to anchor confidential-VM evidence:

- `server/services/attestation-sev-snp.js` verifies an AMD SEV-SNP report's
  VCEK -> ASK -> ARK chain against the AMD roots here.
- `server/services/attestation-tdx.js` verifies an Intel TDX quote's
  PCK -> intermediate -> Intel SGX Root CA chain against the Intel root here.

The verifiers are fail-closed. With these roots absent, a real confidential VM
cannot pass attestation -- which is the intended staged state until the roots
are added and confirmed on real hardware (see Status).

## Status: pending hardware validation

These are real, security-critical vendor certificates. They are added at the
SEV-SNP / TDX hardware-validation pass, when a confidential VM is available to
confirm the full path end to end. Until then this directory contains only this
README, and Cloud Mode attestation fails closed by design. The verifier code is
exercised in CI against self-generated synthetic fixtures, never these roots.

Do not fabricate or hand-edit these certificates. Fetch them only from the
official vendor services below, over TLS, and pin them by fingerprint.

## Layout

    server/data/attestation-roots/
      README.md                 this file
      amd/
        <product>/              lowercase product line: milan, genoa, turin, ...
          ark.pem               AMD Root Key (trust anchor, self-signed)
          ask.pem               AMD SEV Key (intermediate, signed by ARK)
      intel/
        sgx-root-ca.pem         Intel SGX Root CA (trust anchor, self-signed)

Bundle one amd/<product>/ directory per AMD product line whose instance types
are supported. The single Intel root anchors PCK chains for all TDX platforms.

## AMD SEV-SNP roots (ARK + ASK)

Trust chain: the report is signed by the VCEK (per-chip, ECDSA P-384); the VCEK
is signed by the ASK; the ASK is signed by the ARK; the ARK is self-signed. The
VCEK travels with the report (auxblob) or is fetched once from KDS; only the ARK
and ASK are bundled here.

- Source: AMD Key Distribution Service (KDS), base https://kdsintf.amd.com
- Fetch (PEM; returns the ASK then the ARK, concatenated, in that order):
      GET https://kdsintf.amd.com/vcek/v1/{product}/cert_chain
  Split the response into ask.pem and ark.pem.
- product values: Milan, Genoa, Turin (and newer lines as AMD publishes them);
  store the directory name lowercased.
- Algorithms: the ARK and ASK are RSA-4096 with RSASSA-PSS / SHA-384; the VCEK
  and the report signature are ECDSA P-384 / SHA-384.
- VLEK variant: some cloud platforms sign reports with a VLEK rather than a
  VCEK. The VLEK chains VLEK -> ASVK -> ARK; fetch the VLEK chain at
      GET https://kdsintf.amd.com/vlek/v1/{product}/cert_chain
  and bundle the additional intermediate where VLEK is in use.
- Revocation: https://kdsintf.amd.com/vcek/v1/{product}/crl (and the vlek path).
- The VCEK's AMD custom extensions (OID prefix 1.3.6.1.4.1.3704.1) encode the
  per-chip HWID and TCB SVNs; binding them to the report CHIP_ID / REPORTED_TCB
  is the deferred hardening noted in attestation-sev-snp.js.

Verification before bundling:
1. Confirm the ARK is self-signed and the ASK is signed by the ARK.
2. Pin and record the ARK SHA-256 fingerprint per product line below.

ARK SHA-256 fingerprints (filled at the validation pass):
- milan: <pin at validation>
- genoa: <pin at validation>
- turin: <pin at validation>

## Intel TDX root (Intel SGX Root CA)

Trust chain: the TD quote is signed by an attestation key bound to the Quoting
Enclave; the QE report is signed by the platform PCK (ECDSA P-256); the PCK
chains PCK -> PCK Platform or Processor CA (intermediate) -> Intel SGX Root CA.
The PCK leaf and intermediate travel inside the quote (cert-data type 5), so
only the Intel SGX Root CA is bundled here. The one root anchors both SGX and
TDX PCK chains.

- Source: Intel Provisioning Certification Service (PCS),
  base https://api.trustedservices.intel.com/sgx/certification/v4/
  (TDX-specific TCB / QE-identity collateral at .../tdx/certification/v4/).
  The v4 Provisioning Certification Root CA certificate is published on the
  Intel PCS portal in DER and PEM.
- Identity: self-signed; Subject = Issuer = "CN=Intel SGX Root CA, O=Intel
  Corporation, L=Santa Clara, ST=CA, C=US"; Subject Key Identifier == Authority
  Key Identifier 22:65:0C:D6:5A:9D:34:89:F3:83:B4:95:52:BF:50:1B:39:27:06:AC.
- Published fingerprint (v4 production root, SHA-1, as listed by Intel):
      8bd31eb1d63ce37382c0ffaa0d8200a3011ad6ff
- Revocation: https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl

Verification before bundling:
1. Confirm self-signed and that SKI == AKI as above.
2. Confirm the published fingerprint, then also pin the SHA-256 below.

Intel SGX Root CA SHA-256 fingerprint (filled at the validation pass):
- <pin at validation>

## Refresh and rotation

These roots are long-lived but not permanent. Re-fetch and re-pin if a vendor
rotates a root, a new supported product line is added, or a pinned certificate
nears expiry. Any change to a bundled root is a security-relevant commit: record
the new fingerprint here and note the reason. Keep CRL handling in mind when the
revocation wiring lands.

## Validation-pass checklist

- [ ] Fetch AMD ARK/ASK for each supported product line from KDS; split; verify
      the ARK is self-signed and the ASK is signed by the ARK; pin ARK SHA-256.
- [ ] Download the Intel SGX Root CA from the PCS portal; verify self-signed and
      the published fingerprint; pin SHA-256 above.
- [ ] Run a real SEV-SNP report and a real TDX quote through the verifiers and
      confirm the full path (signature, chain, TCB floor, measurement, nonce).
- [ ] Add the VCEK HWID/TCB-extension binding (SEV-SNP) and the QE-identity
      check (TDX), now testable against real vendor collateral.
