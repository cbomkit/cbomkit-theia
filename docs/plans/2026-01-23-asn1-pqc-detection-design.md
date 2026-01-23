# Replace x509 Parsing with ASN1 Parsing for PQC Algorithm Detection

**Issue:** #95
**Date:** 2026-01-23
**Approach:** Hybrid — keep x509 for metadata, add ASN1 fallback for algorithm identification

## Overview

The current certificate scanner uses Go's `crypto/x509` package, which has a fixed `SignatureAlgorithm` enum that doesn't include post-quantum algorithms. This design adds a secondary ASN1 parsing pass for algorithm identification, driven by an external OID registry (JSON), to support PQC algorithms while keeping the stable x509 metadata extraction.

## Data File: `data/oid-registry.json`

A single JSON file serves as the source of truth for all algorithm OID mappings (traditional + PQC). Embedded into the binary via `//go:embed`.

### Schema

```json
{
  "algorithms": {
    "<oid-string>": {
      "name": "string",
      "type": "composite | standalone | hybrid",
      "primitive": "signature | hash | pke | kem",
      "cryptoFunctions": ["sign", "digest", "encapsulate", "decapsulate"],
      "hash": "string (optional, for composite)",
      "signature": "string (optional, for composite)",
      "padding": "string (optional, e.g. PKCS1v15, PSS)",
      "parameterSetIdentifier": "string (optional)",
      "nistStandard": "string (optional, e.g. FIPS204)",
      "components": {
        "hash": "<oid>",
        "signature": "<oid>",
        "traditional": "<oid>",
        "pqc": "<oid>"
      }
    }
  }
}
```

### Entry Types

- **standalone**: Single algorithm (e.g., SHA256, ML-DSA-65, RSA). Produces one CycloneDX component.
- **composite**: Traditional hash+signature combination (e.g., SHA256WithRSA). Produces parent + hash + signature components.
- **hybrid**: PQC+traditional combination (e.g., ML-DSA-65+ECDSA-P256). Produces parent + PQC + traditional components.

## ASN1 Parsing Layer: `scanner/x509/asn1.go`

Minimal ASN1 structures for extracting algorithm OIDs from raw DER bytes:

```go
type asn1Certificate struct {
    TBSCertificate     asn1TBSCertificate
    SignatureAlgorithm  asn1AlgorithmIdentifier
    Signature           asn1.BitString
}

type asn1TBSCertificate struct {
    Raw           asn1.RawContent
    Version       asn1.RawValue `asn1:"optional,explicit,tag:0"`
    SerialNumber  *big.Int
    Signature     asn1AlgorithmIdentifier
    Issuer        asn1.RawValue
    Validity      asn1.RawValue
    Subject       asn1.RawValue
    PublicKeyInfo asn1SubjectPublicKeyInfo
}

type asn1SubjectPublicKeyInfo struct {
    Algorithm asn1AlgorithmIdentifier
    PublicKey asn1.BitString
}

type asn1AlgorithmIdentifier struct {
    Algorithm  asn1.ObjectIdentifier
    Parameters asn1.RawValue `asn1:"optional"`
}
```

**Function:** `extractAlgorithmOIDs(derBytes []byte) (sigOID, pubKeyOID string, err error)`

Only called when `crypto/x509` returns `UnknownSignatureAlgorithm` or `UnknownPublicKeyAlgorithm`.

## OID Registry Loader: `scanner/x509/registry.go`

```go
//go:embed data/oid-registry.json
var registryData []byte

type AlgorithmEntry struct {
    Name                   string            `json:"name"`
    Type                   string            `json:"type"`
    Primitive              string            `json:"primitive"`
    CryptoFunctions        []string          `json:"cryptoFunctions"`
    Hash                   string            `json:"hash,omitempty"`
    Signature              string            `json:"signature,omitempty"`
    Padding                string            `json:"padding,omitempty"`
    ParameterSetIdentifier string            `json:"parameterSetIdentifier,omitempty"`
    NistStandard           string            `json:"nistStandard,omitempty"`
    Components             map[string]string `json:"components,omitempty"`
}

type OIDRegistry struct {
    Algorithms map[string]AlgorithmEntry `json:"algorithms"`
}

func LoadRegistry() (*OIDRegistry, error) { ... }
func (r *OIDRegistry) Lookup(oid string) (AlgorithmEntry, bool) { ... }
```

## Integration Changes: `scanner/x509/x509.go`

### Replace `getSignatureAlgorithmComponents`

Remove the 200-line switch statement. Replace with:

1. Get OID from x509 package (for recognized algorithms, map the enum to its known OID)
2. If `UnknownSignatureAlgorithm`, call `extractAlgorithmOIDs()` on raw DER bytes
3. Look up OID in registry
4. Call `buildComponentsFromEntry()` to generate CycloneDX components

### Replace `getPublicKeyAlgorithmComponent`

Same pattern — registry lookup with ASN1 fallback.

### Remove individual helper functions

Delete `getMD2AlgorithmComponent`, `getMD5AlgorithmComponent`, `getSHA1AlgorithmComponent`, `getSHA256AlgorithmComponent`, `getSHA384AlgorithmComponent`, `getSHA512AlgorithmComponent`, and the hardcoded OID constants. All replaced by generic `buildComponentsFromEntry()`.

### `buildComponentsFromEntry(entry AlgorithmEntry, ...)`

Generates CycloneDX components based on entry type:
- **standalone** → single component with primitive, crypto functions, and parameters
- **composite** → parent component + recursively built sub-components (hash, signature)
- **hybrid** → parent component + traditional sub-component + PQC sub-component

## PQC Algorithms Included

### ML-DSA (FIPS 204, signatures)
| OID | Name |
|-----|------|
| 2.16.840.1.101.3.4.3.17 | ML-DSA-44 |
| 2.16.840.1.101.3.4.3.18 | ML-DSA-65 |
| 2.16.840.1.101.3.4.3.19 | ML-DSA-87 |

### ML-KEM (FIPS 203, key encapsulation)
| OID | Name |
|-----|------|
| 2.16.840.1.101.3.4.4.1 | ML-KEM-512 |
| 2.16.840.1.101.3.4.4.2 | ML-KEM-768 |
| 2.16.840.1.101.3.4.4.3 | ML-KEM-1024 |

### SLH-DSA (FIPS 205, hash-based signatures)
OIDs 2.16.840.1.101.3.4.3.20 through 2.16.840.1.101.3.4.3.31 covering all SHA2/SHAKE, 128/192/256-bit, s/f variants.

### Common Hybrid Combinations (IETF draft OIDs)
- ML-DSA-44 + RSA-2048 (PSS)
- ML-DSA-44 + ECDSA-P256
- ML-DSA-65 + ECDSA-P256
- ML-DSA-65 + Ed25519
- ML-DSA-87 + ECDSA-P384
- ML-DSA-87 + Ed448
- ML-KEM-768 + X25519
- ML-KEM-1024 + P384

## Testing

### Test Certificates
Located in `testdata/certificate/`:
- `ml-dsa-65.pem` — pure ML-DSA-65 certificate
- `ml-dsa-65-ecdsa-p256.pem` — hybrid composite certificate
- `ml-kem-768.pem` — ML-KEM-768 certificate

Generated using oqs-openssl or equivalent PQC-capable tooling.

### Unit Tests
- Registry loading and lookup
- ASN1 OID extraction from PQC certificates
- Component generation for standalone, composite, and hybrid types
- Regression: traditional algorithms produce identical output to current implementation

### Registry Validation
- All `components` OID references must exist in the registry
- No circular references
- Required fields present
- Validated at test time

## Error Handling

- **Unknown OID (not in registry):** Log warning with raw OID, create generic "Unknown Algorithm" component with OID as identifier. Don't silently drop.
- **Malformed ASN1:** Return error. Certificate still created with metadata but without algorithm components.
- **Invalid registry JSON:** Fail fast at startup with clear error message.

## Files Changed

| File | Change |
|------|--------|
| `data/oid-registry.json` | New — unified OID registry |
| `scanner/x509/registry.go` | New — registry loader and lookup |
| `scanner/x509/asn1.go` | New — minimal ASN1 parsing for OID extraction |
| `scanner/x509/x509.go` | Major refactor — replace switch statements with registry lookups |
| `scanner/x509/x509_test.go` | Update tests for new approach + add PQC tests |
| `scanner/key/key.go` | Minor — use registry for key algorithm OID mapping |
| `testdata/certificate/` | New PQC test certificates |
