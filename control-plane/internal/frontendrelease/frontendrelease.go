// Package frontendrelease implements ADR-037's build/sign/verify/publish
// pipeline for the dashboard's content-addressed static frontend bundle.
//
// This package deliberately does not touch the mTLS PKI, the Provider
// Agent's identity key, or any wallet-login signature (internal/userauth,
// internal/walletlogin): it introduces one new, narrowly-scoped Ed25519
// keypair whose only job is authenticating a build artifact (a signed
// manifest naming a content-addressed IPFS CID) to a browser or
// verifier -- never a peer, never a session -- reusing ADR-027 §2's
// "fresh key per purpose, same pattern" reasoning rather than folding
// this into an existing key (ADR-037 §2).
package frontendrelease

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// releaseDomain is this package's own domain-separated signing prefix,
// matching internal/providerjoin's joinDomain/heartbeatDomain and
// internal/walletlogin's loginDomain convention exactly (ADR-037 §2 step
// 4): a signature produced under this domain can never be replayed
// against, or confused with, any of those other three flows, and vice
// versa, even though all four ultimately call the same
// crypto/ed25519.Sign/Verify primitives.
const releaseDomain = "openinfra-frontend-release-v1\x00"

// SchemaVersion is Manifest's own schema version -- bumped only if the
// manifest's shape changes in a way a verifier needs to know about
// (ADR-037 §2 step 3 lists it as the manifest's first field for exactly
// this reason).
const SchemaVersion = 1

var (
	// ErrManifestTampered means the manifest's own manifest_sha256 field
	// does not match a fresh hash recomputed from its other fields --
	// the content-addressing tamper-evidence ADR-037 §2 describes,
	// checked independently of the signature itself so a caller can tell
	// "this manifest was edited after hashing" apart from "this manifest
	// was never validly signed at all."
	ErrManifestTampered = errors.New("frontendrelease: manifest_sha256 does not match the manifest's own content")
	// ErrInvalidSignature covers every reason a signature does not verify
	// -- wrong key, wrong message, corrupted signature -- collapsed into
	// one error the same way userauth.ErrInvalidKey and
	// walletlogin.ErrInvalidSignature collapse their own failure reasons,
	// so a verifier cannot be used as an oracle for which part was wrong.
	ErrInvalidSignature = errors.New("frontendrelease: signature does not verify for the given public key")
)

// ManifestFile is one file's identity within a release's content-addressed
// tree (ADR-037 §2 step 3).
type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest is ADR-037 §2 step 3's signed manifest, published *outside*
// the CID-addressed tree it describes (avoiding the self-referential
// problem of a file needing to name its own hash). Field order here is
// this package's own canonical choice -- encoding/json marshals struct
// fields in declaration order deterministically, which is what makes
// ManifestSHA256 (computed by hashing this same struct with
// ReleaseID/ManifestSHA256/Signature blanked) reproducible across
// re-marshals, not any claim that this exact ordering is mandated by the
// ADR's own prose field list.
type Manifest struct {
	SchemaVersion       int            `json:"schema_version"`
	ReleaseID           string         `json:"release_id"`
	CID                 string         `json:"cid"`
	Files               []ManifestFile `json:"files"`
	ManifestSHA256      string         `json:"manifest_sha256"`
	APIOrigin           string         `json:"api_origin"`
	AllowedLoginOrigins []string       `json:"allowed_login_origins"`
	PreviousCID         string         `json:"previous_cid,omitempty"`
	ReleasedAt          string         `json:"released_at"`
	Signature           string         `json:"signature,omitempty"`
}

// BuildManifest assembles a Manifest from a built, hashed file tree and
// its content-addressed CID, computing ManifestSHA256 and deriving
// ReleaseID from it (ADR-037 §2's example: "<timestamp>-<short-manifest-
// hash>"). files is sorted by Path so ManifestSHA256 does not depend on
// filesystem walk order. The returned Manifest is unsigned -- call Sign
// next.
func BuildManifest(cid string, files []ManifestFile, apiOrigin string, allowedLoginOrigins []string, previousCID string, releasedAt time.Time) (Manifest, error) {
	if cid == "" {
		return Manifest{}, errors.New("frontendrelease: cid must not be empty")
	}
	sorted := append([]ManifestFile(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	m := Manifest{
		SchemaVersion:       SchemaVersion,
		CID:                 cid,
		Files:               sorted,
		APIOrigin:           apiOrigin,
		AllowedLoginOrigins: append([]string(nil), allowedLoginOrigins...),
		PreviousCID:         previousCID,
		ReleasedAt:          releasedAt.UTC().Format(time.RFC3339),
	}
	hash, err := contentHash(m)
	if err != nil {
		return Manifest{}, err
	}
	m.ManifestSHA256 = hash
	shortHash := hash
	if len(shortHash) > 12 {
		shortHash = shortHash[:12]
	}
	m.ReleaseID = m.ReleasedAt + "-" + shortHash
	return m, nil
}

// contentHash computes sha256(canonical JSON of m) with ReleaseID,
// ManifestSHA256, and Signature blanked -- the three fields that either
// derive from this hash (ReleaseID, ManifestSHA256 itself) or are applied
// on top of it after the fact (Signature), and so cannot be part of what
// gets hashed without becoming self-referential (ADR-037 §2 step 3's own
// framing: "avoiding the self-referential problem of a file needing to
// describe its own hash," applied here to the manifest's own hash field).
func contentHash(m Manifest) (string, error) {
	m.ReleaseID = ""
	m.ManifestSHA256 = ""
	m.Signature = ""
	encoded, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("frontendrelease: encode manifest for hashing: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// SigningMessage builds the exact domain-separated byte string ADR-037
// §2 step 4 signs: releaseDomain ‖ manifest_sha256 ‖ cid. Exported so a
// third-party verifier that only has the raw manifest JSON, the public
// key, and this package can reconstruct and check the signature without
// depending on Sign/Verify's own key handling.
func SigningMessage(manifestSHA256Hex, cid string) []byte {
	message := make([]byte, 0, len(releaseDomain)+len(manifestSHA256Hex)+len(cid))
	message = append(message, releaseDomain...)
	message = append(message, manifestSHA256Hex...)
	message = append(message, cid...)
	return message
}

// Sign signs m with priv, setting and returning m.Signature (hex-encoded).
// m.ManifestSHA256 must already be set (via BuildManifest); Sign does not
// recompute or trust any pre-existing m.Signature.
func Sign(priv ed25519.PrivateKey, m Manifest) (Manifest, error) {
	if m.ManifestSHA256 == "" {
		return Manifest{}, errors.New("frontendrelease: manifest_sha256 must be set before signing (call BuildManifest first)")
	}
	m.Signature = ""
	signature := ed25519.Sign(priv, SigningMessage(m.ManifestSHA256, m.CID))
	m.Signature = hex.EncodeToString(signature)
	return m, nil
}

// Verify checks that m's manifest_sha256 truthfully hashes m's other
// fields (ErrManifestTampered otherwise) and that m.Signature is a valid
// Ed25519 signature over SigningMessage(m.ManifestSHA256, m.CID) under
// pub (ErrInvalidSignature otherwise). A nil return means both checks
// passed: this exact manifest, unmodified since it was signed, was
// signed by the holder of priv corresponding to pub.
func Verify(pub ed25519.PublicKey, m Manifest) error {
	expectedHash, err := contentHash(m)
	if err != nil {
		return err
	}
	if expectedHash != m.ManifestSHA256 {
		return ErrManifestTampered
	}
	signature, err := hex.DecodeString(m.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	if !ed25519.Verify(pub, SigningMessage(m.ManifestSHA256, m.CID), signature) {
		return ErrInvalidSignature
	}
	return nil
}

// IsAllowedOrigin reports whether origin (a browser Origin header value,
// e.g. "https://dashboard.example.org") appears verbatim in allowed --
// exact string comparison, no wildcard/subdomain matching, matching
// ADR-037 §4's "allowed_login_origins list -- the canonical DNSLink
// origin and the self-hosted gateway origin, nothing else."
func IsAllowedOrigin(origin string, allowed []string) bool {
	if origin == "" {
		return false
	}
	for _, candidate := range allowed {
		if candidate == origin {
			return true
		}
	}
	return false
}
