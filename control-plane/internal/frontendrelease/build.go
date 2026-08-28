package frontendrelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// CIDComputer computes a directory tree's content ID. KuboCIDComputer is
// the real implementation (shells out to `ipfs add`); tests use a fake.
type CIDComputer interface {
	ComputeCID(ctx context.Context, dir string) (string, error)
}

// KuboCIDComputer shells out to a real `kubo` (IPFS) binary. ADR-037 §2
// step 2 fixes the exact flags below as load-bearing for reproducibility:
// --cid-version=1 and --raw-leaves are not kubo's legacy defaults, and a
// build using different flags produces a different CID for byte-identical
// input. This type never fabricates a CID: a missing/failing `ipfs`
// binary is a hard error, not a silently-fake success (AGENTS.md: no
// placeholder success paths).
type KuboCIDComputer struct {
	// IPFSBinary is the executable to invoke; defaults to "ipfs" (kubo's
	// own CLI binary name) when empty.
	IPFSBinary string
}

func (k KuboCIDComputer) ComputeCID(ctx context.Context, dir string) (string, error) {
	binary := k.IPFSBinary
	if binary == "" {
		binary = "ipfs"
	}
	cmd := exec.CommandContext(ctx, binary, "add", "-Q", "-r", "--cid-version=1", "--raw-leaves", dir)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("frontendrelease: ipfs add (is a kubo node/binary available? ADR-037 §1/§8): %w", err)
	}
	cid := strings.TrimSpace(string(output))
	if cid == "" {
		return "", fmt.Errorf("frontendrelease: ipfs add produced no CID")
	}
	return cid, nil
}

// secretPatterns is ADR-037 §6's "fixed-pattern scan ... over the built
// tree before signing, and refuses to sign and publish on any match" --
// a fail-closed backstop, not evidence a leak is expected. Deliberately
// conservative (a handful of well-known, low-false-positive shapes)
// rather than a general-purpose secret scanner: this package's job is one
// last mechanical check on a tree that structurally should never contain
// any of these (ADR-037 §6's own reasoning), not a replacement for not
// putting secrets there in the first place.
var secretPatterns = []*regexp.Regexp{
	// internal/userauth.keyPrefix ("oiu_") followed by the 64 hex
	// characters GenerateAPIKey's 32-byte secret hex-encodes to.
	regexp.MustCompile(`oiu_[0-9a-fA-F]{64}`),
	// PEM-encoded private key headers, any variant.
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	// AWS access key ID shape.
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	// Slack token shape.
	regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`),
	// Generic "…api_key/secret/token/password": "…" JSON/YAML shape with a
	// non-trivial value, catching accidental config leakage that doesn't
	// match a specific vendor's format.
	regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token)"?\s*[:=]\s*"[^"\s]{12,}"`),
}

// ScanForSecrets walks root and returns one description per match found
// (path + which pattern matched, never the matched text itself, so the
// scan's own output cannot itself leak the secret it found). A non-empty
// result means BuildRelease must refuse to sign and publish.
func ScanForSecrets(root string) ([]string, error) {
	var findings []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("frontendrelease: read %s for secret scan: %w", path, err)
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			relative = path
		}
		for index, pattern := range secretPatterns {
			if pattern.Match(data) {
				findings = append(findings, fmt.Sprintf("%s: matched secret-scan pattern #%d", relative, index))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}

// ErrSecretsFound is returned by BuildRelease when ScanForSecrets finds
// anything -- the fail-closed refusal ADR-037 §6 describes.
type ErrSecretsFound struct{ Findings []string }

func (e *ErrSecretsFound) Error() string {
	return fmt.Sprintf("frontendrelease: refusing to sign/publish: %d secret-scan match(es) found in the built tree", len(e.Findings))
}

// HashTree computes every regular file's sha256/size under root, with
// Path relative to root using forward slashes (so the manifest is
// filesystem/OS-independent). Exported for callers that already have a
// CID computed out of band (e.g. a remote pinning service, or a kubo
// daemon this process cannot shell out to directly) and only need this
// package's hashing/manifest-building, not BuildRelease's own CID
// computation step -- the cmd/frontendrelease `manifest` subcommand is
// exactly this case.
func HashTree(root string) ([]ManifestFile, error) {
	return hashTree(root)
}

func hashTree(root string) ([]ManifestFile, error) {
	var files []ManifestFile
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		hasher := sha256.New()
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err := io.Copy(hasher, file); err != nil {
			return err
		}
		files = append(files, ManifestFile{
			Path:   filepath.ToSlash(relative),
			SHA256: hex.EncodeToString(hasher.Sum(nil)),
			Size:   info.Size(),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

// copyTree copies every regular file from src into dst, preserving the
// relative directory structure, creating dst if needed.
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, relErr := filepath.Rel(src, path)
		if relErr != nil {
			return relErr
		}
		target := filepath.Join(dst, relative)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

// connectSrcPattern matches index.html's CSP <meta> tag's connect-src
// directive so BuildRelease can widen it from the checked-in dev default
// ("connect-src 'self'") to also allow the real canonical API origin
// (ADR-037 §5: "connect-src 'self' becomes connect-src https://<canonical-
// api-origin> explicitly"). 'self' is deliberately kept alongside the
// explicit origin, not replaced outright: config.json itself is always
// fetched same-origin (relative to wherever index.html is served from,
// gateway or canonical alike), so connect-src must still permit 'self'
// for that synchronous XHR to succeed, on top of the explicit api_origin
// permission the ADR's own text asks for.
var connectSrcPattern = regexp.MustCompile(`connect-src 'self'`)

// rewriteCSPForAPIOrigin rewrites index.html's CSP meta tag in place
// under dir to explicitly allow apiOrigin, per ADR-037 §5. A no-op when
// apiOrigin is empty (the direct-serve/same-origin case, where 'self'
// alone is already correct and no rewrite is needed) or index.html is
// absent.
func rewriteCSPForAPIOrigin(dir, apiOrigin string) error {
	if apiOrigin == "" {
		return nil
	}
	path := filepath.Join(dir, "index.html")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	rewritten := connectSrcPattern.ReplaceAll(data, []byte("connect-src 'self' "+apiOrigin))
	return os.WriteFile(path, rewritten, 0o644)
}
