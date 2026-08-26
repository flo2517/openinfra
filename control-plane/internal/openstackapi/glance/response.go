package glance

import "time"

// imageResponseBody is real Glance v2's image representation, trimmed to
// the fields this registry actually has an opinion about. "status" and
// "protected" are constants (never persisted): this registry has no
// upload step (no "queued"/"saving"/"killed" states -- an image is
// "active" from the instant it is registered, since there are no bytes
// here to transition on) and no protected-image-cannot-delete feature
// (issue #26 asks for real immutability of the digest, not a delete
// lock -- keeping this simple rather than over-building it).
type imageResponseBody struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Owner       string `json:"owner"`
	Visibility  string `json:"visibility"`
	Status      string `json:"status"`
	Protected   bool   `json:"protected"`
	OSHashAlgo  string `json:"os_hash_algo"`
	OSHashValue string `json:"os_hash_value"`
	DirectURL   string `json:"direct_url"`
	Size        *int64 `json:"size"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	Schema      string `json:"schema"`
}

type imagesListBody struct {
	Images []imageResponseBody `json:"images"`
	Schema string              `json:"schema"`
	First  string              `json:"first"`
}

func imageBody(image Image) imageResponseBody {
	return imageResponseBody{
		ID:          image.ImageID,
		Name:        image.Name,
		Owner:       image.ProjectID,
		Visibility:  image.Visibility,
		Status:      "active",
		Protected:   false,
		OSHashAlgo:  "sha256",
		OSHashValue: image.DigestSHA256,
		DirectURL:   image.SourceRef,
		Size:        image.SizeBytes,
		CreatedAt:   image.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:   image.UpdatedAt.UTC().Format(time.RFC3339),
		Schema:      "/v2/schemas/image",
	}
}
