package cinder

import (
	"encoding/json"
	"net/http"
	"time"
)

// attachmentBody is real Cinder v3's attachment representation, nested
// inside a volume body's "attachments" list. This slice's single-
// attachment invariant (ADR-034 §2/§8) means the list is always empty or
// has exactly one element, unlike real Cinder's own multi-attach volumes.
type attachmentBody struct {
	ID         string `json:"id"`
	VolumeID   string `json:"volume_id"`
	ServerID   string `json:"server_id"`
	Device     string `json:"device"`
	AttachedAt string `json:"attached_at"`
}

// volumeResponseBody is real Cinder v3's volume representation, trimmed
// to the fields this slice actually has an opinion about -- the same
// "wire-shaped but honest about what's actually implemented" posture
// internal/openstackapi/glance.imageResponseBody's doc comment
// describes for its own trimming.
type volumeResponseBody struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Size        int64            `json:"size"`
	Status      string           `json:"status"`
	Bootable    string           `json:"bootable"`
	Encrypted   bool             `json:"encrypted"`
	Multiattach bool             `json:"multiattach"`
	Attachments []attachmentBody `json:"attachments"`
	CreatedAt   string           `json:"created_at"`
}

func volumeBody(volume Volume) volumeResponseBody {
	attachments := make([]attachmentBody, 0, 1)
	if volume.AttachedWorkloadID != nil {
		device := ""
		if volume.MountPath != nil {
			device = *volume.MountPath
		}
		attachments = append(attachments, attachmentBody{
			ID:         volume.VolumeID,
			VolumeID:   volume.VolumeID,
			ServerID:   *volume.AttachedWorkloadID,
			Device:     device,
			AttachedAt: volume.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	return volumeResponseBody{
		ID:   volume.VolumeID,
		Name: volume.Name,
		Size: volume.SizeGB,
		// cinderStatus below is real Cinder's own vocabulary
		// ("available"/"in-use"/"deleting"/"error"), which happens to be
		// identical to this table's own state column values -- kept as an
		// explicit mapping function (not a bare pass-through) so the two
		// are free to diverge later without a silent behavior change.
		Status:      cinderStatus(volume.State),
		Bootable:    "false",
		Encrypted:   volume.Encrypted,
		Multiattach: false,
		Attachments: attachments,
		CreatedAt:   volume.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func cinderStatus(state string) string {
	switch state {
	case StateAvailable:
		return "available"
	case StateInUse:
		return "in-use"
	case StateDeleting:
		return "deleting"
	default:
		return "error"
	}
}

// cinderFault is real Cinder's own error-body shape --
// {"<faultName>": {"code": ..., "message": ...}} -- identical to
// internal/openstackapi/nova's own novaFault, reproduced locally for the
// same no-import-cycle reason as requireProjectScope.
type cinderFault struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeCinderError(w http.ResponseWriter, status int, faultName, message string) {
	writeJSON(w, status, map[string]cinderFault{faultName: {Code: status, Message: message}})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
