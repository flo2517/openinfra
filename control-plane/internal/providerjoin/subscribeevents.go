package providerjoin

import (
	"encoding/hex"

	"github.com/openinfra/network/internal/eventlog"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// eventExportLimit bounds a single SubscribeEvents call to at most this
// many events -- the same cap eventlog.PostgresRepository.ExportSubject
// already defaults to when given a non-positive/oversized limit. A
// witness whose subject has more unseen history than this simply
// reconnects with since_sequence set to the last sequence it received
// (ADR-039 Tests required, "Partition"/"Catch-up") -- this RPC does not
// itself paginate within one call.
const eventExportLimit = 10000

// SubscribeEvents implements ADR-039 §10's witness export surface. See
// EventExporter's doc comment (service.go) for the fail-loud behavior
// when no exporter is configured.
func (s *Service) SubscribeEvents(request *controlplanev1.SubscribeEventsRequest, stream controlplanev1.ControlPlaneService_SubscribeEventsServer) error {
	if s.eventExporter == nil {
		return status.Error(codes.Unavailable, "event log export is unavailable")
	}
	if request.GetSubjectType() == "" || len(request.GetSubjectId()) == 0 {
		return status.Error(codes.InvalidArgument, "subject_type and subject_id are required")
	}
	entries, err := s.eventExporter.ExportSubject(stream.Context(), eventlog.SubjectType(request.GetSubjectType()), request.GetSubjectId(), request.GetSinceSequence(), eventExportLimit)
	if err != nil {
		return status.Errorf(codes.Internal, "export events: %v", err)
	}
	for _, entry := range entries {
		if err := stream.Send(&controlplanev1.SubscribeEventsResponse{Event: entryToEnvelope(entry)}); err != nil {
			return err
		}
	}
	return nil
}

// entryToEnvelope converts an internal/eventlog.Entry (this Control
// Plane's canonical, signed representation) into the wire-shaped
// EventEnvelope ADR-039 §10 evolves shared.proto's already-reserved
// message into. event_id is hex-encoded into the pre-existing string
// `event_id` field (field 1) -- the same "raw bytes as lowercase hex in a
// string field" convention agent-core's own get_public_key already uses,
// so this stays consistent with every other hex-encoded identity/hash
// this codebase already puts on the wire as a string rather than raw
// bytes.
func entryToEnvelope(entry eventlog.Entry) *sharedv1.EventEnvelope {
	envelope := &sharedv1.EventEnvelope{
		EventId:         hex.EncodeToString(entry.EventID[:]),
		EventType:       entry.EventType,
		Timestamp:       timestamppb.New(entry.RecordedAt),
		Payload:         entry.Payload,
		SubjectType:     string(entry.SubjectType),
		SubjectId:       entry.SubjectID,
		Sequence:        entry.Sequence,
		PrevEventHash:   entry.PrevEventHash[:],
		PayloadHash:     entry.PayloadHash[:],
		SignerPublicKey: entry.SignerPublicKey[:],
		SignatureBytes:  entry.Signature[:],
	}
	if entry.ChainAnchor != nil {
		envelope.ChainAnchor = &sharedv1.ChainAnchor{
			LeaseId:   entry.ChainAnchor.LeaseID,
			BlockHash: entry.ChainAnchor.BlockHash[:],
		}
	}
	return envelope
}
