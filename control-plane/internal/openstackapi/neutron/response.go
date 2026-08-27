package neutron

import (
	"encoding/json"
	"net/http"
	"time"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// qosPolicyBody is real Neutron's qos_policy resource shape (a curated
// subset -- ADR-031 §1's "genuine but partial" compatibility posture).
// id is the workload_id itself: there is no separate policy object
// anywhere in this system (see the package doc comment), and workload_id
// is already UUID-shaped (ADR-031 §context confirms this is the one
// internal id that already is), so no id-mapping problem exists here the
// way it does for provider_id/lease_id elsewhere in this codebase.
type qosPolicyBody struct {
	ID          string                   `json:"id"`
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	ProjectID   string                   `json:"project_id"`
	TenantID    string                   `json:"tenant_id"`
	Shared      bool                     `json:"shared"`
	IsDefault   bool                     `json:"is_default"`
	Rules       []bandwidthLimitRuleBody `json:"rules"`
}

type qosPoliciesBody struct {
	Policies []qosPolicyBody `json:"policies"`
}

type qosPolicyEnvelopeBody struct {
	Policy qosPolicyBody `json:"policy"`
}

// bandwidthLimitRuleBody is real Neutron's qos_bandwidth_limit_rule
// resource shape. XOpeninfraEnforced is a clearly-namespaced, additive
// extension field (real OpenStack clients ignore unrecognized JSON
// fields, per ADR-031 §1) stating plainly whether tc actually programs a
// kernel-enforced ceiling for this direction today: true only for
// egress (agent-executor's rate_limit.rs, ADR-025 §3 -- "targets egress
// only by default... noted as a known asymmetry, not solved here"),
// false for ingress, which is a real, committed reservation in the
// capacity ledger but not yet kernel-enforced on the host side. Stating
// this directly in the response, rather than only in a code comment, is
// the same "never silently claim more than is true" discipline ADR-031
// §4 applies to Nova's approximated container "reboot."
type bandwidthLimitRuleBody struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	MaxKbps            int64  `json:"max_kbps"`
	MaxBurstKbps       int64  `json:"max_burst_kbps"`
	Direction          string `json:"direction"`
	XOpeninfraEnforced bool   `json:"x_openinfra_enforced"`
}

type bandwidthLimitRulesBody struct {
	BandwidthLimitRules []bandwidthLimitRuleBody `json:"bandwidth_limit_rules"`
}

type bandwidthLimitRuleEnvelopeBody struct {
	BandwidthLimitRule bandwidthLimitRuleBody `json:"bandwidth_limit_rule"`
}

func qosPolicyBodyFrom(reservation BandwidthReservation) qosPolicyBody {
	return qosPolicyBody{
		ID:          reservation.WorkloadID,
		Name:        "workload:" + reservation.WorkloadID,
		Description: "bandwidth reservation for workload " + reservation.WorkloadID,
		ProjectID:   reservation.ProjectID,
		TenantID:    reservation.ProjectID,
		Shared:      false,
		IsDefault:   false,
		Rules:       bandwidthLimitRuleBodiesFrom(reservation),
	}
}

func bandwidthLimitRuleBodiesFrom(reservation BandwidthReservation) []bandwidthLimitRuleBody {
	var rules []bandwidthLimitRuleBody
	if reservation.ReservedEgressMbps > 0 {
		rules = append(rules, bandwidthLimitRuleBody{
			ID:                 bandwidthRuleID(reservation.WorkloadID, "egress"),
			Type:               "bandwidth_limit",
			MaxKbps:            reservation.ReservedEgressMbps * 1000,
			MaxBurstKbps:       tcBurstKbps,
			Direction:          "egress",
			XOpeninfraEnforced: true,
		})
	}
	if reservation.ReservedIngressMbps > 0 {
		rules = append(rules, bandwidthLimitRuleBody{
			ID:                 bandwidthRuleID(reservation.WorkloadID, "ingress"),
			Type:               "bandwidth_limit",
			MaxKbps:            reservation.ReservedIngressMbps * 1000,
			MaxBurstKbps:       0,
			Direction:          "ingress",
			XOpeninfraEnforced: false,
		})
	}
	return rules
}

// availabilityZoneBody is real Neutron's availability_zone resource
// shape -- see availability_zone.go's handler doc comment for how "zone"
// maps here.
type availabilityZoneBody struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Resource string `json:"resource"`
}

type availabilityZonesBody struct {
	AvailabilityZones []availabilityZoneBody `json:"availability_zones"`
}

// bandwidthUsageRecordBody is this package's own extension resource
// shape (see usage.go's handler doc comment) -- not a literal Neutron
// resource, since real Neutron has none for this data.
type bandwidthUsageRecordBody struct {
	WorkloadID        string `json:"workload_id"`
	ProviderID        string `json:"provider_id"`
	IngressBytesTotal int64  `json:"ingress_bytes_total"`
	EgressBytesTotal  int64  `json:"egress_bytes_total"`
	WindowStartedAt   string `json:"window_started_at"`
	LastReportedAt    string `json:"last_reported_at"`
}

type bandwidthUsageRecordsBody struct {
	BandwidthUsageRecords []bandwidthUsageRecordBody `json:"bandwidth_usage_records"`
}

type bandwidthUsageRecordEnvelopeBody struct {
	BandwidthUsageRecord bandwidthUsageRecordBody `json:"bandwidth_usage_record"`
}

func bandwidthUsageRecordBodyFrom(usage BandwidthUsage) bandwidthUsageRecordBody {
	return bandwidthUsageRecordBody{
		WorkloadID:        usage.WorkloadID,
		ProviderID:        usage.ProviderID,
		IngressBytesTotal: usage.IngressBytesTotal,
		EgressBytesTotal:  usage.EgressBytesTotal,
		WindowStartedAt:   usage.WindowStartedAt.UTC().Format(time.RFC3339),
		LastReportedAt:    usage.LastReportedAt.UTC().Format(time.RFC3339),
	}
}
