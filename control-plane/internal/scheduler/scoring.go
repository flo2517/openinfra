package scheduler

import (
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

type ScoringEngine struct {
	Weights map[sharedv1.WorkloadProfile]ReputationWeights
}

type ReputationWeights struct {
	Compute      float32
	Storage      float32
	Network      float32
	Availability float32
}

func NewScoringEngine() *ScoringEngine {
	return &ScoringEngine{
		Weights: map[sharedv1.WorkloadProfile]ReputationWeights{
			sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE: {Compute: 0.5, Storage: 0.1, Network: 0.1, Availability: 0.3},
			sharedv1.WorkloadProfile_WORKLOAD_PROFILE_MEMORY_INTENSIVE:  {Compute: 0.4, Storage: 0.2, Network: 0.1, Availability: 0.3},
			sharedv1.WorkloadProfile_WORKLOAD_PROFILE_STORAGE_INTENSIVE: {Compute: 0.1, Storage: 0.5, Network: 0.1, Availability: 0.3},
			sharedv1.WorkloadProfile_WORKLOAD_PROFILE_LATENCY_SENSITIVE: {Compute: 0.1, Storage: 0.1, Network: 0.5, Availability: 0.3},
		},
	}
}

// CalculateScore computes the final utility score for a node given a workload
func (se *ScoringEngine) CalculateScore(
	nodeID string,
	profile sharedv1.WorkloadProfile,
	req *sharedv1.ResourceRequirements,
	rep *sharedv1.ReputationVector,
	avail *sharedv1.ResourceCapability,
	price float32,
	avgPrice float32,
) float32 {
	// 1. Performance Score (S_perf)
	sPerf := se.calculatePerformanceScore(req, avail)

	// 2. Reputation Score (S_rep)
	weights := se.Weights[profile]
	sRep := (weights.Compute * rep.Compute) +
		(weights.Storage * rep.Storage) +
		(weights.Network * rep.Network) +
		(weights.Availability * rep.Availability)

	// 3. Cost Score (S_cost) - Normalization: cheaper is better
	sCost := price / avgPrice

	// Final Weighted Formula:
	// Score = (0.3 * Perf) + (0.3 * Rep) + (0.2 * Reliability) - (0.2 * Cost)
	// Note: Reliability is simplified here as a combination of Avail and Global rep
	sRel := (rep.Availability + rep.Global) / 2

	return (0.3 * sPerf) + (0.3 * sRep) + (0.2 * sRel) - (0.2 * sCost)
}

func (se *ScoringEngine) calculatePerformanceScore(req *sharedv1.ResourceRequirements, avail *sharedv1.ResourceCapability) float32 {
	var cpuScore, ramScore, diskScore float32

	if req.Cpu > 0 {
		cpuScore = avail.CpuAvailable / req.Cpu
	}
	if req.RamMb > 0 {
		ramScore = float32(avail.RamAvailableMb) / float32(req.RamMb)
	}
	if req.StorageGb > 0 {
		diskScore = float32(avail.StorageAvailableGb) / float32(req.StorageGb)
	}

	// Clamp values to 1.0 and return average
	return (clamp(cpuScore) + clamp(ramScore) + clamp(diskScore)) / 3
}

func clamp(v float32) float32 {
	if v > 1.0 {
		return 1.0
	}
	if v < 0 {
		return 0
	}
	return v
}
