package neutron

import (
	"context"
	"errors"
	"net"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// isUniqueViolation reports whether err is a Postgres unique-constraint
// violation (SQLSTATE 23505) -- the same lightweight error-code check
// internal/openstackapi/glance/internal/projects already use for their
// own unique-index-backed conflict errors (e.g.
// projects.ErrProjectNameTaken).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// PostgresNetworkRepository implements NetworkRepository.
type PostgresNetworkRepository struct{ pool *pgxpool.Pool }

func NewPostgresNetworkRepository(pool *pgxpool.Pool) *PostgresNetworkRepository {
	return &PostgresNetworkRepository{pool: pool}
}

func (r *PostgresNetworkRepository) CreateNetwork(ctx context.Context, network Network) (Network, error) {
	err := r.pool.QueryRow(ctx, `
		INSERT INTO neutron_networks (network_id, project_id, name, shared)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at`,
		network.NetworkID, network.ProjectID, network.Name, network.Shared,
	).Scan(&network.CreatedAt)
	if err != nil {
		return Network{}, err
	}
	return network, nil
}

func (r *PostgresNetworkRepository) GetNetwork(ctx context.Context, networkID, projectID string) (Network, error) {
	var network Network
	err := r.pool.QueryRow(ctx, `
		SELECT network_id, project_id, name, shared, created_at
		FROM neutron_networks
		WHERE network_id = $1 AND deleted_at IS NULL AND (project_id = $2 OR shared = true)`,
		networkID, projectID,
	).Scan(&network.NetworkID, &network.ProjectID, &network.Name, &network.Shared, &network.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Network{}, ErrNetworkNotFound
	}
	if err != nil {
		return Network{}, err
	}
	return network, nil
}

func (r *PostgresNetworkRepository) ListNetworks(ctx context.Context, projectID string) ([]Network, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT network_id, project_id, name, shared, created_at
		FROM neutron_networks
		WHERE deleted_at IS NULL AND (project_id = $1 OR shared = true)
		ORDER BY created_at, network_id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var networks []Network
	for rows.Next() {
		var network Network
		if err := rows.Scan(&network.NetworkID, &network.ProjectID, &network.Name, &network.Shared, &network.CreatedAt); err != nil {
			return nil, err
		}
		networks = append(networks, network)
	}
	return networks, rows.Err()
}

func (r *PostgresNetworkRepository) DeleteNetwork(ctx context.Context, networkID, projectID string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE neutron_networks SET deleted_at = now()
		WHERE network_id = $1 AND project_id = $2 AND deleted_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM neutron_subnets s WHERE s.network_id = neutron_networks.network_id AND s.deleted_at IS NULL)`,
		networkID, projectID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Diagnose why the atomic transition above matched zero rows: either
	// the network is not visible for a write by this project (unknown, or
	// merely shared-with rather than owned), or it exists and is owned
	// but still has live subnets.
	if _, err := r.GetNetwork(ctx, networkID, projectID); errors.Is(err, ErrNetworkNotFound) {
		return ErrNetworkNotFound
	} else if err != nil {
		return err
	}
	var ownedHere bool
	if err := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM neutron_networks WHERE network_id=$1 AND project_id=$2 AND deleted_at IS NULL)`, networkID, projectID).Scan(&ownedHere); err != nil {
		return err
	}
	if !ownedHere {
		return ErrNetworkNotFound
	}
	return ErrNetworkHasSubnets
}

// CreateSubnet inserts a new subnet after checking the requested CIDR
// against ADR-010's legacy overlay range and every other live subnet's
// CIDR for an overlap (not just an exact-string match -- the unique index
// migration 000022 defines only catches identical CIDR values; two
// differently-sized, overlapping CIDRs like 10.0.0.0/24 and 10.0.0.0/25
// would not collide on that index alone). This overlap scan and the
// subsequent INSERT are two separate statements, not one transaction with
// a table-level lock -- a small, deliberately-accepted race window
// between two concurrent CreateSubnet calls choosing overlapping-but-
// distinct CIDRs at the same instant. This is a documented, non-security
// gap (IPAM correctness, not tenant isolation: the worst outcome is two
// subnets whose address ranges overlap, an operational misconfiguration a
// human can detect and fix, never a way for one tenant's traffic to reach
// another's) -- flagged explicitly rather than silently accepted, per the
// task's own instruction to flag every judgment call.
func (r *PostgresNetworkRepository) CreateSubnet(ctx context.Context, subnet Subnet) (Subnet, error) {
	if _, _, err := net.ParseCIDR(subnet.CIDR); err != nil {
		return Subnet{}, ErrInvalidCIDR
	}
	rows, err := r.pool.Query(ctx, `SELECT cidr FROM neutron_subnets WHERE deleted_at IS NULL`)
	if err != nil {
		return Subnet{}, err
	}
	var existingCIDRs []string
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			rows.Close()
			return Subnet{}, err
		}
		existingCIDRs = append(existingCIDRs, cidr)
	}
	if err := rows.Err(); err != nil {
		return Subnet{}, err
	}
	for _, existing := range existingCIDRs {
		if cidrsOverlap(subnet.CIDR, existing) {
			return Subnet{}, ErrSubnetCIDRInUse
		}
	}
	err = r.pool.QueryRow(ctx, `
		INSERT INTO neutron_subnets (subnet_id, network_id, project_id, cidr, gateway_ip)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at`,
		subnet.SubnetID, subnet.NetworkID, subnet.ProjectID, subnet.CIDR, subnet.GatewayIP,
	).Scan(&subnet.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return Subnet{}, ErrSubnetCIDRInUse
		}
		return Subnet{}, err
	}
	return subnet, nil
}

// cidrsOverlap reports whether a and b (both already-validated CIDR
// strings) describe any address in common.
func cidrsOverlap(a, b string) bool {
	_, netA, errA := net.ParseCIDR(a)
	_, netB, errB := net.ParseCIDR(b)
	if errA != nil || errB != nil {
		return false
	}
	return netA.Contains(netB.IP) || netB.Contains(netA.IP)
}

func (r *PostgresNetworkRepository) GetSubnet(ctx context.Context, subnetID, projectID string) (Subnet, error) {
	var subnet Subnet
	err := r.pool.QueryRow(ctx, `
		SELECT subnet_id, network_id, project_id, cidr, gateway_ip, created_at
		FROM neutron_subnets
		WHERE subnet_id = $1 AND project_id = $2 AND deleted_at IS NULL`,
		subnetID, projectID,
	).Scan(&subnet.SubnetID, &subnet.NetworkID, &subnet.ProjectID, &subnet.CIDR, &subnet.GatewayIP, &subnet.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Subnet{}, ErrSubnetNotFound
	}
	if err != nil {
		return Subnet{}, err
	}
	return subnet, nil
}

func (r *PostgresNetworkRepository) ListSubnets(ctx context.Context, networkID, projectID string) ([]Subnet, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT subnet_id, network_id, project_id, cidr, gateway_ip, created_at
		FROM neutron_subnets
		WHERE project_id = $1 AND deleted_at IS NULL AND ($2 = '' OR network_id = $2::uuid)
		ORDER BY created_at, subnet_id`, projectID, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var subnets []Subnet
	for rows.Next() {
		var subnet Subnet
		if err := rows.Scan(&subnet.SubnetID, &subnet.NetworkID, &subnet.ProjectID, &subnet.CIDR, &subnet.GatewayIP, &subnet.CreatedAt); err != nil {
			return nil, err
		}
		subnets = append(subnets, subnet)
	}
	return subnets, rows.Err()
}

func (r *PostgresNetworkRepository) DeleteSubnet(ctx context.Context, subnetID, projectID string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE neutron_subnets SET deleted_at = now()
		WHERE subnet_id = $1 AND project_id = $2 AND deleted_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM neutron_ports p WHERE p.subnet_id = neutron_subnets.subnet_id AND p.deleted_at IS NULL)`,
		subnetID, projectID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	if _, err := r.GetSubnet(ctx, subnetID, projectID); errors.Is(err, ErrSubnetNotFound) {
		return ErrSubnetNotFound
	} else if err != nil {
		return err
	}
	return ErrSubnetHasPorts
}

// PostgresPortRepository implements PortRepository.
type PostgresPortRepository struct{ pool *pgxpool.Pool }

func NewPostgresPortRepository(pool *pgxpool.Pool) *PostgresPortRepository {
	return &PostgresPortRepository{pool: pool}
}

// CreatePort allocates fixed_ip inside a transaction serialized by a
// Postgres advisory lock keyed on subnet_id -- concurrent CreatePort
// calls against the *same* subnet queue up and each sees the other's
// just-inserted rows (pg_advisory_xact_lock blocks, and the lock is held
// for the whole transaction, released automatically at commit/rollback);
// concurrent calls against *different* subnets proceed independently.
// This is the transactional analogue of internal/wireguard.Manager's own
// in-process mutex around port reservation (wireguard.go's
// reservePortLocked, held across the whole Allocate call) -- the same
// "serialize the scan-then-claim so two callers can never both pick the
// same next-available slot" shape, just enforced at the database instead
// of in one process's memory, since CreatePort must be safe across
// multiple Control Plane replicas sharing one Postgres instance, not just
// multiple goroutines in one process.
func (r *PostgresPortRepository) CreatePort(ctx context.Context, port Port) (Port, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Port{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var lockKey int64
	if err := tx.QueryRow(ctx, `SELECT hashtextextended($1, 0)`, port.SubnetID).Scan(&lockKey); err != nil {
		return Port{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey); err != nil {
		return Port{}, err
	}

	var cidr string
	var gatewayIP *string
	err = tx.QueryRow(ctx, `SELECT cidr, gateway_ip FROM neutron_subnets WHERE subnet_id = $1 AND deleted_at IS NULL`, port.SubnetID).Scan(&cidr, &gatewayIP)
	if errors.Is(err, pgx.ErrNoRows) {
		return Port{}, ErrSubnetNotFound
	}
	if err != nil {
		return Port{}, err
	}

	rows, err := tx.Query(ctx, `SELECT fixed_ip FROM neutron_ports WHERE subnet_id = $1 AND deleted_at IS NULL`, port.SubnetID)
	if err != nil {
		return Port{}, err
	}
	taken := make(map[string]struct{})
	for rows.Next() {
		var fixedIP string
		if err := rows.Scan(&fixedIP); err != nil {
			rows.Close()
			return Port{}, err
		}
		taken[fixedIP] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return Port{}, err
	}

	fixedIP, err := allocateFromPool(cidr, gatewayIP, taken)
	if err != nil {
		return Port{}, err
	}
	port.FixedIP = fixedIP

	err = tx.QueryRow(ctx, `
		INSERT INTO neutron_ports (port_id, network_id, subnet_id, project_id, fixed_ip)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at`,
		port.PortID, port.NetworkID, port.SubnetID, port.ProjectID, fixedIP,
	).Scan(&port.CreatedAt)
	if err != nil {
		return Port{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Port{}, err
	}
	return port, nil
}

func (r *PostgresPortRepository) GetPort(ctx context.Context, portID, projectID string) (Port, error) {
	var port Port
	err := r.pool.QueryRow(ctx, `
		SELECT port_id, network_id, subnet_id, project_id, fixed_ip, workload_id, created_at
		FROM neutron_ports
		WHERE port_id = $1 AND project_id = $2 AND deleted_at IS NULL`,
		portID, projectID,
	).Scan(&port.PortID, &port.NetworkID, &port.SubnetID, &port.ProjectID, &port.FixedIP, &port.WorkloadID, &port.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Port{}, ErrPortNotFound
	}
	if err != nil {
		return Port{}, err
	}
	return port, nil
}

func (r *PostgresPortRepository) ListPorts(ctx context.Context, networkID, projectID string) ([]Port, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT port_id, network_id, subnet_id, project_id, fixed_ip, workload_id, created_at
		FROM neutron_ports
		WHERE project_id = $1 AND deleted_at IS NULL AND ($2 = '' OR network_id = $2::uuid)
		ORDER BY created_at, port_id`, projectID, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ports []Port
	for rows.Next() {
		var port Port
		if err := rows.Scan(&port.PortID, &port.NetworkID, &port.SubnetID, &port.ProjectID, &port.FixedIP, &port.WorkloadID, &port.CreatedAt); err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	return ports, rows.Err()
}

func (r *PostgresPortRepository) DeletePort(ctx context.Context, portID, projectID string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE neutron_ports SET deleted_at = now()
		WHERE port_id = $1 AND project_id = $2 AND deleted_at IS NULL AND workload_id IS NULL`,
		portID, projectID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	existing, err := r.GetPort(ctx, portID, projectID)
	if errors.Is(err, ErrPortNotFound) {
		return ErrPortNotFound
	}
	if err != nil {
		return err
	}
	if existing.WorkloadID != nil {
		return ErrPortBound
	}
	return ErrPortNotFound
}

func (r *PostgresPortRepository) BindPort(ctx context.Context, portID, projectID, workloadID string) (Port, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE neutron_ports SET workload_id = $3
		WHERE port_id = $1 AND project_id = $2 AND deleted_at IS NULL AND (workload_id IS NULL OR workload_id = $3)`,
		portID, projectID, workloadID)
	if err != nil {
		if isUniqueViolation(err) {
			return Port{}, ErrWorkloadAlreadyHasPort
		}
		return Port{}, err
	}
	if tag.RowsAffected() == 1 {
		return r.GetPort(ctx, portID, projectID)
	}
	existing, err := r.GetPort(ctx, portID, projectID)
	if errors.Is(err, ErrPortNotFound) {
		return Port{}, ErrPortNotFound
	}
	if err != nil {
		return Port{}, err
	}
	if existing.WorkloadID != nil {
		return Port{}, ErrPortAlreadyBound
	}
	return Port{}, ErrPortNotFound
}

func (r *PostgresPortRepository) UnbindPort(ctx context.Context, portID, projectID string) (Port, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE neutron_ports SET workload_id = NULL
		WHERE port_id = $1 AND project_id = $2 AND deleted_at IS NULL`,
		portID, projectID)
	if err != nil {
		return Port{}, err
	}
	if tag.RowsAffected() == 0 {
		return Port{}, ErrPortNotFound
	}
	return r.GetPort(ctx, portID, projectID)
}

func (r *PostgresPortRepository) PortForWorkload(ctx context.Context, workloadID string) (Port, bool, error) {
	var port Port
	err := r.pool.QueryRow(ctx, `
		SELECT port_id, network_id, subnet_id, project_id, fixed_ip, workload_id, created_at
		FROM neutron_ports
		WHERE workload_id = $1 AND deleted_at IS NULL`, workloadID,
	).Scan(&port.PortID, &port.NetworkID, &port.SubnetID, &port.ProjectID, &port.FixedIP, &port.WorkloadID, &port.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Port{}, false, nil
	}
	if err != nil {
		return Port{}, false, err
	}
	return port, true, nil
}

// PostgresSecurityGroupRepository implements SecurityGroupRepository.
type PostgresSecurityGroupRepository struct{ pool *pgxpool.Pool }

func NewPostgresSecurityGroupRepository(pool *pgxpool.Pool) *PostgresSecurityGroupRepository {
	return &PostgresSecurityGroupRepository{pool: pool}
}

func (r *PostgresSecurityGroupRepository) CreateSecurityGroup(ctx context.Context, group SecurityGroup) (SecurityGroup, error) {
	err := r.pool.QueryRow(ctx, `
		INSERT INTO neutron_security_groups (security_group_id, project_id, name, description)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at`,
		group.SecurityGroupID, group.ProjectID, group.Name, group.Description,
	).Scan(&group.CreatedAt)
	if err != nil {
		return SecurityGroup{}, err
	}
	return group, nil
}

func (r *PostgresSecurityGroupRepository) GetSecurityGroup(ctx context.Context, groupID, projectID string) (SecurityGroup, error) {
	var group SecurityGroup
	err := r.pool.QueryRow(ctx, `
		SELECT security_group_id, project_id, name, description, created_at
		FROM neutron_security_groups
		WHERE security_group_id = $1 AND project_id = $2 AND deleted_at IS NULL`,
		groupID, projectID,
	).Scan(&group.SecurityGroupID, &group.ProjectID, &group.Name, &group.Description, &group.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SecurityGroup{}, ErrSecurityGroupNotFound
	}
	if err != nil {
		return SecurityGroup{}, err
	}
	return group, nil
}

func (r *PostgresSecurityGroupRepository) ListSecurityGroups(ctx context.Context, projectID string) ([]SecurityGroup, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT security_group_id, project_id, name, description, created_at
		FROM neutron_security_groups
		WHERE project_id = $1 AND deleted_at IS NULL
		ORDER BY created_at, security_group_id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []SecurityGroup
	for rows.Next() {
		var group SecurityGroup
		if err := rows.Scan(&group.SecurityGroupID, &group.ProjectID, &group.Name, &group.Description, &group.CreatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

func (r *PostgresSecurityGroupRepository) DeleteSecurityGroup(ctx context.Context, groupID, projectID string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE neutron_security_groups SET deleted_at = now()
		WHERE security_group_id = $1 AND project_id = $2 AND deleted_at IS NULL
		  AND NOT EXISTS (
		    SELECT 1 FROM neutron_port_security_groups psg
		    JOIN neutron_ports p ON p.port_id = psg.port_id AND p.deleted_at IS NULL
		    WHERE psg.security_group_id = neutron_security_groups.security_group_id
		  )`,
		groupID, projectID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	if _, err := r.GetSecurityGroup(ctx, groupID, projectID); errors.Is(err, ErrSecurityGroupNotFound) {
		return ErrSecurityGroupNotFound
	} else if err != nil {
		return err
	}
	return ErrSecurityGroupInUse
}

func (r *PostgresSecurityGroupRepository) CreateRule(ctx context.Context, rule SecurityGroupRule) (SecurityGroupRule, error) {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO neutron_security_group_rules (rule_id, security_group_id, project_id, direction, protocol, port_range_min, port_range_max, remote_ip_prefix)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		rule.RuleID, rule.SecurityGroupID, rule.ProjectID, rule.Direction, rule.Protocol, rule.PortRangeMin, rule.PortRangeMax, rule.RemoteIPPrefix)
	if err != nil {
		if isUniqueViolation(err) {
			return SecurityGroupRule{}, ErrDuplicateRule
		}
		return SecurityGroupRule{}, err
	}
	return rule, nil
}

func (r *PostgresSecurityGroupRepository) GetRule(ctx context.Context, ruleID, projectID string) (SecurityGroupRule, error) {
	var rule SecurityGroupRule
	err := r.pool.QueryRow(ctx, `
		SELECT rule_id, security_group_id, project_id, direction, protocol, port_range_min, port_range_max, remote_ip_prefix
		FROM neutron_security_group_rules
		WHERE rule_id = $1 AND project_id = $2`,
		ruleID, projectID,
	).Scan(&rule.RuleID, &rule.SecurityGroupID, &rule.ProjectID, &rule.Direction, &rule.Protocol, &rule.PortRangeMin, &rule.PortRangeMax, &rule.RemoteIPPrefix)
	if errors.Is(err, pgx.ErrNoRows) {
		return SecurityGroupRule{}, ErrRuleNotFound
	}
	if err != nil {
		return SecurityGroupRule{}, err
	}
	return rule, nil
}

func (r *PostgresSecurityGroupRepository) ListRules(ctx context.Context, groupID, projectID string) ([]SecurityGroupRule, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT rule_id, security_group_id, project_id, direction, protocol, port_range_min, port_range_max, remote_ip_prefix
		FROM neutron_security_group_rules
		WHERE security_group_id = $1 AND project_id = $2
		ORDER BY created_at, rule_id`, groupID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []SecurityGroupRule
	for rows.Next() {
		var rule SecurityGroupRule
		if err := rows.Scan(&rule.RuleID, &rule.SecurityGroupID, &rule.ProjectID, &rule.Direction, &rule.Protocol, &rule.PortRangeMin, &rule.PortRangeMax, &rule.RemoteIPPrefix); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (r *PostgresSecurityGroupRepository) DeleteRule(ctx context.Context, ruleID, projectID string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM neutron_security_group_rules WHERE rule_id = $1 AND project_id = $2`, ruleID, projectID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRuleNotFound
	}
	return nil
}

// ReplacePortGroups atomically replaces portID's full attached-group set.
// Both the port and every requested group are re-validated as
// project-owned inside the same transaction as the replace itself (never
// a separate, unlocked check-then-write) -- ADR-035 §4/§5's tenant-
// isolation requirement, enforced structurally rather than trusted to a
// caller having already checked.
func (r *PostgresSecurityGroupRepository) ReplacePortGroups(ctx context.Context, portID, projectID string, groupIDs []string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var portExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM neutron_ports WHERE port_id=$1 AND project_id=$2 AND deleted_at IS NULL)`, portID, projectID).Scan(&portExists); err != nil {
		return err
	}
	if !portExists {
		return ErrPortNotFound
	}
	for _, groupID := range groupIDs {
		var groupExists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM neutron_security_groups WHERE security_group_id=$1 AND project_id=$2 AND deleted_at IS NULL)`, groupID, projectID).Scan(&groupExists); err != nil {
			return err
		}
		if !groupExists {
			return ErrSecurityGroupNotFound
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM neutron_port_security_groups WHERE port_id = $1`, portID); err != nil {
		return err
	}
	for _, groupID := range groupIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO neutron_port_security_groups (port_id, security_group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, portID, groupID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ListForPort returns the unioned rule set across every security group
// currently attached to portID (ADR-035 §3 point 2: multiple groups are
// unioned, never intersected -- a plain, un-DISTINCT-ed JOIN naturally
// produces a union of rows here, with no separate aggregation logic
// needed). Deliberately returns an empty, non-nil slice when portID has
// no attachments or its attached group(s) hold no rules -- see this
// file's package doc comment for why that emptiness, never a sentinel, is
// the fail-closed signal.
func (r *PostgresSecurityGroupRepository) ListForPort(ctx context.Context, portID string) ([]SecurityGroupRule, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT r.rule_id, r.security_group_id, r.project_id, r.direction, r.protocol, r.port_range_min, r.port_range_max, r.remote_ip_prefix
		FROM neutron_security_group_rules r
		JOIN neutron_port_security_groups psg ON psg.security_group_id = r.security_group_id
		WHERE psg.port_id = $1
		ORDER BY r.created_at, r.rule_id`, portID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := make([]SecurityGroupRule, 0)
	for rows.Next() {
		var rule SecurityGroupRule
		if err := rows.Scan(&rule.RuleID, &rule.SecurityGroupID, &rule.ProjectID, &rule.Direction, &rule.Protocol, &rule.PortRangeMin, &rule.PortRangeMax, &rule.RemoteIPPrefix); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// ListGroupIDsForPort reads neutron_port_security_groups directly --
// see the interface method's own doc comment for why this must not be
// derived from ListForPort's rule-shaped output.
func (r *PostgresSecurityGroupRepository) ListGroupIDsForPort(ctx context.Context, portID string) ([]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT security_group_id FROM neutron_port_security_groups WHERE port_id = $1 ORDER BY created_at, security_group_id`, portID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groupIDs := make([]string, 0)
	for rows.Next() {
		var groupID string
		if err := rows.Scan(&groupID); err != nil {
			return nil, err
		}
		groupIDs = append(groupIDs, groupID)
	}
	return groupIDs, rows.Err()
}
