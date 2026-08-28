-- ADR-035 / issue #170 (hard half of issue #25): Neutron-compatible
-- networks, subnets, ports, security groups, and security-group rules.
-- The QoS/AZ "easy half" (ADR-031 §5) shipped separately (PR #180) with no
-- new schema of its own -- this migration is the first schema this
-- package's Neutron surface owns.
--
-- Every table here is project_id-scoped (ADR-035 §4), the identical
-- ownership-via-query pattern ADR-016/ADR-031 §3/ADR-034 §4 already
-- established: every list/get/attach query filters by project_id in the
-- query itself, never a separate fetch-then-compare authorization branch.
--
-- Soft-delete (`deleted_at`), matching glance_images/cinder_volumes'
-- established precedent rather than a hard `DELETE FROM` -- a deleted
-- network/subnet/port/security-group stays available for audit, and every
-- uniqueness/lookup index below is scoped `WHERE deleted_at IS NULL` so a
-- deleted row's identifiers (a subnet's CIDR, a port's fixed_ip) can be
-- reused by a later create.

-- A Neutron "network" does not map 1:1 onto anything that existed before
-- this ADR (ADR-035 §1) -- a new grouping concept, invented here for the
-- first time. `shared` is real Neutron's own field: a shared network's
-- ports may be created by other projects, but its subnets/security-groups
-- remain owned and mutable only by the creating project (ADR-035 §4,
-- "read-attach, not co-write") -- enforced in Go, not expressible as a
-- CHECK constraint here.
CREATE TABLE IF NOT EXISTS neutron_networks (
    network_id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(project_id),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    shared boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);
CREATE INDEX IF NOT EXISTS neutron_networks_project_idx ON neutron_networks (project_id) WHERE deleted_at IS NULL;

-- ADR-035 §2: tenant-chosen subnet CIDRs. `project_id` always matches the
-- owning network's own `project_id` (enforced in Go at create time -- only
-- a network's own project may add a subnet to it, even a shared one), not
-- separately supplied by the caller.
--
-- Collision avoidance with ADR-010's legacy `10.254.0.0/16` range (§2):
-- enforced in Go (network.go's validateSubnetCIDR), not as a native
-- Postgres `inet`/`cidr`-typed CHECK -- this table stores every address
-- field as plain `text`, deliberately: this codebase has no other use of
-- Postgres's native network types anywhere, and getting pgx's binary
-- encode/decode plans for `cidr`/`inet` exactly right has no existing
-- precedent here to follow. `text` plus Go-side `net.ParseCIDR`/
-- `net.ParseIP` validation (the actual enforcement in every case) is the
-- smaller-risk choice; the CHECK below is only a cheap, defense-in-depth
-- shape guard (must contain a `/'), not the real validation.
--
-- ADR-035 §2's own "open question for the accepting reviewer": this first
-- slice requires subnet CIDRs to be **globally unique across all projects
-- and networks**, stricter than real Neutron's per-tenant-isolated CIDR
-- reuse, because this ADR could not fully verify whether
-- `internal/wireguard.CommandBackend`'s `wg`/`openinfra-wireguard-attach`
-- invocations are scoped per-provider-host in production. The unique index
-- below enforces exact-CIDR-string uniqueness (safe under concurrency);
-- catching *overlapping-but-differently-sized* CIDRs (e.g. a /24 and a
-- /25 within it) is an additional Go-side check
-- (postgres_networking.go's CreateSubnet) with a small, documented,
-- non-security-relevant race window -- see that function's own doc
-- comment. Relaxing global uniqueness to per-provider-host uniqueness is
-- future work explicitly flagged by the ADR, not silently assumed safe
-- here.
CREATE TABLE IF NOT EXISTS neutron_subnets (
    subnet_id uuid PRIMARY KEY,
    network_id uuid NOT NULL REFERENCES neutron_networks(network_id),
    project_id uuid NOT NULL REFERENCES projects(project_id),
    cidr text NOT NULL CHECK (position('/' in cidr) > 0 AND length(cidr) <= 64),
    gateway_ip text CHECK (gateway_ip IS NULL OR length(gateway_ip) <= 64),
    created_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS neutron_subnets_cidr_idx ON neutron_subnets (cidr) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS neutron_subnets_network_idx ON neutron_subnets (network_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS neutron_subnets_project_idx ON neutron_subnets (project_id) WHERE deleted_at IS NULL;

-- ADR-035 §1: a port is ADR-010's existing per-workload WireGuard peer
-- allocation, promoted from implicit (address derived from an allocated
-- UDP port number at `Attach` time) to explicit and precreated: creating a
-- port reserves `fixed_ip` from its subnet's pool (§2) and is pure
-- Control-Plane bookkeeping -- no WireGuard peer exists yet, no privileged
-- backend call is made, a port with no bound workload is inert.
--
-- `workload_id` is this table's mirror of real Neutron's own `device_id`
-- field (a port's bound compute instance) -- named `workload_id` to match
-- this codebase's own vocabulary everywhere else, translated to
-- `device_id` only at the JSON response boundary for wire compatibility
-- (see response.go). Nullable: a freshly-created port has none yet, and a
-- port a workload later releases returns to NULL rather than being
-- deleted, per real Neutron's own detach-does-not-delete-the-port
-- semantics.
--
-- `mac_address` is kept only for wire-shape completeness (ADR-035 §1: "not
-- meaningful for a WireGuard-backed port") -- this system's overlay has no
-- L2/MAC concept at all; always NULL, never read by any Go or Rust code
-- path, present purely so a client expecting the field to exist in a real
-- Neutron port response is not confused by its outright absence.
CREATE TABLE IF NOT EXISTS neutron_ports (
    port_id uuid PRIMARY KEY,
    network_id uuid NOT NULL REFERENCES neutron_networks(network_id),
    subnet_id uuid NOT NULL REFERENCES neutron_subnets(subnet_id),
    project_id uuid NOT NULL REFERENCES projects(project_id),
    fixed_ip text NOT NULL CHECK (length(fixed_ip) <= 64),
    mac_address text,
    workload_id uuid REFERENCES workloads(workload_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);
-- Per-subnet allocation uniqueness (ADR-035 §2): "the ordinary, boring way
-- to prevent double-allocation" -- the actual IPAM enforcement backstop
-- behind the Go-level "lowest-available-first" scan, defense in depth
-- matching cinder_volumes/project_quotas' identical CHECK-constraint-
-- alongside-Go-level-validation precedent.
CREATE UNIQUE INDEX IF NOT EXISTS neutron_ports_subnet_fixed_ip_idx ON neutron_ports (subnet_id, fixed_ip) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS neutron_ports_project_idx ON neutron_ports (project_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS neutron_ports_network_idx ON neutron_ports (network_id) WHERE deleted_at IS NULL;
-- A workload may be bound to at most one port at a time -- this table's
-- own structural guard behind the Go-level bind transition, the same
-- "query itself is the check" discipline ADR-034 §2 already established
-- for cinder_volumes' attached_workload_id.
CREATE UNIQUE INDEX IF NOT EXISTS neutron_ports_workload_idx ON neutron_ports (workload_id) WHERE workload_id IS NOT NULL AND deleted_at IS NULL;

-- ADR-035 §3, the security-critical table: a port with no row in
-- neutron_port_security_groups (below), or a security group with zero
-- rows here, denies ALL traffic in both directions -- the fail-closed
-- default is structural (absence of an allow rule), never a stored flag
-- that could be flipped to "allow". There is deliberately no
-- allow-by-default sentinel value anywhere in this schema.
CREATE TABLE IF NOT EXISTS neutron_security_groups (
    security_group_id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(project_id),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    created_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);
CREATE INDEX IF NOT EXISTS neutron_security_groups_project_idx ON neutron_security_groups (project_id) WHERE deleted_at IS NULL;

-- ADR-035 §3's rule vocabulary for this slice: `remote_ip_prefix` (static
-- CIDR match) only -- `remote_group_id` (a rule referencing another
-- security group's live membership) is explicitly Out of scope, a
-- genuinely stateful mechanism this ADR does not design. `protocol =
-- 'any'`/`'icmp'` rules always have NULL port_range_min/max (icmp has no
-- port concept; 'any' matches every protocol and so no single port range
-- would be meaningful) -- enforced by the second CHECK below, matching
-- this table's "protocol determines whether ports are meaningful" shape.
CREATE TABLE IF NOT EXISTS neutron_security_group_rules (
    rule_id uuid PRIMARY KEY,
    security_group_id uuid NOT NULL REFERENCES neutron_security_groups(security_group_id),
    project_id uuid NOT NULL REFERENCES projects(project_id),
    direction text NOT NULL CHECK (direction IN ('ingress', 'egress')),
    protocol text NOT NULL CHECK (protocol IN ('tcp', 'udp', 'icmp', 'any')),
    port_range_min integer CHECK (port_range_min IS NULL OR (port_range_min BETWEEN 0 AND 65535)),
    port_range_max integer CHECK (port_range_max IS NULL OR (port_range_max BETWEEN 0 AND 65535)),
    remote_ip_prefix text NOT NULL CHECK (position('/' in remote_ip_prefix) > 0 AND length(remote_ip_prefix) <= 64),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (port_range_min IS NULL OR port_range_max IS NULL OR port_range_min <= port_range_max),
    CHECK (protocol IN ('tcp', 'udp') OR (port_range_min IS NULL AND port_range_max IS NULL))
);
CREATE INDEX IF NOT EXISTS neutron_security_group_rules_group_idx ON neutron_security_group_rules (security_group_id);
-- Exact-duplicate-rule rejection, real Neutron's own behavior
-- (SecurityGroupRuleExists, 409) -- a functional unique index so
-- 'any'/'icmp' rules (NULL port_range_min/max) still dedup correctly,
-- since a plain UNIQUE constraint treats every NULL as distinct.
CREATE UNIQUE INDEX IF NOT EXISTS neutron_security_group_rules_dedup_idx ON neutron_security_group_rules (
    security_group_id, direction, protocol, remote_ip_prefix, COALESCE(port_range_min, -1), COALESCE(port_range_max, -1)
);

-- Many-to-many join (ADR-035 Consequences: "Neutron allows multiple
-- security groups per port"). Multiple groups on one port are unioned,
-- never intersected (ADR-035 §3 point 2) -- purely an aggregation
-- decision made by the code that reads this table, not expressible (or
-- needed) as schema here.
CREATE TABLE IF NOT EXISTS neutron_port_security_groups (
    port_id uuid NOT NULL REFERENCES neutron_ports(port_id),
    security_group_id uuid NOT NULL REFERENCES neutron_security_groups(security_group_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (port_id, security_group_id)
);
CREATE INDEX IF NOT EXISTS neutron_port_security_groups_port_idx ON neutron_port_security_groups (port_id);
CREATE INDEX IF NOT EXISTS neutron_port_security_groups_group_idx ON neutron_port_security_groups (security_group_id);
