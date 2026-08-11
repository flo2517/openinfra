package userauth_test

import (
	"testing"

	"github.com/openinfra/network/internal/userauth"
)

func TestValidRoleAcceptsExactlyTenantAndTheTwoOperatorLevels(t *testing.T) {
	if !userauth.ValidRole(userauth.RoleTenant) {
		t.Fatal("expected RoleTenant to be valid")
	}
	if !userauth.ValidRole(userauth.RoleOperatorReadOnly) {
		t.Fatal("expected RoleOperatorReadOnly to be valid")
	}
	if !userauth.ValidRole(userauth.RoleOperatorAdmin) {
		t.Fatal("expected RoleOperatorAdmin to be valid")
	}
	// "operator" (the pre-ADR-016-§7-resolution single-tier name) is
	// deliberately no longer valid -- migrations/000013 promoted every
	// existing row off it, so a caller passing the old value should fail
	// closed, not be silently accepted as something.
	for _, bad := range []string{"", "admin", "Tenant", "operator", "operator "} {
		if userauth.ValidRole(bad) {
			t.Fatalf("expected %q to be invalid", bad)
		}
	}
}

func TestRoleSatisfiesOrdering(t *testing.T) {
	cases := []struct {
		actual, required string
		want             bool
	}{
		{userauth.RoleTenant, userauth.RoleTenant, true},
		{userauth.RoleOperatorReadOnly, userauth.RoleTenant, true},
		{userauth.RoleOperatorReadOnly, userauth.RoleOperatorReadOnly, true},
		{userauth.RoleTenant, userauth.RoleOperatorReadOnly, false},
		{userauth.RoleOperatorAdmin, userauth.RoleTenant, true},
		{userauth.RoleOperatorAdmin, userauth.RoleOperatorReadOnly, true},
		{userauth.RoleOperatorAdmin, userauth.RoleOperatorAdmin, true},
		{userauth.RoleOperatorReadOnly, userauth.RoleOperatorAdmin, false},
		{userauth.RoleTenant, userauth.RoleOperatorAdmin, false},
		// An unrecognized role (should never happen once ValidRole is
		// enforced at every write path, but RoleSatisfies must still
		// fail closed rather than panic on a corrupt/future value) ranks
		// below every real role.
		{"unknown", userauth.RoleTenant, false},
		{"unknown", "unknown", false},
	}
	for _, c := range cases {
		if got := userauth.RoleSatisfies(c.actual, c.required); got != c.want {
			t.Errorf("RoleSatisfies(%q, %q) = %v, want %v", c.actual, c.required, got, c.want)
		}
	}
}
