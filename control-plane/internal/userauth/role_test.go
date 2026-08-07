package userauth_test

import (
	"testing"

	"github.com/openinfra/network/internal/userauth"
)

func TestValidRoleAcceptsExactlyTenantAndOperator(t *testing.T) {
	if !userauth.ValidRole(userauth.RoleTenant) {
		t.Fatal("expected RoleTenant to be valid")
	}
	if !userauth.ValidRole(userauth.RoleOperator) {
		t.Fatal("expected RoleOperator to be valid")
	}
	for _, bad := range []string{"", "admin", "Tenant", "operator "} {
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
		{userauth.RoleOperator, userauth.RoleTenant, true},
		{userauth.RoleOperator, userauth.RoleOperator, true},
		{userauth.RoleTenant, userauth.RoleOperator, false},
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
