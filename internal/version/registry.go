package version

// UpdateJoiner is implemented by comparators for version schemes where NVD
// sometimes splits one upstream version across the CPE version and update
// attributes (OpenSSH "9.3p1" vs version "9.3" + update "p1"). JoinUpdate
// returns the effective version and whether the update was absorbed; when
// it was, the matcher does not compare the update attribute separately.
type UpdateJoiner interface {
	JoinUpdate(version, update string) (string, bool)
}

// byProduct selects specialised comparators by canonical "vendor:product".
// Everything else uses the conservative Generic comparator.
var byProduct = map[string]Comparator{
	"openbsd:openssh": OpenSSH{},
}

// For returns the comparator for a canonical CPE vendor and product.
func For(vendor, product string) Comparator {
	if c, ok := byProduct[vendor+":"+product]; ok {
		return c
	}
	return Generic{}
}
