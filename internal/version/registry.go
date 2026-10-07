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
//
// The PEP 440 entries are Python packages whose NVD version bounds are all
// PEP 440-shaped (verified against the dataset). Using it in place of Generic
// adds correct ordering of pre/post/dev releases (4.0rc1 < 4.0) without
// regression: like Generic, it reports UNKNOWN for distro-revisioned versions
// (2.2.1-1ubuntu0.1), which the distribution-advisory path handles. Grow this
// list as more Python products are confirmed.
var byProduct = map[string]Comparator{
	"openbsd:openssh": OpenSSH{},

	"python:python":                PEP440{}, // CPython
	"python:requests":              PEP440{},
	"python:urllib3":               PEP440{},
	"python:setuptools":            PEP440{},
	"djangoproject:django":         PEP440{},
	"palletsprojects:flask":        PEP440{},
	"palletsprojects:werkzeug":     PEP440{},
	"palletsprojects:jinja":        PEP440{},
	"cryptography.io:cryptography": PEP440{},
	"paramiko:paramiko":            PEP440{},
	"tornadoweb:tornado":           PEP440{},
	"sqlalchemy:sqlalchemy":        PEP440{},
	"celeryproject:celery":         PEP440{},
	"numpy:numpy":                  PEP440{},
	"pyyaml:pyyaml":                PEP440{},
	"aiohttp:aiohttp":              PEP440{},
	"scrapy:scrapy":                PEP440{},
	"pypa:pip":                     PEP440{},
	"redhat:ansible":               PEP440{},
}

// For returns the comparator for a canonical CPE vendor and product.
func For(vendor, product string) Comparator {
	if c, ok := byProduct[vendor+":"+product]; ok {
		return c
	}
	return Generic{}
}
