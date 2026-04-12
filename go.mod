module github.com/sirosfoundation/goff

go 1.26

require (
	github.com/antchfx/xmlquery v1.5.1
	github.com/antchfx/xpath v1.3.6
	github.com/beevik/etree v1.6.0
	github.com/russellhaering/goxmldsig v1.5.0
	github.com/sirosfoundation/go-cryptoutil v0.5.0
	gopkg.in/yaml.v3 v3.0.1
	vc v0.4.0
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/miekg/pkcs11 v1.1.2 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/text v0.35.0 // indirect
)

replace vc => github.com/SUNET/vc v0.4.3

replace github.com/russellhaering/goxmldsig => github.com/sirosfoundation/goxmldsig v1.6.0-siros2
