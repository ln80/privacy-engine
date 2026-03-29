module github.com/ln80/privacy-engine

go 1.22.0

require github.com/google/uuid v1.6.0

require (
	github.com/ln80/struct-sensitive v0.6.0
	github.com/sanity-io/litter v1.5.5
)

require (
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
)

replace github.com/ln80/struct-sensitive v0.6.0 => ../struct-sensitive
