// Package fumigator carries the packs and skills inside the binary, so a release tarball or
// `go install` works without a checkout. A packs directory on disk (--packs, FUMIGATOR_PACKS,
// or ./packs) takes precedence, which is how a pack is edited and tested.
package fumigator

import "embed"

// Packs holds packs/<id>/pack.yaml for every shipped pack.
//
//go:embed packs/*/pack.yaml
var Packs embed.FS

// Skills holds the agent skills (SKILL.md and references) for `fumigator skills install`.
//
//go:embed skills/*/SKILL.md skills/*/references
var Skills embed.FS
