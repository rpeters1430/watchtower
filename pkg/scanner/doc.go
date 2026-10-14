// Package scanner runs open-source image vulnerability scanners and turns
// their reports into one normalized model.
//
// A Scanner backend knows how to run one tool and parse its output. Results
// are compared with Compare so an update can report which findings it fixes
// and which it introduces, and the optional severity gate can hold back an
// update whose new image is worse than the running one.
//
// The Trivy backend runs the Trivy CLI in a short-lived container on the
// Docker daemon Watchtower manages (see DockerRunner), because the Watchtower
// image has no shell or room to bundle a scanner binary. A scanner failure is
// an error for the caller to log; it is never a reason by itself to skip an
// update.
package scanner
