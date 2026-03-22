//go:build pkcs11

package main

// buildFeatures overrides the default when the binary is compiled with PKCS#11 support.
var buildFeatures = "pkcs11"
