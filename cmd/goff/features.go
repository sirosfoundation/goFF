package main

// buildFeatures lists compile-time features enabled in this binary.
// Overridden to "pkcs11" when built with the pkcs11 build tag (features_pkcs11.go).
var buildFeatures = "no-pkcs11"
