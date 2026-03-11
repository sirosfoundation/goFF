## goFF - go Federation Feeder

This is a re-implementation of pyFF (github.com/IdentityPython/pyFF) in golang. The goal is simple: support the same configuration structures and pipeline process as the original pyFF but use golangs superior concurrency model to build a faster and more memory-lean implementation of a SAML metadata processor.

You may suggest improvements and simplifications along the way but a pyff pipeline (yaml) should work and produce the same result in goFF.

One simplification you may implement is this: pyFF can be run in batch mode and in server mode. In server mode the pipline is used to perform actions necessary to implement an MDQ server. These actions are better implemented in a standalone server. The MDQ implementation must still use pipelines to generate and update the internal repository of SAML metadata that the MDQ server operates on but it doesn't have to use pipeline constructs to respond to the requests for metadata.

The two modes (batch and server) can be provided in the same binary  -- there is no need to identically reproduce the same coommandline options. 

Use the go-trust service and go-spocp as a model for how to build, package, test the implementation and copy relevant ADRs from those projects. Use the libraries use in the vc project to provide xml security implementations necessary - note that this workspace has a go.work file with important replace directives for those libraries. These are absolutely necessary for SAML metadata signing and verification to work.
