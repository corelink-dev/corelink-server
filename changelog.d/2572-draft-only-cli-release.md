### Changed

- Added an explicit, exact-inventory draft-only CLI release mode. Linux payloads use the existing GPG signer; Windows remains unsigned and deferred with no Authenticode claim. Draft assets cannot pass the production signed-release validator or reach the public publish transition.
