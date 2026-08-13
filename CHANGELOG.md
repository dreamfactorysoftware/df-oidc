# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]
### Added
- Group-to-role mapping: assign a DreamFactory role based on the provider's groups claim (configurable claim name; matches group names or ids). Priority: group mapping > role per app > default role. Includes handling/logging for the Azure AD groups-overage case.
### Fixed
- ID Token validation now uses `firebase/php-jwt` (already in the DreamFactory dependency tree) instead of the undeclared, abandoned `namshi/jose`, which was not installed and caused a 500 when instantiating any OIDC service. Signature/alg-allowlist/issuer/audience/expiry checks are preserved.
### Changed
- Dependencies: added `firebase/php-jwt`; removed the now-unused `phpseclib/phpseclib`.

## [0.5.0] - 2017-12-26
### Added
- Added package discovery
### Changed
- DF-1150 Update copyright and support email

## [0.4.0] - 2017-11-03
### Added
- Added api required endpoint access exceptions
### Changed
- Upgrade Swagger to OpenAPI 3.0 specification

## [0.3.0] - 2017-08-17
### Changed
- Reworked API doc usage and generation

## [0.2.0] - 2017-07-27
### Added
- DF-1117 - Added SAML and OpenID Connect SSO support

## [0.1.0] - 2017-06-05
### Changed
- Cleanup - removal of php-utils dependency
- DF-797 Added support for OpenID Connect

[Unreleased]: https://github.com/dreamfactorysoftware/df-oidc/compare/0.5.0...HEAD
[0.5.0]: https://github.com/dreamfactorysoftware/df-oidc/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/dreamfactorysoftware/df-oidc/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/dreamfactorysoftware/df-oidc/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/dreamfactorysoftware/df-oidc/compare/0.1.0...0.2.0