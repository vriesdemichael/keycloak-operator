# Changelog

## [0.3.4](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.3.3...chart-client-v0.3.4) (2026-01-08)


### Bug Fixes

* **chart-client+chart-operator+operator:** address multiple issues ([#290](https://github.com/vriesdemichael/keycloak-operator/issues/290), [#294](https://github.com/vriesdemichael/keycloak-operator/issues/294), [#170](https://github.com/vriesdemichael/keycloak-operator/issues/170), [#168](https://github.com/vriesdemichael/keycloak-operator/issues/168)) ([0b790ac](https://github.com/vriesdemichael/keycloak-operator/commit/0b790acab044239342f888dfe170afbef874f6bc))

## [0.3.3](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.3.2...chart-client-v0.3.3) (2026-01-04)


### Bug Fixes

* **chart-operator:** update for operator v0.5.12 ([b30cc9b](https://github.com/vriesdemichael/keycloak-operator/commit/b30cc9b5ada6c5dfa182e80fdfc3123a27e74396))

## [0.3.2](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.3.1...chart-client-v0.3.2) (2025-12-27)


### Features

* **chart-client:** add rbac configuration to schema ([6e5a5cb](https://github.com/vriesdemichael/keycloak-operator/commit/6e5a5cbc935cabda4b5f4f51cbd3926b4e88b557))

## [0.3.1](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.3.0...chart-client-v0.3.1) (2025-12-21)


### Bug Fixes

* **chart-client+chart-operator+chart-realm:** update Kubernetes version requirement to 1.27+ ([26e8781](https://github.com/vriesdemichael/keycloak-operator/commit/26e87812994979d2ec22767f9ff3fb11de85f74a))

## [0.3.0](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.2.0...chart-client-v0.3.0) (2025-12-03)


### ⚠ BREAKING CHANGES

* **chart-client+chart-operator+chart-realm:** Helm chart distribution moved to OCI registry

### Features

* **chart-client+chart-operator+chart-realm:** migrate to OCI registry in GHCR ([dc4f59c](https://github.com/vriesdemichael/keycloak-operator/commit/dc4f59c8f9d66be04cd7be6ae685fc714a8aad97))

## [0.2.0](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.1.3...chart-client-v0.2.0) (2025-11-17)


### ⚠ BREAKING CHANGES

* **chart-client+chart-realm:** Removed token-based authorization from all charts
* The API group domain has changed from keycloak.mdvr.nl to vriesdemichael.github.io. Existing installations must migrate by:

### Features

* **chart-client+chart-realm:** update charts for namespace grant authorization ([add6af9](https://github.com/vriesdemichael/keycloak-operator/commit/add6af903c2ff887cd44c5608ceb1a1a6436f23e)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* migrate API group from keycloak.mdvr.nl to vriesdemichael.github.io ([d93b3c1](https://github.com/vriesdemichael/keycloak-operator/commit/d93b3c115d73ba8e3f1fa99c48c1e058f315b075))


### Bug Fixes

* remove authorizationSecretRef from Helm values schemas ([f87585b](https://github.com/vriesdemichael/keycloak-operator/commit/f87585b10b7446822636a909e83f1c45235fa62d)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* update integration tests to use keycloak-prefixed annotations and finalizers ([0baf321](https://github.com/vriesdemichael/keycloak-operator/commit/0baf3213832ba63b853a06a34265244d976f54e6))
* update tests and Helm schema for grant list authorization ([0fe6fca](https://github.com/vriesdemichael/keycloak-operator/commit/0fe6fcae8c638595a117b2093d869ecb85b37f47)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)


### Documentation

* bulk cleanup of authorizationSecretRef in chart READMEs ([7010d85](https://github.com/vriesdemichael/keycloak-operator/commit/7010d855084409af6a36e3d17fae465070afd6b9))
* **chart-client:** add comprehensive README ([7b147c8](https://github.com/vriesdemichael/keycloak-operator/commit/7b147c845b18172f0526182ecc33a469a56b5f07))

## [0.1.3](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.1.2...chart-client-v0.1.3) (2025-11-01)


### Features

* publish JSON schemas for CRDs to enable IDE autocomplete ([72485af](https://github.com/vriesdemichael/keycloak-operator/commit/72485afb83822db7e427e1b876fd2700a91489a5))


### Bug Fixes

* enable mandatory type checking and add Helm linting to pre-commit ([97dc9d7](https://github.com/vriesdemichael/keycloak-operator/commit/97dc9d7062695a9e3999c5554d774ac9c79e6c3d))

## [0.1.2](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.1.1...chart-client-v0.1.2) (2025-10-20)


### Bug Fixes

* Add operator log capture and fix all integration tests ([#14](https://github.com/vriesdemichael/keycloak-operator/issues/14)) ([bf4e84f](https://github.com/vriesdemichael/keycloak-operator/commit/bf4e84ff8e4e5f8a0ebb0210ac2d6922beae2174))

## [0.1.1](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.1.0...chart-client-v0.1.1) (2025-10-17)


### Features

* Add Keycloak Operator and Realm Helm charts ([2d4be4f](https://github.com/vriesdemichael/keycloak-operator/commit/2d4be4f4b8b43665afcecc8f0dacefbe88f66117))
* **charts:** add values.schema.json and extraManifests support ([039e00d](https://github.com/vriesdemichael/keycloak-operator/commit/039e00d1fe0874b2eb24f21d95f5e58d9f4a50cc))
