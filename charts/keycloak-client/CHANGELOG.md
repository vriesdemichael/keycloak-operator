# Changelog

## [0.4.5](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.4.4...chart-client-v0.4.5) (2026-02-21)


### Documentation

* remove stale token-based auth model references ([b567b3d](https://github.com/vriesdemichael/keycloak-operator/commit/b567b3dff3f89493d3e348b6783cd7a188168c6f))

## [0.4.4](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.4.3...chart-client-v0.4.4) (2026-02-17)


### Features

* **chart-client+chart-realm:** add feature parity for realm and client charts ([7b04f00](https://github.com/vriesdemichael/keycloak-operator/commit/7b04f000d05c2100b45f068cfb36657a6266012e))

## [0.4.3](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.4.2...chart-client-v0.4.3) (2026-02-14)


### Features

* **chart-client+operator:** add support for manual client secrets (issue [#495](https://github.com/vriesdemichael/keycloak-operator/issues/495)) ([06359dd](https://github.com/vriesdemichael/keycloak-operator/commit/06359ddbac14ab27194663929610efd759ea2eab))


### Bug Fixes

* **chart-client+operator:** resolve helm validation and ci failures ([e634fe3](https://github.com/vriesdemichael/keycloak-operator/commit/e634fe39ad9eabffb3139b84af5ba6d7ccc019c0))

## [0.4.2](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.4.1...chart-client-v0.4.2) (2026-02-03)


### Features

* **chart-client+chart-operator+chart-realm+operator:** add authorization and organization feature parity ([9979fd0](https://github.com/vriesdemichael/keycloak-operator/commit/9979fd07e10d53ac2fe654f9cdc927e06780f8e7))


### Bug Fixes

* **operator:** address PR review comments and add unit tests ([d0aa0d6](https://github.com/vriesdemichael/keycloak-operator/commit/d0aa0d6b95dd29825f7bb9c5aefeeb126f07ecc6))

## [0.4.1](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.4.0...chart-client-v0.4.1) (2026-02-01)


### Bug Fixes

* **chart-client+operator:** complete secret rotation helm chart and fix review comments ([073ac06](https://github.com/vriesdemichael/keycloak-operator/commit/073ac06e9beb1c3c20d89bc19c9ee0331c8a76d8))
* **chart-client:** always render secretRotation block for GitOps consistency ([2d78477](https://github.com/vriesdemichael/keycloak-operator/commit/2d784776443d0af818111efa891d121e9c87ff58))

## [0.4.0](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.3.7...chart-client-v0.4.0) (2026-01-29)


### ⚠ BREAKING CHANGES

* **chart-client+chart-operator+chart-realm:** Helm chart distribution moved to OCI registry

### Features

* **chart-client+chart-operator+chart-realm:** migrate to OCI registry in GHCR ([3d122c6](https://github.com/vriesdemichael/keycloak-operator/commit/3d122c6b78851ef571b5d4d4af436039e45bb9d0))
* **chart-client+chart-operator+operator:** add missing client settings fields ([0404a43](https://github.com/vriesdemichael/keycloak-operator/commit/0404a43b24fc8988fce32414f75a2b012c68168d))
* **chart-client+operator:** add labels and annotations to managed secrets ([a2fcd36](https://github.com/vriesdemichael/keycloak-operator/commit/a2fcd36ef5e7b46c8b53a747a99353074eb3823e))
* **chart-client+operator:** improve client secret management and monitoring ([555c173](https://github.com/vriesdemichael/keycloak-operator/commit/555c173ca89b8d2f587fd7e7a08e5ad52ae06b57))
* **chart-client:** add rbac configuration to schema ([25b73ec](https://github.com/vriesdemichael/keycloak-operator/commit/25b73ec6f09fc895e45cbaec932c3107fe5b78de))


### Bug Fixes

* **chart-client+chart-operator+chart-realm:** update Kubernetes version requirement to 1.27+ ([f53fe0c](https://github.com/vriesdemichael/keycloak-operator/commit/f53fe0c26425274282fcc8a10095c0484cef9a13))
* **chart-client+chart-operator+operator:** address multiple issues ([#290](https://github.com/vriesdemichael/keycloak-operator/issues/290), [#294](https://github.com/vriesdemichael/keycloak-operator/issues/294), [#170](https://github.com/vriesdemichael/keycloak-operator/issues/170), [#168](https://github.com/vriesdemichael/keycloak-operator/issues/168)) ([23a1dba](https://github.com/vriesdemichael/keycloak-operator/commit/23a1dbafabfd0deb35f6c528b560df1cb19da1e5))
* **chart-operator:** update for operator v0.5.12 ([f79be8a](https://github.com/vriesdemichael/keycloak-operator/commit/f79be8aea6a92412e8eb7d88852c0174bbc72b2a))


### Documentation

* bulk cleanup of authorizationSecretRef in chart READMEs ([3e31d59](https://github.com/vriesdemichael/keycloak-operator/commit/3e31d59534e7df3f7580099987d30c800422ccec))

## [0.3.7](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.3.6...chart-client-v0.3.7) (2026-01-21)


### Features

* **chart-client+operator:** improve client secret management and monitoring ([c182187](https://github.com/vriesdemichael/keycloak-operator/commit/c182187adaa614e89fb2696c74c860c39a86994d))

## [0.3.6](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.3.5...chart-client-v0.3.6) (2026-01-20)


### Features

* **chart-client+operator:** add labels and annotations to managed secrets ([ee64ec1](https://github.com/vriesdemichael/keycloak-operator/commit/ee64ec1ecbe5ead4db3fe9896f16fd83d0c842ef))

## [0.3.5](https://github.com/vriesdemichael/keycloak-operator/compare/chart-client-v0.3.4...chart-client-v0.3.5) (2026-01-14)


### Features

* **chart-client+chart-operator+operator:** add missing client settings fields ([5a17906](https://github.com/vriesdemichael/keycloak-operator/commit/5a179063c098f1fc0afd505b5466dd8be8a2ab79))

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
