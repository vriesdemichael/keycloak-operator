# Changelog

## [0.4.6](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.4.5...chart-realm-v0.4.6) (2026-02-20)


### Features

* **chart-operator+chart-realm+operator:** add scopeMappings support ([39db2ac](https://github.com/vriesdemichael/keycloak-operator/commit/39db2ac5ae4cdf83505bfbbfddc3c498d2a0aa8b))


### Bug Fixes

* **chart-realm+operator:** resolve integration test failures for scope mappings and default roles ([533f44f](https://github.com/vriesdemichael/keycloak-operator/commit/533f44fc3148e0fe638c10feb79ac769fbd63112))
* **operator:** address review comments for scope mappings and default roles ([9b64914](https://github.com/vriesdemichael/keycloak-operator/commit/9b6491472dbccc13ce664e8f096dbf05cde46381))

## [0.4.5](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.4.4...chart-realm-v0.4.5) (2026-02-19)


### Features

* **chart-operator+chart-realm+operator:** add browser security headers support ([7b3fd10](https://github.com/vriesdemichael/keycloak-operator/commit/7b3fd106f4c4f15b1e7692c4ff86d59bc0b68a17))


### Bug Fixes

* **chart-realm+operator:** correct defaults for browser security headers ([0ade724](https://github.com/vriesdemichael/keycloak-operator/commit/0ade724b0cffbec124cc6b82a3ea73dcb2c431a8))

## [0.4.4](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.4.3...chart-realm-v0.4.4) (2026-02-19)


### Features

* **chart-realm+operator:** add WebAuthn policy support ([28278aa](https://github.com/vriesdemichael/keycloak-operator/commit/28278aa391e428f6401089e082ccdbf4284622c7))


### Bug Fixes

* **chart-realm+operator:** address review comments ([5928f07](https://github.com/vriesdemichael/keycloak-operator/commit/5928f07fb8afb226a6e8ab7d6110b8819ee244b9))

## [0.4.3](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.4.2...chart-realm-v0.4.3) (2026-02-18)


### Features

* **chart-operator+chart-realm+operator:** add OTP policy support ([f1fbe54](https://github.com/vriesdemichael/keycloak-operator/commit/f1fbe54d95d9cd9392db668e3b0c88425217df54))


### Bug Fixes

* **chart-realm:** address review comments ([04266e8](https://github.com/vriesdemichael/keycloak-operator/commit/04266e890afce49b766ad4eeb29502990688bd69))

## [0.4.2](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.4.1...chart-realm-v0.4.2) (2026-02-17)


### Features

* **chart-client+chart-realm:** add feature parity for realm and client charts ([7b04f00](https://github.com/vriesdemichael/keycloak-operator/commit/7b04f000d05c2100b45f068cfb36657a6266012e))


### Bug Fixes

* **chart-realm:** address review comments and fix integration tests ([296b8c5](https://github.com/vriesdemichael/keycloak-operator/commit/296b8c5884c4872051b49622b4dfa721a49767cf))

## [0.4.1](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.4.0...chart-realm-v0.4.1) (2026-02-03)


### Features

* **chart-client+chart-operator+chart-realm+operator:** add authorization and organization feature parity ([9979fd0](https://github.com/vriesdemichael/keycloak-operator/commit/9979fd07e10d53ac2fe654f9cdc927e06780f8e7))


### Bug Fixes

* **operator:** address PR review comments and add unit tests ([d0aa0d6](https://github.com/vriesdemichael/keycloak-operator/commit/d0aa0d6b95dd29825f7bb9c5aefeeb126f07ecc6))

## [0.4.0](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.3.9...chart-realm-v0.4.0) (2026-01-29)


### ⚠ BREAKING CHANGES

* **chart-client+chart-operator+chart-realm:** Helm chart distribution moved to OCI registry

### Features

* **chart-client+chart-operator+chart-realm:** migrate to OCI registry in GHCR ([3d122c6](https://github.com/vriesdemichael/keycloak-operator/commit/3d122c6b78851ef571b5d4d4af436039e45bb9d0))
* **chart-operator+chart-realm+operator:** add complete realm role and group management ([add7630](https://github.com/vriesdemichael/keycloak-operator/commit/add763062f9c8d62f3131fba55361d2e7bd40a62))
* **chart-operator+chart-realm+operator:** add password policy and improve events config ([48e91af](https://github.com/vriesdemichael/keycloak-operator/commit/48e91af5ca03940d1e86eb6cc0c50e4c595973f6)), closes [#311](https://github.com/vriesdemichael/keycloak-operator/issues/311)
* **chart-realm:** add client scope management ([bd63d5b](https://github.com/vriesdemichael/keycloak-operator/commit/bd63d5bc4ef514020575390ac2a4eb51d5b57279)), closes [#181](https://github.com/vriesdemichael/keycloak-operator/issues/181)
* **chart-realm:** add missing CRD fields to Helm chart ([fc75111](https://github.com/vriesdemichael/keycloak-operator/commit/fc75111b89a6c575706745249d6ec2dda854a26c)), closes [#274](https://github.com/vriesdemichael/keycloak-operator/issues/274)
* **chart-realm:** add rbac and clientAuthorizationGrants to schema ([31d3d77](https://github.com/vriesdemichael/keycloak-operator/commit/31d3d77122ab0a3143e96df79fddb874d4887801))
* **chart-realm:** add user federation configuration to Helm chart ([db3258c](https://github.com/vriesdemichael/keycloak-operator/commit/db3258c031b4f1d363f7576d8123940b9d72a0bd))


### Bug Fixes

* **chart-client+chart-operator+chart-realm:** update Kubernetes version requirement to 1.27+ ([f53fe0c](https://github.com/vriesdemichael/keycloak-operator/commit/f53fe0c26425274282fcc8a10095c0484cef9a13))
* **chart-operator:** update for operator v0.5.12 ([f79be8a](https://github.com/vriesdemichael/keycloak-operator/commit/f79be8aea6a92412e8eb7d88852c0174bbc72b2a))
* **chart-realm:** add new fields to values.schema.json ([913a581](https://github.com/vriesdemichael/keycloak-operator/commit/913a581ba74d73a28c341bf58e5b3a293f556a09))
* **chart-realm:** update drift detection documentation reference ([930c5e9](https://github.com/vriesdemichael/keycloak-operator/commit/930c5e9ba98d1f7492ad2a40caa33e5b393bcebb))


### Documentation

* bulk cleanup of authorizationSecretRef in chart READMEs ([3e31d59](https://github.com/vriesdemichael/keycloak-operator/commit/3e31d59534e7df3f7580099987d30c800422ccec))
* final cleanup of remaining token references ([96e6086](https://github.com/vriesdemichael/keycloak-operator/commit/96e6086d173abdfedec0bb197a94cf50afb7690a))
* update helm chart READMEs and fix broken links ([a32d3e2](https://github.com/vriesdemichael/keycloak-operator/commit/a32d3e243e7d5f0616bf2d52c3bc14ff2d2f2464))

## [0.3.9](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.3.8...chart-realm-v0.3.9) (2026-01-26)


### Bug Fixes

* **chart-realm:** update drift detection documentation reference ([6f39a48](https://github.com/vriesdemichael/keycloak-operator/commit/6f39a48faaac4fe92c022515972b6ad6ab0ba389))
* **operator:** add operator_namespace override for drift detector tests ([6a0e48c](https://github.com/vriesdemichael/keycloak-operator/commit/6a0e48c0cd9745a4f0745ca4a0ff6407f6abb727))

## [0.3.8](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.3.7...chart-realm-v0.3.8) (2026-01-13)


### Features

* **chart-realm:** add user federation configuration to Helm chart ([f819d18](https://github.com/vriesdemichael/keycloak-operator/commit/f819d1871888fe6fc9d43a0582cb8ceab869882c))

## [0.3.7](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.3.6...chart-realm-v0.3.7) (2026-01-07)


### Features

* **chart-realm:** add client scope management ([708787f](https://github.com/vriesdemichael/keycloak-operator/commit/708787f23200be34947733e9059eaad1a51e02b3)), closes [#181](https://github.com/vriesdemichael/keycloak-operator/issues/181)

## [0.3.6](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.3.5...chart-realm-v0.3.6) (2026-01-05)


### Features

* **chart-operator+chart-realm+operator:** add complete realm role and group management ([d55d6d9](https://github.com/vriesdemichael/keycloak-operator/commit/d55d6d99e94264225275d3fcc026f6cf900a9c44))

## [0.3.5](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.3.4...chart-realm-v0.3.5) (2026-01-04)


### Features

* **chart-operator+chart-realm+operator:** add password policy and improve events config ([3d60b5e](https://github.com/vriesdemichael/keycloak-operator/commit/3d60b5eeddd7f2a5c63416a55e195e07f6804d92)), closes [#311](https://github.com/vriesdemichael/keycloak-operator/issues/311)


### Bug Fixes

* **chart-operator:** update for operator v0.5.12 ([b30cc9b](https://github.com/vriesdemichael/keycloak-operator/commit/b30cc9b5ada6c5dfa182e80fdfc3123a27e74396))

## [0.3.4](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.3.3...chart-realm-v0.3.4) (2025-12-29)


### Features

* **chart-realm:** add missing CRD fields to Helm chart ([c9e5eaa](https://github.com/vriesdemichael/keycloak-operator/commit/c9e5eaaaa1e68a2585f7c25f06bd4dd5cbc0f01b)), closes [#274](https://github.com/vriesdemichael/keycloak-operator/issues/274)


### Bug Fixes

* **chart-realm:** add new fields to values.schema.json ([9b9f1cd](https://github.com/vriesdemichael/keycloak-operator/commit/9b9f1cdb7e140d8db481f81f1e35a4dd9155bbce))

## [0.3.3](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.3.2...chart-realm-v0.3.3) (2025-12-27)


### Documentation

* extend doc validation with external schemas and K8s resources ([7e7ce80](https://github.com/vriesdemichael/keycloak-operator/commit/7e7ce80f2f3d0c6c3d9ced00aba0560c8a757862))

## [0.3.2](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.3.1...chart-realm-v0.3.2) (2025-12-26)


### Features

* **chart-realm:** add rbac and clientAuthorizationGrants to schema ([cbdbc9d](https://github.com/vriesdemichael/keycloak-operator/commit/cbdbc9d0ad58afb8ede5bdf8db640cf7d75e649a))

## [0.3.1](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.3.0...chart-realm-v0.3.1) (2025-12-21)


### Bug Fixes

* **chart-client+chart-operator+chart-realm:** update Kubernetes version requirement to 1.27+ ([26e8781](https://github.com/vriesdemichael/keycloak-operator/commit/26e87812994979d2ec22767f9ff3fb11de85f74a))

## [0.3.0](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.2.0...chart-realm-v0.3.0) (2025-12-03)


### ⚠ BREAKING CHANGES

* **chart-client+chart-operator+chart-realm:** Helm chart distribution moved to OCI registry

### Features

* **chart-client+chart-operator+chart-realm:** migrate to OCI registry in GHCR ([dc4f59c](https://github.com/vriesdemichael/keycloak-operator/commit/dc4f59c8f9d66be04cd7be6ae685fc714a8aad97))

## [0.2.0](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.1.3...chart-realm-v0.2.0) (2025-11-17)


### ⚠ BREAKING CHANGES

* **chart-client+chart-realm:** Removed token-based authorization from all charts
* The API group domain has changed from keycloak.mdvr.nl to vriesdemichael.github.io. Existing installations must migrate by:

### Features

* **chart-client+chart-realm:** update charts for namespace grant authorization ([add6af9](https://github.com/vriesdemichael/keycloak-operator/commit/add6af903c2ff887cd44c5608ceb1a1a6436f23e)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* migrate API group from keycloak.mdvr.nl to vriesdemichael.github.io ([d93b3c1](https://github.com/vriesdemichael/keycloak-operator/commit/d93b3c115d73ba8e3f1fa99c48c1e058f315b075))


### Bug Fixes

* remove authorizationSecretRef from Helm values schemas ([f87585b](https://github.com/vriesdemichael/keycloak-operator/commit/f87585b10b7446822636a909e83f1c45235fa62d)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)


### Documentation

* bulk cleanup of authorizationSecretRef in chart READMEs ([7010d85](https://github.com/vriesdemichael/keycloak-operator/commit/7010d855084409af6a36e3d17fae465070afd6b9))
* **chart-realm:** add comprehensive README ([92c8e95](https://github.com/vriesdemichael/keycloak-operator/commit/92c8e95cd65ebdfa6c90f6b12b1b1fe7a91a80bb))
* final cleanup of remaining token references ([10f83eb](https://github.com/vriesdemichael/keycloak-operator/commit/10f83eb6fd7883b24c27e7d114c017f5e6284992))
* update helm chart READMEs and fix broken links ([dfb210d](https://github.com/vriesdemichael/keycloak-operator/commit/dfb210de7e222159830c5687e47e0e6d5eab354e))

## [0.1.3](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.1.2...chart-realm-v0.1.3) (2025-11-01)


### Features

* publish JSON schemas for CRDs to enable IDE autocomplete ([72485af](https://github.com/vriesdemichael/keycloak-operator/commit/72485afb83822db7e427e1b876fd2700a91489a5))


### Bug Fixes

* enable mandatory type checking and add Helm linting to pre-commit ([97dc9d7](https://github.com/vriesdemichael/keycloak-operator/commit/97dc9d7062695a9e3999c5554d774ac9c79e6c3d))

## [0.1.2](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.1.1...chart-realm-v0.1.2) (2025-10-20)


### Bug Fixes

* Add operator log capture and fix all integration tests ([#14](https://github.com/vriesdemichael/keycloak-operator/issues/14)) ([bf4e84f](https://github.com/vriesdemichael/keycloak-operator/commit/bf4e84ff8e4e5f8a0ebb0210ac2d6922beae2174))

## [0.1.1](https://github.com/vriesdemichael/keycloak-operator/compare/chart-realm-v0.1.0...chart-realm-v0.1.1) (2025-10-17)


### Features

* Add Keycloak Operator and Realm Helm charts ([2d4be4f](https://github.com/vriesdemichael/keycloak-operator/commit/2d4be4f4b8b43665afcecc8f0dacefbe88f66117))
* **charts:** add values.schema.json and extraManifests support ([039e00d](https://github.com/vriesdemichael/keycloak-operator/commit/039e00d1fe0874b2eb24f21d95f5e58d9f4a50cc))
