# Changelog

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
