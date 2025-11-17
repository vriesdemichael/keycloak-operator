# Changelog

## [0.2.1](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.2.0...chart-operator-v0.2.1) (2025-11-17)


### Bug Fixes

* **chart-operator:** update for operator v0.3.3 compatibility ([584c98f](https://github.com/vriesdemichael/keycloak-operator/commit/584c98f080352b39eab75c1c18e5faba838af9e9))

## [0.2.0](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.1.4...chart-operator-v0.2.0) (2025-11-17)


### ⚠ BREAKING CHANGES

* **webhooks:** Admission webhooks now require cert-manager to be installed
* **chart-client+chart-realm:** Removed token-based authorization from all charts
* The API group domain has changed from keycloak.mdvr.nl to vriesdemichael.github.io. Existing installations must migrate by:

### Features

* add OIDC endpoint discovery to realm status ([6dc52f3](https://github.com/vriesdemichael/keycloak-operator/commit/6dc52f3ac9a51547e4431f99abbe91aec1d7dca3))
* **chart-client+chart-realm:** update charts for namespace grant authorization ([add6af9](https://github.com/vriesdemichael/keycloak-operator/commit/add6af903c2ff887cd44c5608ceb1a1a6436f23e)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart-operator:** add 'get' permission for cross-namespace realm reads ([1e9cf4f](https://github.com/vriesdemichael/keycloak-operator/commit/1e9cf4fd7f4c4fb3e2a85d02bc217c8d4449075a)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart-operator:** update CRDs for namespace grant authorization ([b526149](https://github.com/vriesdemichael/keycloak-operator/commit/b52614931946e588730b3cc4312c061e383623fe)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart:** add automated operator version updates ([b303448](https://github.com/vriesdemichael/keycloak-operator/commit/b3034483f890b6ae282f787cc0ef343bc6fe6d03))
* implement admission webhooks for resource validation ([061acae](https://github.com/vriesdemichael/keycloak-operator/commit/061acae11b1af0d5547177c98264ac6ffbaa8f27))
* migrate API group from keycloak.mdvr.nl to vriesdemichael.github.io ([d93b3c1](https://github.com/vriesdemichael/keycloak-operator/commit/d93b3c115d73ba8e3f1fa99c48c1e058f315b075))
* **operator:** fix pydantic-settings environment variable configuration ([20d00b3](https://github.com/vriesdemichael/keycloak-operator/commit/20d00b3ff8a242e08706426ed7bc7a48e3eb2e6e)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* **webhooks:** switch to cert-manager for webhook TLS certificates ([7195217](https://github.com/vriesdemichael/keycloak-operator/commit/7195217d15903d9c2c738999ce4c25acf1daaa88))


### Bug Fixes

* add certbuilder dependency and fix webhook RBAC permissions ([71df4ee](https://github.com/vriesdemichael/keycloak-operator/commit/71df4eebe6573b84eea6fab15fd9f9666806b3d5))
* add get permission for CRDs in ClusterRole ([3455cd6](https://github.com/vriesdemichael/keycloak-operator/commit/3455cd6eef7148d506f33e13add95ea6927759de))
* add missing RBAC permissions and correct readiness probe port ([2300f2a](https://github.com/vriesdemichael/keycloak-operator/commit/2300f2a85d6f007e2f1d6ca9b12ae80745adc95e))
* add patch permission for pods in namespace Role ([43d7fdc](https://github.com/vriesdemichael/keycloak-operator/commit/43d7fdc6f55475da9a6ba5ce42b0987bdb6d6557))
* **chart-operator:** remove admission token configuration from values ([302a27d](https://github.com/vriesdemichael/keycloak-operator/commit/302a27d59db56b064a7888ce1ee4c76f377f77e0))
* disable webhook auto-management and default to false ([0c59b83](https://github.com/vriesdemichael/keycloak-operator/commit/0c59b834d2852d010a6ca97152eb4b2e41e0353b))
* disable webhooks by default to avoid bootstrap issues ([85470ed](https://github.com/vriesdemichael/keycloak-operator/commit/85470ed5f1a6b9a45027fd050622d82042e92b43))
* proper webhook bootstrap with readiness probe and ArgoCD sync waves ([c8dfc52](https://github.com/vriesdemichael/keycloak-operator/commit/c8dfc5200c02cf550e8857d6e44583b50fb11895))
* remove obsolete authorization token references from charts ([880fc98](https://github.com/vriesdemichael/keycloak-operator/commit/880fc98637ff0e0e4c9471fd47162fc1d790b194)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove tests for deleted periodic_leadership_check function ([1ffcba0](https://github.com/vriesdemichael/keycloak-operator/commit/1ffcba0479decb4916a65262f58a46f84ab28ddd))
* remove webhook config template, let Kopf manage it ([57f2e3e](https://github.com/vriesdemichael/keycloak-operator/commit/57f2e3e82a68789d49b73fea4c8cac4e409133c2))
* use httpGet probe instead of exec with wget ([a6135d6](https://github.com/vriesdemichael/keycloak-operator/commit/a6135d6273e3a2377fd4b23e89342f00a2fb7acb))


### Documentation

* add admission webhook documentation and decision record ([396de85](https://github.com/vriesdemichael/keycloak-operator/commit/396de85863b5731e6e55ae2ac11ad21fbc45eeb1))
* bulk cleanup of authorizationSecretRef in chart READMEs ([7010d85](https://github.com/vriesdemichael/keycloak-operator/commit/7010d855084409af6a36e3d17fae465070afd6b9))
* **chart-operator:** add comprehensive README ([759081d](https://github.com/vriesdemichael/keycloak-operator/commit/759081deb9ac3cea713a0aac7843b15624165dd1))
* **chart-operator:** clarify single-tenant dev mode and add Keycloak deployment guidance ([eb3683d](https://github.com/vriesdemichael/keycloak-operator/commit/eb3683d42878d868f8857c726464a26a3a6702b2))
* **chart-operator:** remove all admission token documentation ([528ff2e](https://github.com/vriesdemichael/keycloak-operator/commit/528ff2e42b7f9f7925215c8ca30291142aedf539))
* final cleanup of remaining token references ([10f83eb](https://github.com/vriesdemichael/keycloak-operator/commit/10f83eb6fd7883b24c27e7d114c017f5e6284992))
* update helm chart READMEs and fix broken links ([dfb210d](https://github.com/vriesdemichael/keycloak-operator/commit/dfb210de7e222159830c5687e47e0e6d5eab354e))

## [0.1.4](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.1.3...chart-operator-v0.1.4) (2025-11-01)


### Features

* add drift detection foundation (Phase 1-3) ([80cf043](https://github.com/vriesdemichael/keycloak-operator/commit/80cf0438ef7b0e7568fa9d033e15be305f24ba55))
* publish JSON schemas for CRDs to enable IDE autocomplete ([72485af](https://github.com/vriesdemichael/keycloak-operator/commit/72485afb83822db7e427e1b876fd2700a91489a5))


### Bug Fixes

* enable mandatory type checking and add Helm linting to pre-commit ([97dc9d7](https://github.com/vriesdemichael/keycloak-operator/commit/97dc9d7062695a9e3999c5554d774ac9c79e6c3d))

## [0.1.3](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.1.2...chart-operator-v0.1.3) (2025-10-27)


### Features

* Two-level rate limiting with async/await conversion ([#44](https://github.com/vriesdemichael/keycloak-operator/issues/44)) ([476a6ed](https://github.com/vriesdemichael/keycloak-operator/commit/476a6ed4bbb327d38e7c55bdc1421daa3fdb2a81))

## [0.1.2](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.1.1...chart-operator-v0.1.2) (2025-10-20)


### Features

* Add Keycloak Operator and Realm Helm charts ([2d4be4f](https://github.com/vriesdemichael/keycloak-operator/commit/2d4be4f4b8b43665afcecc8f0dacefbe88f66117))
* Add optimized Keycloak image for 81% faster tests ([#15](https://github.com/vriesdemichael/keycloak-operator/issues/15)) ([3093a10](https://github.com/vriesdemichael/keycloak-operator/commit/3093a10239538b76d4fe7ae094e9ddcc85a519bd))
* **chart:** make admin password optional, leverage auto-generation ([a9fcb1a](https://github.com/vriesdemichael/keycloak-operator/commit/a9fcb1a475b99036b811753f42029a5cd0c0ad12))
* **charts:** add values.schema.json and extraManifests support ([039e00d](https://github.com/vriesdemichael/keycloak-operator/commit/039e00d1fe0874b2eb24f21d95f5e58d9f4a50cc))
* Implement Kopf peering for leader election and update deployment scripts ([a289e3a](https://github.com/vriesdemichael/keycloak-operator/commit/a289e3a55d95ecf2af4e2d29d94399acccf6aa25))
* **monitoring:** add Grafana dashboard and Prometheus alert rules ([e459d0d](https://github.com/vriesdemichael/keycloak-operator/commit/e459d0d11c874f17c844012f641ec51ae53ad24b))


### Bug Fixes

* Add operator log capture and fix all integration tests ([#14](https://github.com/vriesdemichael/keycloak-operator/issues/14)) ([bf4e84f](https://github.com/vriesdemichael/keycloak-operator/commit/bf4e84ff8e4e5f8a0ebb0210ac2d6922beae2174))
* **chart:** align Keycloak CR template with actual CRD spec ([bfa3a62](https://github.com/vriesdemichael/keycloak-operator/commit/bfa3a62c60c715e510670642e69676058375fceb))
* **chart:** remove kustomization file from Helm CRDs folder ([dd80cb3](https://github.com/vriesdemichael/keycloak-operator/commit/dd80cb340bd3c5b5ffd4d64b83e15df918bbe4ae))

## [0.1.1](https://github.com/vriesdemichael/keycloak-operator/compare/chart-v0.1.0...chart-v0.1.1) (2025-10-16)


### Features

* Add Keycloak Operator and Realm Helm charts ([2d4be4f](https://github.com/vriesdemichael/keycloak-operator/commit/2d4be4f4b8b43665afcecc8f0dacefbe88f66117))
* **chart:** make admin password optional, leverage auto-generation ([a9fcb1a](https://github.com/vriesdemichael/keycloak-operator/commit/a9fcb1a475b99036b811753f42029a5cd0c0ad12))
* Implement Kopf peering for leader election and update deployment scripts ([a289e3a](https://github.com/vriesdemichael/keycloak-operator/commit/a289e3a55d95ecf2af4e2d29d94399acccf6aa25))
* **monitoring:** add Grafana dashboard and Prometheus alert rules ([e459d0d](https://github.com/vriesdemichael/keycloak-operator/commit/e459d0d11c874f17c844012f641ec51ae53ad24b))


### Bug Fixes

* **chart:** align Keycloak CR template with actual CRD spec ([bfa3a62](https://github.com/vriesdemichael/keycloak-operator/commit/bfa3a62c60c715e510670642e69676058375fceb))
* **chart:** remove kustomization file from Helm CRDs folder ([dd80cb3](https://github.com/vriesdemichael/keycloak-operator/commit/dd80cb340bd3c5b5ffd4d64b83e15df918bbe4ae))
