# Changelog

## [0.2.4](https://github.com/vriesdemichael/keycloak-operator/compare/operator-v0.2.3...operator-v0.2.4) (2025-10-17)


### Bug Fixes

* **security:** prevent sensitive exception details from leaking in HTTP responses ([b0ff023](https://github.com/vriesdemichael/keycloak-operator/commit/b0ff0236e1e559940b9deb111c30be0b6345708e))

## [0.2.3](https://github.com/vriesdemichael/keycloak-operator/compare/operator-v0.2.2...operator-v0.2.3) (2025-10-17)


### Bug Fixes

* **security:** remove unnecessary verify=False from HTTP health check ([dd5217f](https://github.com/vriesdemichael/keycloak-operator/commit/dd5217f3e0df2407ffb594dd554c238889884b38))

## [0.2.2](https://github.com/vriesdemichael/keycloak-operator/compare/operator-v0.2.1...operator-v0.2.2) (2025-10-17)


### Features

* **charts:** add values.schema.json and extraManifests support ([039e00d](https://github.com/vriesdemichael/keycloak-operator/commit/039e00d1fe0874b2eb24f21d95f5e58d9f4a50cc))
* **ci:** create unified CI/CD pipeline workflow ([3209445](https://github.com/vriesdemichael/keycloak-operator/commit/3209445882e6ed40a67b966939550c5e976259f8))
* **ci:** enable auto-merge for release-please PRs ([0a74683](https://github.com/vriesdemichael/keycloak-operator/commit/0a746834e37fae0ad17088caa6b0c6b0757a0d0e))


### Bug Fixes

* **ci:** add all helm charts to release-please config ([2c2280b](https://github.com/vriesdemichael/keycloak-operator/commit/2c2280bd8d9faab8669738baa9dd3a58607383eb))
* **ci:** resolve release-please bash error and disable CodeQL false positives ([f0479fe](https://github.com/vriesdemichael/keycloak-operator/commit/f0479fec32047fd49a95502d610adb3741807d48))
* **deps:** add missing pytest-xdist to test dependency group ([cb01362](https://github.com/vriesdemichael/keycloak-operator/commit/cb01362dce1f702458b8a605fa223bce11b173b4))
* **examples:** correct Keycloak CR database configuration ([be1495c](https://github.com/vriesdemichael/keycloak-operator/commit/be1495cc70125048d2f73f71b30aa727b2eccb3e))
* race condition in CI/CD and cleanup Makefile ([91b0640](https://github.com/vriesdemichael/keycloak-operator/commit/91b0640961ead705430efaa61c70daa6da8a45c0))
* **tests:** improve integration test reliability for CI environments ([77f6aa0](https://github.com/vriesdemichael/keycloak-operator/commit/77f6aa03aebbcda3fed2104619efa4a2f3da2f59))
* **tests:** resolve Helm chart schema validation error in CI ([7db635e](https://github.com/vriesdemichael/keycloak-operator/commit/7db635e5dd7924e56c4742fa1de8582b11243e85))
* TruffleHog BASE/HEAD commit issue in CI/CD workflow ([9067632](https://github.com/vriesdemichael/keycloak-operator/commit/90676320138f30044c30d1e2c9f494ff2eb056f5))


### Code Refactoring

* **ci:** remove old workflow files ([2205530](https://github.com/vriesdemichael/keycloak-operator/commit/2205530eb3e8bd30ac6cb30c1962517fbad3d807))
* **ci:** use uv run --with for ephemeral dependencies ([649d65f](https://github.com/vriesdemichael/keycloak-operator/commit/649d65f4c3167cf69f0982978255230ce786dd7a))
* use targeted dependency groups in CI and Makefile ([12142e4](https://github.com/vriesdemichael/keycloak-operator/commit/12142e4d22059103603537bcbf9862723698a335))


### Documentation

* **ci:** add complete implementation summary ([b42a0dd](https://github.com/vriesdemichael/keycloak-operator/commit/b42a0dd87beb71689f096a671da89eea2bf97699))
* **ci:** add workflow migration documentation ([7028b35](https://github.com/vriesdemichael/keycloak-operator/commit/7028b354f4b5f0badb48bf3f3f84c457bc2f9280))
* **ci:** update tracking to reflect Phase 2 completion ([33baaf6](https://github.com/vriesdemichael/keycloak-operator/commit/33baaf64537594e4500bc838e5baa64bd00a3b31))
* removed outdated todos ([3f7f227](https://github.com/vriesdemichael/keycloak-operator/commit/3f7f2276767642986318633df1d9ae332daf98a5))
* update README badges to reference unified CI/CD workflow ([03ba009](https://github.com/vriesdemichael/keycloak-operator/commit/03ba009eb0aac6e4db6ebdbc8f6315b0ccf0dd4a))

## [0.2.1](https://github.com/vriesdemichael/keycloak-operator/compare/operator-v0.2.0...operator-v0.2.1) (2025-10-16)


### Features

* **ci:** add CODEOWNERS for automated review requests ([2e81678](https://github.com/vriesdemichael/keycloak-operator/commit/2e81678808cf1cca99dc668878f434cd5ae98310))
* **ci:** add comprehensive security scanning workflow ([116ef6f](https://github.com/vriesdemichael/keycloak-operator/commit/116ef6f12d73fd58bfbe3cc96906b7e38984d2bf))
* **ci:** add Dependabot for automated dependency updates ([61614e5](https://github.com/vriesdemichael/keycloak-operator/commit/61614e512728595dfaff0597882ea473e15b84c4))
* **ci:** add security validation to image publishing ([582caf1](https://github.com/vriesdemichael/keycloak-operator/commit/582caf117d9deb0978030651a7ac94cb0198b563))


### Bug Fixes

* **ci:** improve integration test isolation and coverage ([5a03f23](https://github.com/vriesdemichael/keycloak-operator/commit/5a03f2339bbdd916084ee3f66b6699e2ed4c8a1e))
* **ci:** pin Helm version for deterministic builds ([3acb30f](https://github.com/vriesdemichael/keycloak-operator/commit/3acb30f17687a4bb79e84236ec448739239ee86f))


### Documentation

* add comprehensive security and reliability review for CI/CD workflows ([1fb53d4](https://github.com/vriesdemichael/keycloak-operator/commit/1fb53d4d4716cbc5cd5999e0df0feaca8385f7d9))
* add security scanning badge to README ([8edd36b](https://github.com/vriesdemichael/keycloak-operator/commit/8edd36b9ba27b74717fdd2c6ac44a2b7361d05b6))
* **ci:** add CI/CD improvements tracking document ([67f714a](https://github.com/vriesdemichael/keycloak-operator/commit/67f714ae03578335b85370f1da540e9242a822a0))

## [0.2.0](https://github.com/vriesdemichael/keycloak-operator/compare/operator-v0.1.0...operator-v0.2.0) (2025-10-16)


### ⚠ BREAKING CHANGES

* **ci:** Release configuration now uses container-based versioning instead of Python package versioning
* Remove spec.version field from Keycloak CRD and spec.enabled field from KeycloakRealm CRD
* Multiple CRD field renames and removals for consistency

### Features

* Add centralized operator design and RBAC security implementation plan ([17b3413](https://github.com/vriesdemichael/keycloak-operator/commit/17b3413aa1c21de636b342fd9af0ff7fcc48ad96))
* Add Keycloak Operator and Realm Helm charts ([2d4be4f](https://github.com/vriesdemichael/keycloak-operator/commit/2d4be4f4b8b43665afcecc8f0dacefbe88f66117))
* Add Keycloak version validation and update documentation for version requirements ([8fe9ca1](https://github.com/vriesdemichael/keycloak-operator/commit/8fe9ca1f9d88dbee3e6c66810e0cb037323b0181))
* Add method to retrieve Keycloak instance from realm status ([0e45143](https://github.com/vriesdemichael/keycloak-operator/commit/0e45143500efcc16da48989de21bfd5b238c6480))
* add port-forward fixture for integration tests ([6d61987](https://github.com/vriesdemichael/keycloak-operator/commit/6d6198789568efec742506335fcca2141113eb83))
* **chart:** make admin password optional, leverage auto-generation ([a9fcb1a](https://github.com/vriesdemichael/keycloak-operator/commit/a9fcb1a475b99036b811753f42029a5cd0c0ad12))
* **ci:** add explicit shared Keycloak instance creation step ([dc530a1](https://github.com/vriesdemichael/keycloak-operator/commit/dc530a1f56dea2241bb459478745d8541a31e8ce))
* enhance CNPG integration and admin credential management ([df75ccb](https://github.com/vriesdemichael/keycloak-operator/commit/df75ccbf3e04d6b17127c9f3f7e5351c8b3d8d69))
* Enhance Keycloak models with aliasing and population configuration ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* implement deletion handler fixes and cascading deletion ([13d25bb](https://github.com/vriesdemichael/keycloak-operator/commit/13d25bb5082f0c6aaf367cedb53ab4a600d36d3b))
* Implement Kopf peering for leader election and update deployment scripts ([a289e3a](https://github.com/vriesdemichael/keycloak-operator/commit/a289e3a55d95ecf2af4e2d29d94399acccf6aa25))
* Implement resource existence checks before cleanup in Keycloak reconciler ([e88ff0f](https://github.com/vriesdemichael/keycloak-operator/commit/e88ff0f46292e2bc355d1450f0f8e3406787ef40))
* implement secure SMTP configuration for KeycloakRealm ([d79ef1c](https://github.com/vriesdemichael/keycloak-operator/commit/d79ef1ca109c7dc21019932fb7fc2c1a025bee62))
* Introduce DEFAULT_KEYCLOAK_IMAGE constant for consistent Keycloak image usage ([06d060a](https://github.com/vriesdemichael/keycloak-operator/commit/06d060a6a9813e0ea1ca514e1c4b00927c1f9e81))
* **keycloak-client:** add service account role management ([c548b4b](https://github.com/vriesdemichael/keycloak-operator/commit/c548b4b1904208848ad3d1fbf046722ab99d4b15))
* **kubernetes:** Update database type mapping for Keycloak deployment configuration ([f949506](https://github.com/vriesdemichael/keycloak-operator/commit/f94950607dde501471f39b021df37808379e9ba5))
* **logging:** Enhance structured logging with additional fields for better observability ([f949506](https://github.com/vriesdemichael/keycloak-operator/commit/f94950607dde501471f39b021df37808379e9ba5))
* **monitoring:** add Grafana dashboard and Prometheus alert rules ([e459d0d](https://github.com/vriesdemichael/keycloak-operator/commit/e459d0d11c874f17c844012f641ec51ae53ad24b))
* **resilience:** add circuit breaker and exponential backoff for API stability ([2ada936](https://github.com/vriesdemichael/keycloak-operator/commit/2ada93645579b4f81c2c042a0d53cd3d858a1e78))
* switch Keycloak to production mode with HTTP enabled for ingress TLS termination ([1e64bc9](https://github.com/vriesdemichael/keycloak-operator/commit/1e64bc9d8b6608b24df917f167f81dfd41f51569))
* Update intern implementation guide with recent feature completions and new tools ([8e9e456](https://github.com/vriesdemichael/keycloak-operator/commit/8e9e4569e09fd7d43d2dc15867b986740fbfddc3))


### Bug Fixes

* **chart:** align Keycloak CR template with actual CRD spec ([bfa3a62](https://github.com/vriesdemichael/keycloak-operator/commit/bfa3a62c60c715e510670642e69676058375fceb))
* **chart:** remove kustomization file from Helm CRDs folder ([dd80cb3](https://github.com/vriesdemichael/keycloak-operator/commit/dd80cb340bd3c5b5ffd4d64b83e15df918bbe4ae))
* **ci:** add proper step gating to fail fast on deployment errors ([6a74656](https://github.com/vriesdemichael/keycloak-operator/commit/6a746568809f3829b3ad1413052d4102bc28ae1d))
* **ci:** align operator deployment with current Makefile structure ([49599a0](https://github.com/vriesdemichael/keycloak-operator/commit/49599a0ef6c6c225cb1caa3d137d35b0bec3e6c7))
* **ci:** correct release-please config for container-based releases ([732eaa7](https://github.com/vriesdemichael/keycloak-operator/commit/732eaa72313c7893a5b1595691365fc31d135722))
* **ci:** explicitly set kubeconfig path for integration tests ([c49fc64](https://github.com/vriesdemichael/keycloak-operator/commit/c49fc6470b891b069d30308c973fdd1d426873ef))
* **ci:** install both dev and integration dependency groups ([e1a703e](https://github.com/vriesdemichael/keycloak-operator/commit/e1a703edc24868b8ecef7943afd78102c5317ea2))
* **ci:** install integration test dependencies including pytest-xdist ([4a6330b](https://github.com/vriesdemichael/keycloak-operator/commit/4a6330bf6b76ef164cc069b13f6f4966389afc8e))
* **ci:** prevent image publishing when tests fail ([70952a2](https://github.com/vriesdemichael/keycloak-operator/commit/70952a24be23585e4442ac86605f790c3cb3eba7))
* **ci:** prevent namespace creation conflict in helm deployment ([f50f483](https://github.com/vriesdemichael/keycloak-operator/commit/f50f48396329fbb99abeda0e6050eb0ca01ad77d))
* **ci:** properly wait for Keycloak deployment to be ready ([e0f7a9e](https://github.com/vriesdemichael/keycloak-operator/commit/e0f7a9e53915e0f18d4ab19de1193f9d8239b2fd))
* **ci:** remove leader election and basic functionality tests from integration workflow ([c3fad45](https://github.com/vriesdemichael/keycloak-operator/commit/c3fad4561e29daddb89e92ca824cb68831bbb275))
* **ci:** update Keycloak deployment and pod labels for consistency ([e3c3510](https://github.com/vriesdemichael/keycloak-operator/commit/e3c35108e7e10a9b32f99c62d1c59ec68da99d15))
* **ci:** use correct pod labels for Keycloak readiness check ([e680bbc](https://github.com/vriesdemichael/keycloak-operator/commit/e680bbcc86517d4b557b182f65d9755ae056320a))
* **ci:** wait for CNPG cluster and fix kubeconfig access ([edbc171](https://github.com/vriesdemichael/keycloak-operator/commit/edbc171acf4ec2bd784aaaa2455b1ffc54c436f9))
* convert class-scoped fixtures to synchronous for pytest-xdist compatibility ([816370c](https://github.com/vriesdemichael/keycloak-operator/commit/816370c1060c746586d2b2656d91f73a9e3378df))
* convert SMTP configuration values to strings for Keycloak API compatibility ([8ad98d0](https://github.com/vriesdemichael/keycloak-operator/commit/8ad98d006399fbbf8351f5762ba30c0bdf2fc236))
* correct license references from Apache 2.0 to MIT ([d5323b6](https://github.com/vriesdemichael/keycloak-operator/commit/d5323b67345b34c40d12e5ad9fd416bdf647a879))
* Correct realm health monitoring logic to handle missing current realm ([0d11604](https://github.com/vriesdemichael/keycloak-operator/commit/0d11604b71afe0ba6367e650ebb51cd476d7ebe7))
* enforce same-namespace secrets and fix Pydantic model access ([56d448a](https://github.com/vriesdemichael/keycloak-operator/commit/56d448a1e834f7d7da60172976fa67da3dd6bc89))
* implement Keycloak-compliant redirect URI wildcard validation ([83e7742](https://github.com/vriesdemichael/keycloak-operator/commit/83e7742594ae6cc17b0698d4416a358565569033))
* Improve Kubernetes commands for PostgreSQL and Keycloak operator deployment in integration tests ([ad71e08](https://github.com/vriesdemichael/keycloak-operator/commit/ad71e08685986f1de8dcd38a9a481a6a50e54a06))
* **kubernetes:** Change health check ports to use management port for readiness and liveness probes ([f949506](https://github.com/vriesdemichael/keycloak-operator/commit/f94950607dde501471f39b021df37808379e9ba5))
* make all shell scripts executable for GitHub Actions ([bba6004](https://github.com/vriesdemichael/keycloak-operator/commit/bba6004d311e4073ab28aff28bbe926176eb0825))
* **realm_reconciler:** Simplify logging message for realm creation ([f949506](https://github.com/vriesdemichael/keycloak-operator/commit/f94950607dde501471f39b021df37808379e9ba5))
* Remove last_reconcile_time from status updates ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* replace asyncio.run() with synchronous polling in class-scoped fixtures ([5e7b390](https://github.com/vriesdemichael/keycloak-operator/commit/5e7b390e903fed37731d4d69365fa3a3d7336108))
* resolve Keycloak API reconciliation bugs and update to v26.4.0 ([fff123f](https://github.com/vriesdemichael/keycloak-operator/commit/fff123fb47749b8304a97f0a5963f240459f6f61))
* resolve operator reconciliation bugs ([ead662f](https://github.com/vriesdemichael/keycloak-operator/commit/ead662f3c19e2d8e345aeb554f7558caf9bfe5e8))
* StatusWrapper now updates patch.status directly instead of shadow copy ([7e0746d](https://github.com/vriesdemichael/keycloak-operator/commit/7e0746d4d996ca6bab88815dfae84c3a0440d2a6))
* **tests:** properly mock Kubernetes client in finalizer tests ([df6e7d9](https://github.com/vriesdemichael/keycloak-operator/commit/df6e7d9df14cfd46b809da75d279bd94566acd3f))
* **tests:** run integration tests in 'dev' group for improved organization ([dbe9590](https://github.com/vriesdemichael/keycloak-operator/commit/dbe9590d356ad9ca1ae26b77ac3ac429b625141b))
* Update critical production blockers with progress and remaining work ([8e9e456](https://github.com/vriesdemichael/keycloak-operator/commit/8e9e4569e09fd7d43d2dc15867b986740fbfddc3))


### Performance Improvements

* optimize integration tests with shared Keycloak instances and parallel execution ([a71d754](https://github.com/vriesdemichael/keycloak-operator/commit/a71d754d5c9558d2b2048ce0e88e4a1911706264))


### Code Refactoring

* align CRD schemas with Pydantic models for GitOps compliance ([c06001b](https://github.com/vriesdemichael/keycloak-operator/commit/c06001bfbc6dfff6f09aafe65a767918e7481cc2))
* **ci:** split deployment into clear sequential steps ([ff07e16](https://github.com/vriesdemichael/keycloak-operator/commit/ff07e16aa604dfe1076c89d59ca1d298824e907a))
* **ci:** use operator chart for complete deployment ([5cb1f09](https://github.com/vriesdemichael/keycloak-operator/commit/5cb1f0996723ded97df9f14e3aafea7d14ce14b9))
* consolidate TODO files and enhance Keycloak admin API ([350c88f](https://github.com/vriesdemichael/keycloak-operator/commit/350c88fb0899e166dcea1883c00b2d1c78eeeb90))
* **keycloak_admin:** Introduce validated request method for API calls with Pydantic models ([f949506](https://github.com/vriesdemichael/keycloak-operator/commit/f94950607dde501471f39b021df37808379e9ba5))
* remove version and enabled fields from CRDs for K8s-native design ([11cdf60](https://github.com/vriesdemichael/keycloak-operator/commit/11cdf60a1b21320154fcefe5eba3a4a20386beaf))
* Simplify realm health monitoring logic and improve error handling in Keycloak reconciler ([2ca4a52](https://github.com/vriesdemichael/keycloak-operator/commit/2ca4a5237fd57ab2599e07ead2e41f966eef5700))
* **tests:** enhance integration test setup by optimizing dependency installation and removing unnecessary steps ([b55d6d9](https://github.com/vriesdemichael/keycloak-operator/commit/b55d6d98682c982caf8e1d36e6e67867c95f2d07))
* **tests:** streamline integration test execution and remove Makefile group ([09a2f71](https://github.com/vriesdemichael/keycloak-operator/commit/09a2f717056d109423898f4fd76d7d19b13cd235))
* Update status condition transition tests ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))


### Documentation

* add comprehensive integration testing guidelines ([cbd1325](https://github.com/vriesdemichael/keycloak-operator/commit/cbd13256e71d88a93bd0c5cb60199fad3340fb19))
* add comprehensive observability and security documentation ([8bb3448](https://github.com/vriesdemichael/keycloak-operator/commit/8bb3448a3206362300d0b4c23ee24e2021ec221a))
* add comprehensive Quick Start guide with examples ([723e6d1](https://github.com/vriesdemichael/keycloak-operator/commit/723e6d1e14bc990f4da7ad3958ac1527c4f86ab7))
* Add detailed planning section to CLAUDE.md for clearer implementation guidance ([badff54](https://github.com/vriesdemichael/keycloak-operator/commit/badff541695ac4b3b024eaa439ee597cf17509a3))
* add mandatory RELEASES.md check before commits in CLAUDE.md ([a329050](https://github.com/vriesdemichael/keycloak-operator/commit/a329050c1b5ce19c012ec9a274ca417cb3e83750))
* add SMTP configuration implementation plan ([67d2362](https://github.com/vriesdemichael/keycloak-operator/commit/67d2362fc16d58c8e0ecb65a86c4f524ca29db74))
* Add step-by-step guide for Keycloak API model integration ([8e9e456](https://github.com/vriesdemichael/keycloak-operator/commit/8e9e4569e09fd7d43d2dc15867b986740fbfddc3))
* **design:** add Keycloak state observability analysis ([120eb81](https://github.com/vriesdemichael/keycloak-operator/commit/120eb81c5e8bd4d28c1833f9afaa088f90ce0210))
* Implement robust cleanup system for integration tests ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* mark CRD-model schema alignment as completed ([e2124ab](https://github.com/vriesdemichael/keycloak-operator/commit/e2124ab92619d6d4a24edb63988ccda5a52e0980))
* mark redirect URI validation bug as fixed in TODO ([2d783fa](https://github.com/vriesdemichael/keycloak-operator/commit/2d783fac49f7de9e4a1d591d40e4ac31f942edf5))
* reorganize documentation structure and simplify README ([e0b7bef](https://github.com/vriesdemichael/keycloak-operator/commit/e0b7befc77a9f201965d39f88ef03041c4d5bd22))
* Update CLAUDE.md and TODO/manual-todos with new GitOps support details and commit message guidelines ([279f1a8](https://github.com/vriesdemichael/keycloak-operator/commit/279f1a89334f8f26be424caf5e93ff933d1523ca))
* Update CLAUDE.md with development setup and testing guidelines; refine Makefile targets and improve logging commands ([3deb56e](https://github.com/vriesdemichael/keycloak-operator/commit/3deb56e1819d2d541606c43217f572fc18c900b5))
* update manual-todos to mark CRD design improvements as complete ([80420e9](https://github.com/vriesdemichael/keycloak-operator/commit/80420e925823fc5db290ef4053091d007a110542))
* update phase 6B TODO to reflect production mode completion ([34b6b4d](https://github.com/vriesdemichael/keycloak-operator/commit/34b6b4d22c21dd5c85887e4482f21261582ed198))
