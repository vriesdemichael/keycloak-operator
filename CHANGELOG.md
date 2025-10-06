# Changelog

## [0.2.0](https://github.com/vriesdemichael/keycloak-operator/compare/operator-v0.1.0...operator-v0.2.0) (2025-10-06)


### ⚠ BREAKING CHANGES

* **ci:** Release configuration now uses container-based versioning instead of Python package versioning
* Remove spec.version field from Keycloak CRD and spec.enabled field from KeycloakRealm CRD
* Multiple CRD field renames and removals for consistency

### Features

* Add centralized operator design and RBAC security implementation plan ([17b3413](https://github.com/vriesdemichael/keycloak-operator/commit/17b3413aa1c21de636b342fd9af0ff7fcc48ad96))
* Add Keycloak version validation and update documentation for version requirements ([8fe9ca1](https://github.com/vriesdemichael/keycloak-operator/commit/8fe9ca1f9d88dbee3e6c66810e0cb037323b0181))
* add port-forward fixture for integration tests ([6d61987](https://github.com/vriesdemichael/keycloak-operator/commit/6d6198789568efec742506335fcca2141113eb83))
* enhance CNPG integration and admin credential management ([df75ccb](https://github.com/vriesdemichael/keycloak-operator/commit/df75ccbf3e04d6b17127c9f3f7e5351c8b3d8d69))
* implement deletion handler fixes and cascading deletion ([13d25bb](https://github.com/vriesdemichael/keycloak-operator/commit/13d25bb5082f0c6aaf367cedb53ab4a600d36d3b))
* implement secure SMTP configuration for KeycloakRealm ([d79ef1c](https://github.com/vriesdemichael/keycloak-operator/commit/d79ef1ca109c7dc21019932fb7fc2c1a025bee62))
* Introduce DEFAULT_KEYCLOAK_IMAGE constant for consistent Keycloak image usage ([06d060a](https://github.com/vriesdemichael/keycloak-operator/commit/06d060a6a9813e0ea1ca514e1c4b00927c1f9e81))
* **keycloak-client:** add service account role management ([c548b4b](https://github.com/vriesdemichael/keycloak-operator/commit/c548b4b1904208848ad3d1fbf046722ab99d4b15))
* **kubernetes:** Update database type mapping for Keycloak deployment configuration ([f949506](https://github.com/vriesdemichael/keycloak-operator/commit/f94950607dde501471f39b021df37808379e9ba5))
* **logging:** Enhance structured logging with additional fields for better observability ([f949506](https://github.com/vriesdemichael/keycloak-operator/commit/f94950607dde501471f39b021df37808379e9ba5))
* switch Keycloak to production mode with HTTP enabled for ingress TLS termination ([1e64bc9](https://github.com/vriesdemichael/keycloak-operator/commit/1e64bc9d8b6608b24df917f167f81dfd41f51569))
* Update intern implementation guide with recent feature completions and new tools ([8e9e456](https://github.com/vriesdemichael/keycloak-operator/commit/8e9e4569e09fd7d43d2dc15867b986740fbfddc3))


### Bug Fixes

* **ci:** correct release-please config for container-based releases ([732eaa7](https://github.com/vriesdemichael/keycloak-operator/commit/732eaa72313c7893a5b1595691365fc31d135722))
* **ci:** prevent image publishing when tests fail ([70952a2](https://github.com/vriesdemichael/keycloak-operator/commit/70952a24be23585e4442ac86605f790c3cb3eba7))
* convert class-scoped fixtures to synchronous for pytest-xdist compatibility ([816370c](https://github.com/vriesdemichael/keycloak-operator/commit/816370c1060c746586d2b2656d91f73a9e3378df))
* convert SMTP configuration values to strings for Keycloak API compatibility ([8ad98d0](https://github.com/vriesdemichael/keycloak-operator/commit/8ad98d006399fbbf8351f5762ba30c0bdf2fc236))
* Correct realm health monitoring logic to handle missing current realm ([0d11604](https://github.com/vriesdemichael/keycloak-operator/commit/0d11604b71afe0ba6367e650ebb51cd476d7ebe7))
* enforce same-namespace secrets and fix Pydantic model access ([56d448a](https://github.com/vriesdemichael/keycloak-operator/commit/56d448a1e834f7d7da60172976fa67da3dd6bc89))
* implement Keycloak-compliant redirect URI wildcard validation ([83e7742](https://github.com/vriesdemichael/keycloak-operator/commit/83e7742594ae6cc17b0698d4416a358565569033))
* Improve Kubernetes commands for PostgreSQL and Keycloak operator deployment in integration tests ([ad71e08](https://github.com/vriesdemichael/keycloak-operator/commit/ad71e08685986f1de8dcd38a9a481a6a50e54a06))
* **kubernetes:** Change health check ports to use management port for readiness and liveness probes ([f949506](https://github.com/vriesdemichael/keycloak-operator/commit/f94950607dde501471f39b021df37808379e9ba5))
* **realm_reconciler:** Simplify logging message for realm creation ([f949506](https://github.com/vriesdemichael/keycloak-operator/commit/f94950607dde501471f39b021df37808379e9ba5))
* replace asyncio.run() with synchronous polling in class-scoped fixtures ([5e7b390](https://github.com/vriesdemichael/keycloak-operator/commit/5e7b390e903fed37731d4d69365fa3a3d7336108))
* resolve Keycloak API reconciliation bugs and update to v26.4.0 ([fff123f](https://github.com/vriesdemichael/keycloak-operator/commit/fff123fb47749b8304a97f0a5963f240459f6f61))
* resolve operator reconciliation bugs ([ead662f](https://github.com/vriesdemichael/keycloak-operator/commit/ead662f3c19e2d8e345aeb554f7558caf9bfe5e8))
* StatusWrapper now updates patch.status directly instead of shadow copy ([7e0746d](https://github.com/vriesdemichael/keycloak-operator/commit/7e0746d4d996ca6bab88815dfae84c3a0440d2a6))
* Update critical production blockers with progress and remaining work ([8e9e456](https://github.com/vriesdemichael/keycloak-operator/commit/8e9e4569e09fd7d43d2dc15867b986740fbfddc3))


### Performance Improvements

* optimize integration tests with shared Keycloak instances and parallel execution ([a71d754](https://github.com/vriesdemichael/keycloak-operator/commit/a71d754d5c9558d2b2048ce0e88e4a1911706264))


### Code Refactoring

* align CRD schemas with Pydantic models for GitOps compliance ([c06001b](https://github.com/vriesdemichael/keycloak-operator/commit/c06001bfbc6dfff6f09aafe65a767918e7481cc2))
* consolidate TODO files and enhance Keycloak admin API ([350c88f](https://github.com/vriesdemichael/keycloak-operator/commit/350c88fb0899e166dcea1883c00b2d1c78eeeb90))
* **keycloak_admin:** Introduce validated request method for API calls with Pydantic models ([f949506](https://github.com/vriesdemichael/keycloak-operator/commit/f94950607dde501471f39b021df37808379e9ba5))
* remove version and enabled fields from CRDs for K8s-native design ([11cdf60](https://github.com/vriesdemichael/keycloak-operator/commit/11cdf60a1b21320154fcefe5eba3a4a20386beaf))
* Simplify realm health monitoring logic and improve error handling in Keycloak reconciler ([2ca4a52](https://github.com/vriesdemichael/keycloak-operator/commit/2ca4a5237fd57ab2599e07ead2e41f966eef5700))


### Documentation

* add comprehensive integration testing guidelines ([cbd1325](https://github.com/vriesdemichael/keycloak-operator/commit/cbd13256e71d88a93bd0c5cb60199fad3340fb19))
* Add detailed planning section to CLAUDE.md for clearer implementation guidance ([badff54](https://github.com/vriesdemichael/keycloak-operator/commit/badff541695ac4b3b024eaa439ee597cf17509a3))
* add mandatory RELEASES.md check before commits in CLAUDE.md ([a329050](https://github.com/vriesdemichael/keycloak-operator/commit/a329050c1b5ce19c012ec9a274ca417cb3e83750))
* add SMTP configuration implementation plan ([67d2362](https://github.com/vriesdemichael/keycloak-operator/commit/67d2362fc16d58c8e0ecb65a86c4f524ca29db74))
* Add step-by-step guide for Keycloak API model integration ([8e9e456](https://github.com/vriesdemichael/keycloak-operator/commit/8e9e4569e09fd7d43d2dc15867b986740fbfddc3))
* mark CRD-model schema alignment as completed ([e2124ab](https://github.com/vriesdemichael/keycloak-operator/commit/e2124ab92619d6d4a24edb63988ccda5a52e0980))
* mark redirect URI validation bug as fixed in TODO ([2d783fa](https://github.com/vriesdemichael/keycloak-operator/commit/2d783fac49f7de9e4a1d591d40e4ac31f942edf5))
* Update CLAUDE.md and TODO/manual-todos with new GitOps support details and commit message guidelines ([279f1a8](https://github.com/vriesdemichael/keycloak-operator/commit/279f1a89334f8f26be424caf5e93ff933d1523ca))
* Update CLAUDE.md with development setup and testing guidelines; refine Makefile targets and improve logging commands ([3deb56e](https://github.com/vriesdemichael/keycloak-operator/commit/3deb56e1819d2d541606c43217f572fc18c900b5))
* update manual-todos to mark CRD design improvements as complete ([80420e9](https://github.com/vriesdemichael/keycloak-operator/commit/80420e925823fc5db290ef4053091d007a110542))
* update phase 6B TODO to reflect production mode completion ([34b6b4d](https://github.com/vriesdemichael/keycloak-operator/commit/34b6b4d22c21dd5c85887e4482f21261582ed198))
