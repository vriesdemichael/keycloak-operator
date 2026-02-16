# Changelog

## [0.7.15](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.7.14...operator-image-v0.7.15) (2026-02-16)


### Bug Fixes

* **operator-image:** bump pydantic-settings from 2.12.0 to 2.13.0 ([0328bdf](https://github.com/vriesdemichael/keycloak-operator/commit/0328bdfc0aa0cdc7edd5cd471683e0c566cada39))

## [0.7.14](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.7.13...operator-image-v0.7.14) (2026-02-16)


### Bug Fixes

* **operator:** address remaining review comments ([5281bc4](https://github.com/vriesdemichael/keycloak-operator/commit/5281bc41a0a7dfa3b626a1bee9c21687ca8719d1))
* **operator:** address review comments for Taskfile migration ([de9bbe6](https://github.com/vriesdemichael/keycloak-operator/commit/de9bbe68bfc098738584ed67ee36ea55eee1168a))

## [0.7.13](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.7.12...operator-image-v0.7.13) (2026-02-14)


### Bug Fixes

* **operator:** address review comments ([ee9b705](https://github.com/vriesdemichael/keycloak-operator/commit/ee9b705cb1984c584352d9d7b22de75e370f5f30))

## [0.7.12](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.7.11...operator-image-v0.7.12) (2026-02-14)


### Features

* **chart-client+operator:** add support for manual client secrets (issue [#495](https://github.com/vriesdemichael/keycloak-operator/issues/495)) ([06359dd](https://github.com/vriesdemichael/keycloak-operator/commit/06359ddbac14ab27194663929610efd759ea2eab))


### Bug Fixes

* address PR review comments ([c7d39bd](https://github.com/vriesdemichael/keycloak-operator/commit/c7d39bdfe727c6a102c81af8b8b87f80db29daa1))
* **chart-client+operator:** resolve helm validation and ci failures ([e634fe3](https://github.com/vriesdemichael/keycloak-operator/commit/e634fe39ad9eabffb3139b84af5ba6d7ccc019c0))
* **operator:** keycloak admin tokens are now being reused instead of recreated for every interaction ([0bc4ca7](https://github.com/vriesdemichael/keycloak-operator/commit/0bc4ca75aa19c343adffd1fbec9a310e994ce04a))

## [0.7.11](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.7.10...operator-image-v0.7.11) (2026-02-12)


### Documentation

* update readme badges and links ([#494](https://github.com/vriesdemichael/keycloak-operator/issues/494)) ([9dddfa8](https://github.com/vriesdemichael/keycloak-operator/commit/9dddfa8b6ccc1fbf5ba19237eaa197ddd26dafb6))

## [0.7.10](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.7.9...operator-image-v0.7.10) (2026-02-11)


### Bug Fixes

* **operator-image:** bump cryptography from 46.0.3 to 46.0.5 ([a8ed76e](https://github.com/vriesdemichael/keycloak-operator/commit/a8ed76e955e23d524040f02668803066e2639c10))

## [0.7.9](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.7.8...operator-image-v0.7.9) (2026-02-09)


### Bug Fixes

* **chart-operator+operator:** address PR review comments ([0295cc5](https://github.com/vriesdemichael/keycloak-operator/commit/0295cc59b036fa6c0fcc334a27af8bd69b96bde0))
* **chart-operator+operator:** reduce Prometheus metric cardinality ([5ea9409](https://github.com/vriesdemichael/keycloak-operator/commit/5ea9409614d20dc85cc7be4d2bfd03b23f4888d8)), closes [#171](https://github.com/vriesdemichael/keycloak-operator/issues/171)
* **operator:** fix local coverage combination in make test-unit ([9041ed5](https://github.com/vriesdemichael/keycloak-operator/commit/9041ed5719ea1470d91cf78a451493f483f45fff))

## [0.7.8](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.7.7...operator-image-v0.7.8) (2026-02-08)


### Features

* **operator:** detect build mismatch and raise permanent ConfigurationError ([9cf1bee](https://github.com/vriesdemichael/keycloak-operator/commit/9cf1beeb448cee11887138ef36709b7470fd8619))


### Bug Fixes

* **chart-operator+operator:** address PR review comments and add conditional --optimized flag ([3cd442c](https://github.com/vriesdemichael/keycloak-operator/commit/3cd442c3804de6885ed46d6f3e2eab8008091779))
* **chart-operator+operator:** change optimized default to false and address review comments ([a749e47](https://github.com/vriesdemichael/keycloak-operator/commit/a749e471a075088f51330cf54bed991fc4195fde))
* **operator:** fix unit test failures and load both keycloak image variants ([3414949](https://github.com/vriesdemichael/keycloak-operator/commit/3414949db99f939cc963da43e90b58485d425a92))

## [0.7.7](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.7.6...operator-image-v0.7.7) (2026-02-06)


### Bug Fixes

* **operator:** fix organization tests being skipped ([#463](https://github.com/vriesdemichael/keycloak-operator/issues/463)) ([50b96db](https://github.com/vriesdemichael/keycloak-operator/commit/50b96db28a6707bb315cdbceea5b097e137a5fd8))
* **operator:** skip organization config when feature not enabled ([12a3a0f](https://github.com/vriesdemichael/keycloak-operator/commit/12a3a0f2a485fb44b87acbba4348547f8f1929d1))

## [0.7.6](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.7.5...operator-image-v0.7.6) (2026-02-05)


### Bug Fixes

* **operator-image:** pin kopf to 1.40.1 to avoid memory leak ([b386b91](https://github.com/vriesdemichael/keycloak-operator/commit/b386b917da8d8b18357a7fd8a91db5e0a717dc7a))

## [0.7.5](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.7.4...operator-image-v0.7.5) (2026-02-03)


### Features

* **chart-client+chart-operator+chart-realm+operator:** add authorization and organization feature parity ([9979fd0](https://github.com/vriesdemichael/keycloak-operator/commit/9979fd07e10d53ac2fe654f9cdc927e06780f8e7))
* **operator:** implement organization IdP linking and add integration tests ([5c60496](https://github.com/vriesdemichael/keycloak-operator/commit/5c604961bbf236c8192c295ad975a6ded4bd06b1)), closes [#454](https://github.com/vriesdemichael/keycloak-operator/issues/454)


### Bug Fixes

* **operator:** address PR review comments and add unit tests ([d0aa0d6](https://github.com/vriesdemichael/keycloak-operator/commit/d0aa0d6b95dd29825f7bb9c5aefeeb126f07ecc6))

## [0.7.4](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.7.3...operator-image-v0.7.4) (2026-02-02)


### Features

* **operator:** add OpenTelemetry distributed tracing support ([5dc4dc0](https://github.com/vriesdemichael/keycloak-operator/commit/5dc4dc0f80179970a7771890e05cb78f650c96dd)), closes [#172](https://github.com/vriesdemichael/keycloak-operator/issues/172)
* **operator:** add trace-based debugging infrastructure for integration tests ([cf91123](https://github.com/vriesdemichael/keycloak-operator/commit/cf9112378d007d45e76b75f2e167dd21ce8f8ac7))


### Bug Fixes

* **operator:** address Copilot review feedback for tracing ([4f8e99c](https://github.com/vriesdemichael/keycloak-operator/commit/4f8e99c0daffbf5354cf3eef7d508d0b0835384a))


### Documentation

* **operator:** document trace-based debugging workflow in ADR 082 and TESTING.md ([1fb607a](https://github.com/vriesdemichael/keycloak-operator/commit/1fb607ab33d8646d5d7f0e219480098c41028cbf))

## [0.7.3](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.7.2...operator-image-v0.7.3) (2026-02-01)


### Features

* **chart-client+operator:** add automated client secret rotation ([d95102f](https://github.com/vriesdemichael/keycloak-operator/commit/d95102f7d9d78d85d61df3960cb121f7eae8eac0))
* **operator:** add secret rotation daemon and fix thundering herd ([0e8b4ac](https://github.com/vriesdemichael/keycloak-operator/commit/0e8b4ac21e73cdb9ab14055eeaec858ec6979112))


### Bug Fixes

* **chart-client+operator:** complete secret rotation helm chart and fix review comments ([073ac06](https://github.com/vriesdemichael/keycloak-operator/commit/073ac06e9beb1c3c20d89bc19c9ee0331c8a76d8))

## [0.7.2](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.7.1...operator-image-v0.7.2) (2026-01-30)


### Features

* **operator:** implement security restrictions for client roles and mappers ([d653dbd](https://github.com/vriesdemichael/keycloak-operator/commit/d653dbd42c0c8ec765903c30f492ae6c6345add9))


### Bug Fixes

* **operator:** harden security restrictions and address review comments ([4d0a1dd](https://github.com/vriesdemichael/keycloak-operator/commit/4d0a1dd7f6ecb9ae4a4291892c4664aa97bd2c7a))


### Code Refactoring

* **operator:** remove redundant import ([661c406](https://github.com/vriesdemichael/keycloak-operator/commit/661c4064a98ee87240f70d6433f7605eefa2481d))

## [0.7.1](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.7.0...operator-image-v0.7.1) (2026-01-29)


### Features

* **operator-image:** add OCI image labels ([5bc3332](https://github.com/vriesdemichael/keycloak-operator/commit/5bc3332a02595d61d324496d67941e5a4699360a)), closes [#390](https://github.com/vriesdemichael/keycloak-operator/issues/390)

## [0.7.0](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.6.4...operator-image-v0.7.0) (2026-01-29)


### ⚠ BREAKING CHANGES

* **chart-client+chart-operator+chart-realm:** Helm chart distribution moved to OCI registry
* **operator:** IDP secrets must use configSecrets field, plaintext forbidden
* **webhooks:** Admission webhooks now require cert-manager to be installed

### Features

* **chart-client+chart-operator+chart-realm:** migrate to OCI registry in GHCR ([3d122c6](https://github.com/vriesdemichael/keycloak-operator/commit/3d122c6b78851ef571b5d4d4af436039e45bb9d0))
* **chart-client+chart-operator+operator:** add missing client settings fields ([0404a43](https://github.com/vriesdemichael/keycloak-operator/commit/0404a43b24fc8988fce32414f75a2b012c68168d))
* **chart-client+operator:** add labels and annotations to managed secrets ([a2fcd36](https://github.com/vriesdemichael/keycloak-operator/commit/a2fcd36ef5e7b46c8b53a747a99353074eb3823e))
* **chart-client+operator:** improve client secret management and monitoring ([555c173](https://github.com/vriesdemichael/keycloak-operator/commit/555c173ca89b8d2f587fd7e7a08e5ad52ae06b57))
* **chart-operator+chart-realm+operator:** add complete realm role and group management ([add7630](https://github.com/vriesdemichael/keycloak-operator/commit/add763062f9c8d62f3131fba55361d2e7bd40a62))
* **chart-operator+chart-realm+operator:** add password policy and improve events config ([48e91af](https://github.com/vriesdemichael/keycloak-operator/commit/48e91af5ca03940d1e86eb6cc0c50e4c595973f6)), closes [#311](https://github.com/vriesdemichael/keycloak-operator/issues/311)
* **chart-operator:** add configurable timer intervals for reconciliation ([9ace7e4](https://github.com/vriesdemichael/keycloak-operator/commit/9ace7e47f6406263e9d5c13d0b48755348729102))
* **chart-realm+operator:** add authentication flow and required action support ([ec8092e](https://github.com/vriesdemichael/keycloak-operator/commit/ec8092e33e1255a6e479f1108d0a12a5e518ebf6)), closes [#180](https://github.com/vriesdemichael/keycloak-operator/issues/180)
* **chart-realm:** add client scope management ([bd63d5b](https://github.com/vriesdemichael/keycloak-operator/commit/bd63d5bc4ef514020575390ac2a4eb51d5b57279)), closes [#181](https://github.com/vriesdemichael/keycloak-operator/issues/181)
* **operator:** add comprehensive test coverage infrastructure ([22013f5](https://github.com/vriesdemichael/keycloak-operator/commit/22013f5acbeeb3a9b92c00420ab3263a723f0ed8)), closes [#110](https://github.com/vriesdemichael/keycloak-operator/issues/110)
* **operator:** add multi-version keycloak support (v24-v26) ([cf7c552](https://github.com/vriesdemichael/keycloak-operator/commit/cf7c5521c1f6a9e92c12b58c48e8637757a9e63d))
* **operator:** add quiet logging mode for health probes and webhooks ([76fb7d2](https://github.com/vriesdemichael/keycloak-operator/commit/76fb7d221c31a6921507f9b7c99f1d0d75510ab9))
* **operator:** add stuck finalizer detection to timer handlers ([c803c08](https://github.com/vriesdemichael/keycloak-operator/commit/c803c08916ca69d22f700ec5fbf92376b131c9e7))
* **operator:** add user federation CRUD methods to Keycloak admin client ([965195b](https://github.com/vriesdemichael/keycloak-operator/commit/965195bf981f4d90ae21562087c9cd397fd6f7e3))
* **operator:** Add user federation status to KeycloakRealm CR status ([3c61f98](https://github.com/vriesdemichael/keycloak-operator/commit/3c61f98274a2c9270f169f1063e5596ae062f15d))
* **operator:** align Pydantic models with CRD schemas ([a78c6e5](https://github.com/vriesdemichael/keycloak-operator/commit/a78c6e5a93703b8a0ed9ad80d76ccbc0235f943b))
* **operator:** centralize configuration with pydantic-settings ([a99fd58](https://github.com/vriesdemichael/keycloak-operator/commit/a99fd587667f8efdb020e22eae3d0741b07aaad5)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* **operator:** complete identity provider lifecycle and mapper support ([3b88db5](https://github.com/vriesdemichael/keycloak-operator/commit/3b88db5467eea2b9a4a4274804fa216b8315d0e5)), closes [#178](https://github.com/vriesdemichael/keycloak-operator/issues/178)
* **operator:** complete integration coverage collection ([56e0b2b](https://github.com/vriesdemichael/keycloak-operator/commit/56e0b2b1e702c620931e968ab19c7f0e8b3fa4f0))
* **operator:** enhance user federation models with LDAP/AD/Kerberos support ([2b5f4c6](https://github.com/vriesdemichael/keycloak-operator/commit/2b5f4c63a5cd75aed07c7e58bd38516cf7f0659d))
* **operator:** fix pydantic-settings environment variable configuration ([d1cea04](https://github.com/vriesdemichael/keycloak-operator/commit/d1cea04948658df46e9209d1ba37bdac20c0dab4)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* **operator:** implement drift remediation for realms and clients ([1ab50bc](https://github.com/vriesdemichael/keycloak-operator/commit/1ab50bcb05ac3204b81d6e62ad12811408254707))
* **operator:** implement integration test coverage collection via SIGUSR1 ([6cd88fe](https://github.com/vriesdemichael/keycloak-operator/commit/6cd88fe70d2a798bf64725946cff470a07a5fc5a)), closes [#111](https://github.com/vriesdemichael/keycloak-operator/issues/111)
* **operator:** implement JGroups DNS_PING for horizontal scaling ([3a50ee6](https://github.com/vriesdemichael/keycloak-operator/commit/3a50ee66d2bf7e6048673b174ceee34c329d32c5)), closes [#347](https://github.com/vriesdemichael/keycloak-operator/issues/347)
* **operator:** implement user federation CRUD lifecycle in realm reconciler ([9d05490](https://github.com/vriesdemichael/keycloak-operator/commit/9d05490b867ffa764b378f37970cc4725ed6158b))
* **operator:** improve finalizer debugging and logging ([d7948c2](https://github.com/vriesdemichael/keycloak-operator/commit/d7948c22de78ff01db49c3fb56ae901c3d0f6c9e))
* **operator:** require secret refs for IDP secrets ([be8b366](https://github.com/vriesdemichael/keycloak-operator/commit/be8b3665c67140625b66aa097e7c44e6094818b2))
* **operator:** upgrade base image to python 3.14-slim ([6bd4c80](https://github.com/vriesdemichael/keycloak-operator/commit/6bd4c803294e82e5474c7ab2254075d0816adc4f))
* **operator:** Upgrade to python 3.14 (alpine image for less vulnerabilities) ([50961c6](https://github.com/vriesdemichael/keycloak-operator/commit/50961c6aa13503060859b98523e548705c02c11c))
* use SVG logo and update favicon ([44ee622](https://github.com/vriesdemichael/keycloak-operator/commit/44ee6221c802b5cefac3df0d986d897d6887203a))
* **webhooks:** switch to cert-manager for webhook TLS certificates ([e23dbde](https://github.com/vriesdemichael/keycloak-operator/commit/e23dbde72bb9b60a9eff2a0abb28f0ca88d56ea8))


### Bug Fixes

* allow test tags in operator chart schema ([71012b7](https://github.com/vriesdemichael/keycloak-operator/commit/71012b71951c1bce1c522fc1bed68857859afda8))
* **chart-client+chart-operator+operator:** address multiple issues ([#290](https://github.com/vriesdemichael/keycloak-operator/issues/290), [#294](https://github.com/vriesdemichael/keycloak-operator/issues/294), [#170](https://github.com/vriesdemichael/keycloak-operator/issues/170), [#168](https://github.com/vriesdemichael/keycloak-operator/issues/168)) ([23a1dba](https://github.com/vriesdemichael/keycloak-operator/commit/23a1dbafabfd0deb35f6c528b560df1cb19da1e5))
* configure webhook server with service DNS hostname ([c195630](https://github.com/vriesdemichael/keycloak-operator/commit/c1956307c0d9e26b05009ec5295e9732d9c79d7f))
* create coverage directory in container and fix collection workflow ([91a8114](https://github.com/vriesdemichael/keycloak-operator/commit/91a81147af9f397d6290b046a7fad2a94512a0b8))
* disable webhook auto-management and default to false ([5104c5f](https://github.com/vriesdemichael/keycloak-operator/commit/5104c5f385921d45dc4aa754bb29df7355a0953b))
* import all webhook modules to register handlers ([ff7acd2](https://github.com/vriesdemichael/keycloak-operator/commit/ff7acd27d7084bce9adadae9cd68135d3766adc2))
* **operator-image:** bump aiohttp in the patch-updates group ([a75460a](https://github.com/vriesdemichael/keycloak-operator/commit/a75460a0d3b26271f8a8751588d121fa87d53887))
* **operator-image:** bump kopf from 1.39.1 to 1.40.0 ([be0b316](https://github.com/vriesdemichael/keycloak-operator/commit/be0b316ea0cc4580e1d001671ce204cf2191aa0e))
* **operator-image:** bump kopf in the patch-updates group ([eb685ae](https://github.com/vriesdemichael/keycloak-operator/commit/eb685ae9b3b480b5251d7f98198587b1b8e7d9ff))
* **operator-image:** bump kubernetes from 33.1.0 to 35.0.0 ([81dd693](https://github.com/vriesdemichael/keycloak-operator/commit/81dd6930f2a5dbdaedb6837fed858d3f1d038a4b))
* **operator-image:** bump prometheus-client from 0.23.1 to 0.24.1 ([cc7d50d](https://github.com/vriesdemichael/keycloak-operator/commit/cc7d50df4fcf3b1ccaeeaaab8cef71474616a6b3))
* **operator-image:** bump virtualenv from 20.35.4 to 20.36.1 ([8de6a4f](https://github.com/vriesdemichael/keycloak-operator/commit/8de6a4fe7af6bdad1d3f36d5e1bc949859d7522f))
* **operator-image:** enable full upgrades for security ([ea2dcdf](https://github.com/vriesdemichael/keycloak-operator/commit/ea2dcdfea9dae71a506af9d9a81d3b460f7a288d))
* **operator-image:** ensure deterministic build with pinned versions ([df2f0d9](https://github.com/vriesdemichael/keycloak-operator/commit/df2f0d97b0e02932142416d6c7b68899489e054a))
* **operator-image:** switch to bleeding edge Trixie base with secure setuptools ([dc8a529](https://github.com/vriesdemichael/keycloak-operator/commit/dc8a52980c7dacc791defd93cec173c27d79d5f3))
* **operator-image:** switch to bookworm and upgrade setuptools ([9475dbc](https://github.com/vriesdemichael/keycloak-operator/commit/9475dbca9fff98acb7cfbc6bfff97c5ae25b1af7))
* **operator-image:** upgrade system packages and pip in image ([5b6fb95](https://github.com/vriesdemichael/keycloak-operator/commit/5b6fb95eb312b5437d1dc7031df0110f192f9a7a))
* **operator:** add client_scopes_count to status model ([1f8766a](https://github.com/vriesdemichael/keycloak-operator/commit/1f8766a2673ae2ff84dd306b330527d2522b20e7))
* **operator:** add missing namespace parameters to API calls ([0097651](https://github.com/vriesdemichael/keycloak-operator/commit/0097651ced1cf501bba699e28f33d130b006614b))
* **operator:** add namespace param to user federation admin client methods ([651d49b](https://github.com/vriesdemichael/keycloak-operator/commit/651d49b69fef7448aeecf017cca963ca6c8dec60))
* **operator:** add operator_namespace override for drift detector tests ([3ec8597](https://github.com/vriesdemichael/keycloak-operator/commit/3ec8597f3fccf6b86531afe3fbcbe4c1f1468935))
* **operator:** address PR review comments ([ec31e25](https://github.com/vriesdemichael/keycloak-operator/commit/ec31e2504efc4dc9243b63a1b9a5b89da9372b1f))
* **operator:** address PR review comments and expand documentation ([7b411fd](https://github.com/vriesdemichael/keycloak-operator/commit/7b411fd9f2098fdfade94eab508b50e3b7dffc13))
* **operator:** address review comments ([d447b6e](https://github.com/vriesdemichael/keycloak-operator/commit/d447b6e47f790984f43c0e2abb6ac541c8e67aa6))
* **operator:** address review comments on drift detection ([f30aa69](https://github.com/vriesdemichael/keycloak-operator/commit/f30aa695431d81ec347171469991a4d0e8e9d8a5))
* **operator:** conditionally import webhook modules when webhooks enabled ([7458003](https://github.com/vriesdemichael/keycloak-operator/commit/7458003d38027626da63885aabea71b5d066099e)), closes [#237](https://github.com/vriesdemichael/keycloak-operator/issues/237)
* **operator:** correct parameter order in _fetch_secret_value calls ([e36ae7c](https://github.com/vriesdemichael/keycloak-operator/commit/e36ae7ca199f0a8efa06283a4d85227af1365904))
* **operator:** database passwordSecret support and test fixes ([3389f69](https://github.com/vriesdemichael/keycloak-operator/commit/3389f695a3a10f8fbeb7e9b0f8cb494b55c3f628))
* **operator:** ensure secret is updated when only metadata changes ([17155e1](https://github.com/vriesdemichael/keycloak-operator/commit/17155e1d095e8edd2cb361d2bb882e7fd1675b29))
* **operator:** exclude read-only fields from group update requests ([3a67d59](https://github.com/vriesdemichael/keycloak-operator/commit/3a67d59e96d4b1e559e188f686ce301314fcee59))
* **operator:** fix async update handler for authentication flows ([5e393c8](https://github.com/vriesdemichael/keycloak-operator/commit/5e393c85c33c2f0b6af9f53aa601646d5786916a))
* **operator:** handle 409 conflict as idempotent success for add operations ([37d7c0b](https://github.com/vriesdemichael/keycloak-operator/commit/37d7c0b30c35ab54b18653c4784dcaa4d0f3298e))
* **operator:** handle basic realm field updates in do_update method ([8e8b9a5](https://github.com/vriesdemichael/keycloak-operator/commit/8e8b9a5481b2f42b82c01b1dcbf6da3438f9cb3a))
* **operator:** handle realm deletion gracefully in client cleanup ([211e943](https://github.com/vriesdemichael/keycloak-operator/commit/211e9439edca301ab05e442a7f91e30aa6ba21a2))
* **operator:** identity provider updates use PUT instead of POST ([068a1a9](https://github.com/vriesdemichael/keycloak-operator/commit/068a1a9c0175d74a01099aeadd56f42c6c691abb))
* **operator:** improve finalizer robustness and simplify cascade deletion ([665a282](https://github.com/vriesdemichael/keycloak-operator/commit/665a2825ad2be73af06f05e32d4b382e69218c19))
* **operator:** include id field in update requests for roles and groups ([b82ed27](https://github.com/vriesdemichael/keycloak-operator/commit/b82ed27540d033d140ee1ba6fc5deb88d3a19303))
* **operator:** make client scope operations idempotent ([d7a78fe](https://github.com/vriesdemichael/keycloak-operator/commit/d7a78fe4248ffc849cc808a2947d6529ebe99fa6))
* **operator:** pin urllib3&gt;=2.6.0 to fix CVE ([6566b80](https://github.com/vriesdemichael/keycloak-operator/commit/6566b80f487a1e31f6b86b7e204f4c11b1c19845))
* **operator:** prevent event loop closed errors in httpx client cache ([c7bfa11](https://github.com/vriesdemichael/keycloak-operator/commit/c7bfa113b7757b26928d9c9fea6dca3624de2d2d))
* **operator:** raise error instead of returning 'unknown' client UUID ([46036ef](https://github.com/vriesdemichael/keycloak-operator/commit/46036ef98f0046d119aeea710b875d126cdbe60d))
* **operator:** remove duplicate deletion logic from resume handlers ([d7e8a6d](https://github.com/vriesdemichael/keycloak-operator/commit/d7e8a6d8e454993fa69b28c6564edebfe0a9c097))
* **operator:** remove status param from keycloak cleanup helper ([bb5cc32](https://github.com/vriesdemichael/keycloak-operator/commit/bb5cc326a401bd62cf824e566824c526e0615a6c))
* **operator:** replace secret watcher with health check polling ([1e7aa30](https://github.com/vriesdemichael/keycloak-operator/commit/1e7aa3043ea09ba7adc90e070cc245d9ab4f4b38))
* **operator:** resolve BruteForceStrategy enum serialization and complete multi-version support ([3afb2ea](https://github.com/vriesdemichael/keycloak-operator/commit/3afb2ea815aebf7afd10050db96ad013e4b2a2d2))
* **operator:** resolve drift detection bugs and test failures ([21b3e7e](https://github.com/vriesdemichael/keycloak-operator/commit/21b3e7e9313aa531da75a6e0a41c1ce33f5fdccc))
* **operator:** resolve ingress hostname bug and improve type safety ([36b183e](https://github.com/vriesdemichael/keycloak-operator/commit/36b183e5252c0ddac834d45161df9b16dd0e70f1))
* **operator:** resolve JSON serialization and test timing issues ([266c39c](https://github.com/vriesdemichael/keycloak-operator/commit/266c39ce4dd8635f25bbee966b4394e772aefc39))
* **operator:** resolve linting and test issues for drift detection ([6126533](https://github.com/vriesdemichael/keycloak-operator/commit/612653393d33f58319f0a583f7afe52405c959d1))
* **operator:** resolve linting issues and test configuration ([ece5b52](https://github.com/vriesdemichael/keycloak-operator/commit/ece5b523bf55733b33cd7b037aa9e1b18c1d4d3e))
* **operator:** resolve type checker warnings after dependency upgrade ([c4eb820](https://github.com/vriesdemichael/keycloak-operator/commit/c4eb82084a325e553b71f084d0f50e7183bab289))
* **operator:** restore secret watcher with namespace RBAC support ([e49ff89](https://github.com/vriesdemichael/keycloak-operator/commit/e49ff893e14aecd15e81b5cf8dcd416fccc8f86a))
* **operator:** simplify drift detection using timestamp comparison ([df319fd](https://github.com/vriesdemichael/keycloak-operator/commit/df319fd57d61c8670142b7e3154f517c56c32d6a))
* **operator:** update package metadata with correct author info ([d1dafa5](https://github.com/vriesdemichael/keycloak-operator/commit/d1dafa5ed6e2518fc0829e218ad50741255d1561))
* **operator:** update pyasn1 to 0.6.2 and fix integration test ([e4ce877](https://github.com/vriesdemichael/keycloak-operator/commit/e4ce87702b7df8970b7e30c213dbc585aa3ab715))
* **operator:** upgrade urllib3 to 2.6.3 for CVE-2026-21441 ([f111daa](https://github.com/vriesdemichael/keycloak-operator/commit/f111daa91ccd2a2eb582b5c55be597632e7bdca1))
* **operator:** use asyncio.to_thread for webhook K8s API calls ([5ae4f19](https://github.com/vriesdemichael/keycloak-operator/commit/5ae4f1915c0b46c9cc4db54a6e7487a395395692))
* **operator:** use client-side filtering for user federation components ([fde2a80](https://github.com/vriesdemichael/keycloak-operator/commit/fde2a8012190955809e7e2c23582373169d1c0f7))
* **operator:** use correct camelCase field names in realm update handler ([b1ab515](https://github.com/vriesdemichael/keycloak-operator/commit/b1ab5152bf81b108776141e730c2d3fce0ec04d0))
* **operator:** use correct Keycloak CR name in health check timers ([76fdc59](https://github.com/vriesdemichael/keycloak-operator/commit/76fdc5940b8ad778ed0f54788a5919c6e10b8780))
* **operator:** use coverage run in CMD for proper instrumentation ([10229e2](https://github.com/vriesdemichael/keycloak-operator/commit/10229e2a261d90b60c2fa052efd7dd12bb64e3ac))
* **operator:** use realm ID instead of realm name for federation parentId ([d79321d](https://github.com/vriesdemichael/keycloak-operator/commit/d79321dfe8191c502ab0ea74fcfb47ffdc70d954))
* **operator:** user federation tests and LDAP attribute config keys ([595fbb1](https://github.com/vriesdemichael/keycloak-operator/commit/595fbb11fab3f7cfbcf2e9d5d6843c55c26a0e97)), closes [#179](https://github.com/vriesdemichael/keycloak-operator/issues/179)
* **operator:** verify ownership before deleting Keycloak resources ([114b460](https://github.com/vriesdemichael/keycloak-operator/commit/114b4606c4162a3e0e21b80b4dc87e2dc95f5968))
* prevent premature operator cleanup in pytest-xdist workers ([85e81f0](https://github.com/vriesdemichael/keycloak-operator/commit/85e81f028416a3294eacd469aa80623eedef99e3))
* remove tests for deleted periodic_leadership_check function ([eb4c6ac](https://github.com/vriesdemichael/keycloak-operator/commit/eb4c6acc9e732f91567a26e6d4dbe1e9453c7a60))
* replace old keycloak.mdvr.nl API group with vriesdemichael.github.io ([cb5cbc3](https://github.com/vriesdemichael/keycloak-operator/commit/cb5cbc3f5045c2f1a5fe6f46f580108940f5caaf))


### Performance Improvements

* implement generation-based skip to avoid redundant reconciliations ([8f80267](https://github.com/vriesdemichael/keycloak-operator/commit/8f802678913d965abb69705cf17080bfffa8cca2)), closes [#184](https://github.com/vriesdemichael/keycloak-operator/issues/184)


### Code Refactoring

* address CodeQL false positive and remove unused method ([f21e83c](https://github.com/vriesdemichael/keycloak-operator/commit/f21e83ce1a34b69ec3ae2429883d5ea79d894501))
* **operator:** add decorators for consistent error handling ([22834d5](https://github.com/vriesdemichael/keycloak-operator/commit/22834d568bfb8df995b0a13dc6a543313aa9f18f))
* **operator:** address PR review comments ([a5de970](https://github.com/vriesdemichael/keycloak-operator/commit/a5de970dcaf100bf27e78c7e6fd2c14773d0dca6))
* **operator:** apply error handling decorators to client scope methods ([b1b266b](https://github.com/vriesdemichael/keycloak-operator/commit/b1b266bd8cf5c423a471fb1aa732b4f7afcc3902))
* **operator:** make timer intervals configurable and deduplicate cleanup ([00cb3a3](https://github.com/vriesdemichael/keycloak-operator/commit/00cb3a3c8ea41362f3bd12ea59be9ad758540d00))
* **operator:** simplify drift detection to single Keycloak instance ([624c684](https://github.com/vriesdemichael/keycloak-operator/commit/624c684b70a8f3afec024004b9d5d1f8451f8143))
* **operator:** simplify multi-version support to single canonical model ([c86d345](https://github.com/vriesdemichael/keycloak-operator/commit/c86d3453caf65558e2ec881ff8ec416539acf5fe))
* **operator:** unify Dockerfile with multi-stage targets ([44e5e6c](https://github.com/vriesdemichael/keycloak-operator/commit/44e5e6cc46bb1a0f1a31e6dfe429ce1732b34937))
* split CI/CD workflow into composite actions ([005bde8](https://github.com/vriesdemichael/keycloak-operator/commit/005bde8d6b3366b432d01265cc604fdff2a2a436))
* split CI/CD workflow into composite actions ([896c675](https://github.com/vriesdemichael/keycloak-operator/commit/896c675ced394d9bfeb93ca0dc69e8526d1916f9))
* use unified Kopf-managed finalizer ([9d0d94d](https://github.com/vriesdemichael/keycloak-operator/commit/9d0d94d1a2e871b7ca0164ddb139360346b4aef1))


### Documentation

* add CI/CD and documentation issues task list ([8de19c5](https://github.com/vriesdemichael/keycloak-operator/commit/8de19c56243b657fd614b842ff23bd3c2d0b3179))
* add custom logo and favicon ([005bde8](https://github.com/vriesdemichael/keycloak-operator/commit/005bde8d6b3366b432d01265cc604fdff2a2a436))
* add custom logo and favicon ([896c675](https://github.com/vriesdemichael/keycloak-operator/commit/896c675ced394d9bfeb93ca0dc69e8526d1916f9))
* add Decision Records as separate tab with tag filtering ([2327638](https://github.com/vriesdemichael/keycloak-operator/commit/232763871aee660e29e0627372de2cb8a5739364))
* add Keycloak brand colors and improved styling ([f10f5a3](https://github.com/vriesdemichael/keycloak-operator/commit/f10f5a3957d81392dcc8c7ff710c1652dabd4e3c))
* add Mermaid diagram support and hide home TOC ([ca05577](https://github.com/vriesdemichael/keycloak-operator/commit/ca055773c91714f27477750f2575d3d467b21799))
* address review comments - remove more spec files and redundant version info ([063545a](https://github.com/vriesdemichael/keycloak-operator/commit/063545aaa4f6a3da87a363faccd96197a85b893b))
* enhance dark mode styling with better contrast ([83f77b5](https://github.com/vriesdemichael/keycloak-operator/commit/83f77b5aa0e7459e1692bb257fd606608c5e90da))
* extend doc validation with external schemas and K8s resources ([5e00d2b](https://github.com/vriesdemichael/keycloak-operator/commit/5e00d2b7a14479b08785ae4aa160a29abfe42858))
* final cleanup of remaining token references ([96e6086](https://github.com/vriesdemichael/keycloak-operator/commit/96e6086d173abdfedec0bb197a94cf50afb7690a))
* fix documentation issues from user feedback ([4ccef64](https://github.com/vriesdemichael/keycloak-operator/commit/4ccef641077edc4c9d7462bcbbdaeab448e4043c))
* fix multi-version documentation and remove large spec file ([71af087](https://github.com/vriesdemichael/keycloak-operator/commit/71af0877bd14f7ab930d85c6b6dc6f82154ff2c8))
* move Home into Getting Started section ([86552fb](https://github.com/vriesdemichael/keycloak-operator/commit/86552fbc25376c14f4cd0996645d05bb2a420cfb))
* removed mentions of the authorization token in the readme. ([bde36ec](https://github.com/vriesdemichael/keycloak-operator/commit/bde36ecfe5d61e5914a5cda97c0dd50d48614b27))
* reorganize navigation structure to reduce tab overflow ([4ff0025](https://github.com/vriesdemichael/keycloak-operator/commit/4ff00259eb0a43efb9b0f11ee27da6372491c79d))
* replace tags plugin with manual categorization for decision records ([f0038e9](https://github.com/vriesdemichael/keycloak-operator/commit/f0038e9305622fe9ffe0d83cf5d5d3badd10809c))
* update CI/CD badges to point to unified workflow ([47c8020](https://github.com/vriesdemichael/keycloak-operator/commit/47c8020c858d693b10dac87193493e161ae41827))
* update helm chart READMEs and fix broken links ([a32d3e2](https://github.com/vriesdemichael/keycloak-operator/commit/a32d3e243e7d5f0616bf2d52c3bc14ff2d2f2464))

## [0.6.4](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.6.3...operator-image-v0.6.4) (2026-01-28)


### Features

* **operator:** add multi-version keycloak support (v24-v26) ([ed4dde8](https://github.com/vriesdemichael/keycloak-operator/commit/ed4dde8458178b777d68538c2db8fce6d0b8d702))


### Bug Fixes

* **operator:** resolve BruteForceStrategy enum serialization and complete multi-version support ([569e8e8](https://github.com/vriesdemichael/keycloak-operator/commit/569e8e8a95deddc68f6c34e52de5a2209f9b68e0))


### Code Refactoring

* **operator:** simplify multi-version support to single canonical model ([a3067a5](https://github.com/vriesdemichael/keycloak-operator/commit/a3067a5b0eacf8d7e4a96af3c785179d32c092bf))

## [0.6.3](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.6.2...operator-image-v0.6.3) (2026-01-26)


### Bug Fixes

* **operator-image:** bump kopf in the patch-updates group ([6c9df1d](https://github.com/vriesdemichael/keycloak-operator/commit/6c9df1d0316b44d4901354cdb76bcdb6dced047d))

## [0.6.2](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.6.1...operator-image-v0.6.2) (2026-01-25)


### Features

* **operator:** implement JGroups DNS_PING for horizontal scaling ([ef5b7c3](https://github.com/vriesdemichael/keycloak-operator/commit/ef5b7c3e9007e3d1d96fdef56911f86cb37f87d8)), closes [#347](https://github.com/vriesdemichael/keycloak-operator/issues/347)

## [0.6.1](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.6.0...operator-image-v0.6.1) (2026-01-25)


### Features

* **operator:** implement drift remediation for realms and clients ([2a145fa](https://github.com/vriesdemichael/keycloak-operator/commit/2a145fa2a9a257b98b39302127aa15bf3ea71acf))


### Bug Fixes

* **operator:** add operator_namespace override for drift detector tests ([6a0e48c](https://github.com/vriesdemichael/keycloak-operator/commit/6a0e48c0cd9745a4f0745ca4a0ff6407f6abb727))
* **operator:** address review comments on drift detection ([4eddc79](https://github.com/vriesdemichael/keycloak-operator/commit/4eddc795f009dafc4c9336d5dcd68e66d6938e18))
* **operator:** resolve drift detection bugs and test failures ([263badd](https://github.com/vriesdemichael/keycloak-operator/commit/263badd583e26b3c3b1d23cae0efa78bbae83e57))
* **operator:** resolve linting and test issues for drift detection ([28f4081](https://github.com/vriesdemichael/keycloak-operator/commit/28f4081e30cfd24bfcb8671bf2ff7e161ec63527))
* **operator:** resolve linting issues and test configuration ([f5f038b](https://github.com/vriesdemichael/keycloak-operator/commit/f5f038bdc478324d58eab72adc08132bb6351061))
* **operator:** simplify drift detection using timestamp comparison ([393cfa1](https://github.com/vriesdemichael/keycloak-operator/commit/393cfa1f0137ed1e7659e51df763d75a9ff77060))


### Code Refactoring

* **operator:** simplify drift detection to single Keycloak instance ([282b2bc](https://github.com/vriesdemichael/keycloak-operator/commit/282b2bc3df2eab59fb071a6f9ee2969411623be5))

## [0.6.0](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.21...operator-image-v0.6.0) (2026-01-21)


### ⚠ BREAKING CHANGES

* **chart-client+chart-operator+chart-realm:** Helm chart distribution moved to OCI registry
* **operator:** IDP secrets must use configSecrets field, plaintext forbidden
* **webhooks:** Admission webhooks now require cert-manager to be installed
* **chart-client+chart-realm:** Removed token-based authorization from all charts

### Features

* add OIDC endpoint discovery to realm status ([6dc52f3](https://github.com/vriesdemichael/keycloak-operator/commit/6dc52f3ac9a51547e4431f99abbe91aec1d7dca3))
* **chart-client+chart-operator+chart-realm:** migrate to OCI registry in GHCR ([dc4f59c](https://github.com/vriesdemichael/keycloak-operator/commit/dc4f59c8f9d66be04cd7be6ae685fc714a8aad97))
* **chart-client+chart-operator+operator:** add missing client settings fields ([5a17906](https://github.com/vriesdemichael/keycloak-operator/commit/5a179063c098f1fc0afd505b5466dd8be8a2ab79))
* **chart-client+chart-realm:** update charts for namespace grant authorization ([add6af9](https://github.com/vriesdemichael/keycloak-operator/commit/add6af903c2ff887cd44c5608ceb1a1a6436f23e)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart-client+operator:** add labels and annotations to managed secrets ([ee64ec1](https://github.com/vriesdemichael/keycloak-operator/commit/ee64ec1ecbe5ead4db3fe9896f16fd83d0c842ef))
* **chart-client+operator:** improve client secret management and monitoring ([c182187](https://github.com/vriesdemichael/keycloak-operator/commit/c182187adaa614e89fb2696c74c860c39a86994d))
* **chart-operator+chart-realm+operator:** add complete realm role and group management ([d55d6d9](https://github.com/vriesdemichael/keycloak-operator/commit/d55d6d99e94264225275d3fcc026f6cf900a9c44))
* **chart-operator+chart-realm+operator:** add password policy and improve events config ([3d60b5e](https://github.com/vriesdemichael/keycloak-operator/commit/3d60b5eeddd7f2a5c63416a55e195e07f6804d92)), closes [#311](https://github.com/vriesdemichael/keycloak-operator/issues/311)
* **chart-operator:** add 'get' permission for cross-namespace realm reads ([1e9cf4f](https://github.com/vriesdemichael/keycloak-operator/commit/1e9cf4fd7f4c4fb3e2a85d02bc217c8d4449075a)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart-operator:** add configurable timer intervals for reconciliation ([80e4652](https://github.com/vriesdemichael/keycloak-operator/commit/80e46525e2ea44209c51ea89984d7cfab0c9d25c))
* **chart-operator:** update CRDs for namespace grant authorization ([b526149](https://github.com/vriesdemichael/keycloak-operator/commit/b52614931946e588730b3cc4312c061e383623fe)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart-realm+operator:** add authentication flow and required action support ([f653969](https://github.com/vriesdemichael/keycloak-operator/commit/f653969fd08b30d25af45a1b6465bc6e5ec22c2e)), closes [#180](https://github.com/vriesdemichael/keycloak-operator/issues/180)
* **chart-realm:** add client scope management ([708787f](https://github.com/vriesdemichael/keycloak-operator/commit/708787f23200be34947733e9059eaad1a51e02b3)), closes [#181](https://github.com/vriesdemichael/keycloak-operator/issues/181)
* implement admission webhooks for resource validation ([061acae](https://github.com/vriesdemichael/keycloak-operator/commit/061acae11b1af0d5547177c98264ac6ffbaa8f27))
* **operator:** add comprehensive test coverage infrastructure ([0405cfb](https://github.com/vriesdemichael/keycloak-operator/commit/0405cfbb2b65993696cc820e62ba32be2793788a)), closes [#110](https://github.com/vriesdemichael/keycloak-operator/issues/110)
* **operator:** add quiet logging mode for health probes and webhooks ([3ef5d2c](https://github.com/vriesdemichael/keycloak-operator/commit/3ef5d2cdabd42b4dd9e3200e5b9591e6977f21db))
* **operator:** add stuck finalizer detection to timer handlers ([30bd848](https://github.com/vriesdemichael/keycloak-operator/commit/30bd848d849043ffa21795a950c5243d60327ab9))
* **operator:** add user federation CRUD methods to Keycloak admin client ([cbdbd1a](https://github.com/vriesdemichael/keycloak-operator/commit/cbdbd1ae2e5262fecea014a6b33f8194ecb24941))
* **operator:** Add user federation status to KeycloakRealm CR status ([74bfccf](https://github.com/vriesdemichael/keycloak-operator/commit/74bfccfab5eaca12f3806fc81e2365d96d243c48))
* **operator:** align Pydantic models with CRD schemas ([4f96f7c](https://github.com/vriesdemichael/keycloak-operator/commit/4f96f7c491a62c8d74c9a50d3e5fc16e98427da2))
* **operator:** centralize configuration with pydantic-settings ([dd6078b](https://github.com/vriesdemichael/keycloak-operator/commit/dd6078bf9256e722188343987009f9a26b8ac3ee)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* **operator:** complete identity provider lifecycle and mapper support ([db0ad09](https://github.com/vriesdemichael/keycloak-operator/commit/db0ad0994271e9d4c5ef15bdbef796a85e983d16)), closes [#178](https://github.com/vriesdemichael/keycloak-operator/issues/178)
* **operator:** complete integration coverage collection ([1d4e5a4](https://github.com/vriesdemichael/keycloak-operator/commit/1d4e5a4f4fd369efeb81032539c6e938c9015635))
* **operator:** enhance user federation models with LDAP/AD/Kerberos support ([7c6e1d7](https://github.com/vriesdemichael/keycloak-operator/commit/7c6e1d7bb0dae2e6c0e0b08aac01292020d6ec3d))
* **operator:** fix pydantic-settings environment variable configuration ([20d00b3](https://github.com/vriesdemichael/keycloak-operator/commit/20d00b3ff8a242e08706426ed7bc7a48e3eb2e6e)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* **operator:** implement integration test coverage collection via SIGUSR1 ([259e587](https://github.com/vriesdemichael/keycloak-operator/commit/259e587ab08a5388702e1871d62c923434796c35)), closes [#111](https://github.com/vriesdemichael/keycloak-operator/issues/111)
* **operator:** implement user federation CRUD lifecycle in realm reconciler ([218061b](https://github.com/vriesdemichael/keycloak-operator/commit/218061bc332eecb2761fbf8b18aac5380621f6f6))
* **operator:** improve finalizer debugging and logging ([80137b1](https://github.com/vriesdemichael/keycloak-operator/commit/80137b15f60fe2a8af37865f2069f0941495cdb0))
* **operator:** require secret refs for IDP secrets ([bf377fb](https://github.com/vriesdemichael/keycloak-operator/commit/bf377fb76b504f2c2160cd08c41ff60071505e57))
* **operator:** upgrade base image to python 3.14-slim ([34b95e3](https://github.com/vriesdemichael/keycloak-operator/commit/34b95e3f41580061d54efdb5e4664058f4443a33))
* **operator:** Upgrade to python 3.14 (alpine image for less vulnerabilities) ([f35b32b](https://github.com/vriesdemichael/keycloak-operator/commit/f35b32b242eb5c1794022e2d6c65df6d0f4f9bf9))
* use SVG logo and update favicon ([a180ba2](https://github.com/vriesdemichael/keycloak-operator/commit/a180ba227d9295e9350b478ad47e83584e5da960))
* **webhooks:** switch to cert-manager for webhook TLS certificates ([7195217](https://github.com/vriesdemichael/keycloak-operator/commit/7195217d15903d9c2c738999ce4c25acf1daaa88))


### Bug Fixes

* add certbuilder dependency and fix webhook RBAC permissions ([71df4ee](https://github.com/vriesdemichael/keycloak-operator/commit/71df4eebe6573b84eea6fab15fd9f9666806b3d5))
* add clientAuthorizationGrants to finalizer tests ([954d850](https://github.com/vriesdemichael/keycloak-operator/commit/954d8505d79fc2ebe7a80f6ffab319f8f5d46a1b)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* allow test tags in operator chart schema ([6740046](https://github.com/vriesdemichael/keycloak-operator/commit/6740046724b30ca0d694bc85a40212db826fe596))
* **chart-client+chart-operator+operator:** address multiple issues ([#290](https://github.com/vriesdemichael/keycloak-operator/issues/290), [#294](https://github.com/vriesdemichael/keycloak-operator/issues/294), [#170](https://github.com/vriesdemichael/keycloak-operator/issues/170), [#168](https://github.com/vriesdemichael/keycloak-operator/issues/168)) ([0b790ac](https://github.com/vriesdemichael/keycloak-operator/commit/0b790acab044239342f888dfe170afbef874f6bc))
* configure webhook server with service DNS hostname ([d626c4b](https://github.com/vriesdemichael/keycloak-operator/commit/d626c4bddee90bd1fe3ab72c05c2b6d21552ece9))
* convert snake_case to camelCase in StatusWrapper ([4ad528c](https://github.com/vriesdemichael/keycloak-operator/commit/4ad528c44a76664324b47c26b0230c7b480bef42)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* create coverage directory in container and fix collection workflow ([3b74ee6](https://github.com/vriesdemichael/keycloak-operator/commit/3b74ee6f343bfb57ef4d8e3e70169ec4ffd8925e))
* disable webhook auto-management and default to false ([0c59b83](https://github.com/vriesdemichael/keycloak-operator/commit/0c59b834d2852d010a6ca97152eb4b2e41e0353b))
* import all webhook modules to register handlers ([12b9bbd](https://github.com/vriesdemichael/keycloak-operator/commit/12b9bbddb038caffa83f855eccfa59519b14621a))
* **operator-image:** bump aiohttp in the patch-updates group ([f3c604d](https://github.com/vriesdemichael/keycloak-operator/commit/f3c604d55b2e60e6317cd6ddebefa4be7098b4ea))
* **operator-image:** bump kopf from 1.39.1 to 1.40.0 ([b83ca99](https://github.com/vriesdemichael/keycloak-operator/commit/b83ca99c55b281d26dcf90c4c3cefaa6afd7b802))
* **operator-image:** bump kubernetes from 33.1.0 to 35.0.0 ([bcc6820](https://github.com/vriesdemichael/keycloak-operator/commit/bcc68203b44fc790356d161ae53d1059e477891b))
* **operator-image:** bump prometheus-client from 0.23.1 to 0.24.1 ([50a0292](https://github.com/vriesdemichael/keycloak-operator/commit/50a02924176bfb93fae1369319dda351dcf3df5b))
* **operator-image:** bump virtualenv from 20.35.4 to 20.36.1 ([b977790](https://github.com/vriesdemichael/keycloak-operator/commit/b977790f495ef5ba4b15e937383837a0472fa972))
* **operator-image:** enable full upgrades for security ([ed91e18](https://github.com/vriesdemichael/keycloak-operator/commit/ed91e18e1d9174fc4af4e36622355709403fb2b3))
* **operator-image:** ensure deterministic build with pinned versions ([f3f3158](https://github.com/vriesdemichael/keycloak-operator/commit/f3f3158b2744acf6a2ce238719c043a62cc2b6e0))
* **operator-image:** switch to bleeding edge Trixie base with secure setuptools ([9f2d657](https://github.com/vriesdemichael/keycloak-operator/commit/9f2d657128d4ef59cac295e3c0df8c0e59df5615))
* **operator-image:** switch to bookworm and upgrade setuptools ([c7371f5](https://github.com/vriesdemichael/keycloak-operator/commit/c7371f5f04e132a1145ec40addbdb069568579e0))
* **operator-image:** upgrade system packages and pip in image ([b034da6](https://github.com/vriesdemichael/keycloak-operator/commit/b034da606047f1f6054bb6e13cd127133833d8e6))
* **operator:** add client_scopes_count to status model ([18d4b3c](https://github.com/vriesdemichael/keycloak-operator/commit/18d4b3cbac222ef4345887103eb5c2d510a8b104))
* **operator:** add missing namespace parameters to API calls ([45bf910](https://github.com/vriesdemichael/keycloak-operator/commit/45bf9107989639ea8413b52ac030f4b9a425f102))
* **operator:** add namespace param to user federation admin client methods ([6024fa1](https://github.com/vriesdemichael/keycloak-operator/commit/6024fa1e08b3fd6f7fa2dad44274480b45cca9b5))
* **operator:** address PR review comments ([9de3803](https://github.com/vriesdemichael/keycloak-operator/commit/9de38035a33abd071ac4b88dba9a07cae71a69eb))
* **operator:** address PR review comments and expand documentation ([c05075f](https://github.com/vriesdemichael/keycloak-operator/commit/c05075ff6765aa708c4aad41972521b35e6f822d))
* **operator:** address review comments ([6f86406](https://github.com/vriesdemichael/keycloak-operator/commit/6f864060a51aa9f3dd29d2d7c50ab98d926ba929))
* **operator:** conditionally import webhook modules when webhooks enabled ([380eba0](https://github.com/vriesdemichael/keycloak-operator/commit/380eba070b575ede51371fb25de5984e675b3729)), closes [#237](https://github.com/vriesdemichael/keycloak-operator/issues/237)
* **operator:** correct parameter order in _fetch_secret_value calls ([58e1276](https://github.com/vriesdemichael/keycloak-operator/commit/58e12764e8e33fdd2e99c6c0a166159b1c61e7b0))
* **operator:** database passwordSecret support and test fixes ([038fc18](https://github.com/vriesdemichael/keycloak-operator/commit/038fc18da190e8d99eb02222c89c59393129feee))
* **operator:** ensure secret is updated when only metadata changes ([6dc50c3](https://github.com/vriesdemichael/keycloak-operator/commit/6dc50c3b065e9a1ccbde7e68534b7a371672a030))
* **operator:** exclude read-only fields from group update requests ([145020e](https://github.com/vriesdemichael/keycloak-operator/commit/145020ec919d6e37b93eaad9a1b55403a532d167))
* **operator:** fix async update handler for authentication flows ([e4c7fc4](https://github.com/vriesdemichael/keycloak-operator/commit/e4c7fc42ec694090b0d04f608682eb8f94085771))
* **operator:** handle 409 conflict as idempotent success for add operations ([e5eafab](https://github.com/vriesdemichael/keycloak-operator/commit/e5eafab0361c60b07691d518924ceb5b64ac564d))
* **operator:** handle basic realm field updates in do_update method ([fab2804](https://github.com/vriesdemichael/keycloak-operator/commit/fab2804ad2e1b982f7e7009e11290f68fbaccf0b))
* **operator:** handle realm deletion gracefully in client cleanup ([45b25cd](https://github.com/vriesdemichael/keycloak-operator/commit/45b25cda8c945c56daddbc2538a1c0133713324f))
* **operator:** identity provider updates use PUT instead of POST ([d57b6ca](https://github.com/vriesdemichael/keycloak-operator/commit/d57b6cabbdbb61b95005a874a60bc461ba20a2da))
* **operator:** improve finalizer robustness and simplify cascade deletion ([6e5419f](https://github.com/vriesdemichael/keycloak-operator/commit/6e5419fcc690e9ce5f934f12fb005ad8f7956c0d))
* **operator:** include id field in update requests for roles and groups ([2c2f483](https://github.com/vriesdemichael/keycloak-operator/commit/2c2f4833e6f5c1a82fc3d07eec429df39a4ebdfc))
* **operator:** make client scope operations idempotent ([edd3daf](https://github.com/vriesdemichael/keycloak-operator/commit/edd3daf37730806abb076841b2f8e384299555b4))
* **operator:** pin urllib3&gt;=2.6.0 to fix CVE ([038456f](https://github.com/vriesdemichael/keycloak-operator/commit/038456fbda10b42eae1c81c9fa7f22cad7d50c6e))
* **operator:** prevent event loop closed errors in httpx client cache ([83b8020](https://github.com/vriesdemichael/keycloak-operator/commit/83b80200c7d0df07058856e8ee99e979dba585a8))
* **operator:** raise error instead of returning 'unknown' client UUID ([35d2d3e](https://github.com/vriesdemichael/keycloak-operator/commit/35d2d3eea75e1db284483006de8845824c7a246f))
* **operator:** remove duplicate deletion logic from resume handlers ([ce95458](https://github.com/vriesdemichael/keycloak-operator/commit/ce954586b7127b84ab855355850632ff62b5d5b3))
* **operator:** remove status param from keycloak cleanup helper ([e6e4972](https://github.com/vriesdemichael/keycloak-operator/commit/e6e4972cfc14009a6824a632c8667854b84e650d))
* **operator:** replace secret watcher with health check polling ([0df6785](https://github.com/vriesdemichael/keycloak-operator/commit/0df67854e30ac49efae548594712b0943ef75193))
* **operator:** resolve ingress hostname bug and improve type safety ([eb69b8a](https://github.com/vriesdemichael/keycloak-operator/commit/eb69b8aa61893c39b7143cc8101e39febc63a113))
* **operator:** resolve JSON serialization and test timing issues ([fb29bcb](https://github.com/vriesdemichael/keycloak-operator/commit/fb29bcbd1859e0dbcb2d8ded643a38ecb52c5cb5))
* **operator:** resolve type checker warnings after dependency upgrade ([a4aecdb](https://github.com/vriesdemichael/keycloak-operator/commit/a4aecdb22253e0464e9bf5c23ab1a3b582792c0e))
* **operator:** restore secret watcher with namespace RBAC support ([5db7d65](https://github.com/vriesdemichael/keycloak-operator/commit/5db7d65c6fe8c27e87958d0dc9f42d9753e02078))
* **operator:** update package metadata with correct author info ([96ba785](https://github.com/vriesdemichael/keycloak-operator/commit/96ba785332f12613446cb83e5525ade6cc966e80))
* **operator:** update pyasn1 to 0.6.2 and fix integration test ([97962cd](https://github.com/vriesdemichael/keycloak-operator/commit/97962cd90af3bfc0b9cc603d8833a8d0d953aa78))
* **operator:** upgrade urllib3 to 2.6.3 for CVE-2026-21441 ([4428197](https://github.com/vriesdemichael/keycloak-operator/commit/4428197fe1038323f856ce7950383e4e7df3b7a4))
* **operator:** use asyncio.to_thread for webhook K8s API calls ([d635da9](https://github.com/vriesdemichael/keycloak-operator/commit/d635da9ae8a78928baf613b35686256849e78b80))
* **operator:** use client-side filtering for user federation components ([dbb722f](https://github.com/vriesdemichael/keycloak-operator/commit/dbb722f9da266dda0f08207b12f415d61b003d4f))
* **operator:** use correct camelCase field names in realm update handler ([91636eb](https://github.com/vriesdemichael/keycloak-operator/commit/91636ebdb1afef442a5eb6e9bf46db69585454b8))
* **operator:** use correct Keycloak CR name in health check timers ([8b174cc](https://github.com/vriesdemichael/keycloak-operator/commit/8b174cc8fbbfedb6f862cdb0e76a08cade05458a))
* **operator:** use coverage run in CMD for proper instrumentation ([1665eaa](https://github.com/vriesdemichael/keycloak-operator/commit/1665eaaef1f8bd01616a278edf99a232d6bd7a53))
* **operator:** use realm ID instead of realm name for federation parentId ([8e54566](https://github.com/vriesdemichael/keycloak-operator/commit/8e54566427873c955d7320323d6ddd7381a94246))
* **operator:** user federation tests and LDAP attribute config keys ([ddd7733](https://github.com/vriesdemichael/keycloak-operator/commit/ddd77335e4efa2b0620f110b350fd0dc5c79a095)), closes [#179](https://github.com/vriesdemichael/keycloak-operator/issues/179)
* **operator:** verify ownership before deleting Keycloak resources ([b601a80](https://github.com/vriesdemichael/keycloak-operator/commit/b601a80a0626fe332e59fbd0cd01067b689b5eb2))
* prevent premature operator cleanup in pytest-xdist workers ([8031895](https://github.com/vriesdemichael/keycloak-operator/commit/8031895e2b2347378cbb376555136ee7e395ff49))
* remove await from synchronous API call in capacity check ([2908db5](https://github.com/vriesdemichael/keycloak-operator/commit/2908db581fa9a39f590c67b1a3ef47f27ec978d0)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove obsolete authorization token references from charts ([880fc98](https://github.com/vriesdemichael/keycloak-operator/commit/880fc98637ff0e0e4c9471fd47162fc1d790b194)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove obsolete authorizationSecretName status field ([9952eae](https://github.com/vriesdemichael/keycloak-operator/commit/9952eaef7c155f3013b9a1cc2d7a0c66c7cf4827)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove tests for deleted periodic_leadership_check function ([1ffcba0](https://github.com/vriesdemichael/keycloak-operator/commit/1ffcba0479decb4916a65262f58a46f84ab28ddd))
* Removed await, added explicit k8s_client parameter. ([2908db5](https://github.com/vriesdemichael/keycloak-operator/commit/2908db581fa9a39f590c67b1a3ef47f27ec978d0))
* replace old keycloak.mdvr.nl API group with vriesdemichael.github.io ([da644e0](https://github.com/vriesdemichael/keycloak-operator/commit/da644e09d335803e59f61a2f46f463ebfab0e50b))
* restore correct test image tag for coverage collection ([6cb1675](https://github.com/vriesdemichael/keycloak-operator/commit/6cb16758ce97572f7b98396ea3b6960fb61e122f))
* update tests and Helm schema for grant list authorization ([0fe6fca](https://github.com/vriesdemichael/keycloak-operator/commit/0fe6fcae8c638595a117b2093d869ecb85b37f47)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)


### Performance Improvements

* implement generation-based skip to avoid redundant reconciliations ([af0d4c6](https://github.com/vriesdemichael/keycloak-operator/commit/af0d4c63490122a5d4893f2cb2e5cf6d63fe3f6b)), closes [#184](https://github.com/vriesdemichael/keycloak-operator/issues/184)


### Code Refactoring

* address CodeQL false positive and remove unused method ([66e8faf](https://github.com/vriesdemichael/keycloak-operator/commit/66e8faf9fb9acab4f3206b76e025b52b84c8a79a))
* **operator:** add decorators for consistent error handling ([c1fc4fb](https://github.com/vriesdemichael/keycloak-operator/commit/c1fc4fb2aab49c20f9ce954a26cfc81e02acf6d9))
* **operator:** address PR review comments ([21d5b87](https://github.com/vriesdemichael/keycloak-operator/commit/21d5b872ef3958db11738c5767f5f4a16fb22fcb))
* **operator:** apply error handling decorators to client scope methods ([ae86fa8](https://github.com/vriesdemichael/keycloak-operator/commit/ae86fa898ae68ad037a40571e1ec2a349b090acc))
* **operator:** make timer intervals configurable and deduplicate cleanup ([152e5fd](https://github.com/vriesdemichael/keycloak-operator/commit/152e5fde1dccc6e66acfba0353ebfeccabae3eea))
* **operator:** unify Dockerfile with multi-stage targets ([dd81347](https://github.com/vriesdemichael/keycloak-operator/commit/dd813478441800b2519e184e94bc249fa2a6289c))
* split CI/CD workflow into composite actions ([34da80d](https://github.com/vriesdemichael/keycloak-operator/commit/34da80d4cd5aaa51e07dc4fa998f86e0faccb45f))
* split CI/CD workflow into composite actions ([6a36cb1](https://github.com/vriesdemichael/keycloak-operator/commit/6a36cb1b9fb1f19869b2cfc7ade85f9fc4a6fab7))
* use kopf[dev] extra instead of manual certbuilder ([bf44078](https://github.com/vriesdemichael/keycloak-operator/commit/bf44078d955d50613cc8d1c17605babecb08a3c0))
* use unified Kopf-managed finalizer ([ff83287](https://github.com/vriesdemichael/keycloak-operator/commit/ff832873570114e7ba34450790fe947f4e305ee7))


### Documentation

* add admission webhook documentation and decision record ([396de85](https://github.com/vriesdemichael/keycloak-operator/commit/396de85863b5731e6e55ae2ac11ad21fbc45eeb1))
* add CI/CD and documentation issues task list ([1d09817](https://github.com/vriesdemichael/keycloak-operator/commit/1d0981719319e67cb6872b4408f42e83014edd2e))
* add custom logo and favicon ([34da80d](https://github.com/vriesdemichael/keycloak-operator/commit/34da80d4cd5aaa51e07dc4fa998f86e0faccb45f))
* add custom logo and favicon ([6a36cb1](https://github.com/vriesdemichael/keycloak-operator/commit/6a36cb1b9fb1f19869b2cfc7ade85f9fc4a6fab7))
* add Decision Records as separate tab with tag filtering ([6931bc3](https://github.com/vriesdemichael/keycloak-operator/commit/6931bc3b1989768b98a078161946a2115ed01d41))
* add Keycloak brand colors and improved styling ([fc7a0a5](https://github.com/vriesdemichael/keycloak-operator/commit/fc7a0a50f0993dad3f6b1e04791fc9c36e3d4b1f))
* add Mermaid diagram support and hide home TOC ([b1f2e74](https://github.com/vriesdemichael/keycloak-operator/commit/b1f2e74d7f7a6cff2d8de4b8b29d146c5160b21c))
* enhance dark mode styling with better contrast ([b905878](https://github.com/vriesdemichael/keycloak-operator/commit/b9058784419cc9f9248eddbf9ef0537aed123cf3))
* extend doc validation with external schemas and K8s resources ([7e7ce80](https://github.com/vriesdemichael/keycloak-operator/commit/7e7ce80f2f3d0c6c3d9ced00aba0560c8a757862))
* final cleanup of remaining token references ([10f83eb](https://github.com/vriesdemichael/keycloak-operator/commit/10f83eb6fd7883b24c27e7d114c017f5e6284992))
* final tracking update - 36/36 tests passing ([8462747](https://github.com/vriesdemichael/keycloak-operator/commit/8462747b9610497387e972a3c13def51ef843f21)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* fix ADR 45/49 and add decision records to documentation ([33586ac](https://github.com/vriesdemichael/keycloak-operator/commit/33586ac4705692b4ff9db3063091b107a4c89504))
* fix documentation issues from user feedback ([b0d2ab7](https://github.com/vriesdemichael/keycloak-operator/commit/b0d2ab7ef8828e2d41ce11ebf71dc88476fc4fd5))
* mark Phase 8 complete - all automated tests passing ([61ce95e](https://github.com/vriesdemichael/keycloak-operator/commit/61ce95efea92917ccc46a68915a3337ef736139d)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* move Home into Getting Started section ([bff4ba6](https://github.com/vriesdemichael/keycloak-operator/commit/bff4ba682fbc69862edae9d67631638268262b0f))
* removed mentions of the authorization token in the readme. ([a6d8287](https://github.com/vriesdemichael/keycloak-operator/commit/a6d828700a3e08755fa960baf78ffa18da1c0184))
* reorganize navigation structure to reduce tab overflow ([e1507a9](https://github.com/vriesdemichael/keycloak-operator/commit/e1507a96a270a674151acebe502405cb994bce9a))
* replace tags plugin with manual categorization for decision records ([1c96007](https://github.com/vriesdemichael/keycloak-operator/commit/1c960078a54bdbd9208c0e2fba88cdfd1ad4edb9))
* review and improve decision records ([0c0ea52](https://github.com/vriesdemichael/keycloak-operator/commit/0c0ea52032b0cb4b262d41c65a3c9931a0a3fe4f))
* update CI/CD badges to point to unified workflow ([4419899](https://github.com/vriesdemichael/keycloak-operator/commit/4419899d41bd4bb949f0d4c82d67d48334c6a08c))
* update helm chart READMEs and fix broken links ([dfb210d](https://github.com/vriesdemichael/keycloak-operator/commit/dfb210de7e222159830c5687e47e0e6d5eab354e))

## [0.5.21](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.20...operator-image-v0.5.21) (2026-01-20)


### Features

* **chart-client+operator:** add labels and annotations to managed secrets ([ee64ec1](https://github.com/vriesdemichael/keycloak-operator/commit/ee64ec1ecbe5ead4db3fe9896f16fd83d0c842ef))
* **operator:** upgrade base image to python 3.14-slim ([34b95e3](https://github.com/vriesdemichael/keycloak-operator/commit/34b95e3f41580061d54efdb5e4664058f4443a33))
* **operator:** Upgrade to python 3.14 (alpine image for less vulnerabilities) ([f35b32b](https://github.com/vriesdemichael/keycloak-operator/commit/f35b32b242eb5c1794022e2d6c65df6d0f4f9bf9))


### Bug Fixes

* **operator-image:** enable full upgrades for security ([ed91e18](https://github.com/vriesdemichael/keycloak-operator/commit/ed91e18e1d9174fc4af4e36622355709403fb2b3))
* **operator-image:** ensure deterministic build with pinned versions ([f3f3158](https://github.com/vriesdemichael/keycloak-operator/commit/f3f3158b2744acf6a2ce238719c043a62cc2b6e0))
* **operator-image:** switch to bleeding edge Trixie base with secure setuptools ([9f2d657](https://github.com/vriesdemichael/keycloak-operator/commit/9f2d657128d4ef59cac295e3c0df8c0e59df5615))
* **operator-image:** switch to bookworm and upgrade setuptools ([c7371f5](https://github.com/vriesdemichael/keycloak-operator/commit/c7371f5f04e132a1145ec40addbdb069568579e0))
* **operator-image:** upgrade system packages and pip in image ([b034da6](https://github.com/vriesdemichael/keycloak-operator/commit/b034da606047f1f6054bb6e13cd127133833d8e6))
* **operator:** ensure secret is updated when only metadata changes ([6dc50c3](https://github.com/vriesdemichael/keycloak-operator/commit/6dc50c3b065e9a1ccbde7e68534b7a371672a030))
* **operator:** update pyasn1 to 0.6.2 and fix integration test ([97962cd](https://github.com/vriesdemichael/keycloak-operator/commit/97962cd90af3bfc0b9cc603d8833a8d0d953aa78))

## [0.5.20](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.19...operator-image-v0.5.20) (2026-01-14)


### Features

* **chart-client+chart-operator+operator:** add missing client settings fields ([5a17906](https://github.com/vriesdemichael/keycloak-operator/commit/5a179063c098f1fc0afd505b5466dd8be8a2ab79))


### Bug Fixes

* **operator-image:** bump virtualenv from 20.35.4 to 20.36.1 ([b977790](https://github.com/vriesdemichael/keycloak-operator/commit/b977790f495ef5ba4b15e937383837a0472fa972))

## [0.5.19](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.18...operator-image-v0.5.19) (2026-01-13)


### Features

* **operator:** add user federation CRUD methods to Keycloak admin client ([cbdbd1a](https://github.com/vriesdemichael/keycloak-operator/commit/cbdbd1ae2e5262fecea014a6b33f8194ecb24941))
* **operator:** Add user federation status to KeycloakRealm CR status ([74bfccf](https://github.com/vriesdemichael/keycloak-operator/commit/74bfccfab5eaca12f3806fc81e2365d96d243c48))
* **operator:** enhance user federation models with LDAP/AD/Kerberos support ([7c6e1d7](https://github.com/vriesdemichael/keycloak-operator/commit/7c6e1d7bb0dae2e6c0e0b08aac01292020d6ec3d))
* **operator:** implement user federation CRUD lifecycle in realm reconciler ([218061b](https://github.com/vriesdemichael/keycloak-operator/commit/218061bc332eecb2761fbf8b18aac5380621f6f6))


### Bug Fixes

* **operator:** add namespace param to user federation admin client methods ([6024fa1](https://github.com/vriesdemichael/keycloak-operator/commit/6024fa1e08b3fd6f7fa2dad44274480b45cca9b5))
* **operator:** address PR review comments ([9de3803](https://github.com/vriesdemichael/keycloak-operator/commit/9de38035a33abd071ac4b88dba9a07cae71a69eb))
* **operator:** correct parameter order in _fetch_secret_value calls ([58e1276](https://github.com/vriesdemichael/keycloak-operator/commit/58e12764e8e33fdd2e99c6c0a166159b1c61e7b0))
* **operator:** use client-side filtering for user federation components ([dbb722f](https://github.com/vriesdemichael/keycloak-operator/commit/dbb722f9da266dda0f08207b12f415d61b003d4f))
* **operator:** use realm ID instead of realm name for federation parentId ([8e54566](https://github.com/vriesdemichael/keycloak-operator/commit/8e54566427873c955d7320323d6ddd7381a94246))
* **operator:** user federation tests and LDAP attribute config keys ([ddd7733](https://github.com/vriesdemichael/keycloak-operator/commit/ddd77335e4efa2b0620f110b350fd0dc5c79a095)), closes [#179](https://github.com/vriesdemichael/keycloak-operator/issues/179)

## [0.5.18](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.17...operator-image-v0.5.18) (2026-01-08)


### Features

* **chart-operator:** add configurable timer intervals for reconciliation ([80e4652](https://github.com/vriesdemichael/keycloak-operator/commit/80e46525e2ea44209c51ea89984d7cfab0c9d25c))
* **operator:** add stuck finalizer detection to timer handlers ([30bd848](https://github.com/vriesdemichael/keycloak-operator/commit/30bd848d849043ffa21795a950c5243d60327ab9))
* **operator:** improve finalizer debugging and logging ([80137b1](https://github.com/vriesdemichael/keycloak-operator/commit/80137b15f60fe2a8af37865f2069f0941495cdb0))


### Bug Fixes

* **chart-client+chart-operator+operator:** address multiple issues ([#290](https://github.com/vriesdemichael/keycloak-operator/issues/290), [#294](https://github.com/vriesdemichael/keycloak-operator/issues/294), [#170](https://github.com/vriesdemichael/keycloak-operator/issues/170), [#168](https://github.com/vriesdemichael/keycloak-operator/issues/168)) ([0b790ac](https://github.com/vriesdemichael/keycloak-operator/commit/0b790acab044239342f888dfe170afbef874f6bc))
* **operator:** address review comments ([6f86406](https://github.com/vriesdemichael/keycloak-operator/commit/6f864060a51aa9f3dd29d2d7c50ab98d926ba929))
* **operator:** improve finalizer robustness and simplify cascade deletion ([6e5419f](https://github.com/vriesdemichael/keycloak-operator/commit/6e5419fcc690e9ce5f934f12fb005ad8f7956c0d))
* **operator:** remove status param from keycloak cleanup helper ([e6e4972](https://github.com/vriesdemichael/keycloak-operator/commit/e6e4972cfc14009a6824a632c8667854b84e650d))
* **operator:** upgrade urllib3 to 2.6.3 for CVE-2026-21441 ([4428197](https://github.com/vriesdemichael/keycloak-operator/commit/4428197fe1038323f856ce7950383e4e7df3b7a4))


### Code Refactoring

* **operator:** address PR review comments ([21d5b87](https://github.com/vriesdemichael/keycloak-operator/commit/21d5b872ef3958db11738c5767f5f4a16fb22fcb))
* **operator:** make timer intervals configurable and deduplicate cleanup ([152e5fd](https://github.com/vriesdemichael/keycloak-operator/commit/152e5fde1dccc6e66acfba0353ebfeccabae3eea))
* use unified Kopf-managed finalizer ([ff83287](https://github.com/vriesdemichael/keycloak-operator/commit/ff832873570114e7ba34450790fe947f4e305ee7))

## [0.5.17](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.16...operator-image-v0.5.17) (2026-01-07)


### Features

* **chart-realm:** add client scope management ([708787f](https://github.com/vriesdemichael/keycloak-operator/commit/708787f23200be34947733e9059eaad1a51e02b3)), closes [#181](https://github.com/vriesdemichael/keycloak-operator/issues/181)


### Bug Fixes

* **operator:** add client_scopes_count to status model ([18d4b3c](https://github.com/vriesdemichael/keycloak-operator/commit/18d4b3cbac222ef4345887103eb5c2d510a8b104))
* **operator:** handle 409 conflict as idempotent success for add operations ([e5eafab](https://github.com/vriesdemichael/keycloak-operator/commit/e5eafab0361c60b07691d518924ceb5b64ac564d))
* **operator:** make client scope operations idempotent ([edd3daf](https://github.com/vriesdemichael/keycloak-operator/commit/edd3daf37730806abb076841b2f8e384299555b4))
* **operator:** remove duplicate deletion logic from resume handlers ([ce95458](https://github.com/vriesdemichael/keycloak-operator/commit/ce954586b7127b84ab855355850632ff62b5d5b3))


### Code Refactoring

* **operator:** add decorators for consistent error handling ([c1fc4fb](https://github.com/vriesdemichael/keycloak-operator/commit/c1fc4fb2aab49c20f9ce954a26cfc81e02acf6d9))
* **operator:** apply error handling decorators to client scope methods ([ae86fa8](https://github.com/vriesdemichael/keycloak-operator/commit/ae86fa898ae68ad037a40571e1ec2a349b090acc))

## [0.5.16](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.15...operator-image-v0.5.16) (2026-01-05)


### Features

* **chart-operator+chart-realm+operator:** add complete realm role and group management ([d55d6d9](https://github.com/vriesdemichael/keycloak-operator/commit/d55d6d99e94264225275d3fcc026f6cf900a9c44))


### Bug Fixes

* **operator-image:** bump aiohttp in the patch-updates group ([f3c604d](https://github.com/vriesdemichael/keycloak-operator/commit/f3c604d55b2e60e6317cd6ddebefa4be7098b4ea))
* **operator:** add missing namespace parameters to API calls ([45bf910](https://github.com/vriesdemichael/keycloak-operator/commit/45bf9107989639ea8413b52ac030f4b9a425f102))
* **operator:** exclude read-only fields from group update requests ([145020e](https://github.com/vriesdemichael/keycloak-operator/commit/145020ec919d6e37b93eaad9a1b55403a532d167))
* **operator:** include id field in update requests for roles and groups ([2c2f483](https://github.com/vriesdemichael/keycloak-operator/commit/2c2f4833e6f5c1a82fc3d07eec429df39a4ebdfc))

## [0.5.15](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.14...operator-image-v0.5.15) (2026-01-04)


### Features

* **chart-operator+chart-realm+operator:** add password policy and improve events config ([3d60b5e](https://github.com/vriesdemichael/keycloak-operator/commit/3d60b5eeddd7f2a5c63416a55e195e07f6804d92)), closes [#311](https://github.com/vriesdemichael/keycloak-operator/issues/311)

## [0.5.14](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.13...operator-image-v0.5.14) (2026-01-03)


### Features

* **operator:** complete identity provider lifecycle and mapper support ([db0ad09](https://github.com/vriesdemichael/keycloak-operator/commit/db0ad0994271e9d4c5ef15bdbef796a85e983d16)), closes [#178](https://github.com/vriesdemichael/keycloak-operator/issues/178)

## [0.5.13](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.12...operator-image-v0.5.13) (2026-01-03)


### Bug Fixes

* **operator:** identity provider updates use PUT instead of POST ([d57b6ca](https://github.com/vriesdemichael/keycloak-operator/commit/d57b6cabbdbb61b95005a874a60bc461ba20a2da))
* **operator:** verify ownership before deleting Keycloak resources ([b601a80](https://github.com/vriesdemichael/keycloak-operator/commit/b601a80a0626fe332e59fbd0cd01067b689b5eb2))

## [0.5.12](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.11...operator-image-v0.5.12) (2026-01-02)


### Features

* **chart-realm+operator:** add authentication flow and required action support ([f653969](https://github.com/vriesdemichael/keycloak-operator/commit/f653969fd08b30d25af45a1b6465bc6e5ec22c2e)), closes [#180](https://github.com/vriesdemichael/keycloak-operator/issues/180)


### Bug Fixes

* **operator:** address PR review comments and expand documentation ([c05075f](https://github.com/vriesdemichael/keycloak-operator/commit/c05075ff6765aa708c4aad41972521b35e6f822d))
* **operator:** fix async update handler for authentication flows ([e4c7fc4](https://github.com/vriesdemichael/keycloak-operator/commit/e4c7fc42ec694090b0d04f608682eb8f94085771))


### Code Refactoring

* address CodeQL false positive and remove unused method ([66e8faf](https://github.com/vriesdemichael/keycloak-operator/commit/66e8faf9fb9acab4f3206b76e025b52b84c8a79a))

## [0.5.11](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.10...operator-image-v0.5.11) (2025-12-30)


### Bug Fixes

* **operator:** raise error instead of returning 'unknown' client UUID ([35d2d3e](https://github.com/vriesdemichael/keycloak-operator/commit/35d2d3eea75e1db284483006de8845824c7a246f))

## [0.5.10](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.9...operator-image-v0.5.10) (2025-12-29)


### Bug Fixes

* **operator:** resolve ingress hostname bug and improve type safety ([eb69b8a](https://github.com/vriesdemichael/keycloak-operator/commit/eb69b8aa61893c39b7143cc8101e39febc63a113))

## [0.5.9](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.8...operator-image-v0.5.9) (2025-12-26)


### Features

* **operator:** align Pydantic models with CRD schemas ([4f96f7c](https://github.com/vriesdemichael/keycloak-operator/commit/4f96f7c491a62c8d74c9a50d3e5fc16e98427da2))


### Documentation

* extend doc validation with external schemas and K8s resources ([7e7ce80](https://github.com/vriesdemichael/keycloak-operator/commit/7e7ce80f2f3d0c6c3d9ced00aba0560c8a757862))

## [0.5.8](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.7...operator-image-v0.5.8) (2025-12-23)


### Bug Fixes

* **operator:** use correct Keycloak CR name in health check timers ([8b174cc](https://github.com/vriesdemichael/keycloak-operator/commit/8b174cc8fbbfedb6f862cdb0e76a08cade05458a))

## [0.5.7](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.6...operator-image-v0.5.7) (2025-12-23)


### Features

* **operator:** add quiet logging mode for health probes and webhooks ([3ef5d2c](https://github.com/vriesdemichael/keycloak-operator/commit/3ef5d2cdabd42b4dd9e3200e5b9591e6977f21db))


### Bug Fixes

* **operator:** conditionally import webhook modules when webhooks enabled ([380eba0](https://github.com/vriesdemichael/keycloak-operator/commit/380eba070b575ede51371fb25de5984e675b3729)), closes [#237](https://github.com/vriesdemichael/keycloak-operator/issues/237)

## [0.5.6](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.5...operator-image-v0.5.6) (2025-12-23)


### Documentation

* fix documentation issues from user feedback ([b0d2ab7](https://github.com/vriesdemichael/keycloak-operator/commit/b0d2ab7ef8828e2d41ce11ebf71dc88476fc4fd5))

## [0.5.5](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.4...operator-image-v0.5.5) (2025-12-22)


### Bug Fixes

* **operator:** pin urllib3&gt;=2.6.0 to fix CVE ([038456f](https://github.com/vriesdemichael/keycloak-operator/commit/038456fbda10b42eae1c81c9fa7f22cad7d50c6e))
* **operator:** resolve type checker warnings after dependency upgrade ([a4aecdb](https://github.com/vriesdemichael/keycloak-operator/commit/a4aecdb22253e0464e9bf5c23ab1a3b582792c0e))

## [0.5.4](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.3...operator-image-v0.5.4) (2025-12-19)


### Bug Fixes

* **operator:** add retry loop for finalizer patch in drift tests ([33a86a9](https://github.com/vriesdemichael/keycloak-operator/commit/33a86a9b3ddb8e25c97127a0b8e5f36cafeb2569))

## [0.5.3](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.2...operator-image-v0.5.3) (2025-12-18)


### Bug Fixes

* **operator-image:** handle both single and multiple release output formats ([851d1b5](https://github.com/vriesdemichael/keycloak-operator/commit/851d1b58133694487d845476d57d649132b93164))

## [0.5.2](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.1...operator-image-v0.5.2) (2025-12-18)


### Bug Fixes

* **operator-image:** revert to path-based release-please output keys and add debug ([af2c5bd](https://github.com/vriesdemichael/keycloak-operator/commit/af2c5bdae851705422b0c28ee912fc0cf92ba5e5))

## [0.5.1](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.5.0...operator-image-v0.5.1) (2025-12-17)


### Bug Fixes

* **operator:** use component names for release-please output keys ([3fa2937](https://github.com/vriesdemichael/keycloak-operator/commit/3fa2937f3b463de6de1e144f9be85eab0a12201d))

## [0.5.0](https://github.com/vriesdemichael/keycloak-operator/compare/operator-image-v0.4.3...operator-image-v0.5.0) (2025-12-17)


### ⚠ BREAKING CHANGES

* **chart-client+chart-operator+chart-realm:** Helm chart distribution moved to OCI registry
* **operator:** IDP secrets must use configSecrets field, plaintext forbidden
* **webhooks:** Admission webhooks now require cert-manager to be installed
* **chart-client+chart-realm:** Removed token-based authorization from all charts
* **operator:** latest tag no longer updates on main push, only on releases
* The API group domain has changed from keycloak.mdvr.nl to vriesdemichael.github.io. Existing installations must migrate by:
* **ci:** Release configuration now uses container-based versioning instead of Python package versioning
* Remove spec.version field from Keycloak CRD and spec.enabled field from KeycloakRealm CRD

### Features

* Add centralized operator design and RBAC security implementation plan ([17b3413](https://github.com/vriesdemichael/keycloak-operator/commit/17b3413aa1c21de636b342fd9af0ff7fcc48ad96))
* add drift detection foundation (Phase 1-3) ([80cf043](https://github.com/vriesdemichael/keycloak-operator/commit/80cf0438ef7b0e7568fa9d033e15be305f24ba55))
* Add Keycloak Operator and Realm Helm charts ([2d4be4f](https://github.com/vriesdemichael/keycloak-operator/commit/2d4be4f4b8b43665afcecc8f0dacefbe88f66117))
* add keycloak_admin_client fixture for test isolation ([ea46f21](https://github.com/vriesdemichael/keycloak-operator/commit/ea46f21f8029643e4a31584830793b64f9c8402b))
* Add method to retrieve Keycloak instance from realm status ([0e45143](https://github.com/vriesdemichael/keycloak-operator/commit/0e45143500efcc16da48989de21bfd5b238c6480))
* add OIDC endpoint discovery to realm status ([6dc52f3](https://github.com/vriesdemichael/keycloak-operator/commit/6dc52f3ac9a51547e4431f99abbe91aec1d7dca3))
* Add optimized Keycloak image for 81% faster tests ([#15](https://github.com/vriesdemichael/keycloak-operator/issues/15)) ([3093a10](https://github.com/vriesdemichael/keycloak-operator/commit/3093a10239538b76d4fe7ae094e9ddcc85a519bd))
* Automatic Token Rotation System with Bootstrap Flow ([#26](https://github.com/vriesdemichael/keycloak-operator/issues/26)) ([ca28c1b](https://github.com/vriesdemichael/keycloak-operator/commit/ca28c1b995a8b953935f61d255de49921ac4cd85))
* **chart-client+chart-operator+chart-realm:** migrate to OCI registry in GHCR ([dc4f59c](https://github.com/vriesdemichael/keycloak-operator/commit/dc4f59c8f9d66be04cd7be6ae685fc714a8aad97))
* **chart-client+chart-realm:** update charts for namespace grant authorization ([add6af9](https://github.com/vriesdemichael/keycloak-operator/commit/add6af903c2ff887cd44c5608ceb1a1a6436f23e)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart-operator:** add 'get' permission for cross-namespace realm reads ([1e9cf4f](https://github.com/vriesdemichael/keycloak-operator/commit/1e9cf4fd7f4c4fb3e2a85d02bc217c8d4449075a)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart-operator:** update CRDs for namespace grant authorization ([b526149](https://github.com/vriesdemichael/keycloak-operator/commit/b52614931946e588730b3cc4312c061e383623fe)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart:** add automated operator version updates ([b303448](https://github.com/vriesdemichael/keycloak-operator/commit/b3034483f890b6ae282f787cc0ef343bc6fe6d03))
* **chart:** make admin password optional, leverage auto-generation ([a9fcb1a](https://github.com/vriesdemichael/keycloak-operator/commit/a9fcb1a475b99036b811753f42029a5cd0c0ad12))
* **charts:** add values.schema.json and extraManifests support ([039e00d](https://github.com/vriesdemichael/keycloak-operator/commit/039e00d1fe0874b2eb24f21d95f5e58d9f4a50cc))
* **ci:** add CODEOWNERS for automated review requests ([2e81678](https://github.com/vriesdemichael/keycloak-operator/commit/2e81678808cf1cca99dc668878f434cd5ae98310))
* **ci:** add comprehensive security scanning workflow ([116ef6f](https://github.com/vriesdemichael/keycloak-operator/commit/116ef6f12d73fd58bfbe3cc96906b7e38984d2bf))
* **ci:** add Dependabot for automated dependency updates ([61614e5](https://github.com/vriesdemichael/keycloak-operator/commit/61614e512728595dfaff0597882ea473e15b84c4))
* **ci:** add explicit shared Keycloak instance creation step ([dc530a1](https://github.com/vriesdemichael/keycloak-operator/commit/dc530a1f56dea2241bb459478745d8541a31e8ce))
* **ci:** add security validation to image publishing ([582caf1](https://github.com/vriesdemichael/keycloak-operator/commit/582caf117d9deb0978030651a7ac94cb0198b563))
* **ci:** auto-approve and merge non-major release PRs ([609e19b](https://github.com/vriesdemichael/keycloak-operator/commit/609e19b0b821c478c0c05962d74d1a3325d6781a))
* **ci:** create unified CI/CD pipeline workflow ([3209445](https://github.com/vriesdemichael/keycloak-operator/commit/3209445882e6ed40a67b966939550c5e976259f8))
* **ci:** enable auto-merge for release-please PRs ([0a74683](https://github.com/vriesdemichael/keycloak-operator/commit/0a746834e37fae0ad17088caa6b0c6b0757a0d0e))
* Enhance Keycloak models with aliasing and population configuration ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* implement admission webhooks for resource validation ([061acae](https://github.com/vriesdemichael/keycloak-operator/commit/061acae11b1af0d5547177c98264ac6ffbaa8f27))
* Implement Kopf peering for leader election and update deployment scripts ([a289e3a](https://github.com/vriesdemichael/keycloak-operator/commit/a289e3a55d95ecf2af4e2d29d94399acccf6aa25))
* implement orphan remediation (Phase 5) ([d225065](https://github.com/vriesdemichael/keycloak-operator/commit/d2250654f217dece764edabf4e9a17d8909a125e))
* Implement resource existence checks before cleanup in Keycloak reconciler ([e88ff0f](https://github.com/vriesdemichael/keycloak-operator/commit/e88ff0f46292e2bc355d1450f0f8e3406787ef40))
* migrate API group from keycloak.mdvr.nl to vriesdemichael.github.io ([d93b3c1](https://github.com/vriesdemichael/keycloak-operator/commit/d93b3c115d73ba8e3f1fa99c48c1e058f315b075))
* **operator:** add build attestations for supply chain security ([85a46cc](https://github.com/vriesdemichael/keycloak-operator/commit/85a46cce26775bc13ed809623d4ac998ce6b0152))
* **operator:** add comprehensive test coverage infrastructure ([0405cfb](https://github.com/vriesdemichael/keycloak-operator/commit/0405cfbb2b65993696cc820e62ba32be2793788a)), closes [#110](https://github.com/vriesdemichael/keycloak-operator/issues/110)
* **operator:** add coverage retrieval function (reformatted) ([73ff054](https://github.com/vriesdemichael/keycloak-operator/commit/73ff054f196b3cd076bdc11e16ac2e140e7c5594))
* **operator:** add GitHub deployment environments to workflow ([94b6b9b](https://github.com/vriesdemichael/keycloak-operator/commit/94b6b9bd3531fda63cbe6c43c088994649321d9a))
* **operator:** centralize configuration with pydantic-settings ([dd6078b](https://github.com/vriesdemichael/keycloak-operator/commit/dd6078bf9256e722188343987009f9a26b8ac3ee)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* **operator:** complete integration coverage collection ([1d4e5a4](https://github.com/vriesdemichael/keycloak-operator/commit/1d4e5a4f4fd369efeb81032539c6e938c9015635))
* **operator:** fix pydantic-settings environment variable configuration ([20d00b3](https://github.com/vriesdemichael/keycloak-operator/commit/20d00b3ff8a242e08706426ed7bc7a48e3eb2e6e)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* **operator:** implement integration test coverage collection via SIGUSR1 ([259e587](https://github.com/vriesdemichael/keycloak-operator/commit/259e587ab08a5388702e1871d62c923434796c35)), closes [#111](https://github.com/vriesdemichael/keycloak-operator/issues/111)
* **operator:** require secret refs for IDP secrets ([bf377fb](https://github.com/vriesdemichael/keycloak-operator/commit/bf377fb76b504f2c2160cd08c41ff60071505e57))
* publish JSON schemas for CRDs to enable IDE autocomplete ([72485af](https://github.com/vriesdemichael/keycloak-operator/commit/72485afb83822db7e427e1b876fd2700a91489a5))
* **resilience:** add circuit breaker and exponential backoff for API stability ([2ada936](https://github.com/vriesdemichael/keycloak-operator/commit/2ada93645579b4f81c2c042a0d53cd3d858a1e78))
* simplify issue templates for AI-agent compatibility ([c1a3c54](https://github.com/vriesdemichael/keycloak-operator/commit/c1a3c54e0dbe24c5d242777ddc1770e4e30b4d4e))
* Two-level rate limiting with async/await conversion ([#44](https://github.com/vriesdemichael/keycloak-operator/issues/44)) ([476a6ed](https://github.com/vriesdemichael/keycloak-operator/commit/476a6ed4bbb327d38e7c55bdc1421daa3fdb2a81))
* update release-please configuration and add auto-rebase workflow ([92981a7](https://github.com/vriesdemichael/keycloak-operator/commit/92981a7525a14f8ae7cd97d4228e0547b8c3d09e))
* use SVG logo and update favicon ([a180ba2](https://github.com/vriesdemichael/keycloak-operator/commit/a180ba227d9295e9350b478ad47e83584e5da960))
* **webhooks:** switch to cert-manager for webhook TLS certificates ([7195217](https://github.com/vriesdemichael/keycloak-operator/commit/7195217d15903d9c2c738999ce4c25acf1daaa88))


### Bug Fixes

* add await to second IDP configure call ([a4a2589](https://github.com/vriesdemichael/keycloak-operator/commit/a4a25891530f62b1603794be642b443f6a20563a))
* add camelCase aliases to KeycloakIdentityProvider model ([5a0d9a0](https://github.com/vriesdemichael/keycloak-operator/commit/5a0d9a0fe0d44569db02e242529b6d5c4a2fda75))
* add certbuilder dependency and fix webhook RBAC permissions ([71df4ee](https://github.com/vriesdemichael/keycloak-operator/commit/71df4eebe6573b84eea6fab15fd9f9666806b3d5))
* add clientAuthorizationGrants to finalizer tests ([954d850](https://github.com/vriesdemichael/keycloak-operator/commit/954d8505d79fc2ebe7a80f6ffab319f8f5d46a1b)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* add clientAuthorizationGrants to Helm client test ([5ddf722](https://github.com/vriesdemichael/keycloak-operator/commit/5ddf7222b81f90ddb8c611f5f3e0d4e00e2aa620)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* Add clientAuthorizationGrants to realm test specs ([91e33ca](https://github.com/vriesdemichael/keycloak-operator/commit/91e33cab1b367ecc75e1f507af62f60bcfe2fde8))
* add missing common.sh and config.sh scripts, update documentation ([59a644f](https://github.com/vriesdemichael/keycloak-operator/commit/59a644f580ec57eb8f297789949fe0105a7c8bc6))
* add missing namespace parameter to configure_identity_provider ([24230fd](https://github.com/vriesdemichael/keycloak-operator/commit/24230fd4055e9ab1a19cf0ac29e945f43572f53b))
* add namespace to Dex manifests ([cad2621](https://github.com/vriesdemichael/keycloak-operator/commit/cad2621cda178d90215c622f1e5cec0f2b85a39d))
* Add operator log capture and fix all integration tests ([#14](https://github.com/vriesdemichael/keycloak-operator/issues/14)) ([bf4e84f](https://github.com/vriesdemichael/keycloak-operator/commit/bf4e84ff8e4e5f8a0ebb0210ac2d6922beae2174))
* add patch permission for pods in namespace Role ([43d7fdc](https://github.com/vriesdemichael/keycloak-operator/commit/43d7fdc6f55475da9a6ba5ce42b0987bdb6d6557))
* add Pod Security Standards compliance to Dex deployment ([7ff7673](https://github.com/vriesdemichael/keycloak-operator/commit/7ff7673a74b65e52f525c670976ea07ce459ea21))
* add yq installation to release docs job ([6e53a92](https://github.com/vriesdemichael/keycloak-operator/commit/6e53a92a6ca26979eef60b0d3842d6e754bc9f27))
* address all Copilot review comments ([3ddfd8e](https://github.com/vriesdemichael/keycloak-operator/commit/3ddfd8eecdcaa83334485c616299f5f545f6ce4a))
* address Copilot review comments (resolved conflicts) ([76f6256](https://github.com/vriesdemichael/keycloak-operator/commit/76f6256cccb554ec418fd9195b9de72fbeaf3ad4))
* address Copilot review comments for integration tests ([fc09ef6](https://github.com/vriesdemichael/keycloak-operator/commit/fc09ef6d2c709d2f4b602e6bad3a3e6545b38b32))
* address Copilot review comments on unified CI/CD ([9cb6372](https://github.com/vriesdemichael/keycloak-operator/commit/9cb637234011f17b94db9547d590ed76459adbc3))
* address PR review comments ([3f0608e](https://github.com/vriesdemichael/keycloak-operator/commit/3f0608ef4ea3234b06d05f165c20b79d30395741))
* address PR review comments ([568d934](https://github.com/vriesdemichael/keycloak-operator/commit/568d9342dbbb582ae6c3544656de290735298b00))
* address review comments ([14007df](https://github.com/vriesdemichael/keycloak-operator/commit/14007df5fb013d9d43fdbe0b9732c447baca43f5))
* allow test tags in operator chart schema ([6740046](https://github.com/vriesdemichael/keycloak-operator/commit/6740046724b30ca0d694bc85a40212db826fe596))
* change operator component name to remove space ([e994ac2](https://github.com/vriesdemichael/keycloak-operator/commit/e994ac2a7d9fce824be86d0ade475f24aa17f6cc))
* **chart-operator:** correct digest regex in helm chart publish action ([d9cb566](https://github.com/vriesdemichael/keycloak-operator/commit/d9cb5666a4840df3626382b2f92fa59a45bb3335))
* **chart:** align Keycloak CR template with actual CRD spec ([bfa3a62](https://github.com/vriesdemichael/keycloak-operator/commit/bfa3a62c60c715e510670642e69676058375fceb))
* **ci:** add all helm charts to release-please config ([2c2280b](https://github.com/vriesdemichael/keycloak-operator/commit/2c2280bd8d9faab8669738baa9dd3a58607383eb))
* **ci:** add Docker tag extraction for operator-v prefixed tags ([#28](https://github.com/vriesdemichael/keycloak-operator/issues/28)) ([b761052](https://github.com/vriesdemichael/keycloak-operator/commit/b76105243a369c3a29fee8da425c6aa888142007))
* **ci:** add missing Dockerfile path to publish job ([4986bec](https://github.com/vriesdemichael/keycloak-operator/commit/4986becd3b89c79f48493064a74940a1243a0cd2))
* **ci:** add proper step gating to fail fast on deployment errors ([6a74656](https://github.com/vriesdemichael/keycloak-operator/commit/6a746568809f3829b3ad1413052d4102bc28ae1d))
* **ci:** add semantic version tags to published container images ([2d64ab2](https://github.com/vriesdemichael/keycloak-operator/commit/2d64ab2003a5c314138e93764a4bd1db0a6eebca))
* **ci:** align operator deployment with current Makefile structure ([49599a0](https://github.com/vriesdemichael/keycloak-operator/commit/49599a0ef6c6c225cb1caa3d137d35b0bec3e6c7))
* **ci:** correct JSON syntax errors in release-please manifest ([31577b3](https://github.com/vriesdemichael/keycloak-operator/commit/31577b39ef5accb576f713b162ea62f84b554fd7))
* **ci:** correct release-please config for container-based releases ([732eaa7](https://github.com/vriesdemichael/keycloak-operator/commit/732eaa72313c7893a5b1595691365fc31d135722))
* **ci:** enable semver Docker tags by dispatching CI/CD on release creation ([ff95842](https://github.com/vriesdemichael/keycloak-operator/commit/ff958422945707c65f2556e5813a465028e64789))
* **ci:** explicitly set kubeconfig path for integration tests ([c49fc64](https://github.com/vriesdemichael/keycloak-operator/commit/c49fc6470b891b069d30308c973fdd1d426873ef))
* **ci:** improve integration test isolation and coverage ([5a03f23](https://github.com/vriesdemichael/keycloak-operator/commit/5a03f2339bbdd916084ee3f66b6699e2ed4c8a1e))
* **ci:** install both dev and integration dependency groups ([e1a703e](https://github.com/vriesdemichael/keycloak-operator/commit/e1a703edc24868b8ecef7943afd78102c5317ea2))
* **ci:** install integration test dependencies including pytest-xdist ([4a6330b](https://github.com/vriesdemichael/keycloak-operator/commit/4a6330bf6b76ef164cc069b13f6f4966389afc8e))
* **ci:** pin Helm version for deterministic builds ([3acb30f](https://github.com/vriesdemichael/keycloak-operator/commit/3acb30f17687a4bb79e84236ec448739239ee86f))
* **ci:** prevent image publishing when tests fail ([70952a2](https://github.com/vriesdemichael/keycloak-operator/commit/70952a24be23585e4442ac86605f790c3cb3eba7))
* **ci:** prevent namespace creation conflict in helm deployment ([f50f483](https://github.com/vriesdemichael/keycloak-operator/commit/f50f48396329fbb99abeda0e6050eb0ca01ad77d))
* **ci:** properly wait for Keycloak deployment to be ready ([e0f7a9e](https://github.com/vriesdemichael/keycloak-operator/commit/e0f7a9e53915e0f18d4ab19de1193f9d8239b2fd))
* **ci:** remove approval step to work with auto-merge setting ([5428eb3](https://github.com/vriesdemichael/keycloak-operator/commit/5428eb3ccf96396c4cbd8a6c1869669527078ac5))
* **ci:** remove leader election and basic functionality tests from integration workflow ([c3fad45](https://github.com/vriesdemichael/keycloak-operator/commit/c3fad4561e29daddb89e92ca824cb68831bbb275))
* **ci:** resolve release-please bash error and disable CodeQL false positives ([f0479fe](https://github.com/vriesdemichael/keycloak-operator/commit/f0479fec32047fd49a95502d610adb3741807d48))
* **ci:** update Keycloak deployment and pod labels for consistency ([e3c3510](https://github.com/vriesdemichael/keycloak-operator/commit/e3c35108e7e10a9b32f99c62d1c59ec68da99d15))
* **ci:** use correct pod labels for Keycloak readiness check ([e680bbc](https://github.com/vriesdemichael/keycloak-operator/commit/e680bbcc86517d4b557b182f65d9755ae056320a))
* **ci:** use PAT for release-please to trigger CI workflows ([4091bed](https://github.com/vriesdemichael/keycloak-operator/commit/4091bed6c30d0f37bc2377b2ff5444506c8aa1c7))
* **ci:** wait for CNPG cluster and fix kubeconfig access ([edbc171](https://github.com/vriesdemichael/keycloak-operator/commit/edbc171acf4ec2bd784aaaa2455b1ffc54c436f9))
* clear operator instance ID cache between unit tests ([49d1db7](https://github.com/vriesdemichael/keycloak-operator/commit/49d1db7b1dcdbbb6898ae0110379210af33b23ac))
* combine coverage and convert to XML for Codecov ([ad10407](https://github.com/vriesdemichael/keycloak-operator/commit/ad10407ffe4b57e1ac35c958704cbb6b682d26f2))
* configure webhook server with service DNS hostname ([d626c4b](https://github.com/vriesdemichael/keycloak-operator/commit/d626c4bddee90bd1fe3ab72c05c2b6d21552ece9))
* consolidate documentation workflows with mike ([cd31074](https://github.com/vriesdemichael/keycloak-operator/commit/cd31074e2d0c518bc05c8a50f65313a8eeb48ea3))
* convert snake_case to camelCase in StatusWrapper ([4ad528c](https://github.com/vriesdemichael/keycloak-operator/commit/4ad528c44a76664324b47c26b0230c7b480bef42)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* correct client_cr fixture schema for drift detection tests ([fba3c5d](https://github.com/vriesdemichael/keycloak-operator/commit/fba3c5d243251d02e202e06d3c682f20bb7fcf70))
* correct fixture name in drift detection integration tests ([4694b16](https://github.com/vriesdemichael/keycloak-operator/commit/4694b16e62308399e15125c1cf580dfc9ae6b1f0))
* correct fixture name to k8s_custom_objects ([cde9e20](https://github.com/vriesdemichael/keycloak-operator/commit/cde9e2051de5e23119404e419382a452fd5f24bd))
* correct IDP configure method calls in realm reconciler ([9e19c4c](https://github.com/vriesdemichael/keycloak-operator/commit/9e19c4c85b4a7e4950d5324ecf72961d95dfb4e4))
* correct Keycloak Admin API path for IDP verification ([0a1ca04](https://github.com/vriesdemichael/keycloak-operator/commit/0a1ca04d085fe1c2584cb6bfed47fff9660dde5e))
* correct license references from Apache 2.0 to MIT ([d5323b6](https://github.com/vriesdemichael/keycloak-operator/commit/d5323b67345b34c40d12e5ad9fd416bdf647a879))
* correct operatorRef structure in documentation ([84967e1](https://github.com/vriesdemichael/keycloak-operator/commit/84967e14732017ae62bb0ce2cfa1128b825c9ee7))
* create coverage directory in container and fix collection workflow ([3b74ee6](https://github.com/vriesdemichael/keycloak-operator/commit/3b74ee6f343bfb57ef4d8e3e70169ec4ffd8925e))
* **deps:** add missing pytest-xdist to test dependency group ([cb01362](https://github.com/vriesdemichael/keycloak-operator/commit/cb01362dce1f702458b8a605fa223bce11b173b4))
* disable webhook auto-management and default to false ([0c59b83](https://github.com/vriesdemichael/keycloak-operator/commit/0c59b834d2852d010a6ca97152eb4b2e41e0353b))
* drift detection tests auth token namespace ([763ebd1](https://github.com/vriesdemichael/keycloak-operator/commit/763ebd1b0d451b085a9f9877f429e73d3694b358))
* enable mandatory type checking and add Helm linting to pre-commit ([97dc9d7](https://github.com/vriesdemichael/keycloak-operator/commit/97dc9d7062695a9e3999c5554d774ac9c79e6c3d))
* enforce same-namespace secrets and fix Pydantic model access ([56d448a](https://github.com/vriesdemichael/keycloak-operator/commit/56d448a1e834f7d7da60172976fa67da3dd6bc89))
* **examples:** correct Keycloak CR database configuration ([be1495c](https://github.com/vriesdemichael/keycloak-operator/commit/be1495cc70125048d2f73f71b30aa727b2eccb3e))
* GitHub Actions release-please workflow JSON parsing error ([60081f4](https://github.com/vriesdemichael/keycloak-operator/commit/60081f4f5ea954892fc0f87db3b516d26250a042))
* import all webhook modules to register handlers ([12b9bbd](https://github.com/vriesdemichael/keycloak-operator/commit/12b9bbddb038caffa83f855eccfa59519b14621a))
* improve Dex deployment robustness ([78083fe](https://github.com/vriesdemichael/keycloak-operator/commit/78083fe5cf52fb64d5b30bf3bddcba4b041f5519))
* make all shell scripts executable for GitHub Actions ([bba6004](https://github.com/vriesdemichael/keycloak-operator/commit/bba6004d311e4073ab28aff28bbe926176eb0825))
* make coverage scripts executable and share unit coverage with integration tests ([17615ff](https://github.com/vriesdemichael/keycloak-operator/commit/17615ff3b997c7c86e41d5ca30221993f3d7fe95))
* make realm_cr and client_cr async fixtures ([3d46d6f](https://github.com/vriesdemichael/keycloak-operator/commit/3d46d6fcc22837130b4ee26b2bf4cc100f2c3ed3))
* only retrieve coverage on last worker exit ([236636a](https://github.com/vriesdemichael/keycloak-operator/commit/236636aa843ce6cd73cfe40191f605f3fc31e611))
* **operator:** allow integration coverage failures during outage ([42ece4a](https://github.com/vriesdemichael/keycloak-operator/commit/42ece4ac55598db3969f5129056c4448a6504ca6))
* **operator:** database passwordSecret support and test fixes ([038fc18](https://github.com/vriesdemichael/keycloak-operator/commit/038fc18da190e8d99eb02222c89c59393129feee))
* **operator:** detect release commits merged by users, not just bots ([50a21e9](https://github.com/vriesdemichael/keycloak-operator/commit/50a21e9c619faefe47e9d7a7b688b3d883518120))
* **operator:** disable fail_ci_if_error for codecov uploads ([2e22069](https://github.com/vriesdemichael/keycloak-operator/commit/2e220690d61551e2abca83359eab33bf7990a14e))
* **operator:** enable auto-merge for grouped release PRs ([7c2419a](https://github.com/vriesdemichael/keycloak-operator/commit/7c2419a95aca55264400d1d0252e2af52fec0501))
* **operator:** enforce scope for release-triggering commits ([6c7e271](https://github.com/vriesdemichael/keycloak-operator/commit/6c7e27134917df7e1c53031d86991c2ce74b9a7f))
* **operator:** group release-please PRs to prevent manifest conflicts ([529c990](https://github.com/vriesdemichael/keycloak-operator/commit/529c99037235bd63b315ae3673a1c1506dcccdca))
* **operator:** handle basic realm field updates in do_update method ([fab2804](https://github.com/vriesdemichael/keycloak-operator/commit/fab2804ad2e1b982f7e7009e11290f68fbaccf0b))
* **operator:** handle realm deletion gracefully in client cleanup ([45b25cd](https://github.com/vriesdemichael/keycloak-operator/commit/45b25cda8c945c56daddbc2538a1c0133713324f))
* **operator:** load test-coverage image tag for integration tests ([af358ba](https://github.com/vriesdemichael/keycloak-operator/commit/af358ba923a7e9625920de99abeac52d696a49e2))
* **operator:** make integration coverage non-fatal if not generated ([02022c7](https://github.com/vriesdemichael/keycloak-operator/commit/02022c7a728db530be61accf4961aa1ac70b1f53))
* **operator:** prevent event loop closed errors in httpx client cache ([83b8020](https://github.com/vriesdemichael/keycloak-operator/commit/83b80200c7d0df07058856e8ee99e979dba585a8))
* **operator:** properly fix coverage collection and uv group isolation ([867df0a](https://github.com/vriesdemichael/keycloak-operator/commit/867df0ae0140573ccb9f0788b5308ad231bd5d20))
* **operator:** resolve JSON serialization and test timing issues ([fb29bcb](https://github.com/vriesdemichael/keycloak-operator/commit/fb29bcbd1859e0dbcb2d8ded643a38ecb52c5cb5))
* **operator:** restore --group flags and upload integration coverage files separately ([b067c30](https://github.com/vriesdemichael/keycloak-operator/commit/b067c304459bd556de67f3bc292dab385a5fdac4))
* **operator:** revert uv run --group flag, keep coverage upload fix ([225cef3](https://github.com/vriesdemichael/keycloak-operator/commit/225cef3794076367e1ab25b659197460c25bd218))
* **operator:** run quality checks and tests for code OR chart changes ([a9e8ad2](https://github.com/vriesdemichael/keycloak-operator/commit/a9e8ad27ff84b7b704fdbbe9c8c353057078070c))
* **operator:** temporarily allow codecov failures during global outage ([baa2f58](https://github.com/vriesdemichael/keycloak-operator/commit/baa2f58e714c8e4b2538233fe84ba6c550926401))
* **operator:** update all-complete job to reference new chart jobs ([be5dde3](https://github.com/vriesdemichael/keycloak-operator/commit/be5dde3d28b33a2b78ff713eb5f9ce03df6d628e))
* **operator:** update package metadata with correct author info ([96ba785](https://github.com/vriesdemichael/keycloak-operator/commit/96ba785332f12613446cb83e5525ade6cc966e80))
* **operator:** use asyncio.to_thread for webhook K8s API calls ([d635da9](https://github.com/vriesdemichael/keycloak-operator/commit/d635da9ae8a78928baf613b35686256849e78b80))
* **operator:** use correct camelCase field names in realm update handler ([91636eb](https://github.com/vriesdemichael/keycloak-operator/commit/91636ebdb1afef442a5eb6e9bf46db69585454b8))
* **operator:** use coverage run in CMD for proper instrumentation ([1665eaa](https://github.com/vriesdemichael/keycloak-operator/commit/1665eaaef1f8bd01616a278edf99a232d6bd7a53))
* **operator:** use legacy codecov endpoint only as fallback ([c76ff4a](https://github.com/vriesdemichael/keycloak-operator/commit/c76ff4a0c120329c41266366283193cf3b82fa8e))
* **operator:** use legacy codecov upload as fallback ([1cb9293](https://github.com/vriesdemichael/keycloak-operator/commit/1cb929309a914b58197e0d03e4fe01801826edd5))
* preserve binary data when retrieving coverage files ([1cf7252](https://github.com/vriesdemichael/keycloak-operator/commit/1cf7252de0b3db30d217e011ff667fff0da18b6c))
* prevent premature operator cleanup in pytest-xdist workers ([8031895](https://github.com/vriesdemichael/keycloak-operator/commit/8031895e2b2347378cbb376555136ee7e395ff49))
* prevent premature operator cleanup in pytest-xdist workers ([2a7f4a1](https://github.com/vriesdemichael/keycloak-operator/commit/2a7f4a19892c44ce8a24dd63e2136f6645bad06b))
* proper webhook bootstrap with readiness probe and ArgoCD sync waves ([c8dfc52](https://github.com/vriesdemichael/keycloak-operator/commit/c8dfc5200c02cf550e8857d6e44583b50fb11895))
* properly implement IDP integration tests ([8cf7cb1](https://github.com/vriesdemichael/keycloak-operator/commit/8cf7cb1df097b447a215ccacb46254939d21b4c4))
* race condition in CI/CD and cleanup Makefile ([91b0640](https://github.com/vriesdemichael/keycloak-operator/commit/91b0640961ead705430efaa61c70daa6da8a45c0))
* reduce Dex wait timeout to avoid pytest timeout ([acb0106](https://github.com/vriesdemichael/keycloak-operator/commit/acb01064b8a4df9108b78a5016e7b779a77ceb58))
* refactor pages workflow to fix versioning and artifact issues ([e1d6da1](https://github.com/vriesdemichael/keycloak-operator/commit/e1d6da11bda072ead0d0eff66f87def24905ad0c)), closes [#114](https://github.com/vriesdemichael/keycloak-operator/issues/114)
* remove await from synchronous API call in capacity check ([2908db5](https://github.com/vriesdemichael/keycloak-operator/commit/2908db581fa9a39f590c67b1a3ef47f27ec978d0)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove duplicate coverage retrieval code ([691d70b](https://github.com/vriesdemichael/keycloak-operator/commit/691d70bd3cc8a9c3e1e22b4ac08db229e6b7a41d))
* Remove last_reconcile_time from status updates ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* remove obsolete authorization token references from charts ([880fc98](https://github.com/vriesdemichael/keycloak-operator/commit/880fc98637ff0e0e4c9471fd47162fc1d790b194)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove obsolete authorizationSecretName status field ([9952eae](https://github.com/vriesdemichael/keycloak-operator/commit/9952eaef7c155f3013b9a1cc2d7a0c66c7cf4827)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove tests for deleted periodic_leadership_check function ([1ffcba0](https://github.com/vriesdemichael/keycloak-operator/commit/1ffcba0479decb4916a65262f58a46f84ab28ddd))
* Removed await, added explicit k8s_client parameter. ([2908db5](https://github.com/vriesdemichael/keycloak-operator/commit/2908db581fa9a39f590c67b1a3ef47f27ec978d0))
* replace old keycloak.mdvr.nl API group with vriesdemichael.github.io ([da644e0](https://github.com/vriesdemichael/keycloak-operator/commit/da644e09d335803e59f61a2f46f463ebfab0e50b))
* resolve all three workflow failures ([9c6b5ed](https://github.com/vriesdemichael/keycloak-operator/commit/9c6b5edb50995ee1ccce91f5d9b1d690428f78e5))
* resolve permission denied error for build-adr-docs.sh in GitHub Actions ([4a99239](https://github.com/vriesdemichael/keycloak-operator/commit/4a9923972e933b94ad7559c1a95174b78b6c1afe))
* restore correct test image tag for coverage collection ([6cb1675](https://github.com/vriesdemichael/keycloak-operator/commit/6cb16758ce97572f7b98396ea3b6960fb61e122f))
* restore coverage collection and upload for tests ([0ae218d](https://github.com/vriesdemichael/keycloak-operator/commit/0ae218dc926c3c5bb834c3cf9cedf952b2106c45))
* restore integration test coverage collection ([4f35596](https://github.com/vriesdemichael/keycloak-operator/commit/4f355969c0f95f0445d6cceaf9fb7b260e574723))
* **security:** prevent sensitive exception details from leaking in HTTP responses ([b0ff023](https://github.com/vriesdemichael/keycloak-operator/commit/b0ff0236e1e559940b9deb111c30be0b6345708e))
* **security:** remove unnecessary verify=False from HTTP health check ([dd5217f](https://github.com/vriesdemichael/keycloak-operator/commit/dd5217f3e0df2407ffb594dd554c238889884b38))
* send SIGTERM instead of deleting pod for coverage ([d3fa7eb](https://github.com/vriesdemichael/keycloak-operator/commit/d3fa7eba9a9e4aa51c4d4fa04e55e2c21e49213f))
* simplify coverage - always on, fail hard, let codecov combine ([d953b29](https://github.com/vriesdemichael/keycloak-operator/commit/d953b291e32e8bdc66485fc8ebe2e5e947846ce7))
* streamline coverage workflow - remove merging, retrieve integration coverage immediately ([8fb0eb4](https://github.com/vriesdemichael/keycloak-operator/commit/8fb0eb4c9478b9996decfca81851492e2d6d21df))
* **tests:** fix all 7 drift detection integration tests ([fd5e76f](https://github.com/vriesdemichael/keycloak-operator/commit/fd5e76f4dab5294372d06205b4a4eb12cf3d35a8))
* **tests:** improve integration test reliability for CI environments ([77f6aa0](https://github.com/vriesdemichael/keycloak-operator/commit/77f6aa03aebbcda3fed2104619efa4a2f3da2f59))
* **tests:** properly mock Kubernetes client in finalizer tests ([df6e7d9](https://github.com/vriesdemichael/keycloak-operator/commit/df6e7d9df14cfd46b809da75d279bd94566acd3f))
* **tests:** resolve Helm chart schema validation error in CI ([7db635e](https://github.com/vriesdemichael/keycloak-operator/commit/7db635e5dd7924e56c4742fa1de8582b11243e85))
* **tests:** run integration tests in 'dev' group for improved organization ([dbe9590](https://github.com/vriesdemichael/keycloak-operator/commit/dbe9590d356ad9ca1ae26b77ac3ac429b625141b))
* TruffleHog BASE/HEAD commit issue in CI/CD workflow ([9067632](https://github.com/vriesdemichael/keycloak-operator/commit/90676320138f30044c30d1e2c9f494ff2eb056f5))
* update integration tests for grant list authorization ([9f2e2a6](https://github.com/vriesdemichael/keycloak-operator/commit/9f2e2a663ebd3d8c69ced03079b8405357dc86d1)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* update integration tests to use keycloak-prefixed annotations and finalizers ([0baf321](https://github.com/vriesdemichael/keycloak-operator/commit/0baf3213832ba63b853a06a34265244d976f54e6))
* update security scans to use test-coverage tag ([e65247b](https://github.com/vriesdemichael/keycloak-operator/commit/e65247be81106c06ece373ea6c418735cade9680))
* update tests and Helm schema for grant list authorization ([0fe6fca](https://github.com/vriesdemichael/keycloak-operator/commit/0fe6fcae8c638595a117b2093d869ecb85b37f47)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* upload raw coverage files instead of converting to XML ([64c98c7](https://github.com/vriesdemichael/keycloak-operator/commit/64c98c7b6db0365b820fb3fcfeb790e1364ac0e3))
* use correct image tag in promote workflow SBOM/Trivy steps ([65e5984](https://github.com/vriesdemichael/keycloak-operator/commit/65e59847f23d3a364fdabd4f6e54361d9c72ccd0))
* use correct operator image tag in integration tests ([8b3d7e8](https://github.com/vriesdemichael/keycloak-operator/commit/8b3d7e82a84454d4f5cd646788e150c745887790))
* use correct operator namespace and shared_operator fixture in drift tests ([581a2db](https://github.com/vriesdemichael/keycloak-operator/commit/581a2dbb881b3f0679ef83cfcad1e5f7c365c2c0))
* use correct yq sha256 checksum for v4.44.3 ([f4c7dc0](https://github.com/vriesdemichael/keycloak-operator/commit/f4c7dc0683a368ccb8bb2df25b087776b3d9d5df))
* use Dockerfile.test for coverage-instrumented image ([82f0373](https://github.com/vriesdemichael/keycloak-operator/commit/82f037384444e161cbd5013cd798bf8fe7ea4234))
* Use explicit exists output for artifact conditionals ([f52b7cd](https://github.com/vriesdemichael/keycloak-operator/commit/f52b7cdc66de1d7294fa34e4a3862aaf29b1d286))
* use kubectl for Dex deployment and enable IDP tests ([1e72b0e](https://github.com/vriesdemichael/keycloak-operator/commit/1e72b0ea450cb430cfe9d028e10139cf97bdae8b))
* use proper conventional commit scope for chart updates ([70cf9c0](https://github.com/vriesdemichael/keycloak-operator/commit/70cf9c043040b3405c48ccc5b4b92f23e368c30f))
* use shared_operator namespace directly in drift tests ([e70d3d3](https://github.com/vriesdemichael/keycloak-operator/commit/e70d3d30e06daaf6271237000578ae2424d3ce28))
* use sync client for kubernetes stream() calls ([4a7b524](https://github.com/vriesdemichael/keycloak-operator/commit/4a7b52426b9f68e1984bd6b63eb57a081536bea7))
* use test-coverage tag for operator image ([2f0cce4](https://github.com/vriesdemichael/keycloak-operator/commit/2f0cce4076eb307218cd0e9cddb91bdbffa70bb0))


### Performance Improvements

* implement generation-based skip to avoid redundant reconciliations ([af0d4c6](https://github.com/vriesdemichael/keycloak-operator/commit/af0d4c63490122a5d4893f2cb2e5cf6d63fe3f6b)), closes [#184](https://github.com/vriesdemichael/keycloak-operator/issues/184)


### Code Refactoring

* address PR review comments ([499a0c9](https://github.com/vriesdemichael/keycloak-operator/commit/499a0c93ff4f4a5074cdb5981b54a0f880a69044))
* **ci:** remove old workflow files ([2205530](https://github.com/vriesdemichael/keycloak-operator/commit/2205530eb3e8bd30ac6cb30c1962517fbad3d807))
* **ci:** split deployment into clear sequential steps ([ff07e16](https://github.com/vriesdemichael/keycloak-operator/commit/ff07e16aa604dfe1076c89d59ca1d298824e907a))
* **ci:** unify CI/CD pipeline into single workflow ([ea1b748](https://github.com/vriesdemichael/keycloak-operator/commit/ea1b74895c277ec70b7f2e35d15a5cdcdc0729d9))
* **ci:** use operator chart for complete deployment ([5cb1f09](https://github.com/vriesdemichael/keycloak-operator/commit/5cb1f0996723ded97df9f14e3aafea7d14ce14b9))
* **ci:** use uv run --with for ephemeral dependencies ([649d65f](https://github.com/vriesdemichael/keycloak-operator/commit/649d65f4c3167cf69f0982978255230ce786dd7a))
* clean up Makefile and add cluster reuse workflow ([#59](https://github.com/vriesdemichael/keycloak-operator/issues/59)) ([be3bcd4](https://github.com/vriesdemichael/keycloak-operator/commit/be3bcd4ab1f09413fc23da36aa79f5e00c9df91a))
* consolidate TODO files and enhance Keycloak admin API ([350c88f](https://github.com/vriesdemichael/keycloak-operator/commit/350c88fb0899e166dcea1883c00b2d1c78eeeb90))
* convert drift tests to function-based structure ([f576d14](https://github.com/vriesdemichael/keycloak-operator/commit/f576d143db4d048a6e0c3f53c32a5b75922e52be))
* **operator:** remove redundant uv sync steps when using --group ([c9aea4f](https://github.com/vriesdemichael/keycloak-operator/commit/c9aea4fa42335ae65efcd0a4874341cb9fcfbd2f))
* **operator:** unify Dockerfile with multi-stage targets ([dd81347](https://github.com/vriesdemichael/keycloak-operator/commit/dd813478441800b2519e184e94bc249fa2a6289c))
* **operator:** use manifest diff for major version detection ([3a161be](https://github.com/vriesdemichael/keycloak-operator/commit/3a161beddd0f086f03f5db0e637aaf0d724f21a2))
* remove version and enabled fields from CRDs for K8s-native design ([11cdf60](https://github.com/vriesdemichael/keycloak-operator/commit/11cdf60a1b21320154fcefe5eba3a4a20386beaf))
* restructure decision records with improved schema ([7eb2710](https://github.com/vriesdemichael/keycloak-operator/commit/7eb27104a3da5d4047992709e15ad993f169a1a8))
* simplify ADR structure - remove status field ([90cf325](https://github.com/vriesdemichael/keycloak-operator/commit/90cf3254ca06b062a24f3b87bcdcac75abab15dc))
* simplify CI/CD workflow conditionals ([45fad5c](https://github.com/vriesdemichael/keycloak-operator/commit/45fad5c6467f6f99aef82a543ad55af4b4a42931))
* split CI/CD workflow into composite actions ([34da80d](https://github.com/vriesdemichael/keycloak-operator/commit/34da80d4cd5aaa51e07dc4fa998f86e0faccb45f))
* split CI/CD workflow into composite actions ([6a36cb1](https://github.com/vriesdemichael/keycloak-operator/commit/6a36cb1b9fb1f19869b2cfc7ade85f9fc4a6fab7))
* split CI/CD workflow into composite actions + add custom logo ([610417d](https://github.com/vriesdemichael/keycloak-operator/commit/610417d980cfdaa85ed384a757b8bd0d7b587479))
* **test:** add fixture recommendation helper function ([bab3bfd](https://github.com/vriesdemichael/keycloak-operator/commit/bab3bfdad3e4320c4b9f4b7e12ac8ee77812d3c0))
* **test:** add keycloak_ready composite fixture with Pydantic model ([f6a0878](https://github.com/vriesdemichael/keycloak-operator/commit/f6a087895b40496a19daf9c6bf070dca3344df2d))
* **test:** add type safety with Pydantic models and prefix internal fixtures ([c6cc015](https://github.com/vriesdemichael/keycloak-operator/commit/c6cc01589345ba3fd5a2f482249d449dfe1312f8))
* **test:** consolidate token fixtures and add CR factory functions ([0de7519](https://github.com/vriesdemichael/keycloak-operator/commit/0de75197748dc8e1cef8fcdbeaf59e2a25fbbfae))
* **tests:** enhance integration test setup by optimizing dependency installation and removing unnecessary steps ([b55d6d9](https://github.com/vriesdemichael/keycloak-operator/commit/b55d6d98682c982caf8e1d36e6e67867c95f2d07))
* **tests:** streamline integration test execution and remove Makefile group ([09a2f71](https://github.com/vriesdemichael/keycloak-operator/commit/09a2f717056d109423898f4fd76d7d19b13cd235))
* update decision 005 - no plaintext secrets ([0d0d8ae](https://github.com/vriesdemichael/keycloak-operator/commit/0d0d8ae76a833d0687da957548253ad9f0d3b7af))
* update decision 012 - async API with resilience ([1397a43](https://github.com/vriesdemichael/keycloak-operator/commit/1397a4310c7102ed6b6a2b194c55c82d29bf45cf))
* update decision 013 - focus on data validation ([aae7d62](https://github.com/vriesdemichael/keycloak-operator/commit/aae7d62de24803e780ce79f98e4ee597756b2d43))
* Update status condition transition tests ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* use kopf[dev] extra instead of manual certbuilder ([bf44078](https://github.com/vriesdemichael/keycloak-operator/commit/bf44078d955d50613cc8d1c17605babecb08a3c0))
* use release-please as gatekeeper for CD phase ([8f607bb](https://github.com/vriesdemichael/keycloak-operator/commit/8f607bb6c71adcf1268d16148f55e8fb90b4a6ab))
* use targeted dependency groups in CI and Makefile ([12142e4](https://github.com/vriesdemichael/keycloak-operator/commit/12142e4d22059103603537bcbf9862723698a335))


### Documentation

* add 21 foundational Architecture Decision Records ([bbeb67e](https://github.com/vriesdemichael/keycloak-operator/commit/bbeb67eb9f5b75599b58a0ed6290bfd5d8ef27a9))
* add admission webhook documentation and decision record ([396de85](https://github.com/vriesdemichael/keycloak-operator/commit/396de85863b5731e6e55ae2ac11ad21fbc45eeb1))
* add ADR-064 rejecting force-delete feature ([6df1d50](https://github.com/vriesdemichael/keycloak-operator/commit/6df1d505d090ff22199a125bf30a760c005b402a))
* add Architecture Decision Records (ADR) structure ([d8f488b](https://github.com/vriesdemichael/keycloak-operator/commit/d8f488bb9922b666a0b01d00b386623a991ead72)), closes [#55](https://github.com/vriesdemichael/keycloak-operator/issues/55)
* add architecture diagrams for multi-operator and rate limiting ([927b0d1](https://github.com/vriesdemichael/keycloak-operator/commit/927b0d176a42b7d35059147d6b41f6ead37385ce))
* add CI/CD and documentation issues task list ([1d09817](https://github.com/vriesdemichael/keycloak-operator/commit/1d0981719319e67cb6872b4408f42e83014edd2e))
* add CI/CD and GitOps integration examples ([7225653](https://github.com/vriesdemichael/keycloak-operator/commit/7225653ecc3591fe01c2073ccddc3c47a80868ab))
* add comprehensive CRD field reference documentation ([2ad21a5](https://github.com/vriesdemichael/keycloak-operator/commit/2ad21a5725285277f96f2e40238e278f9ef6c853))
* add comprehensive drift detection documentation (Phase 6) ([c09439d](https://github.com/vriesdemichael/keycloak-operator/commit/c09439d39f7e2147a25bb0a9956e987ba6350835))
* add comprehensive observability and security documentation ([8bb3448](https://github.com/vriesdemichael/keycloak-operator/commit/8bb3448a3206362300d0b4c23ee24e2021ec221a))
* add comprehensive Quick Start guide with examples ([723e6d1](https://github.com/vriesdemichael/keycloak-operator/commit/723e6d1e14bc990f4da7ad3958ac1527c4f86ab7))
* add comprehensive release workflow analysis and fix documentation ([87838c9](https://github.com/vriesdemichael/keycloak-operator/commit/87838c9b57e0d0ad840cf4160e2e6f50ac53d3ab))
* add comprehensive security and reliability review for CI/CD workflows ([1fb53d4](https://github.com/vriesdemichael/keycloak-operator/commit/1fb53d4d4716cbc5cd5999e0df0feaca8385f7d9))
* add comprehensive testing guide and token terminology glossary ([91bf3b5](https://github.com/vriesdemichael/keycloak-operator/commit/91bf3b59ace290b2c618c8e740cb3cdeb78c2885))
* add comprehensive user guides and operations documentation ([92b99b2](https://github.com/vriesdemichael/keycloak-operator/commit/92b99b26005d3377c42427e15e4634264cf9bb7c))
* add custom logo and favicon ([34da80d](https://github.com/vriesdemichael/keycloak-operator/commit/34da80d4cd5aaa51e07dc4fa998f86e0faccb45f))
* add custom logo and favicon ([6a36cb1](https://github.com/vriesdemichael/keycloak-operator/commit/6a36cb1b9fb1f19869b2cfc7ade85f9fc4a6fab7))
* add Decision Records as separate tab with tag filtering ([6931bc3](https://github.com/vriesdemichael/keycloak-operator/commit/6931bc3b1989768b98a078161946a2115ed01d41))
* add decisions 022-023 for type checking and Make automation ([2bf22ec](https://github.com/vriesdemichael/keycloak-operator/commit/2bf22ecbea80ee1e0b75dadd5bc8867af022f9b6))
* add decisions 024-032 for deployment and architecture ([56ba2cc](https://github.com/vriesdemichael/keycloak-operator/commit/56ba2ccbcc3631f9eebdc06b08984ed94a3eb4da))
* add decisions 033-052 completing decision record set ([1dbd5d3](https://github.com/vriesdemichael/keycloak-operator/commit/1dbd5d36c2cd929e43e47aa1dd897d231627f14e))
* add deprecation notices to token-based documentation ([0dc075f](https://github.com/vriesdemichael/keycloak-operator/commit/0dc075f575722619dab823a11aacb222db39a067))
* add helm values JSON schema requirement to ADR-030 ([76f2637](https://github.com/vriesdemichael/keycloak-operator/commit/76f263714eed966ba80b685b2c501732cb3b9129))
* add identity provider documentation and integration tests ([9e6bb6a](https://github.com/vriesdemichael/keycloak-operator/commit/9e6bb6aa7cf74972046f29fac3e746c658dd7548))
* add introductory text to FAQ page ([b3e4116](https://github.com/vriesdemichael/keycloak-operator/commit/b3e4116a9853e9eacf3880db4a1a9c136f69c581))
* add Keycloak brand colors and improved styling ([fc7a0a5](https://github.com/vriesdemichael/keycloak-operator/commit/fc7a0a50f0993dad3f6b1e04791fc9c36e3d4b1f))
* add mandatory RELEASES.md check before commits in CLAUDE.md ([a329050](https://github.com/vriesdemichael/keycloak-operator/commit/a329050c1b5ce19c012ec9a274ca417cb3e83750))
* add Mermaid diagram support and hide home TOC ([b1f2e74](https://github.com/vriesdemichael/keycloak-operator/commit/b1f2e74d7f7a6cff2d8de4b8b29d146c5160b21c))
* add proper procedure for resolving PR review threads ([c4e5735](https://github.com/vriesdemichael/keycloak-operator/commit/c4e57354d0ca66b46743af860cf13f58afeeec63))
* add random jitter to decision 012 retry logic ([0e515b5](https://github.com/vriesdemichael/keycloak-operator/commit/0e515b5f37ce209970b54af80f33f79ac34a92d9))
* add scaling strategy documentation to architecture ([#56](https://github.com/vriesdemichael/keycloak-operator/issues/56)) ([0b496c7](https://github.com/vriesdemichael/keycloak-operator/commit/0b496c7b568a33889b8d9e7980e04b6a9e60b6b3))
* add security scanning badge to README ([8edd36b](https://github.com/vriesdemichael/keycloak-operator/commit/8edd36b9ba27b74717fdd2c6ac44a2b7361d05b6))
* add versioned documentation with mike integration ([c5d0bfd](https://github.com/vriesdemichael/keycloak-operator/commit/c5d0bfd5be47b20223fc8e541e0f8f8f54fec2a5))
* bulk cleanup of authorizationSecretRef in chart READMEs ([7010d85](https://github.com/vriesdemichael/keycloak-operator/commit/7010d855084409af6a36e3d17fae465070afd6b9))
* bulk cleanup remaining authorizationSecretRef references ([61e66a3](https://github.com/vriesdemichael/keycloak-operator/commit/61e66a3321be25ed370702df669f7bcd5299fa27))
* change default merge strategy to rebase ([442c6b9](https://github.com/vriesdemichael/keycloak-operator/commit/442c6b9787787a597010405e822ac468d2b17d66))
* **chart-client:** add comprehensive README ([7b147c8](https://github.com/vriesdemichael/keycloak-operator/commit/7b147c845b18172f0526182ecc33a469a56b5f07))
* **chart-operator:** add comprehensive README ([759081d](https://github.com/vriesdemichael/keycloak-operator/commit/759081deb9ac3cea713a0aac7843b15624165dd1))
* **chart-realm:** add comprehensive README ([92c8e95](https://github.com/vriesdemichael/keycloak-operator/commit/92c8e95cd65ebdfa6c90f6b12b1b1fe7a91a80bb))
* **ci:** add CI/CD improvements tracking document ([67f714a](https://github.com/vriesdemichael/keycloak-operator/commit/67f714ae03578335b85370f1da540e9242a822a0))
* **ci:** add complete implementation summary ([b42a0dd](https://github.com/vriesdemichael/keycloak-operator/commit/b42a0dd87beb71689f096a671da89eea2bf97699))
* **ci:** add workflow migration documentation ([7028b35](https://github.com/vriesdemichael/keycloak-operator/commit/7028b354f4b5f0badb48bf3f3f84c457bc2f9280))
* **ci:** feature requests now require less information ([93945d1](https://github.com/vriesdemichael/keycloak-operator/commit/93945d111c2a1a4d60dd9a630947306bf97e5efe))
* **ci:** update tracking to reflect Phase 2 completion ([33baaf6](https://github.com/vriesdemichael/keycloak-operator/commit/33baaf64537594e4500bc838e5baa64bd00a3b31))
* clarify namespace scope requires cluster-wide RBAC ([ea563db](https://github.com/vriesdemichael/keycloak-operator/commit/ea563db39f1228beb5cd5347923f2988bda88fc7))
* clean authorizationSecretRef from CRD reference docs ([e416d90](https://github.com/vriesdemichael/keycloak-operator/commit/e416d902e9b5cfed1a27522dfc3d4831d23b0030))
* configure mkdocstrings to resolve autorefs warnings in strict mode ([1165559](https://github.com/vriesdemichael/keycloak-operator/commit/11655595007e807c597dbd87565a7fca2a59895c))
* correct tracking document - Phase 3 was already complete ([d374041](https://github.com/vriesdemichael/keycloak-operator/commit/d374041174d5a9657911a1bd24e58b1dae9aa651))
* **design:** add Keycloak state observability analysis ([120eb81](https://github.com/vriesdemichael/keycloak-operator/commit/120eb81c5e8bd4d28c1833f9afaa088f90ce0210))
* enforce least privilege by removing admin console access ([4c788bd](https://github.com/vriesdemichael/keycloak-operator/commit/4c788bdf694d60aa5da0423f28f932dedabb2f8b))
* enhance dark mode styling with better contrast ([b905878](https://github.com/vriesdemichael/keycloak-operator/commit/b9058784419cc9f9248eddbf9ef0537aed123cf3))
* expand decision 009 - AI agents as first-class developers ([7c1a416](https://github.com/vriesdemichael/keycloak-operator/commit/7c1a416a778f228ec4b577658cdd7e97a5d66ee3))
* final cleanup of remaining token references ([10f83eb](https://github.com/vriesdemichael/keycloak-operator/commit/10f83eb6fd7883b24c27e7d114c017f5e6284992))
* final tracking update - 36/36 tests passing ([8462747](https://github.com/vriesdemichael/keycloak-operator/commit/8462747b9610497387e972a3c13def51ef843f21)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* fix ADR 45/49 and add decision records to documentation ([33586ac](https://github.com/vriesdemichael/keycloak-operator/commit/33586ac4705692b4ff9db3063091b107a4c89504))
* fix ASCII diagram spacing and automate decision index ([2ef4cec](https://github.com/vriesdemichael/keycloak-operator/commit/2ef4cecf0bb78f5da3cb68b481c15255f71baa68))
* fix broken anchor links and ADR index page ([34825a9](https://github.com/vriesdemichael/keycloak-operator/commit/34825a9473ab7e7341fbe73f3aff14abb3b284e3))
* fix broken links and cross-references ([64da07d](https://github.com/vriesdemichael/keycloak-operator/commit/64da07d31135ab7bb1e77a41686f6b71ffca61d8))
* fix deployment flow and remove identity realm confusion ([612253d](https://github.com/vriesdemichael/keycloak-operator/commit/612253d6ac90966e1e3d321d82302a8b62f3b3ec))
* fix tab text readability and all broken links ([603de35](https://github.com/vriesdemichael/keycloak-operator/commit/603de357bee74a3ec0037e172c12ddc8b2842575))
* fix YAML schema URLs in identity provider examples ([e7ba31d](https://github.com/vriesdemichael/keycloak-operator/commit/e7ba31d18780fbf8219100aaa1800bf360d88283))
* Implement robust cleanup system for integration tests ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* improve cross-references and navigation ([a2b4352](https://github.com/vriesdemichael/keycloak-operator/commit/a2b4352d397e66fd6cb3e7999ab179938e4f1a21))
* improve navigation and expand development documentation ([169a930](https://github.com/vriesdemichael/keycloak-operator/commit/169a93047479194efd3fc09329dd768dcf9a35c9))
* mark final review complete - ready for PR ([5b859f0](https://github.com/vriesdemichael/keycloak-operator/commit/5b859f0c9d63948798ce942d99df31628d3ae4c0))
* mark Phase 8 complete - all automated tests passing ([61ce95e](https://github.com/vriesdemichael/keycloak-operator/commit/61ce95efea92917ccc46a68915a3337ef736139d)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* move Home into Getting Started section ([bff4ba6](https://github.com/vriesdemichael/keycloak-operator/commit/bff4ba682fbc69862edae9d67631638268262b0f))
* remove authorizationSecretRef from observability and reference docs ([b466677](https://github.com/vriesdemichael/keycloak-operator/commit/b4666776ec7f2e449419d246250cc08b72e975d3))
* remove GitOps examples (too advanced for target audience) ([d5d4e8f](https://github.com/vriesdemichael/keycloak-operator/commit/d5d4e8fdc4e595778966956db6a694a34f2fc5a8))
* remove token system from architecture.md and faq.md ([12a2495](https://github.com/vriesdemichael/keycloak-operator/commit/12a2495369e93fe555174b6780a4917d1fde5085))
* remove tracking documents ([b1d10f4](https://github.com/vriesdemichael/keycloak-operator/commit/b1d10f49e5f3c9d6ac98ea1e867dfe7ec70cdcd6))
* removed mentions of the authorization token in the readme. ([a6d8287](https://github.com/vriesdemichael/keycloak-operator/commit/a6d828700a3e08755fa960baf78ffa18da1c0184))
* removed outdated todos ([3f7f227](https://github.com/vriesdemichael/keycloak-operator/commit/3f7f2276767642986318633df1d9ae332daf98a5))
* rename ADR-054 to reflect cluster RBAC requirement ([de8fb84](https://github.com/vriesdemichael/keycloak-operator/commit/de8fb849ff538d075b07561c8ec21c911ea1234b))
* reorganize documentation structure and simplify README ([e0b7bef](https://github.com/vriesdemichael/keycloak-operator/commit/e0b7befc77a9f201965d39f88ef03041c4d5bd22))
* reorganize navigation structure to reduce tab overflow ([e1507a9](https://github.com/vriesdemichael/keycloak-operator/commit/e1507a96a270a674151acebe502405cb994bce9a))
* replace ASCII art diagrams with Mermaid charts ([d398c4e](https://github.com/vriesdemichael/keycloak-operator/commit/d398c4e9965a1e93a995aa45a09319a92e00f9ac))
* replace landing page and quickstart with current architecture ([4c33aa6](https://github.com/vriesdemichael/keycloak-operator/commit/4c33aa69237d21ae8daa2fc7a726dbbdd351a08a))
* replace tags plugin with manual categorization for decision records ([1c96007](https://github.com/vriesdemichael/keycloak-operator/commit/1c960078a54bdbd9208c0e2fba88cdfd1ad4edb9))
* review and improve decision records ([0c0ea52](https://github.com/vriesdemichael/keycloak-operator/commit/0c0ea52032b0cb4b262d41c65a3c9931a0a3fe4f))
* rewrite charts README to remove token system ([b1ffdc6](https://github.com/vriesdemichael/keycloak-operator/commit/b1ffdc667c083e00c4921f2f6b8e88fcd8542c6b))
* rewrite end-to-end-setup guide sections 5-6 and 9.5 ([0a8f837](https://github.com/vriesdemichael/keycloak-operator/commit/0a8f83722554999d91d2cb2210d6a3529a0f77b6))
* rewrite security.md for namespace grant authorization model ([cfbf2c5](https://github.com/vriesdemichael/keycloak-operator/commit/cfbf2c56e49dd606e3c5675ef8a539f48dc24519))
* rewrite troubleshooting authorization section ([53b637b](https://github.com/vriesdemichael/keycloak-operator/commit/53b637b5ffad7897228f41e11f4e70ca41afd908))
* standardize examples with version compatibility and setup instructions ([98abafb](https://github.com/vriesdemichael/keycloak-operator/commit/98abafb9029d38c6b2b6a99749698267867c8363))
* **test:** improve factory fixture documentation ([b6db340](https://github.com/vriesdemichael/keycloak-operator/commit/b6db340fdbb2cbccab377f776d235af319400456))
* update charts README with token system and new chart references ([65caac0](https://github.com/vriesdemichael/keycloak-operator/commit/65caac08d47bb92ef28f0cc8de04a6d4f38de96a))
* update CI/CD badges to point to unified workflow ([4419899](https://github.com/vriesdemichael/keycloak-operator/commit/4419899d41bd4bb949f0d4c82d67d48334c6a08c))
* update end-to-end-setup.md to use namespace grants ([fe6cd73](https://github.com/vriesdemichael/keycloak-operator/commit/fe6cd73ccd3d41394eff35bebb027f0f61c8126e))
* update FAQ and end-to-end guide to remove token references ([5a583eb](https://github.com/vriesdemichael/keycloak-operator/commit/5a583ebaa238d81c84ac75184912752b2744b356))
* update helm chart READMEs and fix broken links ([dfb210d](https://github.com/vriesdemichael/keycloak-operator/commit/dfb210de7e222159830c5687e47e0e6d5eab354e))
* update manual-todos to mark CRD design improvements as complete ([80420e9](https://github.com/vriesdemichael/keycloak-operator/commit/80420e925823fc5db290ef4053091d007a110542))
* update Phase 1 tracking with review findings and deferred work ([921757b](https://github.com/vriesdemichael/keycloak-operator/commit/921757b796a7c0b87d01ad635d0ddc7f0ce26176))
* update phase 6B TODO to reflect production mode completion ([34b6b4d](https://github.com/vriesdemichael/keycloak-operator/commit/34b6b4d22c21dd5c85887e4482f21261582ed198))
* update README badges to reference unified CI/CD workflow ([03ba009](https://github.com/vriesdemichael/keycloak-operator/commit/03ba009eb0aac6e4db6ebdbc8f6315b0ccf0dd4a))
* update release process for branch protection and PR workflow ([#12](https://github.com/vriesdemichael/keycloak-operator/issues/12)) ([6508868](https://github.com/vriesdemichael/keycloak-operator/commit/6508868dbf3b245f598fa4f1253952ae01193947))
* update tracking document - Phase 1 complete ([5ade37b](https://github.com/vriesdemichael/keycloak-operator/commit/5ade37bbc5097d12f9acbcfdcc9fa4b1e5197fdc))
* update tracking document - Phase 4 complete ([e86c1b9](https://github.com/vriesdemichael/keycloak-operator/commit/e86c1b9fa810f6258be788315ae3834f0c849098))
* update tracking document with post-Phase-2 work ([4f68758](https://github.com/vriesdemichael/keycloak-operator/commit/4f68758ac2d955beb9463daf4dd0e433e75a4311))
* update tracking plan with completed Phase 3 tasks ([e3b0f1b](https://github.com/vriesdemichael/keycloak-operator/commit/e3b0f1b2a17d5641daa0871d23d036d6b1ddfc4a))


### CI/CD

* **operator:** refactor release workflow to build-once promote-on-release pattern ([f4464b1](https://github.com/vriesdemichael/keycloak-operator/commit/f4464b124b41e9d2da3b034d10560c89fda159a5))

## [0.4.3](https://github.com/vriesdemichael/keycloak-operator/compare/v0.4.2...v0.4.3) (2025-12-17)


### Bug Fixes

* **chart-operator:** correct digest regex in helm chart publish action ([d9cb566](https://github.com/vriesdemichael/keycloak-operator/commit/d9cb5666a4840df3626382b2f92fa59a45bb3335))
* **chart-operator:** update for operator v0.4.2 ([3e05ace](https://github.com/vriesdemichael/keycloak-operator/commit/3e05ace25ee4dad3555aa6f3e94487cbdd04c09a))
* **chart-operator:** update for operator v0.4.3 ([59cc41b](https://github.com/vriesdemichael/keycloak-operator/commit/59cc41bceb04de3f4a5d4ebcb960c6863f29211e))


### Performance Improvements

* implement generation-based skip to avoid redundant reconciliations ([af0d4c6](https://github.com/vriesdemichael/keycloak-operator/commit/af0d4c63490122a5d4893f2cb2e5cf6d63fe3f6b)), closes [#184](https://github.com/vriesdemichael/keycloak-operator/issues/184)


### Code Refactoring

* use release-please as gatekeeper for CD phase ([8f607bb](https://github.com/vriesdemichael/keycloak-operator/commit/8f607bb6c71adcf1268d16148f55e8fb90b4a6ab))

## [0.6.0](https://github.com/vriesdemichael/keycloak-operator/compare/v0.5.0...v0.6.0) (2025-12-17)


### ⚠ BREAKING CHANGES

* **chart-client+chart-operator+chart-realm:** Helm chart distribution moved to OCI registry
* **operator:** IDP secrets must use configSecrets field, plaintext forbidden
* **webhooks:** Admission webhooks now require cert-manager to be installed
* **chart-client+chart-realm:** Removed token-based authorization from all charts
* **operator:** latest tag no longer updates on main push, only on releases
* The API group domain has changed from keycloak.mdvr.nl to vriesdemichael.github.io. Existing installations must migrate by:
* **ci:** Release configuration now uses container-based versioning instead of Python package versioning
* Remove spec.version field from Keycloak CRD and spec.enabled field from KeycloakRealm CRD
* Multiple CRD field renames and removals for consistency

### Features

* Add centralized operator design and RBAC security implementation plan ([17b3413](https://github.com/vriesdemichael/keycloak-operator/commit/17b3413aa1c21de636b342fd9af0ff7fcc48ad96))
* add drift detection foundation (Phase 1-3) ([80cf043](https://github.com/vriesdemichael/keycloak-operator/commit/80cf0438ef7b0e7568fa9d033e15be305f24ba55))
* Add Keycloak Operator and Realm Helm charts ([2d4be4f](https://github.com/vriesdemichael/keycloak-operator/commit/2d4be4f4b8b43665afcecc8f0dacefbe88f66117))
* add keycloak_admin_client fixture for test isolation ([ea46f21](https://github.com/vriesdemichael/keycloak-operator/commit/ea46f21f8029643e4a31584830793b64f9c8402b))
* Add method to retrieve Keycloak instance from realm status ([0e45143](https://github.com/vriesdemichael/keycloak-operator/commit/0e45143500efcc16da48989de21bfd5b238c6480))
* add OIDC endpoint discovery to realm status ([6dc52f3](https://github.com/vriesdemichael/keycloak-operator/commit/6dc52f3ac9a51547e4431f99abbe91aec1d7dca3))
* Add optimized Keycloak image for 81% faster tests ([#15](https://github.com/vriesdemichael/keycloak-operator/issues/15)) ([3093a10](https://github.com/vriesdemichael/keycloak-operator/commit/3093a10239538b76d4fe7ae094e9ddcc85a519bd))
* Automatic Token Rotation System with Bootstrap Flow ([#26](https://github.com/vriesdemichael/keycloak-operator/issues/26)) ([ca28c1b](https://github.com/vriesdemichael/keycloak-operator/commit/ca28c1b995a8b953935f61d255de49921ac4cd85))
* **chart-client+chart-operator+chart-realm:** migrate to OCI registry in GHCR ([dc4f59c](https://github.com/vriesdemichael/keycloak-operator/commit/dc4f59c8f9d66be04cd7be6ae685fc714a8aad97))
* **chart-client+chart-realm:** update charts for namespace grant authorization ([add6af9](https://github.com/vriesdemichael/keycloak-operator/commit/add6af903c2ff887cd44c5608ceb1a1a6436f23e)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart-operator:** add 'get' permission for cross-namespace realm reads ([1e9cf4f](https://github.com/vriesdemichael/keycloak-operator/commit/1e9cf4fd7f4c4fb3e2a85d02bc217c8d4449075a)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart-operator:** update CRDs for namespace grant authorization ([b526149](https://github.com/vriesdemichael/keycloak-operator/commit/b52614931946e588730b3cc4312c061e383623fe)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart:** add automated operator version updates ([b303448](https://github.com/vriesdemichael/keycloak-operator/commit/b3034483f890b6ae282f787cc0ef343bc6fe6d03))
* **chart:** make admin password optional, leverage auto-generation ([a9fcb1a](https://github.com/vriesdemichael/keycloak-operator/commit/a9fcb1a475b99036b811753f42029a5cd0c0ad12))
* **charts:** add values.schema.json and extraManifests support ([039e00d](https://github.com/vriesdemichael/keycloak-operator/commit/039e00d1fe0874b2eb24f21d95f5e58d9f4a50cc))
* **ci:** add CODEOWNERS for automated review requests ([2e81678](https://github.com/vriesdemichael/keycloak-operator/commit/2e81678808cf1cca99dc668878f434cd5ae98310))
* **ci:** add comprehensive security scanning workflow ([116ef6f](https://github.com/vriesdemichael/keycloak-operator/commit/116ef6f12d73fd58bfbe3cc96906b7e38984d2bf))
* **ci:** add Dependabot for automated dependency updates ([61614e5](https://github.com/vriesdemichael/keycloak-operator/commit/61614e512728595dfaff0597882ea473e15b84c4))
* **ci:** add explicit shared Keycloak instance creation step ([dc530a1](https://github.com/vriesdemichael/keycloak-operator/commit/dc530a1f56dea2241bb459478745d8541a31e8ce))
* **ci:** add security validation to image publishing ([582caf1](https://github.com/vriesdemichael/keycloak-operator/commit/582caf117d9deb0978030651a7ac94cb0198b563))
* **ci:** auto-approve and merge non-major release PRs ([609e19b](https://github.com/vriesdemichael/keycloak-operator/commit/609e19b0b821c478c0c05962d74d1a3325d6781a))
* **ci:** create unified CI/CD pipeline workflow ([3209445](https://github.com/vriesdemichael/keycloak-operator/commit/3209445882e6ed40a67b966939550c5e976259f8))
* **ci:** enable auto-merge for release-please PRs ([0a74683](https://github.com/vriesdemichael/keycloak-operator/commit/0a746834e37fae0ad17088caa6b0c6b0757a0d0e))
* Enhance Keycloak models with aliasing and population configuration ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* implement admission webhooks for resource validation ([061acae](https://github.com/vriesdemichael/keycloak-operator/commit/061acae11b1af0d5547177c98264ac6ffbaa8f27))
* implement deletion handler fixes and cascading deletion ([13d25bb](https://github.com/vriesdemichael/keycloak-operator/commit/13d25bb5082f0c6aaf367cedb53ab4a600d36d3b))
* Implement Kopf peering for leader election and update deployment scripts ([a289e3a](https://github.com/vriesdemichael/keycloak-operator/commit/a289e3a55d95ecf2af4e2d29d94399acccf6aa25))
* implement orphan remediation (Phase 5) ([d225065](https://github.com/vriesdemichael/keycloak-operator/commit/d2250654f217dece764edabf4e9a17d8909a125e))
* Implement resource existence checks before cleanup in Keycloak reconciler ([e88ff0f](https://github.com/vriesdemichael/keycloak-operator/commit/e88ff0f46292e2bc355d1450f0f8e3406787ef40))
* implement secure SMTP configuration for KeycloakRealm ([d79ef1c](https://github.com/vriesdemichael/keycloak-operator/commit/d79ef1ca109c7dc21019932fb7fc2c1a025bee62))
* migrate API group from keycloak.mdvr.nl to vriesdemichael.github.io ([d93b3c1](https://github.com/vriesdemichael/keycloak-operator/commit/d93b3c115d73ba8e3f1fa99c48c1e058f315b075))
* **monitoring:** add Grafana dashboard and Prometheus alert rules ([e459d0d](https://github.com/vriesdemichael/keycloak-operator/commit/e459d0d11c874f17c844012f641ec51ae53ad24b))
* **operator:** add build attestations for supply chain security ([85a46cc](https://github.com/vriesdemichael/keycloak-operator/commit/85a46cce26775bc13ed809623d4ac998ce6b0152))
* **operator:** add comprehensive test coverage infrastructure ([0405cfb](https://github.com/vriesdemichael/keycloak-operator/commit/0405cfbb2b65993696cc820e62ba32be2793788a)), closes [#110](https://github.com/vriesdemichael/keycloak-operator/issues/110)
* **operator:** add coverage retrieval function (reformatted) ([73ff054](https://github.com/vriesdemichael/keycloak-operator/commit/73ff054f196b3cd076bdc11e16ac2e140e7c5594))
* **operator:** add GitHub deployment environments to workflow ([94b6b9b](https://github.com/vriesdemichael/keycloak-operator/commit/94b6b9bd3531fda63cbe6c43c088994649321d9a))
* **operator:** centralize configuration with pydantic-settings ([dd6078b](https://github.com/vriesdemichael/keycloak-operator/commit/dd6078bf9256e722188343987009f9a26b8ac3ee)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* **operator:** complete integration coverage collection ([1d4e5a4](https://github.com/vriesdemichael/keycloak-operator/commit/1d4e5a4f4fd369efeb81032539c6e938c9015635))
* **operator:** fix pydantic-settings environment variable configuration ([20d00b3](https://github.com/vriesdemichael/keycloak-operator/commit/20d00b3ff8a242e08706426ed7bc7a48e3eb2e6e)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* **operator:** implement integration test coverage collection via SIGUSR1 ([259e587](https://github.com/vriesdemichael/keycloak-operator/commit/259e587ab08a5388702e1871d62c923434796c35)), closes [#111](https://github.com/vriesdemichael/keycloak-operator/issues/111)
* **operator:** require secret refs for IDP secrets ([bf377fb](https://github.com/vriesdemichael/keycloak-operator/commit/bf377fb76b504f2c2160cd08c41ff60071505e57))
* publish JSON schemas for CRDs to enable IDE autocomplete ([72485af](https://github.com/vriesdemichael/keycloak-operator/commit/72485afb83822db7e427e1b876fd2700a91489a5))
* **resilience:** add circuit breaker and exponential backoff for API stability ([2ada936](https://github.com/vriesdemichael/keycloak-operator/commit/2ada93645579b4f81c2c042a0d53cd3d858a1e78))
* simplify issue templates for AI-agent compatibility ([c1a3c54](https://github.com/vriesdemichael/keycloak-operator/commit/c1a3c54e0dbe24c5d242777ddc1770e4e30b4d4e))
* switch Keycloak to production mode with HTTP enabled for ingress TLS termination ([1e64bc9](https://github.com/vriesdemichael/keycloak-operator/commit/1e64bc9d8b6608b24df917f167f81dfd41f51569))
* Two-level rate limiting with async/await conversion ([#44](https://github.com/vriesdemichael/keycloak-operator/issues/44)) ([476a6ed](https://github.com/vriesdemichael/keycloak-operator/commit/476a6ed4bbb327d38e7c55bdc1421daa3fdb2a81))
* update release-please configuration and add auto-rebase workflow ([92981a7](https://github.com/vriesdemichael/keycloak-operator/commit/92981a7525a14f8ae7cd97d4228e0547b8c3d09e))
* use SVG logo and update favicon ([a180ba2](https://github.com/vriesdemichael/keycloak-operator/commit/a180ba227d9295e9350b478ad47e83584e5da960))
* **webhooks:** switch to cert-manager for webhook TLS certificates ([7195217](https://github.com/vriesdemichael/keycloak-operator/commit/7195217d15903d9c2c738999ce4c25acf1daaa88))


### Bug Fixes

* add await to second IDP configure call ([a4a2589](https://github.com/vriesdemichael/keycloak-operator/commit/a4a25891530f62b1603794be642b443f6a20563a))
* add camelCase aliases to KeycloakIdentityProvider model ([5a0d9a0](https://github.com/vriesdemichael/keycloak-operator/commit/5a0d9a0fe0d44569db02e242529b6d5c4a2fda75))
* add certbuilder dependency and fix webhook RBAC permissions ([71df4ee](https://github.com/vriesdemichael/keycloak-operator/commit/71df4eebe6573b84eea6fab15fd9f9666806b3d5))
* add clientAuthorizationGrants to finalizer tests ([954d850](https://github.com/vriesdemichael/keycloak-operator/commit/954d8505d79fc2ebe7a80f6ffab319f8f5d46a1b)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* add clientAuthorizationGrants to Helm client test ([5ddf722](https://github.com/vriesdemichael/keycloak-operator/commit/5ddf7222b81f90ddb8c611f5f3e0d4e00e2aa620)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* Add clientAuthorizationGrants to realm test specs ([91e33ca](https://github.com/vriesdemichael/keycloak-operator/commit/91e33cab1b367ecc75e1f507af62f60bcfe2fde8))
* add get permission for CRDs in ClusterRole ([3455cd6](https://github.com/vriesdemichael/keycloak-operator/commit/3455cd6eef7148d506f33e13add95ea6927759de))
* add missing common.sh and config.sh scripts, update documentation ([59a644f](https://github.com/vriesdemichael/keycloak-operator/commit/59a644f580ec57eb8f297789949fe0105a7c8bc6))
* add missing namespace parameter to configure_identity_provider ([24230fd](https://github.com/vriesdemichael/keycloak-operator/commit/24230fd4055e9ab1a19cf0ac29e945f43572f53b))
* add missing RBAC permissions and correct readiness probe port ([2300f2a](https://github.com/vriesdemichael/keycloak-operator/commit/2300f2a85d6f007e2f1d6ca9b12ae80745adc95e))
* add namespace to Dex manifests ([cad2621](https://github.com/vriesdemichael/keycloak-operator/commit/cad2621cda178d90215c622f1e5cec0f2b85a39d))
* Add operator log capture and fix all integration tests ([#14](https://github.com/vriesdemichael/keycloak-operator/issues/14)) ([bf4e84f](https://github.com/vriesdemichael/keycloak-operator/commit/bf4e84ff8e4e5f8a0ebb0210ac2d6922beae2174))
* add patch permission for pods in namespace Role ([43d7fdc](https://github.com/vriesdemichael/keycloak-operator/commit/43d7fdc6f55475da9a6ba5ce42b0987bdb6d6557))
* add Pod Security Standards compliance to Dex deployment ([7ff7673](https://github.com/vriesdemichael/keycloak-operator/commit/7ff7673a74b65e52f525c670976ea07ce459ea21))
* add yq installation to release docs job ([6e53a92](https://github.com/vriesdemichael/keycloak-operator/commit/6e53a92a6ca26979eef60b0d3842d6e754bc9f27))
* address all Copilot review comments ([3ddfd8e](https://github.com/vriesdemichael/keycloak-operator/commit/3ddfd8eecdcaa83334485c616299f5f545f6ce4a))
* address Copilot review comments (resolved conflicts) ([76f6256](https://github.com/vriesdemichael/keycloak-operator/commit/76f6256cccb554ec418fd9195b9de72fbeaf3ad4))
* address Copilot review comments for integration tests ([fc09ef6](https://github.com/vriesdemichael/keycloak-operator/commit/fc09ef6d2c709d2f4b602e6bad3a3e6545b38b32))
* address Copilot review comments on unified CI/CD ([9cb6372](https://github.com/vriesdemichael/keycloak-operator/commit/9cb637234011f17b94db9547d590ed76459adbc3))
* address PR review comments ([3f0608e](https://github.com/vriesdemichael/keycloak-operator/commit/3f0608ef4ea3234b06d05f165c20b79d30395741))
* address PR review comments ([568d934](https://github.com/vriesdemichael/keycloak-operator/commit/568d9342dbbb582ae6c3544656de290735298b00))
* address review comments ([14007df](https://github.com/vriesdemichael/keycloak-operator/commit/14007df5fb013d9d43fdbe0b9732c447baca43f5))
* allow test tags in operator chart schema ([6740046](https://github.com/vriesdemichael/keycloak-operator/commit/6740046724b30ca0d694bc85a40212db826fe596))
* allow test-* tags in operator chart schema ([8450c8f](https://github.com/vriesdemichael/keycloak-operator/commit/8450c8fa9135190af5c272b641e09327de3f4b56))
* change operator component name to remove space ([e994ac2](https://github.com/vriesdemichael/keycloak-operator/commit/e994ac2a7d9fce824be86d0ade475f24aa17f6cc))
* **chart-operator:** correct digest regex in helm chart publish action ([d9cb566](https://github.com/vriesdemichael/keycloak-operator/commit/d9cb5666a4840df3626382b2f92fa59a45bb3335))
* **chart-operator:** remove admission token configuration from values ([302a27d](https://github.com/vriesdemichael/keycloak-operator/commit/302a27d59db56b064a7888ce1ee4c76f377f77e0))
* **chart-operator:** remove outdated authorization token instructions ([6f2c190](https://github.com/vriesdemichael/keycloak-operator/commit/6f2c1907af74134fc727e132e4a4ca40a5300130))
* **chart-operator:** update for operator v0.3.3 compatibility ([584c98f](https://github.com/vriesdemichael/keycloak-operator/commit/584c98f080352b39eab75c1c18e5faba838af9e9))
* **chart-operator:** update for operator v0.4.2 ([3e05ace](https://github.com/vriesdemichael/keycloak-operator/commit/3e05ace25ee4dad3555aa6f3e94487cbdd04c09a))
* **chart-operator:** update for operator v0.4.3 ([59cc41b](https://github.com/vriesdemichael/keycloak-operator/commit/59cc41bceb04de3f4a5d4ebcb960c6863f29211e))
* **chart:** align Keycloak CR template with actual CRD spec ([bfa3a62](https://github.com/vriesdemichael/keycloak-operator/commit/bfa3a62c60c715e510670642e69676058375fceb))
* **chart:** remove kustomization file from Helm CRDs folder ([dd80cb3](https://github.com/vriesdemichael/keycloak-operator/commit/dd80cb340bd3c5b5ffd4d64b83e15df918bbe4ae))
* **ci:** add all helm charts to release-please config ([2c2280b](https://github.com/vriesdemichael/keycloak-operator/commit/2c2280bd8d9faab8669738baa9dd3a58607383eb))
* **ci:** add Docker tag extraction for operator-v prefixed tags ([#28](https://github.com/vriesdemichael/keycloak-operator/issues/28)) ([b761052](https://github.com/vriesdemichael/keycloak-operator/commit/b76105243a369c3a29fee8da425c6aa888142007))
* **ci:** add missing Dockerfile path to publish job ([4986bec](https://github.com/vriesdemichael/keycloak-operator/commit/4986becd3b89c79f48493064a74940a1243a0cd2))
* **ci:** add proper step gating to fail fast on deployment errors ([6a74656](https://github.com/vriesdemichael/keycloak-operator/commit/6a746568809f3829b3ad1413052d4102bc28ae1d))
* **ci:** add semantic version tags to published container images ([2d64ab2](https://github.com/vriesdemichael/keycloak-operator/commit/2d64ab2003a5c314138e93764a4bd1db0a6eebca))
* **ci:** align operator deployment with current Makefile structure ([49599a0](https://github.com/vriesdemichael/keycloak-operator/commit/49599a0ef6c6c225cb1caa3d137d35b0bec3e6c7))
* **ci:** correct JSON syntax errors in release-please manifest ([31577b3](https://github.com/vriesdemichael/keycloak-operator/commit/31577b39ef5accb576f713b162ea62f84b554fd7))
* **ci:** correct release-please config for container-based releases ([732eaa7](https://github.com/vriesdemichael/keycloak-operator/commit/732eaa72313c7893a5b1595691365fc31d135722))
* **ci:** enable semver Docker tags by dispatching CI/CD on release creation ([ff95842](https://github.com/vriesdemichael/keycloak-operator/commit/ff958422945707c65f2556e5813a465028e64789))
* **ci:** explicitly set kubeconfig path for integration tests ([c49fc64](https://github.com/vriesdemichael/keycloak-operator/commit/c49fc6470b891b069d30308c973fdd1d426873ef))
* **ci:** improve integration test isolation and coverage ([5a03f23](https://github.com/vriesdemichael/keycloak-operator/commit/5a03f2339bbdd916084ee3f66b6699e2ed4c8a1e))
* **ci:** install both dev and integration dependency groups ([e1a703e](https://github.com/vriesdemichael/keycloak-operator/commit/e1a703edc24868b8ecef7943afd78102c5317ea2))
* **ci:** install integration test dependencies including pytest-xdist ([4a6330b](https://github.com/vriesdemichael/keycloak-operator/commit/4a6330bf6b76ef164cc069b13f6f4966389afc8e))
* **ci:** pin Helm version for deterministic builds ([3acb30f](https://github.com/vriesdemichael/keycloak-operator/commit/3acb30f17687a4bb79e84236ec448739239ee86f))
* **ci:** prevent image publishing when tests fail ([70952a2](https://github.com/vriesdemichael/keycloak-operator/commit/70952a24be23585e4442ac86605f790c3cb3eba7))
* **ci:** prevent namespace creation conflict in helm deployment ([f50f483](https://github.com/vriesdemichael/keycloak-operator/commit/f50f48396329fbb99abeda0e6050eb0ca01ad77d))
* **ci:** properly wait for Keycloak deployment to be ready ([e0f7a9e](https://github.com/vriesdemichael/keycloak-operator/commit/e0f7a9e53915e0f18d4ab19de1193f9d8239b2fd))
* **ci:** remove approval step to work with auto-merge setting ([5428eb3](https://github.com/vriesdemichael/keycloak-operator/commit/5428eb3ccf96396c4cbd8a6c1869669527078ac5))
* **ci:** remove leader election and basic functionality tests from integration workflow ([c3fad45](https://github.com/vriesdemichael/keycloak-operator/commit/c3fad4561e29daddb89e92ca824cb68831bbb275))
* **ci:** resolve release-please bash error and disable CodeQL false positives ([f0479fe](https://github.com/vriesdemichael/keycloak-operator/commit/f0479fec32047fd49a95502d610adb3741807d48))
* **ci:** update Keycloak deployment and pod labels for consistency ([e3c3510](https://github.com/vriesdemichael/keycloak-operator/commit/e3c35108e7e10a9b32f99c62d1c59ec68da99d15))
* **ci:** use correct pod labels for Keycloak readiness check ([e680bbc](https://github.com/vriesdemichael/keycloak-operator/commit/e680bbcc86517d4b557b182f65d9755ae056320a))
* **ci:** use PAT for release-please to trigger CI workflows ([4091bed](https://github.com/vriesdemichael/keycloak-operator/commit/4091bed6c30d0f37bc2377b2ff5444506c8aa1c7))
* **ci:** wait for CNPG cluster and fix kubeconfig access ([edbc171](https://github.com/vriesdemichael/keycloak-operator/commit/edbc171acf4ec2bd784aaaa2455b1ffc54c436f9))
* clear operator instance ID cache between unit tests ([49d1db7](https://github.com/vriesdemichael/keycloak-operator/commit/49d1db7b1dcdbbb6898ae0110379210af33b23ac))
* combine coverage and convert to XML for Codecov ([ad10407](https://github.com/vriesdemichael/keycloak-operator/commit/ad10407ffe4b57e1ac35c958704cbb6b682d26f2))
* configure webhook server with service DNS hostname ([d626c4b](https://github.com/vriesdemichael/keycloak-operator/commit/d626c4bddee90bd1fe3ab72c05c2b6d21552ece9))
* consolidate documentation workflows with mike ([cd31074](https://github.com/vriesdemichael/keycloak-operator/commit/cd31074e2d0c518bc05c8a50f65313a8eeb48ea3))
* convert SMTP configuration values to strings for Keycloak API compatibility ([8ad98d0](https://github.com/vriesdemichael/keycloak-operator/commit/8ad98d006399fbbf8351f5762ba30c0bdf2fc236))
* convert snake_case to camelCase in StatusWrapper ([4ad528c](https://github.com/vriesdemichael/keycloak-operator/commit/4ad528c44a76664324b47c26b0230c7b480bef42)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* correct client_cr fixture schema for drift detection tests ([fba3c5d](https://github.com/vriesdemichael/keycloak-operator/commit/fba3c5d243251d02e202e06d3c682f20bb7fcf70))
* correct fixture name in drift detection integration tests ([4694b16](https://github.com/vriesdemichael/keycloak-operator/commit/4694b16e62308399e15125c1cf580dfc9ae6b1f0))
* correct fixture name to k8s_custom_objects ([cde9e20](https://github.com/vriesdemichael/keycloak-operator/commit/cde9e2051de5e23119404e419382a452fd5f24bd))
* correct IDP configure method calls in realm reconciler ([9e19c4c](https://github.com/vriesdemichael/keycloak-operator/commit/9e19c4c85b4a7e4950d5324ecf72961d95dfb4e4))
* correct Keycloak Admin API path for IDP verification ([0a1ca04](https://github.com/vriesdemichael/keycloak-operator/commit/0a1ca04d085fe1c2584cb6bfed47fff9660dde5e))
* correct license references from Apache 2.0 to MIT ([d5323b6](https://github.com/vriesdemichael/keycloak-operator/commit/d5323b67345b34c40d12e5ad9fd416bdf647a879))
* correct operatorRef structure in documentation ([84967e1](https://github.com/vriesdemichael/keycloak-operator/commit/84967e14732017ae62bb0ce2cfa1128b825c9ee7))
* create coverage directory in container and fix collection workflow ([3b74ee6](https://github.com/vriesdemichael/keycloak-operator/commit/3b74ee6f343bfb57ef4d8e3e70169ec4ffd8925e))
* **deps:** add missing pytest-xdist to test dependency group ([cb01362](https://github.com/vriesdemichael/keycloak-operator/commit/cb01362dce1f702458b8a605fa223bce11b173b4))
* disable webhook auto-management and default to false ([0c59b83](https://github.com/vriesdemichael/keycloak-operator/commit/0c59b834d2852d010a6ca97152eb4b2e41e0353b))
* disable webhooks by default to avoid bootstrap issues ([85470ed](https://github.com/vriesdemichael/keycloak-operator/commit/85470ed5f1a6b9a45027fd050622d82042e92b43))
* drift detection tests auth token namespace ([763ebd1](https://github.com/vriesdemichael/keycloak-operator/commit/763ebd1b0d451b085a9f9877f429e73d3694b358))
* enable mandatory type checking and add Helm linting to pre-commit ([97dc9d7](https://github.com/vriesdemichael/keycloak-operator/commit/97dc9d7062695a9e3999c5554d774ac9c79e6c3d))
* enforce same-namespace secrets and fix Pydantic model access ([56d448a](https://github.com/vriesdemichael/keycloak-operator/commit/56d448a1e834f7d7da60172976fa67da3dd6bc89))
* **examples:** correct Keycloak CR database configuration ([be1495c](https://github.com/vriesdemichael/keycloak-operator/commit/be1495cc70125048d2f73f71b30aa727b2eccb3e))
* GitHub Actions release-please workflow JSON parsing error ([60081f4](https://github.com/vriesdemichael/keycloak-operator/commit/60081f4f5ea954892fc0f87db3b516d26250a042))
* implement Keycloak-compliant redirect URI wildcard validation ([83e7742](https://github.com/vriesdemichael/keycloak-operator/commit/83e7742594ae6cc17b0698d4416a358565569033))
* import all webhook modules to register handlers ([12b9bbd](https://github.com/vriesdemichael/keycloak-operator/commit/12b9bbddb038caffa83f855eccfa59519b14621a))
* improve Dex deployment robustness ([78083fe](https://github.com/vriesdemichael/keycloak-operator/commit/78083fe5cf52fb64d5b30bf3bddcba4b041f5519))
* make all shell scripts executable for GitHub Actions ([bba6004](https://github.com/vriesdemichael/keycloak-operator/commit/bba6004d311e4073ab28aff28bbe926176eb0825))
* make coverage scripts executable and share unit coverage with integration tests ([17615ff](https://github.com/vriesdemichael/keycloak-operator/commit/17615ff3b997c7c86e41d5ca30221993f3d7fe95))
* make realm_cr and client_cr async fixtures ([3d46d6f](https://github.com/vriesdemichael/keycloak-operator/commit/3d46d6fcc22837130b4ee26b2bf4cc100f2c3ed3))
* only retrieve coverage on last worker exit ([236636a](https://github.com/vriesdemichael/keycloak-operator/commit/236636aa843ce6cd73cfe40191f605f3fc31e611))
* **operator:** allow integration coverage failures during outage ([42ece4a](https://github.com/vriesdemichael/keycloak-operator/commit/42ece4ac55598db3969f5129056c4448a6504ca6))
* **operator:** database passwordSecret support and test fixes ([038fc18](https://github.com/vriesdemichael/keycloak-operator/commit/038fc18da190e8d99eb02222c89c59393129feee))
* **operator:** detect release commits merged by users, not just bots ([50a21e9](https://github.com/vriesdemichael/keycloak-operator/commit/50a21e9c619faefe47e9d7a7b688b3d883518120))
* **operator:** disable fail_ci_if_error for codecov uploads ([2e22069](https://github.com/vriesdemichael/keycloak-operator/commit/2e220690d61551e2abca83359eab33bf7990a14e))
* **operator:** enable auto-merge for grouped release PRs ([7c2419a](https://github.com/vriesdemichael/keycloak-operator/commit/7c2419a95aca55264400d1d0252e2af52fec0501))
* **operator:** enforce scope for release-triggering commits ([6c7e271](https://github.com/vriesdemichael/keycloak-operator/commit/6c7e27134917df7e1c53031d86991c2ce74b9a7f))
* **operator:** group release-please PRs to prevent manifest conflicts ([529c990](https://github.com/vriesdemichael/keycloak-operator/commit/529c99037235bd63b315ae3673a1c1506dcccdca))
* **operator:** handle basic realm field updates in do_update method ([fab2804](https://github.com/vriesdemichael/keycloak-operator/commit/fab2804ad2e1b982f7e7009e11290f68fbaccf0b))
* **operator:** handle realm deletion gracefully in client cleanup ([45b25cd](https://github.com/vriesdemichael/keycloak-operator/commit/45b25cda8c945c56daddbc2538a1c0133713324f))
* **operator:** load test-coverage image tag for integration tests ([af358ba](https://github.com/vriesdemichael/keycloak-operator/commit/af358ba923a7e9625920de99abeac52d696a49e2))
* **operator:** make integration coverage non-fatal if not generated ([02022c7](https://github.com/vriesdemichael/keycloak-operator/commit/02022c7a728db530be61accf4961aa1ac70b1f53))
* **operator:** prevent event loop closed errors in httpx client cache ([83b8020](https://github.com/vriesdemichael/keycloak-operator/commit/83b80200c7d0df07058856e8ee99e979dba585a8))
* **operator:** properly fix coverage collection and uv group isolation ([867df0a](https://github.com/vriesdemichael/keycloak-operator/commit/867df0ae0140573ccb9f0788b5308ad231bd5d20))
* **operator:** resolve JSON serialization and test timing issues ([fb29bcb](https://github.com/vriesdemichael/keycloak-operator/commit/fb29bcbd1859e0dbcb2d8ded643a38ecb52c5cb5))
* **operator:** restore --group flags and upload integration coverage files separately ([b067c30](https://github.com/vriesdemichael/keycloak-operator/commit/b067c304459bd556de67f3bc292dab385a5fdac4))
* **operator:** revert uv run --group flag, keep coverage upload fix ([225cef3](https://github.com/vriesdemichael/keycloak-operator/commit/225cef3794076367e1ab25b659197460c25bd218))
* **operator:** run quality checks and tests for code OR chart changes ([a9e8ad2](https://github.com/vriesdemichael/keycloak-operator/commit/a9e8ad27ff84b7b704fdbbe9c8c353057078070c))
* **operator:** temporarily allow codecov failures during global outage ([baa2f58](https://github.com/vriesdemichael/keycloak-operator/commit/baa2f58e714c8e4b2538233fe84ba6c550926401))
* **operator:** update all-complete job to reference new chart jobs ([be5dde3](https://github.com/vriesdemichael/keycloak-operator/commit/be5dde3d28b33a2b78ff713eb5f9ce03df6d628e))
* **operator:** update package metadata with correct author info ([96ba785](https://github.com/vriesdemichael/keycloak-operator/commit/96ba785332f12613446cb83e5525ade6cc966e80))
* **operator:** use asyncio.to_thread for webhook K8s API calls ([d635da9](https://github.com/vriesdemichael/keycloak-operator/commit/d635da9ae8a78928baf613b35686256849e78b80))
* **operator:** use correct camelCase field names in realm update handler ([91636eb](https://github.com/vriesdemichael/keycloak-operator/commit/91636ebdb1afef442a5eb6e9bf46db69585454b8))
* **operator:** use coverage run in CMD for proper instrumentation ([1665eaa](https://github.com/vriesdemichael/keycloak-operator/commit/1665eaaef1f8bd01616a278edf99a232d6bd7a53))
* **operator:** use legacy codecov endpoint only as fallback ([c76ff4a](https://github.com/vriesdemichael/keycloak-operator/commit/c76ff4a0c120329c41266366283193cf3b82fa8e))
* **operator:** use legacy codecov upload as fallback ([1cb9293](https://github.com/vriesdemichael/keycloak-operator/commit/1cb929309a914b58197e0d03e4fe01801826edd5))
* preserve binary data when retrieving coverage files ([1cf7252](https://github.com/vriesdemichael/keycloak-operator/commit/1cf7252de0b3db30d217e011ff667fff0da18b6c))
* prevent premature operator cleanup in pytest-xdist workers ([8031895](https://github.com/vriesdemichael/keycloak-operator/commit/8031895e2b2347378cbb376555136ee7e395ff49))
* prevent premature operator cleanup in pytest-xdist workers ([2a7f4a1](https://github.com/vriesdemichael/keycloak-operator/commit/2a7f4a19892c44ce8a24dd63e2136f6645bad06b))
* proper webhook bootstrap with readiness probe and ArgoCD sync waves ([c8dfc52](https://github.com/vriesdemichael/keycloak-operator/commit/c8dfc5200c02cf550e8857d6e44583b50fb11895))
* properly implement IDP integration tests ([8cf7cb1](https://github.com/vriesdemichael/keycloak-operator/commit/8cf7cb1df097b447a215ccacb46254939d21b4c4))
* race condition in CI/CD and cleanup Makefile ([91b0640](https://github.com/vriesdemichael/keycloak-operator/commit/91b0640961ead705430efaa61c70daa6da8a45c0))
* reduce Dex wait timeout to avoid pytest timeout ([acb0106](https://github.com/vriesdemichael/keycloak-operator/commit/acb01064b8a4df9108b78a5016e7b779a77ceb58))
* refactor pages workflow to fix versioning and artifact issues ([e1d6da1](https://github.com/vriesdemichael/keycloak-operator/commit/e1d6da11bda072ead0d0eff66f87def24905ad0c)), closes [#114](https://github.com/vriesdemichael/keycloak-operator/issues/114)
* remove authorizationSecretRef from Helm values schemas ([f87585b](https://github.com/vriesdemichael/keycloak-operator/commit/f87585b10b7446822636a909e83f1c45235fa62d)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove await from synchronous API call in capacity check ([2908db5](https://github.com/vriesdemichael/keycloak-operator/commit/2908db581fa9a39f590c67b1a3ef47f27ec978d0)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove duplicate coverage retrieval code ([691d70b](https://github.com/vriesdemichael/keycloak-operator/commit/691d70bd3cc8a9c3e1e22b4ac08db229e6b7a41d))
* Remove last_reconcile_time from status updates ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* remove obsolete authorization token references from charts ([880fc98](https://github.com/vriesdemichael/keycloak-operator/commit/880fc98637ff0e0e4c9471fd47162fc1d790b194)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove obsolete authorizationSecretName status field ([9952eae](https://github.com/vriesdemichael/keycloak-operator/commit/9952eaef7c155f3013b9a1cc2d7a0c66c7cf4827)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove tests for deleted periodic_leadership_check function ([1ffcba0](https://github.com/vriesdemichael/keycloak-operator/commit/1ffcba0479decb4916a65262f58a46f84ab28ddd))
* remove webhook config template, let Kopf manage it ([57f2e3e](https://github.com/vriesdemichael/keycloak-operator/commit/57f2e3e82a68789d49b73fea4c8cac4e409133c2))
* Removed await, added explicit k8s_client parameter. ([2908db5](https://github.com/vriesdemichael/keycloak-operator/commit/2908db581fa9a39f590c67b1a3ef47f27ec978d0))
* replace old keycloak.mdvr.nl API group with vriesdemichael.github.io ([da644e0](https://github.com/vriesdemichael/keycloak-operator/commit/da644e09d335803e59f61a2f46f463ebfab0e50b))
* resolve all three workflow failures ([9c6b5ed](https://github.com/vriesdemichael/keycloak-operator/commit/9c6b5edb50995ee1ccce91f5d9b1d690428f78e5))
* resolve operator reconciliation bugs ([ead662f](https://github.com/vriesdemichael/keycloak-operator/commit/ead662f3c19e2d8e345aeb554f7558caf9bfe5e8))
* resolve permission denied error for build-adr-docs.sh in GitHub Actions ([4a99239](https://github.com/vriesdemichael/keycloak-operator/commit/4a9923972e933b94ad7559c1a95174b78b6c1afe))
* restore correct test image tag for coverage collection ([6cb1675](https://github.com/vriesdemichael/keycloak-operator/commit/6cb16758ce97572f7b98396ea3b6960fb61e122f))
* restore coverage collection and upload for tests ([0ae218d](https://github.com/vriesdemichael/keycloak-operator/commit/0ae218dc926c3c5bb834c3cf9cedf952b2106c45))
* restore integration test coverage collection ([4f35596](https://github.com/vriesdemichael/keycloak-operator/commit/4f355969c0f95f0445d6cceaf9fb7b260e574723))
* **security:** prevent sensitive exception details from leaking in HTTP responses ([b0ff023](https://github.com/vriesdemichael/keycloak-operator/commit/b0ff0236e1e559940b9deb111c30be0b6345708e))
* **security:** remove unnecessary verify=False from HTTP health check ([dd5217f](https://github.com/vriesdemichael/keycloak-operator/commit/dd5217f3e0df2407ffb594dd554c238889884b38))
* send SIGTERM instead of deleting pod for coverage ([d3fa7eb](https://github.com/vriesdemichael/keycloak-operator/commit/d3fa7eba9a9e4aa51c4d4fa04e55e2c21e49213f))
* simplify coverage - always on, fail hard, let codecov combine ([d953b29](https://github.com/vriesdemichael/keycloak-operator/commit/d953b291e32e8bdc66485fc8ebe2e5e947846ce7))
* streamline coverage workflow - remove merging, retrieve integration coverage immediately ([8fb0eb4](https://github.com/vriesdemichael/keycloak-operator/commit/8fb0eb4c9478b9996decfca81851492e2d6d21df))
* **tests:** fix all 7 drift detection integration tests ([fd5e76f](https://github.com/vriesdemichael/keycloak-operator/commit/fd5e76f4dab5294372d06205b4a4eb12cf3d35a8))
* **tests:** improve integration test reliability for CI environments ([77f6aa0](https://github.com/vriesdemichael/keycloak-operator/commit/77f6aa03aebbcda3fed2104619efa4a2f3da2f59))
* **tests:** properly mock Kubernetes client in finalizer tests ([df6e7d9](https://github.com/vriesdemichael/keycloak-operator/commit/df6e7d9df14cfd46b809da75d279bd94566acd3f))
* **tests:** resolve Helm chart schema validation error in CI ([7db635e](https://github.com/vriesdemichael/keycloak-operator/commit/7db635e5dd7924e56c4742fa1de8582b11243e85))
* **tests:** run integration tests in 'dev' group for improved organization ([dbe9590](https://github.com/vriesdemichael/keycloak-operator/commit/dbe9590d356ad9ca1ae26b77ac3ac429b625141b))
* TruffleHog BASE/HEAD commit issue in CI/CD workflow ([9067632](https://github.com/vriesdemichael/keycloak-operator/commit/90676320138f30044c30d1e2c9f494ff2eb056f5))
* update integration tests for grant list authorization ([9f2e2a6](https://github.com/vriesdemichael/keycloak-operator/commit/9f2e2a663ebd3d8c69ced03079b8405357dc86d1)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* update integration tests to use keycloak-prefixed annotations and finalizers ([0baf321](https://github.com/vriesdemichael/keycloak-operator/commit/0baf3213832ba63b853a06a34265244d976f54e6))
* update security scans to use test-coverage tag ([e65247b](https://github.com/vriesdemichael/keycloak-operator/commit/e65247be81106c06ece373ea6c418735cade9680))
* update tests and Helm schema for grant list authorization ([0fe6fca](https://github.com/vriesdemichael/keycloak-operator/commit/0fe6fcae8c638595a117b2093d869ecb85b37f47)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* upload raw coverage files instead of converting to XML ([64c98c7](https://github.com/vriesdemichael/keycloak-operator/commit/64c98c7b6db0365b820fb3fcfeb790e1364ac0e3))
* use correct image tag in promote workflow SBOM/Trivy steps ([65e5984](https://github.com/vriesdemichael/keycloak-operator/commit/65e59847f23d3a364fdabd4f6e54361d9c72ccd0))
* use correct operator image tag in integration tests ([8b3d7e8](https://github.com/vriesdemichael/keycloak-operator/commit/8b3d7e82a84454d4f5cd646788e150c745887790))
* use correct operator namespace and shared_operator fixture in drift tests ([581a2db](https://github.com/vriesdemichael/keycloak-operator/commit/581a2dbb881b3f0679ef83cfcad1e5f7c365c2c0))
* use correct yq sha256 checksum for v4.44.3 ([f4c7dc0](https://github.com/vriesdemichael/keycloak-operator/commit/f4c7dc0683a368ccb8bb2df25b087776b3d9d5df))
* use Dockerfile.test for coverage-instrumented image ([82f0373](https://github.com/vriesdemichael/keycloak-operator/commit/82f037384444e161cbd5013cd798bf8fe7ea4234))
* Use explicit exists output for artifact conditionals ([f52b7cd](https://github.com/vriesdemichael/keycloak-operator/commit/f52b7cdc66de1d7294fa34e4a3862aaf29b1d286))
* use httpGet probe instead of exec with wget ([a6135d6](https://github.com/vriesdemichael/keycloak-operator/commit/a6135d6273e3a2377fd4b23e89342f00a2fb7acb))
* use kubectl for Dex deployment and enable IDP tests ([1e72b0e](https://github.com/vriesdemichael/keycloak-operator/commit/1e72b0ea450cb430cfe9d028e10139cf97bdae8b))
* use proper conventional commit scope for chart updates ([70cf9c0](https://github.com/vriesdemichael/keycloak-operator/commit/70cf9c043040b3405c48ccc5b4b92f23e368c30f))
* use shared_operator namespace directly in drift tests ([e70d3d3](https://github.com/vriesdemichael/keycloak-operator/commit/e70d3d30e06daaf6271237000578ae2424d3ce28))
* use sync client for kubernetes stream() calls ([4a7b524](https://github.com/vriesdemichael/keycloak-operator/commit/4a7b52426b9f68e1984bd6b63eb57a081536bea7))
* use test-coverage tag for operator image ([2f0cce4](https://github.com/vriesdemichael/keycloak-operator/commit/2f0cce4076eb307218cd0e9cddb91bdbffa70bb0))


### Performance Improvements

* implement generation-based skip to avoid redundant reconciliations ([af0d4c6](https://github.com/vriesdemichael/keycloak-operator/commit/af0d4c63490122a5d4893f2cb2e5cf6d63fe3f6b)), closes [#184](https://github.com/vriesdemichael/keycloak-operator/issues/184)


### Code Refactoring

* address PR review comments ([499a0c9](https://github.com/vriesdemichael/keycloak-operator/commit/499a0c93ff4f4a5074cdb5981b54a0f880a69044))
* align CRD schemas with Pydantic models for GitOps compliance ([c06001b](https://github.com/vriesdemichael/keycloak-operator/commit/c06001bfbc6dfff6f09aafe65a767918e7481cc2))
* **ci:** remove old workflow files ([2205530](https://github.com/vriesdemichael/keycloak-operator/commit/2205530eb3e8bd30ac6cb30c1962517fbad3d807))
* **ci:** split deployment into clear sequential steps ([ff07e16](https://github.com/vriesdemichael/keycloak-operator/commit/ff07e16aa604dfe1076c89d59ca1d298824e907a))
* **ci:** unify CI/CD pipeline into single workflow ([ea1b748](https://github.com/vriesdemichael/keycloak-operator/commit/ea1b74895c277ec70b7f2e35d15a5cdcdc0729d9))
* **ci:** use operator chart for complete deployment ([5cb1f09](https://github.com/vriesdemichael/keycloak-operator/commit/5cb1f0996723ded97df9f14e3aafea7d14ce14b9))
* **ci:** use uv run --with for ephemeral dependencies ([649d65f](https://github.com/vriesdemichael/keycloak-operator/commit/649d65f4c3167cf69f0982978255230ce786dd7a))
* clean up Makefile and add cluster reuse workflow ([#59](https://github.com/vriesdemichael/keycloak-operator/issues/59)) ([be3bcd4](https://github.com/vriesdemichael/keycloak-operator/commit/be3bcd4ab1f09413fc23da36aa79f5e00c9df91a))
* consolidate TODO files and enhance Keycloak admin API ([350c88f](https://github.com/vriesdemichael/keycloak-operator/commit/350c88fb0899e166dcea1883c00b2d1c78eeeb90))
* convert drift tests to function-based structure ([f576d14](https://github.com/vriesdemichael/keycloak-operator/commit/f576d143db4d048a6e0c3f53c32a5b75922e52be))
* **operator:** remove redundant uv sync steps when using --group ([c9aea4f](https://github.com/vriesdemichael/keycloak-operator/commit/c9aea4fa42335ae65efcd0a4874341cb9fcfbd2f))
* **operator:** unify Dockerfile with multi-stage targets ([dd81347](https://github.com/vriesdemichael/keycloak-operator/commit/dd813478441800b2519e184e94bc249fa2a6289c))
* **operator:** use manifest diff for major version detection ([3a161be](https://github.com/vriesdemichael/keycloak-operator/commit/3a161beddd0f086f03f5db0e637aaf0d724f21a2))
* remove version and enabled fields from CRDs for K8s-native design ([11cdf60](https://github.com/vriesdemichael/keycloak-operator/commit/11cdf60a1b21320154fcefe5eba3a4a20386beaf))
* restructure decision records with improved schema ([7eb2710](https://github.com/vriesdemichael/keycloak-operator/commit/7eb27104a3da5d4047992709e15ad993f169a1a8))
* simplify ADR structure - remove status field ([90cf325](https://github.com/vriesdemichael/keycloak-operator/commit/90cf3254ca06b062a24f3b87bcdcac75abab15dc))
* simplify CI/CD workflow conditionals ([45fad5c](https://github.com/vriesdemichael/keycloak-operator/commit/45fad5c6467f6f99aef82a543ad55af4b4a42931))
* split CI/CD workflow into composite actions ([34da80d](https://github.com/vriesdemichael/keycloak-operator/commit/34da80d4cd5aaa51e07dc4fa998f86e0faccb45f))
* split CI/CD workflow into composite actions ([6a36cb1](https://github.com/vriesdemichael/keycloak-operator/commit/6a36cb1b9fb1f19869b2cfc7ade85f9fc4a6fab7))
* split CI/CD workflow into composite actions + add custom logo ([610417d](https://github.com/vriesdemichael/keycloak-operator/commit/610417d980cfdaa85ed384a757b8bd0d7b587479))
* **test:** add fixture recommendation helper function ([bab3bfd](https://github.com/vriesdemichael/keycloak-operator/commit/bab3bfdad3e4320c4b9f4b7e12ac8ee77812d3c0))
* **test:** add keycloak_ready composite fixture with Pydantic model ([f6a0878](https://github.com/vriesdemichael/keycloak-operator/commit/f6a087895b40496a19daf9c6bf070dca3344df2d))
* **test:** add type safety with Pydantic models and prefix internal fixtures ([c6cc015](https://github.com/vriesdemichael/keycloak-operator/commit/c6cc01589345ba3fd5a2f482249d449dfe1312f8))
* **test:** consolidate token fixtures and add CR factory functions ([0de7519](https://github.com/vriesdemichael/keycloak-operator/commit/0de75197748dc8e1cef8fcdbeaf59e2a25fbbfae))
* **tests:** enhance integration test setup by optimizing dependency installation and removing unnecessary steps ([b55d6d9](https://github.com/vriesdemichael/keycloak-operator/commit/b55d6d98682c982caf8e1d36e6e67867c95f2d07))
* **tests:** streamline integration test execution and remove Makefile group ([09a2f71](https://github.com/vriesdemichael/keycloak-operator/commit/09a2f717056d109423898f4fd76d7d19b13cd235))
* update decision 005 - no plaintext secrets ([0d0d8ae](https://github.com/vriesdemichael/keycloak-operator/commit/0d0d8ae76a833d0687da957548253ad9f0d3b7af))
* update decision 012 - async API with resilience ([1397a43](https://github.com/vriesdemichael/keycloak-operator/commit/1397a4310c7102ed6b6a2b194c55c82d29bf45cf))
* update decision 013 - focus on data validation ([aae7d62](https://github.com/vriesdemichael/keycloak-operator/commit/aae7d62de24803e780ce79f98e4ee597756b2d43))
* Update status condition transition tests ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* use kopf[dev] extra instead of manual certbuilder ([bf44078](https://github.com/vriesdemichael/keycloak-operator/commit/bf44078d955d50613cc8d1c17605babecb08a3c0))
* use release-please as gatekeeper for CD phase ([8f607bb](https://github.com/vriesdemichael/keycloak-operator/commit/8f607bb6c71adcf1268d16148f55e8fb90b4a6ab))
* use targeted dependency groups in CI and Makefile ([12142e4](https://github.com/vriesdemichael/keycloak-operator/commit/12142e4d22059103603537bcbf9862723698a335))


### Documentation

* add 21 foundational Architecture Decision Records ([bbeb67e](https://github.com/vriesdemichael/keycloak-operator/commit/bbeb67eb9f5b75599b58a0ed6290bfd5d8ef27a9))
* add admission webhook documentation and decision record ([396de85](https://github.com/vriesdemichael/keycloak-operator/commit/396de85863b5731e6e55ae2ac11ad21fbc45eeb1))
* add ADR-064 rejecting force-delete feature ([6df1d50](https://github.com/vriesdemichael/keycloak-operator/commit/6df1d505d090ff22199a125bf30a760c005b402a))
* add Architecture Decision Records (ADR) structure ([d8f488b](https://github.com/vriesdemichael/keycloak-operator/commit/d8f488bb9922b666a0b01d00b386623a991ead72)), closes [#55](https://github.com/vriesdemichael/keycloak-operator/issues/55)
* add architecture diagrams for multi-operator and rate limiting ([927b0d1](https://github.com/vriesdemichael/keycloak-operator/commit/927b0d176a42b7d35059147d6b41f6ead37385ce))
* add CI/CD and documentation issues task list ([1d09817](https://github.com/vriesdemichael/keycloak-operator/commit/1d0981719319e67cb6872b4408f42e83014edd2e))
* add CI/CD and GitOps integration examples ([7225653](https://github.com/vriesdemichael/keycloak-operator/commit/7225653ecc3591fe01c2073ccddc3c47a80868ab))
* add comprehensive CRD field reference documentation ([2ad21a5](https://github.com/vriesdemichael/keycloak-operator/commit/2ad21a5725285277f96f2e40238e278f9ef6c853))
* add comprehensive drift detection documentation (Phase 6) ([c09439d](https://github.com/vriesdemichael/keycloak-operator/commit/c09439d39f7e2147a25bb0a9956e987ba6350835))
* add comprehensive observability and security documentation ([8bb3448](https://github.com/vriesdemichael/keycloak-operator/commit/8bb3448a3206362300d0b4c23ee24e2021ec221a))
* add comprehensive Quick Start guide with examples ([723e6d1](https://github.com/vriesdemichael/keycloak-operator/commit/723e6d1e14bc990f4da7ad3958ac1527c4f86ab7))
* add comprehensive release workflow analysis and fix documentation ([87838c9](https://github.com/vriesdemichael/keycloak-operator/commit/87838c9b57e0d0ad840cf4160e2e6f50ac53d3ab))
* add comprehensive security and reliability review for CI/CD workflows ([1fb53d4](https://github.com/vriesdemichael/keycloak-operator/commit/1fb53d4d4716cbc5cd5999e0df0feaca8385f7d9))
* add comprehensive testing guide and token terminology glossary ([91bf3b5](https://github.com/vriesdemichael/keycloak-operator/commit/91bf3b59ace290b2c618c8e740cb3cdeb78c2885))
* add comprehensive user guides and operations documentation ([92b99b2](https://github.com/vriesdemichael/keycloak-operator/commit/92b99b26005d3377c42427e15e4634264cf9bb7c))
* add custom logo and favicon ([34da80d](https://github.com/vriesdemichael/keycloak-operator/commit/34da80d4cd5aaa51e07dc4fa998f86e0faccb45f))
* add custom logo and favicon ([6a36cb1](https://github.com/vriesdemichael/keycloak-operator/commit/6a36cb1b9fb1f19869b2cfc7ade85f9fc4a6fab7))
* add Decision Records as separate tab with tag filtering ([6931bc3](https://github.com/vriesdemichael/keycloak-operator/commit/6931bc3b1989768b98a078161946a2115ed01d41))
* add decisions 022-023 for type checking and Make automation ([2bf22ec](https://github.com/vriesdemichael/keycloak-operator/commit/2bf22ecbea80ee1e0b75dadd5bc8867af022f9b6))
* add decisions 024-032 for deployment and architecture ([56ba2cc](https://github.com/vriesdemichael/keycloak-operator/commit/56ba2ccbcc3631f9eebdc06b08984ed94a3eb4da))
* add decisions 033-052 completing decision record set ([1dbd5d3](https://github.com/vriesdemichael/keycloak-operator/commit/1dbd5d36c2cd929e43e47aa1dd897d231627f14e))
* add deprecation notices to token-based documentation ([0dc075f](https://github.com/vriesdemichael/keycloak-operator/commit/0dc075f575722619dab823a11aacb222db39a067))
* add helm values JSON schema requirement to ADR-030 ([76f2637](https://github.com/vriesdemichael/keycloak-operator/commit/76f263714eed966ba80b685b2c501732cb3b9129))
* add identity provider documentation and integration tests ([9e6bb6a](https://github.com/vriesdemichael/keycloak-operator/commit/9e6bb6aa7cf74972046f29fac3e746c658dd7548))
* add introductory text to FAQ page ([b3e4116](https://github.com/vriesdemichael/keycloak-operator/commit/b3e4116a9853e9eacf3880db4a1a9c136f69c581))
* add Keycloak brand colors and improved styling ([fc7a0a5](https://github.com/vriesdemichael/keycloak-operator/commit/fc7a0a50f0993dad3f6b1e04791fc9c36e3d4b1f))
* add mandatory RELEASES.md check before commits in CLAUDE.md ([a329050](https://github.com/vriesdemichael/keycloak-operator/commit/a329050c1b5ce19c012ec9a274ca417cb3e83750))
* add Mermaid diagram support and hide home TOC ([b1f2e74](https://github.com/vriesdemichael/keycloak-operator/commit/b1f2e74d7f7a6cff2d8de4b8b29d146c5160b21c))
* add proper procedure for resolving PR review threads ([c4e5735](https://github.com/vriesdemichael/keycloak-operator/commit/c4e57354d0ca66b46743af860cf13f58afeeec63))
* add random jitter to decision 012 retry logic ([0e515b5](https://github.com/vriesdemichael/keycloak-operator/commit/0e515b5f37ce209970b54af80f33f79ac34a92d9))
* add scaling strategy documentation to architecture ([#56](https://github.com/vriesdemichael/keycloak-operator/issues/56)) ([0b496c7](https://github.com/vriesdemichael/keycloak-operator/commit/0b496c7b568a33889b8d9e7980e04b6a9e60b6b3))
* add security scanning badge to README ([8edd36b](https://github.com/vriesdemichael/keycloak-operator/commit/8edd36b9ba27b74717fdd2c6ac44a2b7361d05b6))
* add SMTP configuration implementation plan ([67d2362](https://github.com/vriesdemichael/keycloak-operator/commit/67d2362fc16d58c8e0ecb65a86c4f524ca29db74))
* add versioned documentation with mike integration ([c5d0bfd](https://github.com/vriesdemichael/keycloak-operator/commit/c5d0bfd5be47b20223fc8e541e0f8f8f54fec2a5))
* bulk cleanup of authorizationSecretRef in chart READMEs ([7010d85](https://github.com/vriesdemichael/keycloak-operator/commit/7010d855084409af6a36e3d17fae465070afd6b9))
* bulk cleanup remaining authorizationSecretRef references ([61e66a3](https://github.com/vriesdemichael/keycloak-operator/commit/61e66a3321be25ed370702df669f7bcd5299fa27))
* change default merge strategy to rebase ([442c6b9](https://github.com/vriesdemichael/keycloak-operator/commit/442c6b9787787a597010405e822ac468d2b17d66))
* **chart-client:** add comprehensive README ([7b147c8](https://github.com/vriesdemichael/keycloak-operator/commit/7b147c845b18172f0526182ecc33a469a56b5f07))
* **chart-operator:** add comprehensive README ([759081d](https://github.com/vriesdemichael/keycloak-operator/commit/759081deb9ac3cea713a0aac7843b15624165dd1))
* **chart-operator:** clarify single-tenant dev mode and add Keycloak deployment guidance ([eb3683d](https://github.com/vriesdemichael/keycloak-operator/commit/eb3683d42878d868f8857c726464a26a3a6702b2))
* **chart-operator:** remove all admission token documentation ([528ff2e](https://github.com/vriesdemichael/keycloak-operator/commit/528ff2e42b7f9f7925215c8ca30291142aedf539))
* **chart-realm:** add comprehensive README ([92c8e95](https://github.com/vriesdemichael/keycloak-operator/commit/92c8e95cd65ebdfa6c90f6b12b1b1fe7a91a80bb))
* **ci:** add CI/CD improvements tracking document ([67f714a](https://github.com/vriesdemichael/keycloak-operator/commit/67f714ae03578335b85370f1da540e9242a822a0))
* **ci:** add complete implementation summary ([b42a0dd](https://github.com/vriesdemichael/keycloak-operator/commit/b42a0dd87beb71689f096a671da89eea2bf97699))
* **ci:** add workflow migration documentation ([7028b35](https://github.com/vriesdemichael/keycloak-operator/commit/7028b354f4b5f0badb48bf3f3f84c457bc2f9280))
* **ci:** feature requests now require less information ([93945d1](https://github.com/vriesdemichael/keycloak-operator/commit/93945d111c2a1a4d60dd9a630947306bf97e5efe))
* **ci:** update tracking to reflect Phase 2 completion ([33baaf6](https://github.com/vriesdemichael/keycloak-operator/commit/33baaf64537594e4500bc838e5baa64bd00a3b31))
* clarify namespace scope requires cluster-wide RBAC ([ea563db](https://github.com/vriesdemichael/keycloak-operator/commit/ea563db39f1228beb5cd5347923f2988bda88fc7))
* clean authorizationSecretRef from CRD reference docs ([e416d90](https://github.com/vriesdemichael/keycloak-operator/commit/e416d902e9b5cfed1a27522dfc3d4831d23b0030))
* configure mkdocstrings to resolve autorefs warnings in strict mode ([1165559](https://github.com/vriesdemichael/keycloak-operator/commit/11655595007e807c597dbd87565a7fca2a59895c))
* correct tracking document - Phase 3 was already complete ([d374041](https://github.com/vriesdemichael/keycloak-operator/commit/d374041174d5a9657911a1bd24e58b1dae9aa651))
* **design:** add Keycloak state observability analysis ([120eb81](https://github.com/vriesdemichael/keycloak-operator/commit/120eb81c5e8bd4d28c1833f9afaa088f90ce0210))
* enforce least privilege by removing admin console access ([4c788bd](https://github.com/vriesdemichael/keycloak-operator/commit/4c788bdf694d60aa5da0423f28f932dedabb2f8b))
* enhance dark mode styling with better contrast ([b905878](https://github.com/vriesdemichael/keycloak-operator/commit/b9058784419cc9f9248eddbf9ef0537aed123cf3))
* expand decision 009 - AI agents as first-class developers ([7c1a416](https://github.com/vriesdemichael/keycloak-operator/commit/7c1a416a778f228ec4b577658cdd7e97a5d66ee3))
* final cleanup of remaining token references ([10f83eb](https://github.com/vriesdemichael/keycloak-operator/commit/10f83eb6fd7883b24c27e7d114c017f5e6284992))
* final tracking update - 36/36 tests passing ([8462747](https://github.com/vriesdemichael/keycloak-operator/commit/8462747b9610497387e972a3c13def51ef843f21)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* fix ADR 45/49 and add decision records to documentation ([33586ac](https://github.com/vriesdemichael/keycloak-operator/commit/33586ac4705692b4ff9db3063091b107a4c89504))
* fix ASCII diagram spacing and automate decision index ([2ef4cec](https://github.com/vriesdemichael/keycloak-operator/commit/2ef4cecf0bb78f5da3cb68b481c15255f71baa68))
* fix broken anchor links and ADR index page ([34825a9](https://github.com/vriesdemichael/keycloak-operator/commit/34825a9473ab7e7341fbe73f3aff14abb3b284e3))
* fix broken links and cross-references ([64da07d](https://github.com/vriesdemichael/keycloak-operator/commit/64da07d31135ab7bb1e77a41686f6b71ffca61d8))
* fix deployment flow and remove identity realm confusion ([612253d](https://github.com/vriesdemichael/keycloak-operator/commit/612253d6ac90966e1e3d321d82302a8b62f3b3ec))
* fix tab text readability and all broken links ([603de35](https://github.com/vriesdemichael/keycloak-operator/commit/603de357bee74a3ec0037e172c12ddc8b2842575))
* fix YAML schema URLs in identity provider examples ([e7ba31d](https://github.com/vriesdemichael/keycloak-operator/commit/e7ba31d18780fbf8219100aaa1800bf360d88283))
* Implement robust cleanup system for integration tests ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* improve cross-references and navigation ([a2b4352](https://github.com/vriesdemichael/keycloak-operator/commit/a2b4352d397e66fd6cb3e7999ab179938e4f1a21))
* improve navigation and expand development documentation ([169a930](https://github.com/vriesdemichael/keycloak-operator/commit/169a93047479194efd3fc09329dd768dcf9a35c9))
* improve operator chart values documentation ([61e00a3](https://github.com/vriesdemichael/keycloak-operator/commit/61e00a39ab4818585d2dd15ad7b9fe90effbb6df))
* mark CRD-model schema alignment as completed ([e2124ab](https://github.com/vriesdemichael/keycloak-operator/commit/e2124ab92619d6d4a24edb63988ccda5a52e0980))
* mark final review complete - ready for PR ([5b859f0](https://github.com/vriesdemichael/keycloak-operator/commit/5b859f0c9d63948798ce942d99df31628d3ae4c0))
* mark Phase 8 complete - all automated tests passing ([61ce95e](https://github.com/vriesdemichael/keycloak-operator/commit/61ce95efea92917ccc46a68915a3337ef736139d)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* mark redirect URI validation bug as fixed in TODO ([2d783fa](https://github.com/vriesdemichael/keycloak-operator/commit/2d783fac49f7de9e4a1d591d40e4ac31f942edf5))
* move Home into Getting Started section ([bff4ba6](https://github.com/vriesdemichael/keycloak-operator/commit/bff4ba682fbc69862edae9d67631638268262b0f))
* remove authorizationSecretRef from observability and reference docs ([b466677](https://github.com/vriesdemichael/keycloak-operator/commit/b4666776ec7f2e449419d246250cc08b72e975d3))
* remove GitOps examples (too advanced for target audience) ([d5d4e8f](https://github.com/vriesdemichael/keycloak-operator/commit/d5d4e8fdc4e595778966956db6a694a34f2fc5a8))
* remove token system from architecture.md and faq.md ([12a2495](https://github.com/vriesdemichael/keycloak-operator/commit/12a2495369e93fe555174b6780a4917d1fde5085))
* remove tracking documents ([b1d10f4](https://github.com/vriesdemichael/keycloak-operator/commit/b1d10f49e5f3c9d6ac98ea1e867dfe7ec70cdcd6))
* removed mentions of the authorization token in the readme. ([a6d8287](https://github.com/vriesdemichael/keycloak-operator/commit/a6d828700a3e08755fa960baf78ffa18da1c0184))
* removed outdated todos ([3f7f227](https://github.com/vriesdemichael/keycloak-operator/commit/3f7f2276767642986318633df1d9ae332daf98a5))
* rename ADR-054 to reflect cluster RBAC requirement ([de8fb84](https://github.com/vriesdemichael/keycloak-operator/commit/de8fb849ff538d075b07561c8ec21c911ea1234b))
* reorganize documentation structure and simplify README ([e0b7bef](https://github.com/vriesdemichael/keycloak-operator/commit/e0b7befc77a9f201965d39f88ef03041c4d5bd22))
* reorganize navigation structure to reduce tab overflow ([e1507a9](https://github.com/vriesdemichael/keycloak-operator/commit/e1507a96a270a674151acebe502405cb994bce9a))
* replace ASCII art diagrams with Mermaid charts ([d398c4e](https://github.com/vriesdemichael/keycloak-operator/commit/d398c4e9965a1e93a995aa45a09319a92e00f9ac))
* replace landing page and quickstart with current architecture ([4c33aa6](https://github.com/vriesdemichael/keycloak-operator/commit/4c33aa69237d21ae8daa2fc7a726dbbdd351a08a))
* replace tags plugin with manual categorization for decision records ([1c96007](https://github.com/vriesdemichael/keycloak-operator/commit/1c960078a54bdbd9208c0e2fba88cdfd1ad4edb9))
* review and improve decision records ([0c0ea52](https://github.com/vriesdemichael/keycloak-operator/commit/0c0ea52032b0cb4b262d41c65a3c9931a0a3fe4f))
* rewrite charts README to remove token system ([b1ffdc6](https://github.com/vriesdemichael/keycloak-operator/commit/b1ffdc667c083e00c4921f2f6b8e88fcd8542c6b))
* rewrite end-to-end-setup guide sections 5-6 and 9.5 ([0a8f837](https://github.com/vriesdemichael/keycloak-operator/commit/0a8f83722554999d91d2cb2210d6a3529a0f77b6))
* rewrite security.md for namespace grant authorization model ([cfbf2c5](https://github.com/vriesdemichael/keycloak-operator/commit/cfbf2c56e49dd606e3c5675ef8a539f48dc24519))
* rewrite troubleshooting authorization section ([53b637b](https://github.com/vriesdemichael/keycloak-operator/commit/53b637b5ffad7897228f41e11f4e70ca41afd908))
* standardize examples with version compatibility and setup instructions ([98abafb](https://github.com/vriesdemichael/keycloak-operator/commit/98abafb9029d38c6b2b6a99749698267867c8363))
* **test:** improve factory fixture documentation ([b6db340](https://github.com/vriesdemichael/keycloak-operator/commit/b6db340fdbb2cbccab377f776d235af319400456))
* update charts README with token system and new chart references ([65caac0](https://github.com/vriesdemichael/keycloak-operator/commit/65caac08d47bb92ef28f0cc8de04a6d4f38de96a))
* update CI/CD badges to point to unified workflow ([4419899](https://github.com/vriesdemichael/keycloak-operator/commit/4419899d41bd4bb949f0d4c82d67d48334c6a08c))
* update end-to-end-setup.md to use namespace grants ([fe6cd73](https://github.com/vriesdemichael/keycloak-operator/commit/fe6cd73ccd3d41394eff35bebb027f0f61c8126e))
* update FAQ and end-to-end guide to remove token references ([5a583eb](https://github.com/vriesdemichael/keycloak-operator/commit/5a583ebaa238d81c84ac75184912752b2744b356))
* update helm chart READMEs and fix broken links ([dfb210d](https://github.com/vriesdemichael/keycloak-operator/commit/dfb210de7e222159830c5687e47e0e6d5eab354e))
* update manual-todos to mark CRD design improvements as complete ([80420e9](https://github.com/vriesdemichael/keycloak-operator/commit/80420e925823fc5db290ef4053091d007a110542))
* update Phase 1 tracking with review findings and deferred work ([921757b](https://github.com/vriesdemichael/keycloak-operator/commit/921757b796a7c0b87d01ad635d0ddc7f0ce26176))
* update phase 6B TODO to reflect production mode completion ([34b6b4d](https://github.com/vriesdemichael/keycloak-operator/commit/34b6b4d22c21dd5c85887e4482f21261582ed198))
* update README badges to reference unified CI/CD workflow ([03ba009](https://github.com/vriesdemichael/keycloak-operator/commit/03ba009eb0aac6e4db6ebdbc8f6315b0ccf0dd4a))
* update release process for branch protection and PR workflow ([#12](https://github.com/vriesdemichael/keycloak-operator/issues/12)) ([6508868](https://github.com/vriesdemichael/keycloak-operator/commit/6508868dbf3b245f598fa4f1253952ae01193947))
* update tracking document - Phase 1 complete ([5ade37b](https://github.com/vriesdemichael/keycloak-operator/commit/5ade37bbc5097d12f9acbcfdcc9fa4b1e5197fdc))
* update tracking document - Phase 4 complete ([e86c1b9](https://github.com/vriesdemichael/keycloak-operator/commit/e86c1b9fa810f6258be788315ae3834f0c849098))
* update tracking document with post-Phase-2 work ([4f68758](https://github.com/vriesdemichael/keycloak-operator/commit/4f68758ac2d955beb9463daf4dd0e433e75a4311))
* update tracking plan with completed Phase 3 tasks ([e3b0f1b](https://github.com/vriesdemichael/keycloak-operator/commit/e3b0f1b2a17d5641daa0871d23d036d6b1ddfc4a))


### CI/CD

* **operator:** refactor release workflow to build-once promote-on-release pattern ([f4464b1](https://github.com/vriesdemichael/keycloak-operator/commit/f4464b124b41e9d2da3b034d10560c89fda159a5))

## [0.5.0](https://github.com/vriesdemichael/keycloak-operator/compare/v0.4.3...v0.5.0) (2025-12-17)


### ⚠ BREAKING CHANGES

* **chart-client+chart-operator+chart-realm:** Helm chart distribution moved to OCI registry
* **operator:** IDP secrets must use configSecrets field, plaintext forbidden
* **webhooks:** Admission webhooks now require cert-manager to be installed
* **chart-client+chart-realm:** Removed token-based authorization from all charts
* **operator:** latest tag no longer updates on main push, only on releases
* The API group domain has changed from keycloak.mdvr.nl to vriesdemichael.github.io. Existing installations must migrate by:
* **ci:** Release configuration now uses container-based versioning instead of Python package versioning
* Remove spec.version field from Keycloak CRD and spec.enabled field from KeycloakRealm CRD
* Multiple CRD field renames and removals for consistency

### Features

* Add centralized operator design and RBAC security implementation plan ([17b3413](https://github.com/vriesdemichael/keycloak-operator/commit/17b3413aa1c21de636b342fd9af0ff7fcc48ad96))
* add drift detection foundation (Phase 1-3) ([80cf043](https://github.com/vriesdemichael/keycloak-operator/commit/80cf0438ef7b0e7568fa9d033e15be305f24ba55))
* Add Keycloak Operator and Realm Helm charts ([2d4be4f](https://github.com/vriesdemichael/keycloak-operator/commit/2d4be4f4b8b43665afcecc8f0dacefbe88f66117))
* add keycloak_admin_client fixture for test isolation ([ea46f21](https://github.com/vriesdemichael/keycloak-operator/commit/ea46f21f8029643e4a31584830793b64f9c8402b))
* Add method to retrieve Keycloak instance from realm status ([0e45143](https://github.com/vriesdemichael/keycloak-operator/commit/0e45143500efcc16da48989de21bfd5b238c6480))
* add OIDC endpoint discovery to realm status ([6dc52f3](https://github.com/vriesdemichael/keycloak-operator/commit/6dc52f3ac9a51547e4431f99abbe91aec1d7dca3))
* Add optimized Keycloak image for 81% faster tests ([#15](https://github.com/vriesdemichael/keycloak-operator/issues/15)) ([3093a10](https://github.com/vriesdemichael/keycloak-operator/commit/3093a10239538b76d4fe7ae094e9ddcc85a519bd))
* Automatic Token Rotation System with Bootstrap Flow ([#26](https://github.com/vriesdemichael/keycloak-operator/issues/26)) ([ca28c1b](https://github.com/vriesdemichael/keycloak-operator/commit/ca28c1b995a8b953935f61d255de49921ac4cd85))
* **chart-client+chart-operator+chart-realm:** migrate to OCI registry in GHCR ([dc4f59c](https://github.com/vriesdemichael/keycloak-operator/commit/dc4f59c8f9d66be04cd7be6ae685fc714a8aad97))
* **chart-client+chart-realm:** update charts for namespace grant authorization ([add6af9](https://github.com/vriesdemichael/keycloak-operator/commit/add6af903c2ff887cd44c5608ceb1a1a6436f23e)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart-operator:** add 'get' permission for cross-namespace realm reads ([1e9cf4f](https://github.com/vriesdemichael/keycloak-operator/commit/1e9cf4fd7f4c4fb3e2a85d02bc217c8d4449075a)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart-operator:** update CRDs for namespace grant authorization ([b526149](https://github.com/vriesdemichael/keycloak-operator/commit/b52614931946e588730b3cc4312c061e383623fe)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart:** add automated operator version updates ([b303448](https://github.com/vriesdemichael/keycloak-operator/commit/b3034483f890b6ae282f787cc0ef343bc6fe6d03))
* **chart:** make admin password optional, leverage auto-generation ([a9fcb1a](https://github.com/vriesdemichael/keycloak-operator/commit/a9fcb1a475b99036b811753f42029a5cd0c0ad12))
* **charts:** add values.schema.json and extraManifests support ([039e00d](https://github.com/vriesdemichael/keycloak-operator/commit/039e00d1fe0874b2eb24f21d95f5e58d9f4a50cc))
* **ci:** add CODEOWNERS for automated review requests ([2e81678](https://github.com/vriesdemichael/keycloak-operator/commit/2e81678808cf1cca99dc668878f434cd5ae98310))
* **ci:** add comprehensive security scanning workflow ([116ef6f](https://github.com/vriesdemichael/keycloak-operator/commit/116ef6f12d73fd58bfbe3cc96906b7e38984d2bf))
* **ci:** add Dependabot for automated dependency updates ([61614e5](https://github.com/vriesdemichael/keycloak-operator/commit/61614e512728595dfaff0597882ea473e15b84c4))
* **ci:** add explicit shared Keycloak instance creation step ([dc530a1](https://github.com/vriesdemichael/keycloak-operator/commit/dc530a1f56dea2241bb459478745d8541a31e8ce))
* **ci:** add security validation to image publishing ([582caf1](https://github.com/vriesdemichael/keycloak-operator/commit/582caf117d9deb0978030651a7ac94cb0198b563))
* **ci:** auto-approve and merge non-major release PRs ([609e19b](https://github.com/vriesdemichael/keycloak-operator/commit/609e19b0b821c478c0c05962d74d1a3325d6781a))
* **ci:** create unified CI/CD pipeline workflow ([3209445](https://github.com/vriesdemichael/keycloak-operator/commit/3209445882e6ed40a67b966939550c5e976259f8))
* **ci:** enable auto-merge for release-please PRs ([0a74683](https://github.com/vriesdemichael/keycloak-operator/commit/0a746834e37fae0ad17088caa6b0c6b0757a0d0e))
* Enhance Keycloak models with aliasing and population configuration ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* implement admission webhooks for resource validation ([061acae](https://github.com/vriesdemichael/keycloak-operator/commit/061acae11b1af0d5547177c98264ac6ffbaa8f27))
* implement deletion handler fixes and cascading deletion ([13d25bb](https://github.com/vriesdemichael/keycloak-operator/commit/13d25bb5082f0c6aaf367cedb53ab4a600d36d3b))
* Implement Kopf peering for leader election and update deployment scripts ([a289e3a](https://github.com/vriesdemichael/keycloak-operator/commit/a289e3a55d95ecf2af4e2d29d94399acccf6aa25))
* implement orphan remediation (Phase 5) ([d225065](https://github.com/vriesdemichael/keycloak-operator/commit/d2250654f217dece764edabf4e9a17d8909a125e))
* Implement resource existence checks before cleanup in Keycloak reconciler ([e88ff0f](https://github.com/vriesdemichael/keycloak-operator/commit/e88ff0f46292e2bc355d1450f0f8e3406787ef40))
* implement secure SMTP configuration for KeycloakRealm ([d79ef1c](https://github.com/vriesdemichael/keycloak-operator/commit/d79ef1ca109c7dc21019932fb7fc2c1a025bee62))
* migrate API group from keycloak.mdvr.nl to vriesdemichael.github.io ([d93b3c1](https://github.com/vriesdemichael/keycloak-operator/commit/d93b3c115d73ba8e3f1fa99c48c1e058f315b075))
* **monitoring:** add Grafana dashboard and Prometheus alert rules ([e459d0d](https://github.com/vriesdemichael/keycloak-operator/commit/e459d0d11c874f17c844012f641ec51ae53ad24b))
* **operator:** add build attestations for supply chain security ([85a46cc](https://github.com/vriesdemichael/keycloak-operator/commit/85a46cce26775bc13ed809623d4ac998ce6b0152))
* **operator:** add comprehensive test coverage infrastructure ([0405cfb](https://github.com/vriesdemichael/keycloak-operator/commit/0405cfbb2b65993696cc820e62ba32be2793788a)), closes [#110](https://github.com/vriesdemichael/keycloak-operator/issues/110)
* **operator:** add coverage retrieval function (reformatted) ([73ff054](https://github.com/vriesdemichael/keycloak-operator/commit/73ff054f196b3cd076bdc11e16ac2e140e7c5594))
* **operator:** add GitHub deployment environments to workflow ([94b6b9b](https://github.com/vriesdemichael/keycloak-operator/commit/94b6b9bd3531fda63cbe6c43c088994649321d9a))
* **operator:** centralize configuration with pydantic-settings ([dd6078b](https://github.com/vriesdemichael/keycloak-operator/commit/dd6078bf9256e722188343987009f9a26b8ac3ee)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* **operator:** complete integration coverage collection ([1d4e5a4](https://github.com/vriesdemichael/keycloak-operator/commit/1d4e5a4f4fd369efeb81032539c6e938c9015635))
* **operator:** fix pydantic-settings environment variable configuration ([20d00b3](https://github.com/vriesdemichael/keycloak-operator/commit/20d00b3ff8a242e08706426ed7bc7a48e3eb2e6e)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* **operator:** implement integration test coverage collection via SIGUSR1 ([259e587](https://github.com/vriesdemichael/keycloak-operator/commit/259e587ab08a5388702e1871d62c923434796c35)), closes [#111](https://github.com/vriesdemichael/keycloak-operator/issues/111)
* **operator:** require secret refs for IDP secrets ([bf377fb](https://github.com/vriesdemichael/keycloak-operator/commit/bf377fb76b504f2c2160cd08c41ff60071505e57))
* publish JSON schemas for CRDs to enable IDE autocomplete ([72485af](https://github.com/vriesdemichael/keycloak-operator/commit/72485afb83822db7e427e1b876fd2700a91489a5))
* **resilience:** add circuit breaker and exponential backoff for API stability ([2ada936](https://github.com/vriesdemichael/keycloak-operator/commit/2ada93645579b4f81c2c042a0d53cd3d858a1e78))
* simplify issue templates for AI-agent compatibility ([c1a3c54](https://github.com/vriesdemichael/keycloak-operator/commit/c1a3c54e0dbe24c5d242777ddc1770e4e30b4d4e))
* switch Keycloak to production mode with HTTP enabled for ingress TLS termination ([1e64bc9](https://github.com/vriesdemichael/keycloak-operator/commit/1e64bc9d8b6608b24df917f167f81dfd41f51569))
* Two-level rate limiting with async/await conversion ([#44](https://github.com/vriesdemichael/keycloak-operator/issues/44)) ([476a6ed](https://github.com/vriesdemichael/keycloak-operator/commit/476a6ed4bbb327d38e7c55bdc1421daa3fdb2a81))
* update release-please configuration and add auto-rebase workflow ([92981a7](https://github.com/vriesdemichael/keycloak-operator/commit/92981a7525a14f8ae7cd97d4228e0547b8c3d09e))
* use SVG logo and update favicon ([a180ba2](https://github.com/vriesdemichael/keycloak-operator/commit/a180ba227d9295e9350b478ad47e83584e5da960))
* **webhooks:** switch to cert-manager for webhook TLS certificates ([7195217](https://github.com/vriesdemichael/keycloak-operator/commit/7195217d15903d9c2c738999ce4c25acf1daaa88))


### Bug Fixes

* add await to second IDP configure call ([a4a2589](https://github.com/vriesdemichael/keycloak-operator/commit/a4a25891530f62b1603794be642b443f6a20563a))
* add camelCase aliases to KeycloakIdentityProvider model ([5a0d9a0](https://github.com/vriesdemichael/keycloak-operator/commit/5a0d9a0fe0d44569db02e242529b6d5c4a2fda75))
* add certbuilder dependency and fix webhook RBAC permissions ([71df4ee](https://github.com/vriesdemichael/keycloak-operator/commit/71df4eebe6573b84eea6fab15fd9f9666806b3d5))
* add clientAuthorizationGrants to finalizer tests ([954d850](https://github.com/vriesdemichael/keycloak-operator/commit/954d8505d79fc2ebe7a80f6ffab319f8f5d46a1b)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* add clientAuthorizationGrants to Helm client test ([5ddf722](https://github.com/vriesdemichael/keycloak-operator/commit/5ddf7222b81f90ddb8c611f5f3e0d4e00e2aa620)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* Add clientAuthorizationGrants to realm test specs ([91e33ca](https://github.com/vriesdemichael/keycloak-operator/commit/91e33cab1b367ecc75e1f507af62f60bcfe2fde8))
* add get permission for CRDs in ClusterRole ([3455cd6](https://github.com/vriesdemichael/keycloak-operator/commit/3455cd6eef7148d506f33e13add95ea6927759de))
* add missing common.sh and config.sh scripts, update documentation ([59a644f](https://github.com/vriesdemichael/keycloak-operator/commit/59a644f580ec57eb8f297789949fe0105a7c8bc6))
* add missing namespace parameter to configure_identity_provider ([24230fd](https://github.com/vriesdemichael/keycloak-operator/commit/24230fd4055e9ab1a19cf0ac29e945f43572f53b))
* add missing RBAC permissions and correct readiness probe port ([2300f2a](https://github.com/vriesdemichael/keycloak-operator/commit/2300f2a85d6f007e2f1d6ca9b12ae80745adc95e))
* add namespace to Dex manifests ([cad2621](https://github.com/vriesdemichael/keycloak-operator/commit/cad2621cda178d90215c622f1e5cec0f2b85a39d))
* Add operator log capture and fix all integration tests ([#14](https://github.com/vriesdemichael/keycloak-operator/issues/14)) ([bf4e84f](https://github.com/vriesdemichael/keycloak-operator/commit/bf4e84ff8e4e5f8a0ebb0210ac2d6922beae2174))
* add patch permission for pods in namespace Role ([43d7fdc](https://github.com/vriesdemichael/keycloak-operator/commit/43d7fdc6f55475da9a6ba5ce42b0987bdb6d6557))
* add Pod Security Standards compliance to Dex deployment ([7ff7673](https://github.com/vriesdemichael/keycloak-operator/commit/7ff7673a74b65e52f525c670976ea07ce459ea21))
* add yq installation to release docs job ([6e53a92](https://github.com/vriesdemichael/keycloak-operator/commit/6e53a92a6ca26979eef60b0d3842d6e754bc9f27))
* address all Copilot review comments ([3ddfd8e](https://github.com/vriesdemichael/keycloak-operator/commit/3ddfd8eecdcaa83334485c616299f5f545f6ce4a))
* address Copilot review comments (resolved conflicts) ([76f6256](https://github.com/vriesdemichael/keycloak-operator/commit/76f6256cccb554ec418fd9195b9de72fbeaf3ad4))
* address Copilot review comments for integration tests ([fc09ef6](https://github.com/vriesdemichael/keycloak-operator/commit/fc09ef6d2c709d2f4b602e6bad3a3e6545b38b32))
* address Copilot review comments on unified CI/CD ([9cb6372](https://github.com/vriesdemichael/keycloak-operator/commit/9cb637234011f17b94db9547d590ed76459adbc3))
* address PR review comments ([3f0608e](https://github.com/vriesdemichael/keycloak-operator/commit/3f0608ef4ea3234b06d05f165c20b79d30395741))
* address PR review comments ([568d934](https://github.com/vriesdemichael/keycloak-operator/commit/568d9342dbbb582ae6c3544656de290735298b00))
* address review comments ([14007df](https://github.com/vriesdemichael/keycloak-operator/commit/14007df5fb013d9d43fdbe0b9732c447baca43f5))
* allow test tags in operator chart schema ([6740046](https://github.com/vriesdemichael/keycloak-operator/commit/6740046724b30ca0d694bc85a40212db826fe596))
* allow test-* tags in operator chart schema ([8450c8f](https://github.com/vriesdemichael/keycloak-operator/commit/8450c8fa9135190af5c272b641e09327de3f4b56))
* change operator component name to remove space ([e994ac2](https://github.com/vriesdemichael/keycloak-operator/commit/e994ac2a7d9fce824be86d0ade475f24aa17f6cc))
* **chart-operator:** correct digest regex in helm chart publish action ([d9cb566](https://github.com/vriesdemichael/keycloak-operator/commit/d9cb5666a4840df3626382b2f92fa59a45bb3335))
* **chart-operator:** remove admission token configuration from values ([302a27d](https://github.com/vriesdemichael/keycloak-operator/commit/302a27d59db56b064a7888ce1ee4c76f377f77e0))
* **chart-operator:** remove outdated authorization token instructions ([6f2c190](https://github.com/vriesdemichael/keycloak-operator/commit/6f2c1907af74134fc727e132e4a4ca40a5300130))
* **chart-operator:** update for operator v0.3.3 compatibility ([584c98f](https://github.com/vriesdemichael/keycloak-operator/commit/584c98f080352b39eab75c1c18e5faba838af9e9))
* **chart-operator:** update for operator v0.4.2 ([3e05ace](https://github.com/vriesdemichael/keycloak-operator/commit/3e05ace25ee4dad3555aa6f3e94487cbdd04c09a))
* **chart-operator:** update for operator v0.4.3 ([59cc41b](https://github.com/vriesdemichael/keycloak-operator/commit/59cc41bceb04de3f4a5d4ebcb960c6863f29211e))
* **chart:** align Keycloak CR template with actual CRD spec ([bfa3a62](https://github.com/vriesdemichael/keycloak-operator/commit/bfa3a62c60c715e510670642e69676058375fceb))
* **chart:** remove kustomization file from Helm CRDs folder ([dd80cb3](https://github.com/vriesdemichael/keycloak-operator/commit/dd80cb340bd3c5b5ffd4d64b83e15df918bbe4ae))
* **ci:** add all helm charts to release-please config ([2c2280b](https://github.com/vriesdemichael/keycloak-operator/commit/2c2280bd8d9faab8669738baa9dd3a58607383eb))
* **ci:** add Docker tag extraction for operator-v prefixed tags ([#28](https://github.com/vriesdemichael/keycloak-operator/issues/28)) ([b761052](https://github.com/vriesdemichael/keycloak-operator/commit/b76105243a369c3a29fee8da425c6aa888142007))
* **ci:** add missing Dockerfile path to publish job ([4986bec](https://github.com/vriesdemichael/keycloak-operator/commit/4986becd3b89c79f48493064a74940a1243a0cd2))
* **ci:** add proper step gating to fail fast on deployment errors ([6a74656](https://github.com/vriesdemichael/keycloak-operator/commit/6a746568809f3829b3ad1413052d4102bc28ae1d))
* **ci:** add semantic version tags to published container images ([2d64ab2](https://github.com/vriesdemichael/keycloak-operator/commit/2d64ab2003a5c314138e93764a4bd1db0a6eebca))
* **ci:** align operator deployment with current Makefile structure ([49599a0](https://github.com/vriesdemichael/keycloak-operator/commit/49599a0ef6c6c225cb1caa3d137d35b0bec3e6c7))
* **ci:** correct JSON syntax errors in release-please manifest ([31577b3](https://github.com/vriesdemichael/keycloak-operator/commit/31577b39ef5accb576f713b162ea62f84b554fd7))
* **ci:** correct release-please config for container-based releases ([732eaa7](https://github.com/vriesdemichael/keycloak-operator/commit/732eaa72313c7893a5b1595691365fc31d135722))
* **ci:** enable semver Docker tags by dispatching CI/CD on release creation ([ff95842](https://github.com/vriesdemichael/keycloak-operator/commit/ff958422945707c65f2556e5813a465028e64789))
* **ci:** explicitly set kubeconfig path for integration tests ([c49fc64](https://github.com/vriesdemichael/keycloak-operator/commit/c49fc6470b891b069d30308c973fdd1d426873ef))
* **ci:** improve integration test isolation and coverage ([5a03f23](https://github.com/vriesdemichael/keycloak-operator/commit/5a03f2339bbdd916084ee3f66b6699e2ed4c8a1e))
* **ci:** install both dev and integration dependency groups ([e1a703e](https://github.com/vriesdemichael/keycloak-operator/commit/e1a703edc24868b8ecef7943afd78102c5317ea2))
* **ci:** install integration test dependencies including pytest-xdist ([4a6330b](https://github.com/vriesdemichael/keycloak-operator/commit/4a6330bf6b76ef164cc069b13f6f4966389afc8e))
* **ci:** pin Helm version for deterministic builds ([3acb30f](https://github.com/vriesdemichael/keycloak-operator/commit/3acb30f17687a4bb79e84236ec448739239ee86f))
* **ci:** prevent image publishing when tests fail ([70952a2](https://github.com/vriesdemichael/keycloak-operator/commit/70952a24be23585e4442ac86605f790c3cb3eba7))
* **ci:** prevent namespace creation conflict in helm deployment ([f50f483](https://github.com/vriesdemichael/keycloak-operator/commit/f50f48396329fbb99abeda0e6050eb0ca01ad77d))
* **ci:** properly wait for Keycloak deployment to be ready ([e0f7a9e](https://github.com/vriesdemichael/keycloak-operator/commit/e0f7a9e53915e0f18d4ab19de1193f9d8239b2fd))
* **ci:** remove approval step to work with auto-merge setting ([5428eb3](https://github.com/vriesdemichael/keycloak-operator/commit/5428eb3ccf96396c4cbd8a6c1869669527078ac5))
* **ci:** remove leader election and basic functionality tests from integration workflow ([c3fad45](https://github.com/vriesdemichael/keycloak-operator/commit/c3fad4561e29daddb89e92ca824cb68831bbb275))
* **ci:** resolve release-please bash error and disable CodeQL false positives ([f0479fe](https://github.com/vriesdemichael/keycloak-operator/commit/f0479fec32047fd49a95502d610adb3741807d48))
* **ci:** update Keycloak deployment and pod labels for consistency ([e3c3510](https://github.com/vriesdemichael/keycloak-operator/commit/e3c35108e7e10a9b32f99c62d1c59ec68da99d15))
* **ci:** use correct pod labels for Keycloak readiness check ([e680bbc](https://github.com/vriesdemichael/keycloak-operator/commit/e680bbcc86517d4b557b182f65d9755ae056320a))
* **ci:** use PAT for release-please to trigger CI workflows ([4091bed](https://github.com/vriesdemichael/keycloak-operator/commit/4091bed6c30d0f37bc2377b2ff5444506c8aa1c7))
* **ci:** wait for CNPG cluster and fix kubeconfig access ([edbc171](https://github.com/vriesdemichael/keycloak-operator/commit/edbc171acf4ec2bd784aaaa2455b1ffc54c436f9))
* clear operator instance ID cache between unit tests ([49d1db7](https://github.com/vriesdemichael/keycloak-operator/commit/49d1db7b1dcdbbb6898ae0110379210af33b23ac))
* combine coverage and convert to XML for Codecov ([ad10407](https://github.com/vriesdemichael/keycloak-operator/commit/ad10407ffe4b57e1ac35c958704cbb6b682d26f2))
* configure webhook server with service DNS hostname ([d626c4b](https://github.com/vriesdemichael/keycloak-operator/commit/d626c4bddee90bd1fe3ab72c05c2b6d21552ece9))
* consolidate documentation workflows with mike ([cd31074](https://github.com/vriesdemichael/keycloak-operator/commit/cd31074e2d0c518bc05c8a50f65313a8eeb48ea3))
* convert SMTP configuration values to strings for Keycloak API compatibility ([8ad98d0](https://github.com/vriesdemichael/keycloak-operator/commit/8ad98d006399fbbf8351f5762ba30c0bdf2fc236))
* convert snake_case to camelCase in StatusWrapper ([4ad528c](https://github.com/vriesdemichael/keycloak-operator/commit/4ad528c44a76664324b47c26b0230c7b480bef42)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* correct client_cr fixture schema for drift detection tests ([fba3c5d](https://github.com/vriesdemichael/keycloak-operator/commit/fba3c5d243251d02e202e06d3c682f20bb7fcf70))
* correct fixture name in drift detection integration tests ([4694b16](https://github.com/vriesdemichael/keycloak-operator/commit/4694b16e62308399e15125c1cf580dfc9ae6b1f0))
* correct fixture name to k8s_custom_objects ([cde9e20](https://github.com/vriesdemichael/keycloak-operator/commit/cde9e2051de5e23119404e419382a452fd5f24bd))
* correct IDP configure method calls in realm reconciler ([9e19c4c](https://github.com/vriesdemichael/keycloak-operator/commit/9e19c4c85b4a7e4950d5324ecf72961d95dfb4e4))
* correct Keycloak Admin API path for IDP verification ([0a1ca04](https://github.com/vriesdemichael/keycloak-operator/commit/0a1ca04d085fe1c2584cb6bfed47fff9660dde5e))
* correct license references from Apache 2.0 to MIT ([d5323b6](https://github.com/vriesdemichael/keycloak-operator/commit/d5323b67345b34c40d12e5ad9fd416bdf647a879))
* correct operatorRef structure in documentation ([84967e1](https://github.com/vriesdemichael/keycloak-operator/commit/84967e14732017ae62bb0ce2cfa1128b825c9ee7))
* create coverage directory in container and fix collection workflow ([3b74ee6](https://github.com/vriesdemichael/keycloak-operator/commit/3b74ee6f343bfb57ef4d8e3e70169ec4ffd8925e))
* **deps:** add missing pytest-xdist to test dependency group ([cb01362](https://github.com/vriesdemichael/keycloak-operator/commit/cb01362dce1f702458b8a605fa223bce11b173b4))
* disable webhook auto-management and default to false ([0c59b83](https://github.com/vriesdemichael/keycloak-operator/commit/0c59b834d2852d010a6ca97152eb4b2e41e0353b))
* disable webhooks by default to avoid bootstrap issues ([85470ed](https://github.com/vriesdemichael/keycloak-operator/commit/85470ed5f1a6b9a45027fd050622d82042e92b43))
* drift detection tests auth token namespace ([763ebd1](https://github.com/vriesdemichael/keycloak-operator/commit/763ebd1b0d451b085a9f9877f429e73d3694b358))
* enable mandatory type checking and add Helm linting to pre-commit ([97dc9d7](https://github.com/vriesdemichael/keycloak-operator/commit/97dc9d7062695a9e3999c5554d774ac9c79e6c3d))
* enforce same-namespace secrets and fix Pydantic model access ([56d448a](https://github.com/vriesdemichael/keycloak-operator/commit/56d448a1e834f7d7da60172976fa67da3dd6bc89))
* **examples:** correct Keycloak CR database configuration ([be1495c](https://github.com/vriesdemichael/keycloak-operator/commit/be1495cc70125048d2f73f71b30aa727b2eccb3e))
* GitHub Actions release-please workflow JSON parsing error ([60081f4](https://github.com/vriesdemichael/keycloak-operator/commit/60081f4f5ea954892fc0f87db3b516d26250a042))
* implement Keycloak-compliant redirect URI wildcard validation ([83e7742](https://github.com/vriesdemichael/keycloak-operator/commit/83e7742594ae6cc17b0698d4416a358565569033))
* import all webhook modules to register handlers ([12b9bbd](https://github.com/vriesdemichael/keycloak-operator/commit/12b9bbddb038caffa83f855eccfa59519b14621a))
* improve Dex deployment robustness ([78083fe](https://github.com/vriesdemichael/keycloak-operator/commit/78083fe5cf52fb64d5b30bf3bddcba4b041f5519))
* make all shell scripts executable for GitHub Actions ([bba6004](https://github.com/vriesdemichael/keycloak-operator/commit/bba6004d311e4073ab28aff28bbe926176eb0825))
* make coverage scripts executable and share unit coverage with integration tests ([17615ff](https://github.com/vriesdemichael/keycloak-operator/commit/17615ff3b997c7c86e41d5ca30221993f3d7fe95))
* make realm_cr and client_cr async fixtures ([3d46d6f](https://github.com/vriesdemichael/keycloak-operator/commit/3d46d6fcc22837130b4ee26b2bf4cc100f2c3ed3))
* only retrieve coverage on last worker exit ([236636a](https://github.com/vriesdemichael/keycloak-operator/commit/236636aa843ce6cd73cfe40191f605f3fc31e611))
* **operator:** allow integration coverage failures during outage ([42ece4a](https://github.com/vriesdemichael/keycloak-operator/commit/42ece4ac55598db3969f5129056c4448a6504ca6))
* **operator:** database passwordSecret support and test fixes ([038fc18](https://github.com/vriesdemichael/keycloak-operator/commit/038fc18da190e8d99eb02222c89c59393129feee))
* **operator:** detect release commits merged by users, not just bots ([50a21e9](https://github.com/vriesdemichael/keycloak-operator/commit/50a21e9c619faefe47e9d7a7b688b3d883518120))
* **operator:** disable fail_ci_if_error for codecov uploads ([2e22069](https://github.com/vriesdemichael/keycloak-operator/commit/2e220690d61551e2abca83359eab33bf7990a14e))
* **operator:** enable auto-merge for grouped release PRs ([7c2419a](https://github.com/vriesdemichael/keycloak-operator/commit/7c2419a95aca55264400d1d0252e2af52fec0501))
* **operator:** enforce scope for release-triggering commits ([6c7e271](https://github.com/vriesdemichael/keycloak-operator/commit/6c7e27134917df7e1c53031d86991c2ce74b9a7f))
* **operator:** group release-please PRs to prevent manifest conflicts ([529c990](https://github.com/vriesdemichael/keycloak-operator/commit/529c99037235bd63b315ae3673a1c1506dcccdca))
* **operator:** handle basic realm field updates in do_update method ([fab2804](https://github.com/vriesdemichael/keycloak-operator/commit/fab2804ad2e1b982f7e7009e11290f68fbaccf0b))
* **operator:** handle realm deletion gracefully in client cleanup ([45b25cd](https://github.com/vriesdemichael/keycloak-operator/commit/45b25cda8c945c56daddbc2538a1c0133713324f))
* **operator:** load test-coverage image tag for integration tests ([af358ba](https://github.com/vriesdemichael/keycloak-operator/commit/af358ba923a7e9625920de99abeac52d696a49e2))
* **operator:** make integration coverage non-fatal if not generated ([02022c7](https://github.com/vriesdemichael/keycloak-operator/commit/02022c7a728db530be61accf4961aa1ac70b1f53))
* **operator:** prevent event loop closed errors in httpx client cache ([83b8020](https://github.com/vriesdemichael/keycloak-operator/commit/83b80200c7d0df07058856e8ee99e979dba585a8))
* **operator:** properly fix coverage collection and uv group isolation ([867df0a](https://github.com/vriesdemichael/keycloak-operator/commit/867df0ae0140573ccb9f0788b5308ad231bd5d20))
* **operator:** resolve JSON serialization and test timing issues ([fb29bcb](https://github.com/vriesdemichael/keycloak-operator/commit/fb29bcbd1859e0dbcb2d8ded643a38ecb52c5cb5))
* **operator:** restore --group flags and upload integration coverage files separately ([b067c30](https://github.com/vriesdemichael/keycloak-operator/commit/b067c304459bd556de67f3bc292dab385a5fdac4))
* **operator:** revert uv run --group flag, keep coverage upload fix ([225cef3](https://github.com/vriesdemichael/keycloak-operator/commit/225cef3794076367e1ab25b659197460c25bd218))
* **operator:** run quality checks and tests for code OR chart changes ([a9e8ad2](https://github.com/vriesdemichael/keycloak-operator/commit/a9e8ad27ff84b7b704fdbbe9c8c353057078070c))
* **operator:** temporarily allow codecov failures during global outage ([baa2f58](https://github.com/vriesdemichael/keycloak-operator/commit/baa2f58e714c8e4b2538233fe84ba6c550926401))
* **operator:** update all-complete job to reference new chart jobs ([be5dde3](https://github.com/vriesdemichael/keycloak-operator/commit/be5dde3d28b33a2b78ff713eb5f9ce03df6d628e))
* **operator:** update package metadata with correct author info ([96ba785](https://github.com/vriesdemichael/keycloak-operator/commit/96ba785332f12613446cb83e5525ade6cc966e80))
* **operator:** use asyncio.to_thread for webhook K8s API calls ([d635da9](https://github.com/vriesdemichael/keycloak-operator/commit/d635da9ae8a78928baf613b35686256849e78b80))
* **operator:** use correct camelCase field names in realm update handler ([91636eb](https://github.com/vriesdemichael/keycloak-operator/commit/91636ebdb1afef442a5eb6e9bf46db69585454b8))
* **operator:** use coverage run in CMD for proper instrumentation ([1665eaa](https://github.com/vriesdemichael/keycloak-operator/commit/1665eaaef1f8bd01616a278edf99a232d6bd7a53))
* **operator:** use legacy codecov endpoint only as fallback ([c76ff4a](https://github.com/vriesdemichael/keycloak-operator/commit/c76ff4a0c120329c41266366283193cf3b82fa8e))
* **operator:** use legacy codecov upload as fallback ([1cb9293](https://github.com/vriesdemichael/keycloak-operator/commit/1cb929309a914b58197e0d03e4fe01801826edd5))
* preserve binary data when retrieving coverage files ([1cf7252](https://github.com/vriesdemichael/keycloak-operator/commit/1cf7252de0b3db30d217e011ff667fff0da18b6c))
* prevent premature operator cleanup in pytest-xdist workers ([8031895](https://github.com/vriesdemichael/keycloak-operator/commit/8031895e2b2347378cbb376555136ee7e395ff49))
* prevent premature operator cleanup in pytest-xdist workers ([2a7f4a1](https://github.com/vriesdemichael/keycloak-operator/commit/2a7f4a19892c44ce8a24dd63e2136f6645bad06b))
* proper webhook bootstrap with readiness probe and ArgoCD sync waves ([c8dfc52](https://github.com/vriesdemichael/keycloak-operator/commit/c8dfc5200c02cf550e8857d6e44583b50fb11895))
* properly implement IDP integration tests ([8cf7cb1](https://github.com/vriesdemichael/keycloak-operator/commit/8cf7cb1df097b447a215ccacb46254939d21b4c4))
* race condition in CI/CD and cleanup Makefile ([91b0640](https://github.com/vriesdemichael/keycloak-operator/commit/91b0640961ead705430efaa61c70daa6da8a45c0))
* reduce Dex wait timeout to avoid pytest timeout ([acb0106](https://github.com/vriesdemichael/keycloak-operator/commit/acb01064b8a4df9108b78a5016e7b779a77ceb58))
* refactor pages workflow to fix versioning and artifact issues ([e1d6da1](https://github.com/vriesdemichael/keycloak-operator/commit/e1d6da11bda072ead0d0eff66f87def24905ad0c)), closes [#114](https://github.com/vriesdemichael/keycloak-operator/issues/114)
* remove authorizationSecretRef from Helm values schemas ([f87585b](https://github.com/vriesdemichael/keycloak-operator/commit/f87585b10b7446822636a909e83f1c45235fa62d)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove await from synchronous API call in capacity check ([2908db5](https://github.com/vriesdemichael/keycloak-operator/commit/2908db581fa9a39f590c67b1a3ef47f27ec978d0)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove duplicate coverage retrieval code ([691d70b](https://github.com/vriesdemichael/keycloak-operator/commit/691d70bd3cc8a9c3e1e22b4ac08db229e6b7a41d))
* Remove last_reconcile_time from status updates ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* remove obsolete authorization token references from charts ([880fc98](https://github.com/vriesdemichael/keycloak-operator/commit/880fc98637ff0e0e4c9471fd47162fc1d790b194)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove obsolete authorizationSecretName status field ([9952eae](https://github.com/vriesdemichael/keycloak-operator/commit/9952eaef7c155f3013b9a1cc2d7a0c66c7cf4827)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove tests for deleted periodic_leadership_check function ([1ffcba0](https://github.com/vriesdemichael/keycloak-operator/commit/1ffcba0479decb4916a65262f58a46f84ab28ddd))
* remove webhook config template, let Kopf manage it ([57f2e3e](https://github.com/vriesdemichael/keycloak-operator/commit/57f2e3e82a68789d49b73fea4c8cac4e409133c2))
* Removed await, added explicit k8s_client parameter. ([2908db5](https://github.com/vriesdemichael/keycloak-operator/commit/2908db581fa9a39f590c67b1a3ef47f27ec978d0))
* replace old keycloak.mdvr.nl API group with vriesdemichael.github.io ([da644e0](https://github.com/vriesdemichael/keycloak-operator/commit/da644e09d335803e59f61a2f46f463ebfab0e50b))
* resolve all three workflow failures ([9c6b5ed](https://github.com/vriesdemichael/keycloak-operator/commit/9c6b5edb50995ee1ccce91f5d9b1d690428f78e5))
* resolve operator reconciliation bugs ([ead662f](https://github.com/vriesdemichael/keycloak-operator/commit/ead662f3c19e2d8e345aeb554f7558caf9bfe5e8))
* resolve permission denied error for build-adr-docs.sh in GitHub Actions ([4a99239](https://github.com/vriesdemichael/keycloak-operator/commit/4a9923972e933b94ad7559c1a95174b78b6c1afe))
* restore correct test image tag for coverage collection ([6cb1675](https://github.com/vriesdemichael/keycloak-operator/commit/6cb16758ce97572f7b98396ea3b6960fb61e122f))
* restore coverage collection and upload for tests ([0ae218d](https://github.com/vriesdemichael/keycloak-operator/commit/0ae218dc926c3c5bb834c3cf9cedf952b2106c45))
* restore integration test coverage collection ([4f35596](https://github.com/vriesdemichael/keycloak-operator/commit/4f355969c0f95f0445d6cceaf9fb7b260e574723))
* **security:** prevent sensitive exception details from leaking in HTTP responses ([b0ff023](https://github.com/vriesdemichael/keycloak-operator/commit/b0ff0236e1e559940b9deb111c30be0b6345708e))
* **security:** remove unnecessary verify=False from HTTP health check ([dd5217f](https://github.com/vriesdemichael/keycloak-operator/commit/dd5217f3e0df2407ffb594dd554c238889884b38))
* send SIGTERM instead of deleting pod for coverage ([d3fa7eb](https://github.com/vriesdemichael/keycloak-operator/commit/d3fa7eba9a9e4aa51c4d4fa04e55e2c21e49213f))
* simplify coverage - always on, fail hard, let codecov combine ([d953b29](https://github.com/vriesdemichael/keycloak-operator/commit/d953b291e32e8bdc66485fc8ebe2e5e947846ce7))
* streamline coverage workflow - remove merging, retrieve integration coverage immediately ([8fb0eb4](https://github.com/vriesdemichael/keycloak-operator/commit/8fb0eb4c9478b9996decfca81851492e2d6d21df))
* **tests:** fix all 7 drift detection integration tests ([fd5e76f](https://github.com/vriesdemichael/keycloak-operator/commit/fd5e76f4dab5294372d06205b4a4eb12cf3d35a8))
* **tests:** improve integration test reliability for CI environments ([77f6aa0](https://github.com/vriesdemichael/keycloak-operator/commit/77f6aa03aebbcda3fed2104619efa4a2f3da2f59))
* **tests:** properly mock Kubernetes client in finalizer tests ([df6e7d9](https://github.com/vriesdemichael/keycloak-operator/commit/df6e7d9df14cfd46b809da75d279bd94566acd3f))
* **tests:** resolve Helm chart schema validation error in CI ([7db635e](https://github.com/vriesdemichael/keycloak-operator/commit/7db635e5dd7924e56c4742fa1de8582b11243e85))
* **tests:** run integration tests in 'dev' group for improved organization ([dbe9590](https://github.com/vriesdemichael/keycloak-operator/commit/dbe9590d356ad9ca1ae26b77ac3ac429b625141b))
* TruffleHog BASE/HEAD commit issue in CI/CD workflow ([9067632](https://github.com/vriesdemichael/keycloak-operator/commit/90676320138f30044c30d1e2c9f494ff2eb056f5))
* update integration tests for grant list authorization ([9f2e2a6](https://github.com/vriesdemichael/keycloak-operator/commit/9f2e2a663ebd3d8c69ced03079b8405357dc86d1)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* update integration tests to use keycloak-prefixed annotations and finalizers ([0baf321](https://github.com/vriesdemichael/keycloak-operator/commit/0baf3213832ba63b853a06a34265244d976f54e6))
* update security scans to use test-coverage tag ([e65247b](https://github.com/vriesdemichael/keycloak-operator/commit/e65247be81106c06ece373ea6c418735cade9680))
* update tests and Helm schema for grant list authorization ([0fe6fca](https://github.com/vriesdemichael/keycloak-operator/commit/0fe6fcae8c638595a117b2093d869ecb85b37f47)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* upload raw coverage files instead of converting to XML ([64c98c7](https://github.com/vriesdemichael/keycloak-operator/commit/64c98c7b6db0365b820fb3fcfeb790e1364ac0e3))
* use correct image tag in promote workflow SBOM/Trivy steps ([65e5984](https://github.com/vriesdemichael/keycloak-operator/commit/65e59847f23d3a364fdabd4f6e54361d9c72ccd0))
* use correct operator image tag in integration tests ([8b3d7e8](https://github.com/vriesdemichael/keycloak-operator/commit/8b3d7e82a84454d4f5cd646788e150c745887790))
* use correct operator namespace and shared_operator fixture in drift tests ([581a2db](https://github.com/vriesdemichael/keycloak-operator/commit/581a2dbb881b3f0679ef83cfcad1e5f7c365c2c0))
* use correct yq sha256 checksum for v4.44.3 ([f4c7dc0](https://github.com/vriesdemichael/keycloak-operator/commit/f4c7dc0683a368ccb8bb2df25b087776b3d9d5df))
* use Dockerfile.test for coverage-instrumented image ([82f0373](https://github.com/vriesdemichael/keycloak-operator/commit/82f037384444e161cbd5013cd798bf8fe7ea4234))
* Use explicit exists output for artifact conditionals ([f52b7cd](https://github.com/vriesdemichael/keycloak-operator/commit/f52b7cdc66de1d7294fa34e4a3862aaf29b1d286))
* use httpGet probe instead of exec with wget ([a6135d6](https://github.com/vriesdemichael/keycloak-operator/commit/a6135d6273e3a2377fd4b23e89342f00a2fb7acb))
* use kubectl for Dex deployment and enable IDP tests ([1e72b0e](https://github.com/vriesdemichael/keycloak-operator/commit/1e72b0ea450cb430cfe9d028e10139cf97bdae8b))
* use proper conventional commit scope for chart updates ([70cf9c0](https://github.com/vriesdemichael/keycloak-operator/commit/70cf9c043040b3405c48ccc5b4b92f23e368c30f))
* use shared_operator namespace directly in drift tests ([e70d3d3](https://github.com/vriesdemichael/keycloak-operator/commit/e70d3d30e06daaf6271237000578ae2424d3ce28))
* use sync client for kubernetes stream() calls ([4a7b524](https://github.com/vriesdemichael/keycloak-operator/commit/4a7b52426b9f68e1984bd6b63eb57a081536bea7))
* use test-coverage tag for operator image ([2f0cce4](https://github.com/vriesdemichael/keycloak-operator/commit/2f0cce4076eb307218cd0e9cddb91bdbffa70bb0))


### Performance Improvements

* implement generation-based skip to avoid redundant reconciliations ([af0d4c6](https://github.com/vriesdemichael/keycloak-operator/commit/af0d4c63490122a5d4893f2cb2e5cf6d63fe3f6b)), closes [#184](https://github.com/vriesdemichael/keycloak-operator/issues/184)


### Code Refactoring

* address PR review comments ([499a0c9](https://github.com/vriesdemichael/keycloak-operator/commit/499a0c93ff4f4a5074cdb5981b54a0f880a69044))
* align CRD schemas with Pydantic models for GitOps compliance ([c06001b](https://github.com/vriesdemichael/keycloak-operator/commit/c06001bfbc6dfff6f09aafe65a767918e7481cc2))
* **ci:** remove old workflow files ([2205530](https://github.com/vriesdemichael/keycloak-operator/commit/2205530eb3e8bd30ac6cb30c1962517fbad3d807))
* **ci:** split deployment into clear sequential steps ([ff07e16](https://github.com/vriesdemichael/keycloak-operator/commit/ff07e16aa604dfe1076c89d59ca1d298824e907a))
* **ci:** unify CI/CD pipeline into single workflow ([ea1b748](https://github.com/vriesdemichael/keycloak-operator/commit/ea1b74895c277ec70b7f2e35d15a5cdcdc0729d9))
* **ci:** use operator chart for complete deployment ([5cb1f09](https://github.com/vriesdemichael/keycloak-operator/commit/5cb1f0996723ded97df9f14e3aafea7d14ce14b9))
* **ci:** use uv run --with for ephemeral dependencies ([649d65f](https://github.com/vriesdemichael/keycloak-operator/commit/649d65f4c3167cf69f0982978255230ce786dd7a))
* clean up Makefile and add cluster reuse workflow ([#59](https://github.com/vriesdemichael/keycloak-operator/issues/59)) ([be3bcd4](https://github.com/vriesdemichael/keycloak-operator/commit/be3bcd4ab1f09413fc23da36aa79f5e00c9df91a))
* consolidate TODO files and enhance Keycloak admin API ([350c88f](https://github.com/vriesdemichael/keycloak-operator/commit/350c88fb0899e166dcea1883c00b2d1c78eeeb90))
* convert drift tests to function-based structure ([f576d14](https://github.com/vriesdemichael/keycloak-operator/commit/f576d143db4d048a6e0c3f53c32a5b75922e52be))
* **operator:** remove redundant uv sync steps when using --group ([c9aea4f](https://github.com/vriesdemichael/keycloak-operator/commit/c9aea4fa42335ae65efcd0a4874341cb9fcfbd2f))
* **operator:** unify Dockerfile with multi-stage targets ([dd81347](https://github.com/vriesdemichael/keycloak-operator/commit/dd813478441800b2519e184e94bc249fa2a6289c))
* **operator:** use manifest diff for major version detection ([3a161be](https://github.com/vriesdemichael/keycloak-operator/commit/3a161beddd0f086f03f5db0e637aaf0d724f21a2))
* remove version and enabled fields from CRDs for K8s-native design ([11cdf60](https://github.com/vriesdemichael/keycloak-operator/commit/11cdf60a1b21320154fcefe5eba3a4a20386beaf))
* restructure decision records with improved schema ([7eb2710](https://github.com/vriesdemichael/keycloak-operator/commit/7eb27104a3da5d4047992709e15ad993f169a1a8))
* simplify ADR structure - remove status field ([90cf325](https://github.com/vriesdemichael/keycloak-operator/commit/90cf3254ca06b062a24f3b87bcdcac75abab15dc))
* simplify CI/CD workflow conditionals ([45fad5c](https://github.com/vriesdemichael/keycloak-operator/commit/45fad5c6467f6f99aef82a543ad55af4b4a42931))
* split CI/CD workflow into composite actions ([34da80d](https://github.com/vriesdemichael/keycloak-operator/commit/34da80d4cd5aaa51e07dc4fa998f86e0faccb45f))
* split CI/CD workflow into composite actions ([6a36cb1](https://github.com/vriesdemichael/keycloak-operator/commit/6a36cb1b9fb1f19869b2cfc7ade85f9fc4a6fab7))
* split CI/CD workflow into composite actions + add custom logo ([610417d](https://github.com/vriesdemichael/keycloak-operator/commit/610417d980cfdaa85ed384a757b8bd0d7b587479))
* **test:** add fixture recommendation helper function ([bab3bfd](https://github.com/vriesdemichael/keycloak-operator/commit/bab3bfdad3e4320c4b9f4b7e12ac8ee77812d3c0))
* **test:** add keycloak_ready composite fixture with Pydantic model ([f6a0878](https://github.com/vriesdemichael/keycloak-operator/commit/f6a087895b40496a19daf9c6bf070dca3344df2d))
* **test:** add type safety with Pydantic models and prefix internal fixtures ([c6cc015](https://github.com/vriesdemichael/keycloak-operator/commit/c6cc01589345ba3fd5a2f482249d449dfe1312f8))
* **test:** consolidate token fixtures and add CR factory functions ([0de7519](https://github.com/vriesdemichael/keycloak-operator/commit/0de75197748dc8e1cef8fcdbeaf59e2a25fbbfae))
* **tests:** enhance integration test setup by optimizing dependency installation and removing unnecessary steps ([b55d6d9](https://github.com/vriesdemichael/keycloak-operator/commit/b55d6d98682c982caf8e1d36e6e67867c95f2d07))
* **tests:** streamline integration test execution and remove Makefile group ([09a2f71](https://github.com/vriesdemichael/keycloak-operator/commit/09a2f717056d109423898f4fd76d7d19b13cd235))
* update decision 005 - no plaintext secrets ([0d0d8ae](https://github.com/vriesdemichael/keycloak-operator/commit/0d0d8ae76a833d0687da957548253ad9f0d3b7af))
* update decision 012 - async API with resilience ([1397a43](https://github.com/vriesdemichael/keycloak-operator/commit/1397a4310c7102ed6b6a2b194c55c82d29bf45cf))
* update decision 013 - focus on data validation ([aae7d62](https://github.com/vriesdemichael/keycloak-operator/commit/aae7d62de24803e780ce79f98e4ee597756b2d43))
* Update status condition transition tests ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* use kopf[dev] extra instead of manual certbuilder ([bf44078](https://github.com/vriesdemichael/keycloak-operator/commit/bf44078d955d50613cc8d1c17605babecb08a3c0))
* use release-please as gatekeeper for CD phase ([8f607bb](https://github.com/vriesdemichael/keycloak-operator/commit/8f607bb6c71adcf1268d16148f55e8fb90b4a6ab))
* use targeted dependency groups in CI and Makefile ([12142e4](https://github.com/vriesdemichael/keycloak-operator/commit/12142e4d22059103603537bcbf9862723698a335))


### Documentation

* add 21 foundational Architecture Decision Records ([bbeb67e](https://github.com/vriesdemichael/keycloak-operator/commit/bbeb67eb9f5b75599b58a0ed6290bfd5d8ef27a9))
* add admission webhook documentation and decision record ([396de85](https://github.com/vriesdemichael/keycloak-operator/commit/396de85863b5731e6e55ae2ac11ad21fbc45eeb1))
* add ADR-064 rejecting force-delete feature ([6df1d50](https://github.com/vriesdemichael/keycloak-operator/commit/6df1d505d090ff22199a125bf30a760c005b402a))
* add Architecture Decision Records (ADR) structure ([d8f488b](https://github.com/vriesdemichael/keycloak-operator/commit/d8f488bb9922b666a0b01d00b386623a991ead72)), closes [#55](https://github.com/vriesdemichael/keycloak-operator/issues/55)
* add architecture diagrams for multi-operator and rate limiting ([927b0d1](https://github.com/vriesdemichael/keycloak-operator/commit/927b0d176a42b7d35059147d6b41f6ead37385ce))
* add CI/CD and documentation issues task list ([1d09817](https://github.com/vriesdemichael/keycloak-operator/commit/1d0981719319e67cb6872b4408f42e83014edd2e))
* add CI/CD and GitOps integration examples ([7225653](https://github.com/vriesdemichael/keycloak-operator/commit/7225653ecc3591fe01c2073ccddc3c47a80868ab))
* add comprehensive CRD field reference documentation ([2ad21a5](https://github.com/vriesdemichael/keycloak-operator/commit/2ad21a5725285277f96f2e40238e278f9ef6c853))
* add comprehensive drift detection documentation (Phase 6) ([c09439d](https://github.com/vriesdemichael/keycloak-operator/commit/c09439d39f7e2147a25bb0a9956e987ba6350835))
* add comprehensive integration testing guidelines ([cbd1325](https://github.com/vriesdemichael/keycloak-operator/commit/cbd13256e71d88a93bd0c5cb60199fad3340fb19))
* add comprehensive observability and security documentation ([8bb3448](https://github.com/vriesdemichael/keycloak-operator/commit/8bb3448a3206362300d0b4c23ee24e2021ec221a))
* add comprehensive Quick Start guide with examples ([723e6d1](https://github.com/vriesdemichael/keycloak-operator/commit/723e6d1e14bc990f4da7ad3958ac1527c4f86ab7))
* add comprehensive release workflow analysis and fix documentation ([87838c9](https://github.com/vriesdemichael/keycloak-operator/commit/87838c9b57e0d0ad840cf4160e2e6f50ac53d3ab))
* add comprehensive security and reliability review for CI/CD workflows ([1fb53d4](https://github.com/vriesdemichael/keycloak-operator/commit/1fb53d4d4716cbc5cd5999e0df0feaca8385f7d9))
* add comprehensive testing guide and token terminology glossary ([91bf3b5](https://github.com/vriesdemichael/keycloak-operator/commit/91bf3b59ace290b2c618c8e740cb3cdeb78c2885))
* add comprehensive user guides and operations documentation ([92b99b2](https://github.com/vriesdemichael/keycloak-operator/commit/92b99b26005d3377c42427e15e4634264cf9bb7c))
* add custom logo and favicon ([34da80d](https://github.com/vriesdemichael/keycloak-operator/commit/34da80d4cd5aaa51e07dc4fa998f86e0faccb45f))
* add custom logo and favicon ([6a36cb1](https://github.com/vriesdemichael/keycloak-operator/commit/6a36cb1b9fb1f19869b2cfc7ade85f9fc4a6fab7))
* add Decision Records as separate tab with tag filtering ([6931bc3](https://github.com/vriesdemichael/keycloak-operator/commit/6931bc3b1989768b98a078161946a2115ed01d41))
* add decisions 022-023 for type checking and Make automation ([2bf22ec](https://github.com/vriesdemichael/keycloak-operator/commit/2bf22ecbea80ee1e0b75dadd5bc8867af022f9b6))
* add decisions 024-032 for deployment and architecture ([56ba2cc](https://github.com/vriesdemichael/keycloak-operator/commit/56ba2ccbcc3631f9eebdc06b08984ed94a3eb4da))
* add decisions 033-052 completing decision record set ([1dbd5d3](https://github.com/vriesdemichael/keycloak-operator/commit/1dbd5d36c2cd929e43e47aa1dd897d231627f14e))
* add deprecation notices to token-based documentation ([0dc075f](https://github.com/vriesdemichael/keycloak-operator/commit/0dc075f575722619dab823a11aacb222db39a067))
* add helm values JSON schema requirement to ADR-030 ([76f2637](https://github.com/vriesdemichael/keycloak-operator/commit/76f263714eed966ba80b685b2c501732cb3b9129))
* add identity provider documentation and integration tests ([9e6bb6a](https://github.com/vriesdemichael/keycloak-operator/commit/9e6bb6aa7cf74972046f29fac3e746c658dd7548))
* add introductory text to FAQ page ([b3e4116](https://github.com/vriesdemichael/keycloak-operator/commit/b3e4116a9853e9eacf3880db4a1a9c136f69c581))
* add Keycloak brand colors and improved styling ([fc7a0a5](https://github.com/vriesdemichael/keycloak-operator/commit/fc7a0a50f0993dad3f6b1e04791fc9c36e3d4b1f))
* add mandatory RELEASES.md check before commits in CLAUDE.md ([a329050](https://github.com/vriesdemichael/keycloak-operator/commit/a329050c1b5ce19c012ec9a274ca417cb3e83750))
* add Mermaid diagram support and hide home TOC ([b1f2e74](https://github.com/vriesdemichael/keycloak-operator/commit/b1f2e74d7f7a6cff2d8de4b8b29d146c5160b21c))
* add proper procedure for resolving PR review threads ([c4e5735](https://github.com/vriesdemichael/keycloak-operator/commit/c4e57354d0ca66b46743af860cf13f58afeeec63))
* add random jitter to decision 012 retry logic ([0e515b5](https://github.com/vriesdemichael/keycloak-operator/commit/0e515b5f37ce209970b54af80f33f79ac34a92d9))
* add scaling strategy documentation to architecture ([#56](https://github.com/vriesdemichael/keycloak-operator/issues/56)) ([0b496c7](https://github.com/vriesdemichael/keycloak-operator/commit/0b496c7b568a33889b8d9e7980e04b6a9e60b6b3))
* add security scanning badge to README ([8edd36b](https://github.com/vriesdemichael/keycloak-operator/commit/8edd36b9ba27b74717fdd2c6ac44a2b7361d05b6))
* add SMTP configuration implementation plan ([67d2362](https://github.com/vriesdemichael/keycloak-operator/commit/67d2362fc16d58c8e0ecb65a86c4f524ca29db74))
* add versioned documentation with mike integration ([c5d0bfd](https://github.com/vriesdemichael/keycloak-operator/commit/c5d0bfd5be47b20223fc8e541e0f8f8f54fec2a5))
* bulk cleanup of authorizationSecretRef in chart READMEs ([7010d85](https://github.com/vriesdemichael/keycloak-operator/commit/7010d855084409af6a36e3d17fae465070afd6b9))
* bulk cleanup remaining authorizationSecretRef references ([61e66a3](https://github.com/vriesdemichael/keycloak-operator/commit/61e66a3321be25ed370702df669f7bcd5299fa27))
* change default merge strategy to rebase ([442c6b9](https://github.com/vriesdemichael/keycloak-operator/commit/442c6b9787787a597010405e822ac468d2b17d66))
* **chart-client:** add comprehensive README ([7b147c8](https://github.com/vriesdemichael/keycloak-operator/commit/7b147c845b18172f0526182ecc33a469a56b5f07))
* **chart-operator:** add comprehensive README ([759081d](https://github.com/vriesdemichael/keycloak-operator/commit/759081deb9ac3cea713a0aac7843b15624165dd1))
* **chart-operator:** clarify single-tenant dev mode and add Keycloak deployment guidance ([eb3683d](https://github.com/vriesdemichael/keycloak-operator/commit/eb3683d42878d868f8857c726464a26a3a6702b2))
* **chart-operator:** remove all admission token documentation ([528ff2e](https://github.com/vriesdemichael/keycloak-operator/commit/528ff2e42b7f9f7925215c8ca30291142aedf539))
* **chart-realm:** add comprehensive README ([92c8e95](https://github.com/vriesdemichael/keycloak-operator/commit/92c8e95cd65ebdfa6c90f6b12b1b1fe7a91a80bb))
* **ci:** add CI/CD improvements tracking document ([67f714a](https://github.com/vriesdemichael/keycloak-operator/commit/67f714ae03578335b85370f1da540e9242a822a0))
* **ci:** add complete implementation summary ([b42a0dd](https://github.com/vriesdemichael/keycloak-operator/commit/b42a0dd87beb71689f096a671da89eea2bf97699))
* **ci:** add workflow migration documentation ([7028b35](https://github.com/vriesdemichael/keycloak-operator/commit/7028b354f4b5f0badb48bf3f3f84c457bc2f9280))
* **ci:** feature requests now require less information ([93945d1](https://github.com/vriesdemichael/keycloak-operator/commit/93945d111c2a1a4d60dd9a630947306bf97e5efe))
* **ci:** update tracking to reflect Phase 2 completion ([33baaf6](https://github.com/vriesdemichael/keycloak-operator/commit/33baaf64537594e4500bc838e5baa64bd00a3b31))
* clarify namespace scope requires cluster-wide RBAC ([ea563db](https://github.com/vriesdemichael/keycloak-operator/commit/ea563db39f1228beb5cd5347923f2988bda88fc7))
* clean authorizationSecretRef from CRD reference docs ([e416d90](https://github.com/vriesdemichael/keycloak-operator/commit/e416d902e9b5cfed1a27522dfc3d4831d23b0030))
* configure mkdocstrings to resolve autorefs warnings in strict mode ([1165559](https://github.com/vriesdemichael/keycloak-operator/commit/11655595007e807c597dbd87565a7fca2a59895c))
* correct tracking document - Phase 3 was already complete ([d374041](https://github.com/vriesdemichael/keycloak-operator/commit/d374041174d5a9657911a1bd24e58b1dae9aa651))
* **design:** add Keycloak state observability analysis ([120eb81](https://github.com/vriesdemichael/keycloak-operator/commit/120eb81c5e8bd4d28c1833f9afaa088f90ce0210))
* enforce least privilege by removing admin console access ([4c788bd](https://github.com/vriesdemichael/keycloak-operator/commit/4c788bdf694d60aa5da0423f28f932dedabb2f8b))
* enhance dark mode styling with better contrast ([b905878](https://github.com/vriesdemichael/keycloak-operator/commit/b9058784419cc9f9248eddbf9ef0537aed123cf3))
* expand decision 009 - AI agents as first-class developers ([7c1a416](https://github.com/vriesdemichael/keycloak-operator/commit/7c1a416a778f228ec4b577658cdd7e97a5d66ee3))
* final cleanup of remaining token references ([10f83eb](https://github.com/vriesdemichael/keycloak-operator/commit/10f83eb6fd7883b24c27e7d114c017f5e6284992))
* final tracking update - 36/36 tests passing ([8462747](https://github.com/vriesdemichael/keycloak-operator/commit/8462747b9610497387e972a3c13def51ef843f21)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* fix ADR 45/49 and add decision records to documentation ([33586ac](https://github.com/vriesdemichael/keycloak-operator/commit/33586ac4705692b4ff9db3063091b107a4c89504))
* fix ASCII diagram spacing and automate decision index ([2ef4cec](https://github.com/vriesdemichael/keycloak-operator/commit/2ef4cecf0bb78f5da3cb68b481c15255f71baa68))
* fix broken anchor links and ADR index page ([34825a9](https://github.com/vriesdemichael/keycloak-operator/commit/34825a9473ab7e7341fbe73f3aff14abb3b284e3))
* fix broken links and cross-references ([64da07d](https://github.com/vriesdemichael/keycloak-operator/commit/64da07d31135ab7bb1e77a41686f6b71ffca61d8))
* fix deployment flow and remove identity realm confusion ([612253d](https://github.com/vriesdemichael/keycloak-operator/commit/612253d6ac90966e1e3d321d82302a8b62f3b3ec))
* fix tab text readability and all broken links ([603de35](https://github.com/vriesdemichael/keycloak-operator/commit/603de357bee74a3ec0037e172c12ddc8b2842575))
* fix YAML schema URLs in identity provider examples ([e7ba31d](https://github.com/vriesdemichael/keycloak-operator/commit/e7ba31d18780fbf8219100aaa1800bf360d88283))
* Implement robust cleanup system for integration tests ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* improve cross-references and navigation ([a2b4352](https://github.com/vriesdemichael/keycloak-operator/commit/a2b4352d397e66fd6cb3e7999ab179938e4f1a21))
* improve navigation and expand development documentation ([169a930](https://github.com/vriesdemichael/keycloak-operator/commit/169a93047479194efd3fc09329dd768dcf9a35c9))
* improve operator chart values documentation ([61e00a3](https://github.com/vriesdemichael/keycloak-operator/commit/61e00a39ab4818585d2dd15ad7b9fe90effbb6df))
* mark CRD-model schema alignment as completed ([e2124ab](https://github.com/vriesdemichael/keycloak-operator/commit/e2124ab92619d6d4a24edb63988ccda5a52e0980))
* mark final review complete - ready for PR ([5b859f0](https://github.com/vriesdemichael/keycloak-operator/commit/5b859f0c9d63948798ce942d99df31628d3ae4c0))
* mark Phase 8 complete - all automated tests passing ([61ce95e](https://github.com/vriesdemichael/keycloak-operator/commit/61ce95efea92917ccc46a68915a3337ef736139d)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* mark redirect URI validation bug as fixed in TODO ([2d783fa](https://github.com/vriesdemichael/keycloak-operator/commit/2d783fac49f7de9e4a1d591d40e4ac31f942edf5))
* move Home into Getting Started section ([bff4ba6](https://github.com/vriesdemichael/keycloak-operator/commit/bff4ba682fbc69862edae9d67631638268262b0f))
* remove authorizationSecretRef from observability and reference docs ([b466677](https://github.com/vriesdemichael/keycloak-operator/commit/b4666776ec7f2e449419d246250cc08b72e975d3))
* remove GitOps examples (too advanced for target audience) ([d5d4e8f](https://github.com/vriesdemichael/keycloak-operator/commit/d5d4e8fdc4e595778966956db6a694a34f2fc5a8))
* remove token system from architecture.md and faq.md ([12a2495](https://github.com/vriesdemichael/keycloak-operator/commit/12a2495369e93fe555174b6780a4917d1fde5085))
* remove tracking documents ([b1d10f4](https://github.com/vriesdemichael/keycloak-operator/commit/b1d10f49e5f3c9d6ac98ea1e867dfe7ec70cdcd6))
* removed mentions of the authorization token in the readme. ([a6d8287](https://github.com/vriesdemichael/keycloak-operator/commit/a6d828700a3e08755fa960baf78ffa18da1c0184))
* removed outdated todos ([3f7f227](https://github.com/vriesdemichael/keycloak-operator/commit/3f7f2276767642986318633df1d9ae332daf98a5))
* rename ADR-054 to reflect cluster RBAC requirement ([de8fb84](https://github.com/vriesdemichael/keycloak-operator/commit/de8fb849ff538d075b07561c8ec21c911ea1234b))
* reorganize documentation structure and simplify README ([e0b7bef](https://github.com/vriesdemichael/keycloak-operator/commit/e0b7befc77a9f201965d39f88ef03041c4d5bd22))
* reorganize navigation structure to reduce tab overflow ([e1507a9](https://github.com/vriesdemichael/keycloak-operator/commit/e1507a96a270a674151acebe502405cb994bce9a))
* replace ASCII art diagrams with Mermaid charts ([d398c4e](https://github.com/vriesdemichael/keycloak-operator/commit/d398c4e9965a1e93a995aa45a09319a92e00f9ac))
* replace landing page and quickstart with current architecture ([4c33aa6](https://github.com/vriesdemichael/keycloak-operator/commit/4c33aa69237d21ae8daa2fc7a726dbbdd351a08a))
* replace tags plugin with manual categorization for decision records ([1c96007](https://github.com/vriesdemichael/keycloak-operator/commit/1c960078a54bdbd9208c0e2fba88cdfd1ad4edb9))
* review and improve decision records ([0c0ea52](https://github.com/vriesdemichael/keycloak-operator/commit/0c0ea52032b0cb4b262d41c65a3c9931a0a3fe4f))
* rewrite charts README to remove token system ([b1ffdc6](https://github.com/vriesdemichael/keycloak-operator/commit/b1ffdc667c083e00c4921f2f6b8e88fcd8542c6b))
* rewrite end-to-end-setup guide sections 5-6 and 9.5 ([0a8f837](https://github.com/vriesdemichael/keycloak-operator/commit/0a8f83722554999d91d2cb2210d6a3529a0f77b6))
* rewrite security.md for namespace grant authorization model ([cfbf2c5](https://github.com/vriesdemichael/keycloak-operator/commit/cfbf2c56e49dd606e3c5675ef8a539f48dc24519))
* rewrite troubleshooting authorization section ([53b637b](https://github.com/vriesdemichael/keycloak-operator/commit/53b637b5ffad7897228f41e11f4e70ca41afd908))
* standardize examples with version compatibility and setup instructions ([98abafb](https://github.com/vriesdemichael/keycloak-operator/commit/98abafb9029d38c6b2b6a99749698267867c8363))
* **test:** improve factory fixture documentation ([b6db340](https://github.com/vriesdemichael/keycloak-operator/commit/b6db340fdbb2cbccab377f776d235af319400456))
* update charts README with token system and new chart references ([65caac0](https://github.com/vriesdemichael/keycloak-operator/commit/65caac08d47bb92ef28f0cc8de04a6d4f38de96a))
* update CI/CD badges to point to unified workflow ([4419899](https://github.com/vriesdemichael/keycloak-operator/commit/4419899d41bd4bb949f0d4c82d67d48334c6a08c))
* update end-to-end-setup.md to use namespace grants ([fe6cd73](https://github.com/vriesdemichael/keycloak-operator/commit/fe6cd73ccd3d41394eff35bebb027f0f61c8126e))
* update FAQ and end-to-end guide to remove token references ([5a583eb](https://github.com/vriesdemichael/keycloak-operator/commit/5a583ebaa238d81c84ac75184912752b2744b356))
* update helm chart READMEs and fix broken links ([dfb210d](https://github.com/vriesdemichael/keycloak-operator/commit/dfb210de7e222159830c5687e47e0e6d5eab354e))
* update manual-todos to mark CRD design improvements as complete ([80420e9](https://github.com/vriesdemichael/keycloak-operator/commit/80420e925823fc5db290ef4053091d007a110542))
* update Phase 1 tracking with review findings and deferred work ([921757b](https://github.com/vriesdemichael/keycloak-operator/commit/921757b796a7c0b87d01ad635d0ddc7f0ce26176))
* update phase 6B TODO to reflect production mode completion ([34b6b4d](https://github.com/vriesdemichael/keycloak-operator/commit/34b6b4d22c21dd5c85887e4482f21261582ed198))
* update README badges to reference unified CI/CD workflow ([03ba009](https://github.com/vriesdemichael/keycloak-operator/commit/03ba009eb0aac6e4db6ebdbc8f6315b0ccf0dd4a))
* update release process for branch protection and PR workflow ([#12](https://github.com/vriesdemichael/keycloak-operator/issues/12)) ([6508868](https://github.com/vriesdemichael/keycloak-operator/commit/6508868dbf3b245f598fa4f1253952ae01193947))
* update tracking document - Phase 1 complete ([5ade37b](https://github.com/vriesdemichael/keycloak-operator/commit/5ade37bbc5097d12f9acbcfdcc9fa4b1e5197fdc))
* update tracking document - Phase 4 complete ([e86c1b9](https://github.com/vriesdemichael/keycloak-operator/commit/e86c1b9fa810f6258be788315ae3834f0c849098))
* update tracking document with post-Phase-2 work ([4f68758](https://github.com/vriesdemichael/keycloak-operator/commit/4f68758ac2d955beb9463daf4dd0e433e75a4311))
* update tracking plan with completed Phase 3 tasks ([e3b0f1b](https://github.com/vriesdemichael/keycloak-operator/commit/e3b0f1b2a17d5641daa0871d23d036d6b1ddfc4a))


### CI/CD

* **operator:** refactor release workflow to build-once promote-on-release pattern ([f4464b1](https://github.com/vriesdemichael/keycloak-operator/commit/f4464b124b41e9d2da3b034d10560c89fda159a5))

## [0.4.3](https://github.com/vriesdemichael/keycloak-operator/compare/v0.4.2...v0.4.3) (2025-12-16)


### Bug Fixes

* **chart-operator:** update for operator v0.4.2 ([3e05ace](https://github.com/vriesdemichael/keycloak-operator/commit/3e05ace25ee4dad3555aa6f3e94487cbdd04c09a))


### Performance Improvements

* implement generation-based skip to avoid redundant reconciliations ([af0d4c6](https://github.com/vriesdemichael/keycloak-operator/commit/af0d4c63490122a5d4893f2cb2e5cf6d63fe3f6b)), closes [#184](https://github.com/vriesdemichael/keycloak-operator/issues/184)

## [0.4.2](https://github.com/vriesdemichael/keycloak-operator/compare/v0.4.1...v0.4.2) (2025-12-04)


### Bug Fixes

* **operator:** prevent event loop closed errors in httpx client cache ([83b8020](https://github.com/vriesdemichael/keycloak-operator/commit/83b80200c7d0df07058856e8ee99e979dba585a8))
* **operator:** update package metadata with correct author info ([96ba785](https://github.com/vriesdemichael/keycloak-operator/commit/96ba785332f12613446cb83e5525ade6cc966e80))


### Documentation

* removed mentions of the authorization token in the readme. ([a6d8287](https://github.com/vriesdemichael/keycloak-operator/commit/a6d828700a3e08755fa960baf78ffa18da1c0184))

## [0.4.1](https://github.com/vriesdemichael/keycloak-operator/compare/v0.4.0...v0.4.1) (2025-12-04)


### Code Refactoring

* **operator:** unify Dockerfile with multi-stage targets ([dd81347](https://github.com/vriesdemichael/keycloak-operator/commit/dd813478441800b2519e184e94bc249fa2a6289c))

## [0.4.0](https://github.com/vriesdemichael/keycloak-operator/compare/v0.3.9...v0.4.0) (2025-12-03)


### ⚠ BREAKING CHANGES

* **chart-client+chart-operator+chart-realm:** Helm chart distribution moved to OCI registry

### Features

* **chart-client+chart-operator+chart-realm:** migrate to OCI registry in GHCR ([dc4f59c](https://github.com/vriesdemichael/keycloak-operator/commit/dc4f59c8f9d66be04cd7be6ae685fc714a8aad97))
* **operator:** add build attestations for supply chain security ([85a46cc](https://github.com/vriesdemichael/keycloak-operator/commit/85a46cce26775bc13ed809623d4ac998ce6b0152))
* **operator:** add GitHub deployment environments to workflow ([94b6b9b](https://github.com/vriesdemichael/keycloak-operator/commit/94b6b9bd3531fda63cbe6c43c088994649321d9a))
* use SVG logo and update favicon ([a180ba2](https://github.com/vriesdemichael/keycloak-operator/commit/a180ba227d9295e9350b478ad47e83584e5da960))


### Bug Fixes

* Add clientAuthorizationGrants to realm test specs ([91e33ca](https://github.com/vriesdemichael/keycloak-operator/commit/91e33cab1b367ecc75e1f507af62f60bcfe2fde8))
* allow test tags in operator chart schema ([6740046](https://github.com/vriesdemichael/keycloak-operator/commit/6740046724b30ca0d694bc85a40212db826fe596))
* allow test-* tags in operator chart schema ([8450c8f](https://github.com/vriesdemichael/keycloak-operator/commit/8450c8fa9135190af5c272b641e09327de3f4b56))
* **chart-operator:** remove outdated authorization token instructions ([6f2c190](https://github.com/vriesdemichael/keycloak-operator/commit/6f2c1907af74134fc727e132e4a4ca40a5300130))
* combine coverage and convert to XML for Codecov ([ad10407](https://github.com/vriesdemichael/keycloak-operator/commit/ad10407ffe4b57e1ac35c958704cbb6b682d26f2))
* consolidate documentation workflows with mike ([cd31074](https://github.com/vriesdemichael/keycloak-operator/commit/cd31074e2d0c518bc05c8a50f65313a8eeb48ea3))
* **operator:** allow integration coverage failures during outage ([42ece4a](https://github.com/vriesdemichael/keycloak-operator/commit/42ece4ac55598db3969f5129056c4448a6504ca6))
* **operator:** database passwordSecret support and test fixes ([038fc18](https://github.com/vriesdemichael/keycloak-operator/commit/038fc18da190e8d99eb02222c89c59393129feee))
* **operator:** disable fail_ci_if_error for codecov uploads ([2e22069](https://github.com/vriesdemichael/keycloak-operator/commit/2e220690d61551e2abca83359eab33bf7990a14e))
* **operator:** enforce scope for release-triggering commits ([6c7e271](https://github.com/vriesdemichael/keycloak-operator/commit/6c7e27134917df7e1c53031d86991c2ce74b9a7f))
* **operator:** handle basic realm field updates in do_update method ([fab2804](https://github.com/vriesdemichael/keycloak-operator/commit/fab2804ad2e1b982f7e7009e11290f68fbaccf0b))
* **operator:** handle realm deletion gracefully in client cleanup ([45b25cd](https://github.com/vriesdemichael/keycloak-operator/commit/45b25cda8c945c56daddbc2538a1c0133713324f))
* **operator:** resolve JSON serialization and test timing issues ([fb29bcb](https://github.com/vriesdemichael/keycloak-operator/commit/fb29bcbd1859e0dbcb2d8ded643a38ecb52c5cb5))
* **operator:** run quality checks and tests for code OR chart changes ([a9e8ad2](https://github.com/vriesdemichael/keycloak-operator/commit/a9e8ad27ff84b7b704fdbbe9c8c353057078070c))
* **operator:** temporarily allow codecov failures during global outage ([baa2f58](https://github.com/vriesdemichael/keycloak-operator/commit/baa2f58e714c8e4b2538233fe84ba6c550926401))
* **operator:** update all-complete job to reference new chart jobs ([be5dde3](https://github.com/vriesdemichael/keycloak-operator/commit/be5dde3d28b33a2b78ff713eb5f9ce03df6d628e))
* **operator:** use asyncio.to_thread for webhook K8s API calls ([d635da9](https://github.com/vriesdemichael/keycloak-operator/commit/d635da9ae8a78928baf613b35686256849e78b80))
* **operator:** use correct camelCase field names in realm update handler ([91636eb](https://github.com/vriesdemichael/keycloak-operator/commit/91636ebdb1afef442a5eb6e9bf46db69585454b8))
* **operator:** use legacy codecov endpoint only as fallback ([c76ff4a](https://github.com/vriesdemichael/keycloak-operator/commit/c76ff4a0c120329c41266366283193cf3b82fa8e))
* **operator:** use legacy codecov upload as fallback ([1cb9293](https://github.com/vriesdemichael/keycloak-operator/commit/1cb929309a914b58197e0d03e4fe01801826edd5))
* restore correct test image tag for coverage collection ([6cb1675](https://github.com/vriesdemichael/keycloak-operator/commit/6cb16758ce97572f7b98396ea3b6960fb61e122f))
* restore integration test coverage collection ([4f35596](https://github.com/vriesdemichael/keycloak-operator/commit/4f355969c0f95f0445d6cceaf9fb7b260e574723))
* simplify coverage - always on, fail hard, let codecov combine ([d953b29](https://github.com/vriesdemichael/keycloak-operator/commit/d953b291e32e8bdc66485fc8ebe2e5e947846ce7))
* update security scans to use test-coverage tag ([e65247b](https://github.com/vriesdemichael/keycloak-operator/commit/e65247be81106c06ece373ea6c418735cade9680))
* upload raw coverage files instead of converting to XML ([64c98c7](https://github.com/vriesdemichael/keycloak-operator/commit/64c98c7b6db0365b820fb3fcfeb790e1364ac0e3))
* use correct operator image tag in integration tests ([8b3d7e8](https://github.com/vriesdemichael/keycloak-operator/commit/8b3d7e82a84454d4f5cd646788e150c745887790))
* use Dockerfile.test for coverage-instrumented image ([82f0373](https://github.com/vriesdemichael/keycloak-operator/commit/82f037384444e161cbd5013cd798bf8fe7ea4234))
* use test-coverage tag for operator image ([2f0cce4](https://github.com/vriesdemichael/keycloak-operator/commit/2f0cce4076eb307218cd0e9cddb91bdbffa70bb0))


### Code Refactoring

* address PR review comments ([499a0c9](https://github.com/vriesdemichael/keycloak-operator/commit/499a0c93ff4f4a5074cdb5981b54a0f880a69044))
* simplify CI/CD workflow conditionals ([45fad5c](https://github.com/vriesdemichael/keycloak-operator/commit/45fad5c6467f6f99aef82a543ad55af4b4a42931))
* split CI/CD workflow into composite actions ([34da80d](https://github.com/vriesdemichael/keycloak-operator/commit/34da80d4cd5aaa51e07dc4fa998f86e0faccb45f))
* split CI/CD workflow into composite actions ([6a36cb1](https://github.com/vriesdemichael/keycloak-operator/commit/6a36cb1b9fb1f19869b2cfc7ade85f9fc4a6fab7))
* split CI/CD workflow into composite actions + add custom logo ([610417d](https://github.com/vriesdemichael/keycloak-operator/commit/610417d980cfdaa85ed384a757b8bd0d7b587479))


### Documentation

* add CI/CD and documentation issues task list ([1d09817](https://github.com/vriesdemichael/keycloak-operator/commit/1d0981719319e67cb6872b4408f42e83014edd2e))
* add custom logo and favicon ([34da80d](https://github.com/vriesdemichael/keycloak-operator/commit/34da80d4cd5aaa51e07dc4fa998f86e0faccb45f))
* add custom logo and favicon ([6a36cb1](https://github.com/vriesdemichael/keycloak-operator/commit/6a36cb1b9fb1f19869b2cfc7ade85f9fc4a6fab7))
* add introductory text to FAQ page ([b3e4116](https://github.com/vriesdemichael/keycloak-operator/commit/b3e4116a9853e9eacf3880db4a1a9c136f69c581))
* improve operator chart values documentation ([61e00a3](https://github.com/vriesdemichael/keycloak-operator/commit/61e00a39ab4818585d2dd15ad7b9fe90effbb6df))
* replace ASCII art diagrams with Mermaid charts ([d398c4e](https://github.com/vriesdemichael/keycloak-operator/commit/d398c4e9965a1e93a995aa45a09319a92e00f9ac))

## [0.3.9](https://github.com/vriesdemichael/keycloak-operator/compare/v0.3.8...v0.3.9) (2025-11-18)


### Bug Fixes

* **operator:** enable auto-merge for grouped release PRs ([7c2419a](https://github.com/vriesdemichael/keycloak-operator/commit/7c2419a95aca55264400d1d0252e2af52fec0501))
* **operator:** group release-please PRs to prevent manifest conflicts ([529c990](https://github.com/vriesdemichael/keycloak-operator/commit/529c99037235bd63b315ae3673a1c1506dcccdca))


### Code Refactoring

* **operator:** use manifest diff for major version detection ([3a161be](https://github.com/vriesdemichael/keycloak-operator/commit/3a161beddd0f086f03f5db0e637aaf0d724f21a2))

## [0.3.8](https://github.com/vriesdemichael/keycloak-operator/compare/v0.3.7...v0.3.8) (2025-11-18)


### Documentation

* update CI/CD badges to point to unified workflow ([4419899](https://github.com/vriesdemichael/keycloak-operator/commit/4419899d41bd4bb949f0d4c82d67d48334c6a08c))

## [0.3.7](https://github.com/vriesdemichael/keycloak-operator/compare/v0.3.6...v0.3.7) (2025-11-18)


### Bug Fixes

* **operator:** detect release commits merged by users, not just bots ([50a21e9](https://github.com/vriesdemichael/keycloak-operator/commit/50a21e9c619faefe47e9d7a7b688b3d883518120))
* **operator:** load test-coverage image tag for integration tests ([af358ba](https://github.com/vriesdemichael/keycloak-operator/commit/af358ba923a7e9625920de99abeac52d696a49e2))
* **operator:** make integration coverage non-fatal if not generated ([02022c7](https://github.com/vriesdemichael/keycloak-operator/commit/02022c7a728db530be61accf4961aa1ac70b1f53))
* **operator:** properly fix coverage collection and uv group isolation ([867df0a](https://github.com/vriesdemichael/keycloak-operator/commit/867df0ae0140573ccb9f0788b5308ad231bd5d20))
* **operator:** restore --group flags and upload integration coverage files separately ([b067c30](https://github.com/vriesdemichael/keycloak-operator/commit/b067c304459bd556de67f3bc292dab385a5fdac4))
* **operator:** revert uv run --group flag, keep coverage upload fix ([225cef3](https://github.com/vriesdemichael/keycloak-operator/commit/225cef3794076367e1ab25b659197460c25bd218))


### Code Refactoring

* **operator:** remove redundant uv sync steps when using --group ([c9aea4f](https://github.com/vriesdemichael/keycloak-operator/commit/c9aea4fa42335ae65efcd0a4874341cb9fcfbd2f))

## [0.3.6](https://github.com/vriesdemichael/keycloak-operator/compare/v0.3.5...v0.3.6) (2025-11-17)


### Bug Fixes

* restore coverage collection and upload for tests ([0ae218d](https://github.com/vriesdemichael/keycloak-operator/commit/0ae218dc926c3c5bb834c3cf9cedf952b2106c45))

## [0.3.5](https://github.com/vriesdemichael/keycloak-operator/compare/v0.3.4...v0.3.5) (2025-11-17)


### Bug Fixes

* use proper conventional commit scope for chart updates ([70cf9c0](https://github.com/vriesdemichael/keycloak-operator/commit/70cf9c043040b3405c48ccc5b4b92f23e368c30f))

## [0.3.4](https://github.com/vriesdemichael/keycloak-operator/compare/v0.3.3...v0.3.4) (2025-11-17)


### Bug Fixes

* **chart-operator:** update for operator v0.3.3 compatibility ([584c98f](https://github.com/vriesdemichael/keycloak-operator/commit/584c98f080352b39eab75c1c18e5faba838af9e9))

## [0.3.3](https://github.com/vriesdemichael/keycloak-operator/compare/v0.3.2...v0.3.3) (2025-11-17)


### Bug Fixes

* add yq installation to release docs job ([6e53a92](https://github.com/vriesdemichael/keycloak-operator/commit/6e53a92a6ca26979eef60b0d3842d6e754bc9f27))
* address Copilot review comments on unified CI/CD ([9cb6372](https://github.com/vriesdemichael/keycloak-operator/commit/9cb637234011f17b94db9547d590ed76459adbc3))
* use correct yq sha256 checksum for v4.44.3 ([f4c7dc0](https://github.com/vriesdemichael/keycloak-operator/commit/f4c7dc0683a368ccb8bb2df25b087776b3d9d5df))


### Code Refactoring

* **ci:** unify CI/CD pipeline into single workflow ([ea1b748](https://github.com/vriesdemichael/keycloak-operator/commit/ea1b74895c277ec70b7f2e35d15a5cdcdc0729d9))

## [0.3.2](https://github.com/vriesdemichael/keycloak-operator/compare/v0.3.1...v0.3.2) (2025-11-17)


### Bug Fixes

* resolve all three workflow failures ([9c6b5ed](https://github.com/vriesdemichael/keycloak-operator/commit/9c6b5edb50995ee1ccce91f5d9b1d690428f78e5))

## [0.3.1](https://github.com/vriesdemichael/keycloak-operator/compare/v0.3.0...v0.3.1) (2025-11-17)


### Bug Fixes

* use correct image tag in promote workflow SBOM/Trivy steps ([65e5984](https://github.com/vriesdemichael/keycloak-operator/commit/65e59847f23d3a364fdabd4f6e54361d9c72ccd0))

## [0.3.0](https://github.com/vriesdemichael/keycloak-operator/compare/v0.2.15...v0.3.0) (2025-11-17)


### ⚠ BREAKING CHANGES

* **operator:** IDP secrets must use configSecrets field, plaintext forbidden
* **webhooks:** Admission webhooks now require cert-manager to be installed
* **chart-client+chart-realm:** Removed token-based authorization from all charts

### Features

* **chart-client+chart-realm:** update charts for namespace grant authorization ([add6af9](https://github.com/vriesdemichael/keycloak-operator/commit/add6af903c2ff887cd44c5608ceb1a1a6436f23e)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* implement admission webhooks for resource validation ([061acae](https://github.com/vriesdemichael/keycloak-operator/commit/061acae11b1af0d5547177c98264ac6ffbaa8f27))
* **operator:** add comprehensive test coverage infrastructure ([0405cfb](https://github.com/vriesdemichael/keycloak-operator/commit/0405cfbb2b65993696cc820e62ba32be2793788a)), closes [#110](https://github.com/vriesdemichael/keycloak-operator/issues/110)
* **operator:** add coverage retrieval function (reformatted) ([73ff054](https://github.com/vriesdemichael/keycloak-operator/commit/73ff054f196b3cd076bdc11e16ac2e140e7c5594))
* **operator:** centralize configuration with pydantic-settings ([dd6078b](https://github.com/vriesdemichael/keycloak-operator/commit/dd6078bf9256e722188343987009f9a26b8ac3ee)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* **operator:** complete integration coverage collection ([1d4e5a4](https://github.com/vriesdemichael/keycloak-operator/commit/1d4e5a4f4fd369efeb81032539c6e938c9015635))
* **operator:** fix pydantic-settings environment variable configuration ([20d00b3](https://github.com/vriesdemichael/keycloak-operator/commit/20d00b3ff8a242e08706426ed7bc7a48e3eb2e6e)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* **operator:** implement integration test coverage collection via SIGUSR1 ([259e587](https://github.com/vriesdemichael/keycloak-operator/commit/259e587ab08a5388702e1871d62c923434796c35)), closes [#111](https://github.com/vriesdemichael/keycloak-operator/issues/111)
* **operator:** require secret refs for IDP secrets ([bf377fb](https://github.com/vriesdemichael/keycloak-operator/commit/bf377fb76b504f2c2160cd08c41ff60071505e57))
* **webhooks:** switch to cert-manager for webhook TLS certificates ([7195217](https://github.com/vriesdemichael/keycloak-operator/commit/7195217d15903d9c2c738999ce4c25acf1daaa88))


### Bug Fixes

* add certbuilder dependency and fix webhook RBAC permissions ([71df4ee](https://github.com/vriesdemichael/keycloak-operator/commit/71df4eebe6573b84eea6fab15fd9f9666806b3d5))
* add clientAuthorizationGrants to finalizer tests ([954d850](https://github.com/vriesdemichael/keycloak-operator/commit/954d8505d79fc2ebe7a80f6ffab319f8f5d46a1b)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* add clientAuthorizationGrants to Helm client test ([5ddf722](https://github.com/vriesdemichael/keycloak-operator/commit/5ddf7222b81f90ddb8c611f5f3e0d4e00e2aa620)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* add get permission for CRDs in ClusterRole ([3455cd6](https://github.com/vriesdemichael/keycloak-operator/commit/3455cd6eef7148d506f33e13add95ea6927759de))
* add missing RBAC permissions and correct readiness probe port ([2300f2a](https://github.com/vriesdemichael/keycloak-operator/commit/2300f2a85d6f007e2f1d6ca9b12ae80745adc95e))
* add patch permission for pods in namespace Role ([43d7fdc](https://github.com/vriesdemichael/keycloak-operator/commit/43d7fdc6f55475da9a6ba5ce42b0987bdb6d6557))
* change operator component name to remove space ([e994ac2](https://github.com/vriesdemichael/keycloak-operator/commit/e994ac2a7d9fce824be86d0ade475f24aa17f6cc))
* **chart-operator:** remove admission token configuration from values ([302a27d](https://github.com/vriesdemichael/keycloak-operator/commit/302a27d59db56b064a7888ce1ee4c76f377f77e0))
* configure webhook server with service DNS hostname ([d626c4b](https://github.com/vriesdemichael/keycloak-operator/commit/d626c4bddee90bd1fe3ab72c05c2b6d21552ece9))
* convert snake_case to camelCase in StatusWrapper ([4ad528c](https://github.com/vriesdemichael/keycloak-operator/commit/4ad528c44a76664324b47c26b0230c7b480bef42)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* create coverage directory in container and fix collection workflow ([3b74ee6](https://github.com/vriesdemichael/keycloak-operator/commit/3b74ee6f343bfb57ef4d8e3e70169ec4ffd8925e))
* disable webhook auto-management and default to false ([0c59b83](https://github.com/vriesdemichael/keycloak-operator/commit/0c59b834d2852d010a6ca97152eb4b2e41e0353b))
* disable webhooks by default to avoid bootstrap issues ([85470ed](https://github.com/vriesdemichael/keycloak-operator/commit/85470ed5f1a6b9a45027fd050622d82042e92b43))
* import all webhook modules to register handlers ([12b9bbd](https://github.com/vriesdemichael/keycloak-operator/commit/12b9bbddb038caffa83f855eccfa59519b14621a))
* make coverage scripts executable and share unit coverage with integration tests ([17615ff](https://github.com/vriesdemichael/keycloak-operator/commit/17615ff3b997c7c86e41d5ca30221993f3d7fe95))
* only retrieve coverage on last worker exit ([236636a](https://github.com/vriesdemichael/keycloak-operator/commit/236636aa843ce6cd73cfe40191f605f3fc31e611))
* **operator:** use coverage run in CMD for proper instrumentation ([1665eaa](https://github.com/vriesdemichael/keycloak-operator/commit/1665eaaef1f8bd01616a278edf99a232d6bd7a53))
* preserve binary data when retrieving coverage files ([1cf7252](https://github.com/vriesdemichael/keycloak-operator/commit/1cf7252de0b3db30d217e011ff667fff0da18b6c))
* prevent premature operator cleanup in pytest-xdist workers ([8031895](https://github.com/vriesdemichael/keycloak-operator/commit/8031895e2b2347378cbb376555136ee7e395ff49))
* prevent premature operator cleanup in pytest-xdist workers ([2a7f4a1](https://github.com/vriesdemichael/keycloak-operator/commit/2a7f4a19892c44ce8a24dd63e2136f6645bad06b))
* proper webhook bootstrap with readiness probe and ArgoCD sync waves ([c8dfc52](https://github.com/vriesdemichael/keycloak-operator/commit/c8dfc5200c02cf550e8857d6e44583b50fb11895))
* refactor pages workflow to fix versioning and artifact issues ([e1d6da1](https://github.com/vriesdemichael/keycloak-operator/commit/e1d6da11bda072ead0d0eff66f87def24905ad0c)), closes [#114](https://github.com/vriesdemichael/keycloak-operator/issues/114)
* remove authorizationSecretRef from Helm values schemas ([f87585b](https://github.com/vriesdemichael/keycloak-operator/commit/f87585b10b7446822636a909e83f1c45235fa62d)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove await from synchronous API call in capacity check ([2908db5](https://github.com/vriesdemichael/keycloak-operator/commit/2908db581fa9a39f590c67b1a3ef47f27ec978d0)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove duplicate coverage retrieval code ([691d70b](https://github.com/vriesdemichael/keycloak-operator/commit/691d70bd3cc8a9c3e1e22b4ac08db229e6b7a41d))
* remove obsolete authorization token references from charts ([880fc98](https://github.com/vriesdemichael/keycloak-operator/commit/880fc98637ff0e0e4c9471fd47162fc1d790b194)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove obsolete authorizationSecretName status field ([9952eae](https://github.com/vriesdemichael/keycloak-operator/commit/9952eaef7c155f3013b9a1cc2d7a0c66c7cf4827)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove tests for deleted periodic_leadership_check function ([1ffcba0](https://github.com/vriesdemichael/keycloak-operator/commit/1ffcba0479decb4916a65262f58a46f84ab28ddd))
* remove webhook config template, let Kopf manage it ([57f2e3e](https://github.com/vriesdemichael/keycloak-operator/commit/57f2e3e82a68789d49b73fea4c8cac4e409133c2))
* Removed await, added explicit k8s_client parameter. ([2908db5](https://github.com/vriesdemichael/keycloak-operator/commit/2908db581fa9a39f590c67b1a3ef47f27ec978d0))
* replace old keycloak.mdvr.nl API group with vriesdemichael.github.io ([da644e0](https://github.com/vriesdemichael/keycloak-operator/commit/da644e09d335803e59f61a2f46f463ebfab0e50b))
* send SIGTERM instead of deleting pod for coverage ([d3fa7eb](https://github.com/vriesdemichael/keycloak-operator/commit/d3fa7eba9a9e4aa51c4d4fa04e55e2c21e49213f))
* streamline coverage workflow - remove merging, retrieve integration coverage immediately ([8fb0eb4](https://github.com/vriesdemichael/keycloak-operator/commit/8fb0eb4c9478b9996decfca81851492e2d6d21df))
* update integration tests for grant list authorization ([9f2e2a6](https://github.com/vriesdemichael/keycloak-operator/commit/9f2e2a663ebd3d8c69ced03079b8405357dc86d1)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* update tests and Helm schema for grant list authorization ([0fe6fca](https://github.com/vriesdemichael/keycloak-operator/commit/0fe6fcae8c638595a117b2093d869ecb85b37f47)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* use httpGet probe instead of exec with wget ([a6135d6](https://github.com/vriesdemichael/keycloak-operator/commit/a6135d6273e3a2377fd4b23e89342f00a2fb7acb))
* use sync client for kubernetes stream() calls ([4a7b524](https://github.com/vriesdemichael/keycloak-operator/commit/4a7b52426b9f68e1984bd6b63eb57a081536bea7))


### Code Refactoring

* use kopf[dev] extra instead of manual certbuilder ([bf44078](https://github.com/vriesdemichael/keycloak-operator/commit/bf44078d955d50613cc8d1c17605babecb08a3c0))


### Documentation

* add admission webhook documentation and decision record ([396de85](https://github.com/vriesdemichael/keycloak-operator/commit/396de85863b5731e6e55ae2ac11ad21fbc45eeb1))
* add ADR-064 rejecting force-delete feature ([6df1d50](https://github.com/vriesdemichael/keycloak-operator/commit/6df1d505d090ff22199a125bf30a760c005b402a))
* add Decision Records as separate tab with tag filtering ([6931bc3](https://github.com/vriesdemichael/keycloak-operator/commit/6931bc3b1989768b98a078161946a2115ed01d41))
* add deprecation notices to token-based documentation ([0dc075f](https://github.com/vriesdemichael/keycloak-operator/commit/0dc075f575722619dab823a11aacb222db39a067))
* add Keycloak brand colors and improved styling ([fc7a0a5](https://github.com/vriesdemichael/keycloak-operator/commit/fc7a0a50f0993dad3f6b1e04791fc9c36e3d4b1f))
* add Mermaid diagram support and hide home TOC ([b1f2e74](https://github.com/vriesdemichael/keycloak-operator/commit/b1f2e74d7f7a6cff2d8de4b8b29d146c5160b21c))
* bulk cleanup of authorizationSecretRef in chart READMEs ([7010d85](https://github.com/vriesdemichael/keycloak-operator/commit/7010d855084409af6a36e3d17fae465070afd6b9))
* bulk cleanup remaining authorizationSecretRef references ([61e66a3](https://github.com/vriesdemichael/keycloak-operator/commit/61e66a3321be25ed370702df669f7bcd5299fa27))
* **chart-operator:** remove all admission token documentation ([528ff2e](https://github.com/vriesdemichael/keycloak-operator/commit/528ff2e42b7f9f7925215c8ca30291142aedf539))
* clarify namespace scope requires cluster-wide RBAC ([ea563db](https://github.com/vriesdemichael/keycloak-operator/commit/ea563db39f1228beb5cd5347923f2988bda88fc7))
* clean authorizationSecretRef from CRD reference docs ([e416d90](https://github.com/vriesdemichael/keycloak-operator/commit/e416d902e9b5cfed1a27522dfc3d4831d23b0030))
* enhance dark mode styling with better contrast ([b905878](https://github.com/vriesdemichael/keycloak-operator/commit/b9058784419cc9f9248eddbf9ef0537aed123cf3))
* final cleanup of remaining token references ([10f83eb](https://github.com/vriesdemichael/keycloak-operator/commit/10f83eb6fd7883b24c27e7d114c017f5e6284992))
* final tracking update - 36/36 tests passing ([8462747](https://github.com/vriesdemichael/keycloak-operator/commit/8462747b9610497387e972a3c13def51ef843f21)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* fix ASCII diagram spacing and automate decision index ([2ef4cec](https://github.com/vriesdemichael/keycloak-operator/commit/2ef4cecf0bb78f5da3cb68b481c15255f71baa68))
* fix broken anchor links and ADR index page ([34825a9](https://github.com/vriesdemichael/keycloak-operator/commit/34825a9473ab7e7341fbe73f3aff14abb3b284e3))
* fix deployment flow and remove identity realm confusion ([612253d](https://github.com/vriesdemichael/keycloak-operator/commit/612253d6ac90966e1e3d321d82302a8b62f3b3ec))
* fix tab text readability and all broken links ([603de35](https://github.com/vriesdemichael/keycloak-operator/commit/603de357bee74a3ec0037e172c12ddc8b2842575))
* mark Phase 8 complete - all automated tests passing ([61ce95e](https://github.com/vriesdemichael/keycloak-operator/commit/61ce95efea92917ccc46a68915a3337ef736139d)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* move Home into Getting Started section ([bff4ba6](https://github.com/vriesdemichael/keycloak-operator/commit/bff4ba682fbc69862edae9d67631638268262b0f))
* remove authorizationSecretRef from observability and reference docs ([b466677](https://github.com/vriesdemichael/keycloak-operator/commit/b4666776ec7f2e449419d246250cc08b72e975d3))
* remove token system from architecture.md and faq.md ([12a2495](https://github.com/vriesdemichael/keycloak-operator/commit/12a2495369e93fe555174b6780a4917d1fde5085))
* rename ADR-054 to reflect cluster RBAC requirement ([de8fb84](https://github.com/vriesdemichael/keycloak-operator/commit/de8fb849ff538d075b07561c8ec21c911ea1234b))
* reorganize navigation structure to reduce tab overflow ([e1507a9](https://github.com/vriesdemichael/keycloak-operator/commit/e1507a96a270a674151acebe502405cb994bce9a))
* replace landing page and quickstart with current architecture ([4c33aa6](https://github.com/vriesdemichael/keycloak-operator/commit/4c33aa69237d21ae8daa2fc7a726dbbdd351a08a))
* replace tags plugin with manual categorization for decision records ([1c96007](https://github.com/vriesdemichael/keycloak-operator/commit/1c960078a54bdbd9208c0e2fba88cdfd1ad4edb9))
* rewrite charts README to remove token system ([b1ffdc6](https://github.com/vriesdemichael/keycloak-operator/commit/b1ffdc667c083e00c4921f2f6b8e88fcd8542c6b))
* rewrite end-to-end-setup guide sections 5-6 and 9.5 ([0a8f837](https://github.com/vriesdemichael/keycloak-operator/commit/0a8f83722554999d91d2cb2210d6a3529a0f77b6))
* rewrite security.md for namespace grant authorization model ([cfbf2c5](https://github.com/vriesdemichael/keycloak-operator/commit/cfbf2c56e49dd606e3c5675ef8a539f48dc24519))
* rewrite troubleshooting authorization section ([53b637b](https://github.com/vriesdemichael/keycloak-operator/commit/53b637b5ffad7897228f41e11f4e70ca41afd908))
* update end-to-end-setup.md to use namespace grants ([fe6cd73](https://github.com/vriesdemichael/keycloak-operator/commit/fe6cd73ccd3d41394eff35bebb027f0f61c8126e))
* update FAQ and end-to-end guide to remove token references ([5a583eb](https://github.com/vriesdemichael/keycloak-operator/commit/5a583ebaa238d81c84ac75184912752b2744b356))
* update helm chart READMEs and fix broken links ([dfb210d](https://github.com/vriesdemichael/keycloak-operator/commit/dfb210de7e222159830c5687e47e0e6d5eab354e))

## [0.2.15](https://github.com/vriesdemichael/keycloak-operator/compare/v0.2.14...v0.2.15) (2025-11-01)


### Features

* update release-please configuration and add auto-rebase workflow ([92981a7](https://github.com/vriesdemichael/keycloak-operator/commit/92981a7525a14f8ae7cd97d4228e0547b8c3d09e))

## [0.2.14](https://github.com/vriesdemichael/keycloak-operator/compare/v0.2.13...v0.2.14) (2025-11-01)


### Features

* publish JSON schemas for CRDs to enable IDE autocomplete ([72485af](https://github.com/vriesdemichael/keycloak-operator/commit/72485afb83822db7e427e1b876fd2700a91489a5))


### Bug Fixes

* address review comments ([14007df](https://github.com/vriesdemichael/keycloak-operator/commit/14007df5fb013d9d43fdbe0b9732c447baca43f5))


### Documentation

* change default merge strategy to rebase ([442c6b9](https://github.com/vriesdemichael/keycloak-operator/commit/442c6b9787787a597010405e822ac468d2b17d66))

## [0.2.13](https://github.com/vriesdemichael/keycloak-operator/compare/v0.2.12...v0.2.13) (2025-11-01)


### Features

* add drift detection foundation (Phase 1-3) ([80cf043](https://github.com/vriesdemichael/keycloak-operator/commit/80cf0438ef7b0e7568fa9d033e15be305f24ba55))
* add keycloak_admin_client fixture for test isolation ([ea46f21](https://github.com/vriesdemichael/keycloak-operator/commit/ea46f21f8029643e4a31584830793b64f9c8402b))
* implement orphan remediation (Phase 5) ([d225065](https://github.com/vriesdemichael/keycloak-operator/commit/d2250654f217dece764edabf4e9a17d8909a125e))


### Bug Fixes

* add missing common.sh and config.sh scripts, update documentation ([59a644f](https://github.com/vriesdemichael/keycloak-operator/commit/59a644f580ec57eb8f297789949fe0105a7c8bc6))
* address Copilot review comments (resolved conflicts) ([76f6256](https://github.com/vriesdemichael/keycloak-operator/commit/76f6256cccb554ec418fd9195b9de72fbeaf3ad4))
* address Copilot review comments for integration tests ([fc09ef6](https://github.com/vriesdemichael/keycloak-operator/commit/fc09ef6d2c709d2f4b602e6bad3a3e6545b38b32))
* address PR review comments ([568d934](https://github.com/vriesdemichael/keycloak-operator/commit/568d9342dbbb582ae6c3544656de290735298b00))
* **ci:** use PAT for release-please to trigger CI workflows ([4091bed](https://github.com/vriesdemichael/keycloak-operator/commit/4091bed6c30d0f37bc2377b2ff5444506c8aa1c7))
* clear operator instance ID cache between unit tests ([49d1db7](https://github.com/vriesdemichael/keycloak-operator/commit/49d1db7b1dcdbbb6898ae0110379210af33b23ac))
* correct client_cr fixture schema for drift detection tests ([fba3c5d](https://github.com/vriesdemichael/keycloak-operator/commit/fba3c5d243251d02e202e06d3c682f20bb7fcf70))
* correct fixture name in drift detection integration tests ([4694b16](https://github.com/vriesdemichael/keycloak-operator/commit/4694b16e62308399e15125c1cf580dfc9ae6b1f0))
* drift detection tests auth token namespace ([763ebd1](https://github.com/vriesdemichael/keycloak-operator/commit/763ebd1b0d451b085a9f9877f429e73d3694b358))
* enable mandatory type checking and add Helm linting to pre-commit ([97dc9d7](https://github.com/vriesdemichael/keycloak-operator/commit/97dc9d7062695a9e3999c5554d774ac9c79e6c3d))
* GitHub Actions release-please workflow JSON parsing error ([60081f4](https://github.com/vriesdemichael/keycloak-operator/commit/60081f4f5ea954892fc0f87db3b516d26250a042))
* make realm_cr and client_cr async fixtures ([3d46d6f](https://github.com/vriesdemichael/keycloak-operator/commit/3d46d6fcc22837130b4ee26b2bf4cc100f2c3ed3))
* **tests:** fix all 7 drift detection integration tests ([fd5e76f](https://github.com/vriesdemichael/keycloak-operator/commit/fd5e76f4dab5294372d06205b4a4eb12cf3d35a8))
* use correct operator namespace and shared_operator fixture in drift tests ([581a2db](https://github.com/vriesdemichael/keycloak-operator/commit/581a2dbb881b3f0679ef83cfcad1e5f7c365c2c0))
* use shared_operator namespace directly in drift tests ([e70d3d3](https://github.com/vriesdemichael/keycloak-operator/commit/e70d3d30e06daaf6271237000578ae2424d3ce28))


### Code Refactoring

* convert drift tests to function-based structure ([f576d14](https://github.com/vriesdemichael/keycloak-operator/commit/f576d143db4d048a6e0c3f53c32a5b75922e52be))
* **test:** add fixture recommendation helper function ([bab3bfd](https://github.com/vriesdemichael/keycloak-operator/commit/bab3bfdad3e4320c4b9f4b7e12ac8ee77812d3c0))
* **test:** add keycloak_ready composite fixture with Pydantic model ([f6a0878](https://github.com/vriesdemichael/keycloak-operator/commit/f6a087895b40496a19daf9c6bf070dca3344df2d))
* **test:** add type safety with Pydantic models and prefix internal fixtures ([c6cc015](https://github.com/vriesdemichael/keycloak-operator/commit/c6cc01589345ba3fd5a2f482249d449dfe1312f8))
* **test:** consolidate token fixtures and add CR factory functions ([0de7519](https://github.com/vriesdemichael/keycloak-operator/commit/0de75197748dc8e1cef8fcdbeaf59e2a25fbbfae))


### Documentation

* add comprehensive drift detection documentation (Phase 6) ([c09439d](https://github.com/vriesdemichael/keycloak-operator/commit/c09439d39f7e2147a25bb0a9956e987ba6350835))
* add proper procedure for resolving PR review threads ([c4e5735](https://github.com/vriesdemichael/keycloak-operator/commit/c4e57354d0ca66b46743af860cf13f58afeeec63))
* **test:** improve factory fixture documentation ([b6db340](https://github.com/vriesdemichael/keycloak-operator/commit/b6db340fdbb2cbccab377f776d235af319400456))

## [0.2.12](https://github.com/vriesdemichael/keycloak-operator/compare/v0.2.11...v0.2.12) (2025-10-28)


### Code Refactoring

* clean up Makefile and add cluster reuse workflow ([#59](https://github.com/vriesdemichael/keycloak-operator/issues/59)) ([be3bcd4](https://github.com/vriesdemichael/keycloak-operator/commit/be3bcd4ab1f09413fc23da36aa79f5e00c9df91a))

## [Unreleased]

### Features

* **drift-detection:** Add comprehensive drift detection and auto-remediation ([#43](https://github.com/vriesdemichael/keycloak-operator/issues/43))
  - Ownership tracking via Keycloak resource attributes
  - Periodic background scans for orphaned resources (created by operator, CR deleted)
  - Detection of unmanaged resources (not created by any operator)
  - Configurable auto-remediation with 24h minimum age safety check
  - Multi-operator support via unique instance IDs
  - Prometheus metrics for monitoring drift and remediation
  - Comprehensive documentation in `docs/drift-detection.md`

* **rate-limiting:** Implement comprehensive two-level rate limiting for Keycloak API calls
  - Global rate limiter (50 req/s default) protects Keycloak from total overload
  - Per-namespace rate limiter (5 req/s default) ensures fair access across teams
  - Prevents API flooding on operator restart via jitter (0-5s random delay)
  - Protects against DDoS via spam creation of thousands of realms/clients
  - Addresses issue #31

* **async:** Complete async/await conversion of Keycloak Admin Client
  - Migrated from `requests` to `aiohttp` for async HTTP operations
  - All 44 admin client methods converted to async
  - All reconcilers updated to use async admin client
  - All handlers updated with jitter and rate limiter integration

* **metrics:** Add Prometheus metrics for drift detection
  - `keycloak_operator_orphaned_resources` - Orphaned resource count
  - `keycloak_operator_config_drift` - Configuration drift count
  - `keycloak_unmanaged_resources` - Unmanaged resource count
  - `keycloak_operator_remediation_total` - Remediation actions performed
  - `keycloak_operator_drift_check_duration_seconds` - Drift scan duration

### Breaking Changes

* **drift-detection:** Resources created before this version will not have ownership attributes
  - Existing realms/clients will be treated as "unmanaged" resources
  - They will NOT be affected by drift detection or auto-remediation
  - See `docs/drift-detection.md` for migration options

* **admin-client:** KeycloakAdminClient methods now require `namespace` parameter
  - All methods accept `namespace: str` for rate limiting
  - Factory function `get_keycloak_admin_client` now accepts `rate_limiter` parameter
  - Circuit breaker removed (replaced by rate limiting)

### Documentation

* Add comprehensive drift detection documentation
* Add example Prometheus alerts for drift detection
* Update README.md with drift detection feature
* Update CLAUDE.md with async patterns and rate limiting architecture


## [0.2.11](https://github.com/vriesdemichael/keycloak-operator/compare/v0.2.10...v0.2.11) (2025-10-27)


### Documentation

* add scaling strategy documentation to architecture ([#56](https://github.com/vriesdemichael/keycloak-operator/issues/56)) ([0b496c7](https://github.com/vriesdemichael/keycloak-operator/commit/0b496c7b568a33889b8d9e7980e04b6a9e60b6b3))

## [0.2.10](https://github.com/vriesdemichael/keycloak-operator/compare/v0.2.9...v0.2.10) (2025-10-27)


### Features

* Two-level rate limiting with async/await conversion ([#44](https://github.com/vriesdemichael/keycloak-operator/issues/44)) ([476a6ed](https://github.com/vriesdemichael/keycloak-operator/commit/476a6ed4bbb327d38e7c55bdc1421daa3fdb2a81))

## [Unreleased]

### Features

* **rate-limiting:** Implement comprehensive two-level rate limiting for Keycloak API calls
  - Global rate limiter (50 req/s default) protects Keycloak from total overload
  - Per-namespace rate limiter (5 req/s default) ensures fair access across teams
  - Prevents API flooding on operator restart via jitter (0-5s random delay)
  - Protects against DDoS via spam creation of thousands of realms/clients
  - Addresses issue #31

* **async:** Complete async/await conversion of Keycloak Admin Client
  - Migrated from `requests` to `aiohttp` for async HTTP operations
  - All 44 admin client methods converted to async
  - All reconcilers updated to use async admin client
  - All handlers updated with jitter and rate limiter integration

* **metrics:** Add Prometheus metrics for rate limiting observability
  - `keycloak_api_rate_limit_wait_seconds` - Time waiting for tokens
  - `keycloak_api_rate_limit_acquired_total` - Successful acquisitions
  - `keycloak_api_rate_limit_timeouts_total` - Timeout errors
  - `keycloak_api_tokens_available` - Current available tokens

### Breaking Changes

* **admin-client:** KeycloakAdminClient methods now require `namespace` parameter
  - All methods accept `namespace: str` for rate limiting
  - Factory function `get_keycloak_admin_client` now accepts `rate_limiter` parameter
  - Circuit breaker removed (replaced by rate limiting)

### Documentation

* Add comprehensive rate limiting documentation to README.md
* Update CLAUDE.md with async patterns and rate limiting architecture
* Add implementation plan in `docs/rate-limiting-implementation-plan.md`

## [0.2.9](https://github.com/vriesdemichael/keycloak-operator/compare/v0.2.8...v0.2.9) (2025-10-22)


### Documentation

* **ci:** feature requests now require less information ([93945d1](https://github.com/vriesdemichael/keycloak-operator/commit/93945d111c2a1a4d60dd9a630947306bf97e5efe))

## [0.2.8](https://github.com/vriesdemichael/keycloak-operator/compare/v0.2.7...v0.2.8) (2025-10-22)


### Bug Fixes

* **ci:** add Docker tag extraction for operator-v prefixed tags ([#28](https://github.com/vriesdemichael/keycloak-operator/issues/28)) ([b761052](https://github.com/vriesdemichael/keycloak-operator/commit/b76105243a369c3a29fee8da425c6aa888142007))

## [0.2.7](https://github.com/vriesdemichael/keycloak-operator/compare/operator-v0.2.6...operator-v0.2.7) (2025-10-21)


### Features

* Automatic Token Rotation System with Bootstrap Flow ([#26](https://github.com/vriesdemichael/keycloak-operator/issues/26)) ([ca28c1b](https://github.com/vriesdemichael/keycloak-operator/commit/ca28c1b995a8b953935f61d255de49921ac4cd85))

## [0.2.6](https://github.com/vriesdemichael/keycloak-operator/compare/operator-v0.2.5...operator-v0.2.6) (2025-10-20)


### Features

* **ci:** auto-approve and merge non-major release PRs ([609e19b](https://github.com/vriesdemichael/keycloak-operator/commit/609e19b0b821c478c0c05962d74d1a3325d6781a))


### Bug Fixes

* **ci:** add missing Dockerfile path to publish job ([4986bec](https://github.com/vriesdemichael/keycloak-operator/commit/4986becd3b89c79f48493064a74940a1243a0cd2))
* **ci:** remove approval step to work with auto-merge setting ([5428eb3](https://github.com/vriesdemichael/keycloak-operator/commit/5428eb3ccf96396c4cbd8a6c1869669527078ac5))

## [0.2.5](https://github.com/vriesdemichael/keycloak-operator/compare/operator-v0.2.4...operator-v0.2.5) (2025-10-20)


### Features

* Add optimized Keycloak image for 81% faster tests ([#15](https://github.com/vriesdemichael/keycloak-operator/issues/15)) ([3093a10](https://github.com/vriesdemichael/keycloak-operator/commit/3093a10239538b76d4fe7ae094e9ddcc85a519bd))


### Bug Fixes

* Add operator log capture and fix all integration tests ([#14](https://github.com/vriesdemichael/keycloak-operator/issues/14)) ([bf4e84f](https://github.com/vriesdemichael/keycloak-operator/commit/bf4e84ff8e4e5f8a0ebb0210ac2d6922beae2174))
* **ci:** correct JSON syntax errors in release-please manifest ([31577b3](https://github.com/vriesdemichael/keycloak-operator/commit/31577b39ef5accb576f713b162ea62f84b554fd7))
* **ci:** enable semver Docker tags by dispatching CI/CD on release creation ([ff95842](https://github.com/vriesdemichael/keycloak-operator/commit/ff958422945707c65f2556e5813a465028e64789))
* Use explicit exists output for artifact conditionals ([f52b7cd](https://github.com/vriesdemichael/keycloak-operator/commit/f52b7cdc66de1d7294fa34e4a3862aaf29b1d286))


### Documentation

* add comprehensive release workflow analysis and fix documentation ([87838c9](https://github.com/vriesdemichael/keycloak-operator/commit/87838c9b57e0d0ad840cf4160e2e6f50ac53d3ab))
* update release process for branch protection and PR workflow ([#12](https://github.com/vriesdemichael/keycloak-operator/issues/12)) ([6508868](https://github.com/vriesdemichael/keycloak-operator/commit/6508868dbf3b245f598fa4f1253952ae01193947))

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
* **design:** add Keycloak state observability analysis ([120eb81](https://github.com/vriesdemichael/keycloak-operator/commit/120eb81c5e8bd4d28c1833f9afaa088f90ce0210))
* Implement robust cleanup system for integration tests ([ca233c6](https://github.com/vriesdemichael/keycloak-operator/commit/ca233c64eab58b8441a746743105056a439d703b))
* reorganize documentation structure and simplify README ([e0b7bef](https://github.com/vriesdemichael/keycloak-operator/commit/e0b7befc77a9f201965d39f88ef03041c4d5bd22))
