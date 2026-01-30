# Changelog

## [0.4.1](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.4.0...chart-operator-v0.4.1) (2026-01-30)


### Features

* **chart-operator+operator:** expose security settings in helm chart ([50c8d9a](https://github.com/vriesdemichael/keycloak-operator/commit/50c8d9ac2159f533a49b3138d09339b3c7ef5c6e))
* **chart-operator:** expose rate limiting and metrics settings ([fbada3e](https://github.com/vriesdemichael/keycloak-operator/commit/fbada3ef55a1333e9fcb581d0aaec6dbc0d2a793))

## [0.4.0](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.30...chart-operator-v0.4.0) (2026-01-29)


### ⚠ BREAKING CHANGES

* **chart-client+chart-operator+chart-realm:** Helm chart distribution moved to OCI registry
* **webhooks:** Admission webhooks now require cert-manager to be installed

### Features

* **chart-client+chart-operator+chart-realm:** migrate to OCI registry in GHCR ([3d122c6](https://github.com/vriesdemichael/keycloak-operator/commit/3d122c6b78851ef571b5d4d4af436039e45bb9d0))
* **chart-client+chart-operator+operator:** add missing client settings fields ([0404a43](https://github.com/vriesdemichael/keycloak-operator/commit/0404a43b24fc8988fce32414f75a2b012c68168d))
* **chart-client+operator:** add labels and annotations to managed secrets ([a2fcd36](https://github.com/vriesdemichael/keycloak-operator/commit/a2fcd36ef5e7b46c8b53a747a99353074eb3823e))
* **chart-operator+chart-realm+operator:** add complete realm role and group management ([add7630](https://github.com/vriesdemichael/keycloak-operator/commit/add763062f9c8d62f3131fba55361d2e7bd40a62))
* **chart-operator+chart-realm+operator:** add password policy and improve events config ([48e91af](https://github.com/vriesdemichael/keycloak-operator/commit/48e91af5ca03940d1e86eb6cc0c50e4c595973f6)), closes [#311](https://github.com/vriesdemichael/keycloak-operator/issues/311)
* **chart-operator:** add CNPG and connection pool schema fields ([c3140b7](https://github.com/vriesdemichael/keycloak-operator/commit/c3140b720c6eb7a157cd9bc86d2eda0e00e74bc5))
* **chart-operator:** add configurable timer intervals for reconciliation ([9ace7e4](https://github.com/vriesdemichael/keycloak-operator/commit/9ace7e47f6406263e9d5c13d0b48755348729102))
* **chart-operator:** add documentation link to values.yaml header ([e7ea45f](https://github.com/vriesdemichael/keycloak-operator/commit/e7ea45fe694f73dcf273b1ee9255a77d6d49a787))
* **chart-operator:** add PriorityClass for operator pods ([#173](https://github.com/vriesdemichael/keycloak-operator/issues/173)) ([e151175](https://github.com/vriesdemichael/keycloak-operator/commit/e151175232428fa4b251d8511de19bcb0e04ad78))
* **chart-realm+operator:** add authentication flow and required action support ([ec8092e](https://github.com/vriesdemichael/keycloak-operator/commit/ec8092e33e1255a6e479f1108d0a12a5e518ebf6)), closes [#180](https://github.com/vriesdemichael/keycloak-operator/issues/180)
* **chart-realm:** add client scope management ([bd63d5b](https://github.com/vriesdemichael/keycloak-operator/commit/bd63d5bc4ef514020575390ac2a4eb51d5b57279)), closes [#181](https://github.com/vriesdemichael/keycloak-operator/issues/181)
* **operator:** add quiet logging mode for health probes and webhooks ([76fb7d2](https://github.com/vriesdemichael/keycloak-operator/commit/76fb7d221c31a6921507f9b7c99f1d0d75510ab9))
* **operator:** enhance user federation models with LDAP/AD/Kerberos support ([2b5f4c6](https://github.com/vriesdemichael/keycloak-operator/commit/2b5f4c63a5cd75aed07c7e58bd38516cf7f0659d))
* **operator:** fix pydantic-settings environment variable configuration ([d1cea04](https://github.com/vriesdemichael/keycloak-operator/commit/d1cea04948658df46e9209d1ba37bdac20c0dab4)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* **webhooks:** switch to cert-manager for webhook TLS certificates ([e23dbde](https://github.com/vriesdemichael/keycloak-operator/commit/e23dbde72bb9b60a9eff2a0abb28f0ca88d56ea8))


### Bug Fixes

* add get permission for CRDs in ClusterRole ([61af8a8](https://github.com/vriesdemichael/keycloak-operator/commit/61af8a8842ebd02b1df9226bf91c1dbbbe19ac66))
* allow test tags in operator chart schema ([71012b7](https://github.com/vriesdemichael/keycloak-operator/commit/71012b71951c1bce1c522fc1bed68857859afda8))
* allow test-* tags in operator chart schema ([22a75db](https://github.com/vriesdemichael/keycloak-operator/commit/22a75dbdbe0f44b6aeaeb94b98fbc03350102573))
* **chart-client+chart-operator+chart-realm:** update Kubernetes version requirement to 1.27+ ([f53fe0c](https://github.com/vriesdemichael/keycloak-operator/commit/f53fe0c26425274282fcc8a10095c0484cef9a13))
* **chart-client+chart-operator+operator:** address multiple issues ([#290](https://github.com/vriesdemichael/keycloak-operator/issues/290), [#294](https://github.com/vriesdemichael/keycloak-operator/issues/294), [#170](https://github.com/vriesdemichael/keycloak-operator/issues/170), [#168](https://github.com/vriesdemichael/keycloak-operator/issues/168)) ([23a1dba](https://github.com/vriesdemichael/keycloak-operator/commit/23a1dbafabfd0deb35f6c528b560df1cb19da1e5))
* **chart-operator:** add secret watch/delete permissions to RBAC ([4de6384](https://github.com/vriesdemichael/keycloak-operator/commit/4de6384c7131c612352dd6f2297483b3b15cd554))
* **chart-operator:** align helm ingress values with keycloak CRD schema ([47ed813](https://github.com/vriesdemichael/keycloak-operator/commit/47ed813a1bc8675dce9c7bac0a8b0e60aca0b563))
* **chart-operator:** remove admission token configuration from values ([c20ae4c](https://github.com/vriesdemichael/keycloak-operator/commit/c20ae4cfebc4257658604d5addbd5bcb10a80524))
* **chart-operator:** remove outdated authorization token instructions ([898814f](https://github.com/vriesdemichael/keycloak-operator/commit/898814f64bbf4bdc2c5bafc987f22dec971664f2))
* **chart-operator:** update for operator v0.3.3 compatibility ([794a415](https://github.com/vriesdemichael/keycloak-operator/commit/794a415695d6ebad69332e0c2c0ff7a7484a224e))
* **chart-operator:** update for operator v0.4.2 ([6920fcf](https://github.com/vriesdemichael/keycloak-operator/commit/6920fcf6ce459479c2ada87f22790898e0b3fb21))
* **chart-operator:** update for operator v0.4.3 ([63935e4](https://github.com/vriesdemichael/keycloak-operator/commit/63935e4b3d4406e5c31011743ebfce8f3d701492))
* **chart-operator:** update for operator v0.5.10 ([dcd4a75](https://github.com/vriesdemichael/keycloak-operator/commit/dcd4a758e7500e1db124fa742b977bde471b468d))
* **chart-operator:** update for operator v0.5.11 ([0b5c68c](https://github.com/vriesdemichael/keycloak-operator/commit/0b5c68c8fe55b1f1226e3cb8cde615684908d01f))
* **chart-operator:** update for operator v0.5.12 ([f79be8a](https://github.com/vriesdemichael/keycloak-operator/commit/f79be8aea6a92412e8eb7d88852c0174bbc72b2a))
* **chart-operator:** update for operator v0.5.12 ([30cd277](https://github.com/vriesdemichael/keycloak-operator/commit/30cd277f4bacd3ba9ef90f8f31bd9aa0b158570c))
* **chart-operator:** update for operator v0.5.13 ([e15182e](https://github.com/vriesdemichael/keycloak-operator/commit/e15182ea29ce4f649ddd996ea9ed91d8b50ac5b4))
* **chart-operator:** update for operator v0.5.15 ([0c834a1](https://github.com/vriesdemichael/keycloak-operator/commit/0c834a106bc136c1dc9caa0782e91d938f83e042))
* **chart-operator:** update for operator v0.5.16 ([712e3a2](https://github.com/vriesdemichael/keycloak-operator/commit/712e3a221b0f1fc71c373920124e3e5cde0f8e86))
* **chart-operator:** update for operator v0.5.17 ([aad3798](https://github.com/vriesdemichael/keycloak-operator/commit/aad3798f0cc07abfcc612760ab85d5c61fcf5041))
* **chart-operator:** update for operator v0.5.18 ([f86e34f](https://github.com/vriesdemichael/keycloak-operator/commit/f86e34f5fb74baea824e182677dcc52a249d2692))
* **chart-operator:** update for operator v0.5.19 ([2a7b24f](https://github.com/vriesdemichael/keycloak-operator/commit/2a7b24fb6f2c861ba84c5aa65154afe0a49a4ff9))
* **chart-operator:** update for operator v0.5.20 ([5b6be7a](https://github.com/vriesdemichael/keycloak-operator/commit/5b6be7ac2d03b3442924301ce556b741355b505f))
* **chart-operator:** update for operator v0.5.3 ([8e80e43](https://github.com/vriesdemichael/keycloak-operator/commit/8e80e43261ecffe14d5fddab875a7c0078dfd05b))
* **chart-operator:** update for operator v0.5.5 ([f2e5050](https://github.com/vriesdemichael/keycloak-operator/commit/f2e50503e2e80f71dc2271cb49b1999c78bc74d2))
* **chart-operator:** update for operator v0.5.6 ([818ecc6](https://github.com/vriesdemichael/keycloak-operator/commit/818ecc6be13cba92f21b24eb1d37da2abe27ec00))
* **chart-operator:** update for operator v0.5.7 ([3d0cc01](https://github.com/vriesdemichael/keycloak-operator/commit/3d0cc01d1931f506d1231bb4e7c4990bc4abe34c))
* **chart-operator:** update for operator v0.5.8 ([4c4c9ad](https://github.com/vriesdemichael/keycloak-operator/commit/4c4c9ade2b4db1f04f4a3803932e8b2775fb65ba))
* **chart-operator:** update for operator v0.5.9 ([a3596f1](https://github.com/vriesdemichael/keycloak-operator/commit/a3596f1e0943b25ea3cf214065ecf5110ab06f12))
* **chart-operator:** update for operator v0.6.0 ([72dec6d](https://github.com/vriesdemichael/keycloak-operator/commit/72dec6dae8fd63591e33b3f03bc3ea7dda71be08))
* **chart-operator:** update for operator v0.6.1 ([50dc4f6](https://github.com/vriesdemichael/keycloak-operator/commit/50dc4f6cf673d98aac5ca61e5d34d53a58801407))
* **chart-operator:** update for operator v0.6.2 ([f2324c3](https://github.com/vriesdemichael/keycloak-operator/commit/f2324c34e4f79310414cfc2f41f69bfdbfd21bf1))
* **chart-operator:** update for operator v0.6.3 ([4dd93c0](https://github.com/vriesdemichael/keycloak-operator/commit/4dd93c07388e3bbc41415c359faf69c548d2303b))
* **chart-operator:** use values for CNPG storage configuration ([002f6ec](https://github.com/vriesdemichael/keycloak-operator/commit/002f6ecb468bb6f5e0b022e6d8b4382eb85fd7da)), closes [#233](https://github.com/vriesdemichael/keycloak-operator/issues/233)
* disable webhook auto-management and default to false ([5104c5f](https://github.com/vriesdemichael/keycloak-operator/commit/5104c5f385921d45dc4aa754bb29df7355a0953b))
* **operator:** add configSecrets field to identity provider CRD schema ([95a12a6](https://github.com/vriesdemichael/keycloak-operator/commit/95a12a69ddc3e2a7979fee6358ce5765ca1a0a3e))
* **operator:** database passwordSecret support and test fixes ([3389f69](https://github.com/vriesdemichael/keycloak-operator/commit/3389f695a3a10f8fbeb7e9b0f8cb494b55c3f628))
* **operator:** resolve BruteForceStrategy enum serialization and complete multi-version support ([3afb2ea](https://github.com/vriesdemichael/keycloak-operator/commit/3afb2ea815aebf7afd10050db96ad013e4b2a2d2))
* remove tests for deleted periodic_leadership_check function ([eb4c6ac](https://github.com/vriesdemichael/keycloak-operator/commit/eb4c6acc9e732f91567a26e6d4dbe1e9453c7a60))
* remove webhook config template, let Kopf manage it ([b84b0d5](https://github.com/vriesdemichael/keycloak-operator/commit/b84b0d5aaf9c5814b6ed6e375c45c3918c5e1f8f))
* restore correct test image tag for coverage collection ([09d1da3](https://github.com/vriesdemichael/keycloak-operator/commit/09d1da3686bfa1aa6ba6d7920f34b031de40d76a))


### Documentation

* bulk cleanup of authorizationSecretRef in chart READMEs ([3e31d59](https://github.com/vriesdemichael/keycloak-operator/commit/3e31d59534e7df3f7580099987d30c800422ccec))
* **chart-operator:** remove all admission token documentation ([d37113c](https://github.com/vriesdemichael/keycloak-operator/commit/d37113c8716323e2336e4518daa73adb023d8401))
* document webhook timeout behavior on fresh install ([7b4d010](https://github.com/vriesdemichael/keycloak-operator/commit/7b4d010514f0f8298fb7ba1fc125c73dfc626dbc)), closes [#240](https://github.com/vriesdemichael/keycloak-operator/issues/240)
* final cleanup of remaining token references ([96e6086](https://github.com/vriesdemichael/keycloak-operator/commit/96e6086d173abdfedec0bb197a94cf50afb7690a))
* improve operator chart values documentation ([2ada78e](https://github.com/vriesdemichael/keycloak-operator/commit/2ada78e95daca86a5c7397e522807d5dee7abb7d))
* update helm chart READMEs and fix broken links ([a32d3e2](https://github.com/vriesdemichael/keycloak-operator/commit/a32d3e243e7d5f0616bf2d52c3bc14ff2d2f2464))

## [0.3.30](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.29...chart-operator-v0.3.30) (2026-01-28)


### Bug Fixes

* **operator:** resolve BruteForceStrategy enum serialization and complete multi-version support ([569e8e8](https://github.com/vriesdemichael/keycloak-operator/commit/569e8e8a95deddc68f6c34e52de5a2209f9b68e0))

## [0.3.29](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.28...chart-operator-v0.3.29) (2026-01-26)


### Bug Fixes

* **chart-operator:** update for operator v0.6.2 ([01fe239](https://github.com/vriesdemichael/keycloak-operator/commit/01fe239014f1a4b3975504feef3e41254669dfdf))

## [0.3.28](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.27...chart-operator-v0.3.28) (2026-01-25)


### Bug Fixes

* **chart-operator:** update for operator v0.6.1 ([a8eac22](https://github.com/vriesdemichael/keycloak-operator/commit/a8eac22a3d3e67d16aaf4e5b885bbc303812ca60))

## [0.3.27](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.26...chart-operator-v0.3.27) (2026-01-21)


### Bug Fixes

* **chart-operator:** update for operator v0.6.0 ([c43238a](https://github.com/vriesdemichael/keycloak-operator/commit/c43238a067aa8d9eefb4b14746223b9437dea030))

## [0.3.26](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.25...chart-operator-v0.3.26) (2026-01-21)


### Bug Fixes

* **chart-operator:** add secret watch/delete permissions to RBAC ([d971179](https://github.com/vriesdemichael/keycloak-operator/commit/d971179f3b5951fd35e149490e760d9c7a4f93ac))

## [0.3.25](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.24...chart-operator-v0.3.25) (2026-01-20)


### Features

* **chart-client+operator:** add labels and annotations to managed secrets ([ee64ec1](https://github.com/vriesdemichael/keycloak-operator/commit/ee64ec1ecbe5ead4db3fe9896f16fd83d0c842ef))

## [0.3.24](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.23...chart-operator-v0.3.24) (2026-01-14)


### Bug Fixes

* **chart-operator:** update for operator v0.5.20 ([11f1ce8](https://github.com/vriesdemichael/keycloak-operator/commit/11f1ce89fa516784fc931836f807aa17765573b3))

## [0.3.23](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.22...chart-operator-v0.3.23) (2026-01-14)


### Features

* **chart-client+chart-operator+operator:** add missing client settings fields ([5a17906](https://github.com/vriesdemichael/keycloak-operator/commit/5a179063c098f1fc0afd505b5466dd8be8a2ab79))

## [0.3.22](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.21...chart-operator-v0.3.22) (2026-01-13)


### Bug Fixes

* **chart-operator:** update for operator v0.5.19 ([eab9b60](https://github.com/vriesdemichael/keycloak-operator/commit/eab9b60ca976d6f932ad6b2376e8eb98d1989515))

## [0.3.21](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.20...chart-operator-v0.3.21) (2026-01-13)


### Features

* **operator:** enhance user federation models with LDAP/AD/Kerberos support ([7c6e1d7](https://github.com/vriesdemichael/keycloak-operator/commit/7c6e1d7bb0dae2e6c0e0b08aac01292020d6ec3d))

## [0.3.20](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.19...chart-operator-v0.3.20) (2026-01-08)


### Features

* **chart-operator:** add configurable timer intervals for reconciliation ([80e4652](https://github.com/vriesdemichael/keycloak-operator/commit/80e46525e2ea44209c51ea89984d7cfab0c9d25c))
* **chart-operator:** add PriorityClass for operator pods ([#173](https://github.com/vriesdemichael/keycloak-operator/issues/173)) ([6c1ec8d](https://github.com/vriesdemichael/keycloak-operator/commit/6c1ec8d8c6b451730d8f25cb9fa97b1373283469))


### Bug Fixes

* **chart-client+chart-operator+operator:** address multiple issues ([#290](https://github.com/vriesdemichael/keycloak-operator/issues/290), [#294](https://github.com/vriesdemichael/keycloak-operator/issues/294), [#170](https://github.com/vriesdemichael/keycloak-operator/issues/170), [#168](https://github.com/vriesdemichael/keycloak-operator/issues/168)) ([0b790ac](https://github.com/vriesdemichael/keycloak-operator/commit/0b790acab044239342f888dfe170afbef874f6bc))

## [0.3.19](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.18...chart-operator-v0.3.19) (2026-01-07)


### Bug Fixes

* **chart-operator:** update for operator v0.5.17 ([039ce75](https://github.com/vriesdemichael/keycloak-operator/commit/039ce75ead72be5602635b897e758903777ae8cb))

## [0.3.18](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.17...chart-operator-v0.3.18) (2026-01-07)


### Features

* **chart-realm:** add client scope management ([708787f](https://github.com/vriesdemichael/keycloak-operator/commit/708787f23200be34947733e9059eaad1a51e02b3)), closes [#181](https://github.com/vriesdemichael/keycloak-operator/issues/181)

## [0.3.17](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.16...chart-operator-v0.3.17) (2026-01-06)


### Bug Fixes

* **chart-operator:** update for operator v0.5.16 ([35ec416](https://github.com/vriesdemichael/keycloak-operator/commit/35ec416f774c68abdd1163668a784c7a5cbb1443))

## [0.3.16](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.15...chart-operator-v0.3.16) (2026-01-06)


### Features

* **chart-operator+chart-realm+operator:** add complete realm role and group management ([d55d6d9](https://github.com/vriesdemichael/keycloak-operator/commit/d55d6d99e94264225275d3fcc026f6cf900a9c44))

## [0.3.15](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.14...chart-operator-v0.3.15) (2026-01-04)


### Features

* **chart-operator+chart-realm+operator:** add password policy and improve events config ([3d60b5e](https://github.com/vriesdemichael/keycloak-operator/commit/3d60b5eeddd7f2a5c63416a55e195e07f6804d92)), closes [#311](https://github.com/vriesdemichael/keycloak-operator/issues/311)


### Bug Fixes

* **chart-operator:** update for operator v0.5.12 ([b30cc9b](https://github.com/vriesdemichael/keycloak-operator/commit/b30cc9b5ada6c5dfa182e80fdfc3123a27e74396))
* **chart-operator:** update for operator v0.5.15 ([b5b9593](https://github.com/vriesdemichael/keycloak-operator/commit/b5b9593ebe1c05f802b27f0bdd0135f6ae7c3998))

## [0.3.14](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.13...chart-operator-v0.3.14) (2026-01-03)


### Bug Fixes

* **chart-operator:** update for operator v0.5.13 ([86b3bf6](https://github.com/vriesdemichael/keycloak-operator/commit/86b3bf6e6248ab5eeef84f3a9e280f5e120cae3e))

## [0.3.13](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.12...chart-operator-v0.3.13) (2026-01-02)


### Features

* **chart-realm+operator:** add authentication flow and required action support ([f653969](https://github.com/vriesdemichael/keycloak-operator/commit/f653969fd08b30d25af45a1b6465bc6e5ec22c2e)), closes [#180](https://github.com/vriesdemichael/keycloak-operator/issues/180)

## [0.3.12](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.11...chart-operator-v0.3.12) (2025-12-30)


### Bug Fixes

* **chart-operator:** update for operator v0.5.11 ([2d862d8](https://github.com/vriesdemichael/keycloak-operator/commit/2d862d8e34e7544165518f512e8212d7d185d3b1))

## [0.3.11](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.10...chart-operator-v0.3.11) (2025-12-29)


### Bug Fixes

* **chart-operator:** update for operator v0.5.10 ([617d0fc](https://github.com/vriesdemichael/keycloak-operator/commit/617d0fcee0893cbead43b027c6339e5adaa34e12))

## [0.3.10](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.9...chart-operator-v0.3.10) (2025-12-27)


### Bug Fixes

* **chart-operator:** update for operator v0.5.9 ([8e83b03](https://github.com/vriesdemichael/keycloak-operator/commit/8e83b03c4f9d9103fdee815a9239140ba0cb8d5d))

## [0.3.9](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.8...chart-operator-v0.3.9) (2025-12-26)


### Features

* **chart-operator:** add CNPG and connection pool schema fields ([9ffaa57](https://github.com/vriesdemichael/keycloak-operator/commit/9ffaa57a87fa1b1ac49df603a72efbe5dcdc797c))

## [0.3.8](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.7...chart-operator-v0.3.8) (2025-12-23)


### Features

* **operator:** add quiet logging mode for health probes and webhooks ([3ef5d2c](https://github.com/vriesdemichael/keycloak-operator/commit/3ef5d2cdabd42b4dd9e3200e5b9591e6977f21db))


### Bug Fixes

* **chart-operator:** update for operator v0.5.7 ([96b38c0](https://github.com/vriesdemichael/keycloak-operator/commit/96b38c0bed09d208372e6ba5610b88165976882c))
* **chart-operator:** update for operator v0.5.8 ([8ece479](https://github.com/vriesdemichael/keycloak-operator/commit/8ece4790bab0309cfbaa6269a85dc62c744ed84b))
* **operator:** add configSecrets field to identity provider CRD schema ([e743712](https://github.com/vriesdemichael/keycloak-operator/commit/e743712f2fffd545f5c6a3403ba9a776b3e96a23))

## [0.3.7](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.6...chart-operator-v0.3.7) (2025-12-23)


### Bug Fixes

* **chart-operator:** align helm ingress values with keycloak CRD schema ([c0cd75b](https://github.com/vriesdemichael/keycloak-operator/commit/c0cd75b9b0bc4a19e30f91b4b06911082dbac14d))

## [0.3.6](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.5...chart-operator-v0.3.6) (2025-12-23)


### Bug Fixes

* **chart-operator:** update for operator v0.5.6 ([f7f3323](https://github.com/vriesdemichael/keycloak-operator/commit/f7f33239c652d72fcd8de0388135ec6fe59ae80e))
* **chart-operator:** use values for CNPG storage configuration ([441058f](https://github.com/vriesdemichael/keycloak-operator/commit/441058f99ffda32142b6fa6bca6d433e40fff177)), closes [#233](https://github.com/vriesdemichael/keycloak-operator/issues/233)


### Documentation

* document webhook timeout behavior on fresh install ([0d8d3f0](https://github.com/vriesdemichael/keycloak-operator/commit/0d8d3f0de6c218f42197277829a82425003e959f)), closes [#240](https://github.com/vriesdemichael/keycloak-operator/issues/240)

## [0.3.5](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.4...chart-operator-v0.3.5) (2025-12-22)


### Bug Fixes

* **chart-operator:** update for operator v0.5.5 ([2342795](https://github.com/vriesdemichael/keycloak-operator/commit/234279516192b119aa439a4de057e65c6749ba2d))

## [0.3.4](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.3...chart-operator-v0.3.4) (2025-12-21)


### Bug Fixes

* **chart-client+chart-operator+chart-realm:** update Kubernetes version requirement to 1.27+ ([26e8781](https://github.com/vriesdemichael/keycloak-operator/commit/26e87812994979d2ec22767f9ff3fb11de85f74a))

## [0.3.3](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.2...chart-operator-v0.3.3) (2025-12-18)


### Bug Fixes

* **chart-operator:** update for operator v0.5.3 ([cb76df9](https://github.com/vriesdemichael/keycloak-operator/commit/cb76df99ab64245af89221b2e297dc137800bb9f))

## [0.3.2](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.1...chart-operator-v0.3.2) (2025-12-17)


### Features

* **chart-operator:** add documentation link to values.yaml header ([3ef4016](https://github.com/vriesdemichael/keycloak-operator/commit/3ef40163c31513868c98775d831124018152586f))

## [0.3.1](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.0...chart-operator-v0.3.1) (2025-12-17)


### Bug Fixes

* **chart-operator:** update for operator v0.4.2 ([3e05ace](https://github.com/vriesdemichael/keycloak-operator/commit/3e05ace25ee4dad3555aa6f3e94487cbdd04c09a))
* **chart-operator:** update for operator v0.4.3 ([59cc41b](https://github.com/vriesdemichael/keycloak-operator/commit/59cc41bceb04de3f4a5d4ebcb960c6863f29211e))

## [0.5.0](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.4.0...chart-operator-v0.5.0) (2025-12-17)


### ⚠ BREAKING CHANGES

* **chart-client+chart-operator+chart-realm:** Helm chart distribution moved to OCI registry
* **webhooks:** Admission webhooks now require cert-manager to be installed
* **chart-client+chart-realm:** Removed token-based authorization from all charts
* The API group domain has changed from keycloak.mdvr.nl to vriesdemichael.github.io. Existing installations must migrate by:

### Features

* add drift detection foundation (Phase 1-3) ([80cf043](https://github.com/vriesdemichael/keycloak-operator/commit/80cf0438ef7b0e7568fa9d033e15be305f24ba55))
* Add Keycloak Operator and Realm Helm charts ([2d4be4f](https://github.com/vriesdemichael/keycloak-operator/commit/2d4be4f4b8b43665afcecc8f0dacefbe88f66117))
* add OIDC endpoint discovery to realm status ([6dc52f3](https://github.com/vriesdemichael/keycloak-operator/commit/6dc52f3ac9a51547e4431f99abbe91aec1d7dca3))
* Add optimized Keycloak image for 81% faster tests ([#15](https://github.com/vriesdemichael/keycloak-operator/issues/15)) ([3093a10](https://github.com/vriesdemichael/keycloak-operator/commit/3093a10239538b76d4fe7ae094e9ddcc85a519bd))
* **chart-client+chart-operator+chart-realm:** migrate to OCI registry in GHCR ([dc4f59c](https://github.com/vriesdemichael/keycloak-operator/commit/dc4f59c8f9d66be04cd7be6ae685fc714a8aad97))
* **chart-client+chart-realm:** update charts for namespace grant authorization ([add6af9](https://github.com/vriesdemichael/keycloak-operator/commit/add6af903c2ff887cd44c5608ceb1a1a6436f23e)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart-operator:** add 'get' permission for cross-namespace realm reads ([1e9cf4f](https://github.com/vriesdemichael/keycloak-operator/commit/1e9cf4fd7f4c4fb3e2a85d02bc217c8d4449075a)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart-operator:** update CRDs for namespace grant authorization ([b526149](https://github.com/vriesdemichael/keycloak-operator/commit/b52614931946e588730b3cc4312c061e383623fe)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart:** add automated operator version updates ([b303448](https://github.com/vriesdemichael/keycloak-operator/commit/b3034483f890b6ae282f787cc0ef343bc6fe6d03))
* **chart:** make admin password optional, leverage auto-generation ([a9fcb1a](https://github.com/vriesdemichael/keycloak-operator/commit/a9fcb1a475b99036b811753f42029a5cd0c0ad12))
* **charts:** add values.schema.json and extraManifests support ([039e00d](https://github.com/vriesdemichael/keycloak-operator/commit/039e00d1fe0874b2eb24f21d95f5e58d9f4a50cc))
* implement admission webhooks for resource validation ([061acae](https://github.com/vriesdemichael/keycloak-operator/commit/061acae11b1af0d5547177c98264ac6ffbaa8f27))
* Implement Kopf peering for leader election and update deployment scripts ([a289e3a](https://github.com/vriesdemichael/keycloak-operator/commit/a289e3a55d95ecf2af4e2d29d94399acccf6aa25))
* migrate API group from keycloak.mdvr.nl to vriesdemichael.github.io ([d93b3c1](https://github.com/vriesdemichael/keycloak-operator/commit/d93b3c115d73ba8e3f1fa99c48c1e058f315b075))
* **monitoring:** add Grafana dashboard and Prometheus alert rules ([e459d0d](https://github.com/vriesdemichael/keycloak-operator/commit/e459d0d11c874f17c844012f641ec51ae53ad24b))
* **operator:** fix pydantic-settings environment variable configuration ([20d00b3](https://github.com/vriesdemichael/keycloak-operator/commit/20d00b3ff8a242e08706426ed7bc7a48e3eb2e6e)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* publish JSON schemas for CRDs to enable IDE autocomplete ([72485af](https://github.com/vriesdemichael/keycloak-operator/commit/72485afb83822db7e427e1b876fd2700a91489a5))
* Two-level rate limiting with async/await conversion ([#44](https://github.com/vriesdemichael/keycloak-operator/issues/44)) ([476a6ed](https://github.com/vriesdemichael/keycloak-operator/commit/476a6ed4bbb327d38e7c55bdc1421daa3fdb2a81))
* **webhooks:** switch to cert-manager for webhook TLS certificates ([7195217](https://github.com/vriesdemichael/keycloak-operator/commit/7195217d15903d9c2c738999ce4c25acf1daaa88))


### Bug Fixes

* add certbuilder dependency and fix webhook RBAC permissions ([71df4ee](https://github.com/vriesdemichael/keycloak-operator/commit/71df4eebe6573b84eea6fab15fd9f9666806b3d5))
* add get permission for CRDs in ClusterRole ([3455cd6](https://github.com/vriesdemichael/keycloak-operator/commit/3455cd6eef7148d506f33e13add95ea6927759de))
* add missing RBAC permissions and correct readiness probe port ([2300f2a](https://github.com/vriesdemichael/keycloak-operator/commit/2300f2a85d6f007e2f1d6ca9b12ae80745adc95e))
* Add operator log capture and fix all integration tests ([#14](https://github.com/vriesdemichael/keycloak-operator/issues/14)) ([bf4e84f](https://github.com/vriesdemichael/keycloak-operator/commit/bf4e84ff8e4e5f8a0ebb0210ac2d6922beae2174))
* add patch permission for pods in namespace Role ([43d7fdc](https://github.com/vriesdemichael/keycloak-operator/commit/43d7fdc6f55475da9a6ba5ce42b0987bdb6d6557))
* allow test tags in operator chart schema ([6740046](https://github.com/vriesdemichael/keycloak-operator/commit/6740046724b30ca0d694bc85a40212db826fe596))
* allow test-* tags in operator chart schema ([8450c8f](https://github.com/vriesdemichael/keycloak-operator/commit/8450c8fa9135190af5c272b641e09327de3f4b56))
* **chart-operator:** remove admission token configuration from values ([302a27d](https://github.com/vriesdemichael/keycloak-operator/commit/302a27d59db56b064a7888ce1ee4c76f377f77e0))
* **chart-operator:** remove outdated authorization token instructions ([6f2c190](https://github.com/vriesdemichael/keycloak-operator/commit/6f2c1907af74134fc727e132e4a4ca40a5300130))
* **chart-operator:** update for operator v0.3.3 compatibility ([584c98f](https://github.com/vriesdemichael/keycloak-operator/commit/584c98f080352b39eab75c1c18e5faba838af9e9))
* **chart-operator:** update for operator v0.4.2 ([3e05ace](https://github.com/vriesdemichael/keycloak-operator/commit/3e05ace25ee4dad3555aa6f3e94487cbdd04c09a))
* **chart-operator:** update for operator v0.4.3 ([59cc41b](https://github.com/vriesdemichael/keycloak-operator/commit/59cc41bceb04de3f4a5d4ebcb960c6863f29211e))
* **chart:** align Keycloak CR template with actual CRD spec ([bfa3a62](https://github.com/vriesdemichael/keycloak-operator/commit/bfa3a62c60c715e510670642e69676058375fceb))
* **chart:** remove kustomization file from Helm CRDs folder ([dd80cb3](https://github.com/vriesdemichael/keycloak-operator/commit/dd80cb340bd3c5b5ffd4d64b83e15df918bbe4ae))
* disable webhook auto-management and default to false ([0c59b83](https://github.com/vriesdemichael/keycloak-operator/commit/0c59b834d2852d010a6ca97152eb4b2e41e0353b))
* disable webhooks by default to avoid bootstrap issues ([85470ed](https://github.com/vriesdemichael/keycloak-operator/commit/85470ed5f1a6b9a45027fd050622d82042e92b43))
* enable mandatory type checking and add Helm linting to pre-commit ([97dc9d7](https://github.com/vriesdemichael/keycloak-operator/commit/97dc9d7062695a9e3999c5554d774ac9c79e6c3d))
* **operator:** database passwordSecret support and test fixes ([038fc18](https://github.com/vriesdemichael/keycloak-operator/commit/038fc18da190e8d99eb02222c89c59393129feee))
* **operator:** run quality checks and tests for code OR chart changes ([a9e8ad2](https://github.com/vriesdemichael/keycloak-operator/commit/a9e8ad27ff84b7b704fdbbe9c8c353057078070c))
* proper webhook bootstrap with readiness probe and ArgoCD sync waves ([c8dfc52](https://github.com/vriesdemichael/keycloak-operator/commit/c8dfc5200c02cf550e8857d6e44583b50fb11895))
* remove obsolete authorization token references from charts ([880fc98](https://github.com/vriesdemichael/keycloak-operator/commit/880fc98637ff0e0e4c9471fd47162fc1d790b194)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove tests for deleted periodic_leadership_check function ([1ffcba0](https://github.com/vriesdemichael/keycloak-operator/commit/1ffcba0479decb4916a65262f58a46f84ab28ddd))
* remove webhook config template, let Kopf manage it ([57f2e3e](https://github.com/vriesdemichael/keycloak-operator/commit/57f2e3e82a68789d49b73fea4c8cac4e409133c2))
* restore correct test image tag for coverage collection ([6cb1675](https://github.com/vriesdemichael/keycloak-operator/commit/6cb16758ce97572f7b98396ea3b6960fb61e122f))
* use httpGet probe instead of exec with wget ([a6135d6](https://github.com/vriesdemichael/keycloak-operator/commit/a6135d6273e3a2377fd4b23e89342f00a2fb7acb))


### Documentation

* add admission webhook documentation and decision record ([396de85](https://github.com/vriesdemichael/keycloak-operator/commit/396de85863b5731e6e55ae2ac11ad21fbc45eeb1))
* bulk cleanup of authorizationSecretRef in chart READMEs ([7010d85](https://github.com/vriesdemichael/keycloak-operator/commit/7010d855084409af6a36e3d17fae465070afd6b9))
* **chart-operator:** add comprehensive README ([759081d](https://github.com/vriesdemichael/keycloak-operator/commit/759081deb9ac3cea713a0aac7843b15624165dd1))
* **chart-operator:** clarify single-tenant dev mode and add Keycloak deployment guidance ([eb3683d](https://github.com/vriesdemichael/keycloak-operator/commit/eb3683d42878d868f8857c726464a26a3a6702b2))
* **chart-operator:** remove all admission token documentation ([528ff2e](https://github.com/vriesdemichael/keycloak-operator/commit/528ff2e42b7f9f7925215c8ca30291142aedf539))
* final cleanup of remaining token references ([10f83eb](https://github.com/vriesdemichael/keycloak-operator/commit/10f83eb6fd7883b24c27e7d114c017f5e6284992))
* improve operator chart values documentation ([61e00a3](https://github.com/vriesdemichael/keycloak-operator/commit/61e00a39ab4818585d2dd15ad7b9fe90effbb6df))
* update helm chart READMEs and fix broken links ([dfb210d](https://github.com/vriesdemichael/keycloak-operator/commit/dfb210de7e222159830c5687e47e0e6d5eab354e))

## [0.4.0](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.1...chart-operator-v0.4.0) (2025-12-17)


### ⚠ BREAKING CHANGES

* **chart-client+chart-operator+chart-realm:** Helm chart distribution moved to OCI registry
* **webhooks:** Admission webhooks now require cert-manager to be installed
* **chart-client+chart-realm:** Removed token-based authorization from all charts
* The API group domain has changed from keycloak.mdvr.nl to vriesdemichael.github.io. Existing installations must migrate by:

### Features

* add drift detection foundation (Phase 1-3) ([80cf043](https://github.com/vriesdemichael/keycloak-operator/commit/80cf0438ef7b0e7568fa9d033e15be305f24ba55))
* Add Keycloak Operator and Realm Helm charts ([2d4be4f](https://github.com/vriesdemichael/keycloak-operator/commit/2d4be4f4b8b43665afcecc8f0dacefbe88f66117))
* add OIDC endpoint discovery to realm status ([6dc52f3](https://github.com/vriesdemichael/keycloak-operator/commit/6dc52f3ac9a51547e4431f99abbe91aec1d7dca3))
* Add optimized Keycloak image for 81% faster tests ([#15](https://github.com/vriesdemichael/keycloak-operator/issues/15)) ([3093a10](https://github.com/vriesdemichael/keycloak-operator/commit/3093a10239538b76d4fe7ae094e9ddcc85a519bd))
* **chart-client+chart-operator+chart-realm:** migrate to OCI registry in GHCR ([dc4f59c](https://github.com/vriesdemichael/keycloak-operator/commit/dc4f59c8f9d66be04cd7be6ae685fc714a8aad97))
* **chart-client+chart-realm:** update charts for namespace grant authorization ([add6af9](https://github.com/vriesdemichael/keycloak-operator/commit/add6af903c2ff887cd44c5608ceb1a1a6436f23e)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart-operator:** add 'get' permission for cross-namespace realm reads ([1e9cf4f](https://github.com/vriesdemichael/keycloak-operator/commit/1e9cf4fd7f4c4fb3e2a85d02bc217c8d4449075a)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart-operator:** update CRDs for namespace grant authorization ([b526149](https://github.com/vriesdemichael/keycloak-operator/commit/b52614931946e588730b3cc4312c061e383623fe)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* **chart:** add automated operator version updates ([b303448](https://github.com/vriesdemichael/keycloak-operator/commit/b3034483f890b6ae282f787cc0ef343bc6fe6d03))
* **chart:** make admin password optional, leverage auto-generation ([a9fcb1a](https://github.com/vriesdemichael/keycloak-operator/commit/a9fcb1a475b99036b811753f42029a5cd0c0ad12))
* **charts:** add values.schema.json and extraManifests support ([039e00d](https://github.com/vriesdemichael/keycloak-operator/commit/039e00d1fe0874b2eb24f21d95f5e58d9f4a50cc))
* implement admission webhooks for resource validation ([061acae](https://github.com/vriesdemichael/keycloak-operator/commit/061acae11b1af0d5547177c98264ac6ffbaa8f27))
* Implement Kopf peering for leader election and update deployment scripts ([a289e3a](https://github.com/vriesdemichael/keycloak-operator/commit/a289e3a55d95ecf2af4e2d29d94399acccf6aa25))
* migrate API group from keycloak.mdvr.nl to vriesdemichael.github.io ([d93b3c1](https://github.com/vriesdemichael/keycloak-operator/commit/d93b3c115d73ba8e3f1fa99c48c1e058f315b075))
* **monitoring:** add Grafana dashboard and Prometheus alert rules ([e459d0d](https://github.com/vriesdemichael/keycloak-operator/commit/e459d0d11c874f17c844012f641ec51ae53ad24b))
* **operator:** fix pydantic-settings environment variable configuration ([20d00b3](https://github.com/vriesdemichael/keycloak-operator/commit/20d00b3ff8a242e08706426ed7bc7a48e3eb2e6e)), closes [#108](https://github.com/vriesdemichael/keycloak-operator/issues/108)
* publish JSON schemas for CRDs to enable IDE autocomplete ([72485af](https://github.com/vriesdemichael/keycloak-operator/commit/72485afb83822db7e427e1b876fd2700a91489a5))
* Two-level rate limiting with async/await conversion ([#44](https://github.com/vriesdemichael/keycloak-operator/issues/44)) ([476a6ed](https://github.com/vriesdemichael/keycloak-operator/commit/476a6ed4bbb327d38e7c55bdc1421daa3fdb2a81))
* **webhooks:** switch to cert-manager for webhook TLS certificates ([7195217](https://github.com/vriesdemichael/keycloak-operator/commit/7195217d15903d9c2c738999ce4c25acf1daaa88))


### Bug Fixes

* add certbuilder dependency and fix webhook RBAC permissions ([71df4ee](https://github.com/vriesdemichael/keycloak-operator/commit/71df4eebe6573b84eea6fab15fd9f9666806b3d5))
* add get permission for CRDs in ClusterRole ([3455cd6](https://github.com/vriesdemichael/keycloak-operator/commit/3455cd6eef7148d506f33e13add95ea6927759de))
* add missing RBAC permissions and correct readiness probe port ([2300f2a](https://github.com/vriesdemichael/keycloak-operator/commit/2300f2a85d6f007e2f1d6ca9b12ae80745adc95e))
* Add operator log capture and fix all integration tests ([#14](https://github.com/vriesdemichael/keycloak-operator/issues/14)) ([bf4e84f](https://github.com/vriesdemichael/keycloak-operator/commit/bf4e84ff8e4e5f8a0ebb0210ac2d6922beae2174))
* add patch permission for pods in namespace Role ([43d7fdc](https://github.com/vriesdemichael/keycloak-operator/commit/43d7fdc6f55475da9a6ba5ce42b0987bdb6d6557))
* address review comments ([14007df](https://github.com/vriesdemichael/keycloak-operator/commit/14007df5fb013d9d43fdbe0b9732c447baca43f5))
* allow test tags in operator chart schema ([6740046](https://github.com/vriesdemichael/keycloak-operator/commit/6740046724b30ca0d694bc85a40212db826fe596))
* allow test-* tags in operator chart schema ([8450c8f](https://github.com/vriesdemichael/keycloak-operator/commit/8450c8fa9135190af5c272b641e09327de3f4b56))
* **chart-operator:** remove admission token configuration from values ([302a27d](https://github.com/vriesdemichael/keycloak-operator/commit/302a27d59db56b064a7888ce1ee4c76f377f77e0))
* **chart-operator:** remove outdated authorization token instructions ([6f2c190](https://github.com/vriesdemichael/keycloak-operator/commit/6f2c1907af74134fc727e132e4a4ca40a5300130))
* **chart-operator:** update for operator v0.3.3 compatibility ([584c98f](https://github.com/vriesdemichael/keycloak-operator/commit/584c98f080352b39eab75c1c18e5faba838af9e9))
* **chart-operator:** update for operator v0.4.2 ([3e05ace](https://github.com/vriesdemichael/keycloak-operator/commit/3e05ace25ee4dad3555aa6f3e94487cbdd04c09a))
* **chart-operator:** update for operator v0.4.3 ([59cc41b](https://github.com/vriesdemichael/keycloak-operator/commit/59cc41bceb04de3f4a5d4ebcb960c6863f29211e))
* **chart:** align Keycloak CR template with actual CRD spec ([bfa3a62](https://github.com/vriesdemichael/keycloak-operator/commit/bfa3a62c60c715e510670642e69676058375fceb))
* **chart:** remove kustomization file from Helm CRDs folder ([dd80cb3](https://github.com/vriesdemichael/keycloak-operator/commit/dd80cb340bd3c5b5ffd4d64b83e15df918bbe4ae))
* disable webhook auto-management and default to false ([0c59b83](https://github.com/vriesdemichael/keycloak-operator/commit/0c59b834d2852d010a6ca97152eb4b2e41e0353b))
* disable webhooks by default to avoid bootstrap issues ([85470ed](https://github.com/vriesdemichael/keycloak-operator/commit/85470ed5f1a6b9a45027fd050622d82042e92b43))
* enable mandatory type checking and add Helm linting to pre-commit ([97dc9d7](https://github.com/vriesdemichael/keycloak-operator/commit/97dc9d7062695a9e3999c5554d774ac9c79e6c3d))
* **operator:** database passwordSecret support and test fixes ([038fc18](https://github.com/vriesdemichael/keycloak-operator/commit/038fc18da190e8d99eb02222c89c59393129feee))
* **operator:** run quality checks and tests for code OR chart changes ([a9e8ad2](https://github.com/vriesdemichael/keycloak-operator/commit/a9e8ad27ff84b7b704fdbbe9c8c353057078070c))
* proper webhook bootstrap with readiness probe and ArgoCD sync waves ([c8dfc52](https://github.com/vriesdemichael/keycloak-operator/commit/c8dfc5200c02cf550e8857d6e44583b50fb11895))
* remove obsolete authorization token references from charts ([880fc98](https://github.com/vriesdemichael/keycloak-operator/commit/880fc98637ff0e0e4c9471fd47162fc1d790b194)), closes [#102](https://github.com/vriesdemichael/keycloak-operator/issues/102)
* remove tests for deleted periodic_leadership_check function ([1ffcba0](https://github.com/vriesdemichael/keycloak-operator/commit/1ffcba0479decb4916a65262f58a46f84ab28ddd))
* remove webhook config template, let Kopf manage it ([57f2e3e](https://github.com/vriesdemichael/keycloak-operator/commit/57f2e3e82a68789d49b73fea4c8cac4e409133c2))
* restore correct test image tag for coverage collection ([6cb1675](https://github.com/vriesdemichael/keycloak-operator/commit/6cb16758ce97572f7b98396ea3b6960fb61e122f))
* update integration tests to use keycloak-prefixed annotations and finalizers ([0baf321](https://github.com/vriesdemichael/keycloak-operator/commit/0baf3213832ba63b853a06a34265244d976f54e6))
* use httpGet probe instead of exec with wget ([a6135d6](https://github.com/vriesdemichael/keycloak-operator/commit/a6135d6273e3a2377fd4b23e89342f00a2fb7acb))


### Documentation

* add admission webhook documentation and decision record ([396de85](https://github.com/vriesdemichael/keycloak-operator/commit/396de85863b5731e6e55ae2ac11ad21fbc45eeb1))
* bulk cleanup of authorizationSecretRef in chart READMEs ([7010d85](https://github.com/vriesdemichael/keycloak-operator/commit/7010d855084409af6a36e3d17fae465070afd6b9))
* **chart-operator:** add comprehensive README ([759081d](https://github.com/vriesdemichael/keycloak-operator/commit/759081deb9ac3cea713a0aac7843b15624165dd1))
* **chart-operator:** clarify single-tenant dev mode and add Keycloak deployment guidance ([eb3683d](https://github.com/vriesdemichael/keycloak-operator/commit/eb3683d42878d868f8857c726464a26a3a6702b2))
* **chart-operator:** remove all admission token documentation ([528ff2e](https://github.com/vriesdemichael/keycloak-operator/commit/528ff2e42b7f9f7925215c8ca30291142aedf539))
* final cleanup of remaining token references ([10f83eb](https://github.com/vriesdemichael/keycloak-operator/commit/10f83eb6fd7883b24c27e7d114c017f5e6284992))
* improve operator chart values documentation ([61e00a3](https://github.com/vriesdemichael/keycloak-operator/commit/61e00a39ab4818585d2dd15ad7b9fe90effbb6df))
* update helm chart READMEs and fix broken links ([dfb210d](https://github.com/vriesdemichael/keycloak-operator/commit/dfb210de7e222159830c5687e47e0e6d5eab354e))

## [0.3.1](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.3.0...chart-operator-v0.3.1) (2025-12-16)


### Bug Fixes

* **chart-operator:** update for operator v0.4.2 ([3e05ace](https://github.com/vriesdemichael/keycloak-operator/commit/3e05ace25ee4dad3555aa6f3e94487cbdd04c09a))

## [0.3.0](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.2.1...chart-operator-v0.3.0) (2025-12-03)


### ⚠ BREAKING CHANGES

* **chart-client+chart-operator+chart-realm:** Helm chart distribution moved to OCI registry

### Features

* **chart-client+chart-operator+chart-realm:** migrate to OCI registry in GHCR ([dc4f59c](https://github.com/vriesdemichael/keycloak-operator/commit/dc4f59c8f9d66be04cd7be6ae685fc714a8aad97))


### Bug Fixes

* allow test tags in operator chart schema ([6740046](https://github.com/vriesdemichael/keycloak-operator/commit/6740046724b30ca0d694bc85a40212db826fe596))
* allow test-* tags in operator chart schema ([8450c8f](https://github.com/vriesdemichael/keycloak-operator/commit/8450c8fa9135190af5c272b641e09327de3f4b56))
* **chart-operator:** remove outdated authorization token instructions ([6f2c190](https://github.com/vriesdemichael/keycloak-operator/commit/6f2c1907af74134fc727e132e4a4ca40a5300130))
* **operator:** database passwordSecret support and test fixes ([038fc18](https://github.com/vriesdemichael/keycloak-operator/commit/038fc18da190e8d99eb02222c89c59393129feee))
* **operator:** run quality checks and tests for code OR chart changes ([a9e8ad2](https://github.com/vriesdemichael/keycloak-operator/commit/a9e8ad27ff84b7b704fdbbe9c8c353057078070c))
* restore correct test image tag for coverage collection ([6cb1675](https://github.com/vriesdemichael/keycloak-operator/commit/6cb16758ce97572f7b98396ea3b6960fb61e122f))


### Documentation

* improve operator chart values documentation ([61e00a3](https://github.com/vriesdemichael/keycloak-operator/commit/61e00a39ab4818585d2dd15ad7b9fe90effbb6df))

## [0.2.1](https://github.com/vriesdemichael/keycloak-operator/compare/chart-operator-v0.2.0...chart-operator-v0.2.1) (2025-11-18)


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
