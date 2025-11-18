# Changelog

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
