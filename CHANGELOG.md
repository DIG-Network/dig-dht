# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.5.2] - 2026-07-24

### Features
- **service:** Live add_peer/remove_peer routing seed (#1574) (#12)

## [0.5.1] - 2026-07-23

### Chores
- **deps:** Bump dig-nat 0.10 -> 0.11 (cascade #1550) — release 0.5.1 (#11)

## [0.5.0] - 2026-07-22

### Chores
- **deps:** Adopt dig-nat 0.10 (cascade #1494) — release 0.5.0 (#10)

## [0.4.1] - 2026-07-22

### CI
- **lockfile:** Gate Cargo.lock own-version + --locked in ci (#9)

## [0.4.0] - 2026-07-21

### Features
- **dig-dht:** Holdings ingest + active retract + holder-set query (#1424) (#8)

## [0.3.0] - 2026-07-21

### Chores
- **dig-dht:** Bump dig-nat to 0.8 (cascade) (#7)

## [0.2.2] - 2026-07-20

### Chores
- **deps:** Bump dig-nat to 0.7 (full NAT ladder unification, #836) (#6)

## [0.2.1] - 2026-07-20

### Chores
- **deps:** Bump dig-nat to 0.6.0 (dig-tls cert cutover) (#5)

## [0.2.0] - 2026-07-18

### Features
- **dig-dht:** Derive address family ordering from canonical dig-ip crate (#4)

## [0.1.3] - 2026-07-18

### Features
- **dig-dht:** Bump to dig-nat 0.3 (latest) (#947) (#3)

## [0.1.2] - 2026-07-17

### Bug Fixes
- **deps:** Resolve dig-nat 0.2 from crates.io (#2)

## [0.1.1] - 2026-07-12

### Bug Fixes
- **deps:** Re-resolve DIG git deps to rewritten (co-author/signed) revs

### CI
- Re-arm crates.io auto-publish on version tag (token in org secrets; auto-publish-everything #230)- Add flaky-test management (#489) (#1)

## [0.1.0] - 2026-07-04

### CI
- Enforce version increment in PRs (package.json / Cargo.toml)- Enforce Conventional Commits with commitlint on PRs- Enforce Conventional Commits with commitlint on PRs- Release automation (git-cliff changelog + tag on merge); publish is manual workflow_dispatch (#230)

### Chores
- **changelog:** Add git-cliff config for Conventional-Commit changelog


