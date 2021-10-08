# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to the following versioning pattern:

Given a version number MAJOR.MINOR.PATCH, increment:

- MAJOR version when **breaking changes** are introduced;
- MINOR version when **backwards compatible changes** are introduced;
- PATCH version when backwards compatible bug **fixes** are implemented.


## [Unreleased]

## [2.0.0] - 2021-10-08
### Added
- root imports: from ellipticcurve import PrivateKey, PublicKey, Signature, Ecdsa, File
### Changed
- return type of toDer() methods from str to bytes
- internal DER parsing structure for better maintainability, translatability and usability

## [1.1.1] - 2021-06-06
### Fixed
- unstable results on certain curves due to missing modulo operator on signature verification

## [1.1.0] - 2020-09-04
### Added
- recoveryId generation and encoding in Signatures

## [1.0.0] - 2020-04-13
### Added
- first official version
