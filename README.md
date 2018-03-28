# haveibeenpwned

[![GitHub release](http://img.shields.io/github/release/jakewarren/haveibeenpwned.svg?style=flat-square)](https://github.com/jakewarren/haveibeenpwned/releases])
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](https://github.com/jakewarren/haveibeenpwned/blob/master/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/jakewarren/haveibeenpwned)](https://goreportcard.com/report/github.com/jakewarren/haveibeenpwned)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=shields)](http://makeapullrequest.com)

> library and cmd-line client for the HIBP API

## Install
### Option 1: Binary

Download the latest release from [https://github.com/jakewarren/haveibeenpwned/releases/latest](https://github.com/jakewarren/haveibeenpwned/releases/latest)

### Option 2: From source

```
go get github.com/jakewarren/haveibeenpwned
```

## Usage

```
❯ haveibeenpwned -h
usage: haveibeenpwned [<flags>] <email>

Un-official API client for haveibeenpwned.com.

Optional flags:
  -h, --help                     Show context-sensitive help (also try --help-long and --help-man).
  -d, --debug                    print debug info
  -f, --filter-date=FILTER-DATE  only print breaches released after specified date
  -s, --silent                   suppress response message, only display results
  -V, --version                  Show application version.

Args:
  <email>  the email address to lookup.
```

## Changes

All notable changes to this project will be documented in the [changelog].

The format is based on [Keep a Changelog](http://keepachangelog.com/) and this project adheres to [Semantic Versioning](http://semver.org/).

## License

MIT © 2018 Jake Warren

[changelog]: https://github.com/jakewarren/haveibeenpwned/blob/master/CHANGELOG.md