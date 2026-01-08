<p align="center">
    <h1 align="center">
        gowntools
    </h1>
</p>
<p align="center">
    <strong>
        Go library for CTF pwn challenges and binary exploitation
    </strong>
</p>
<p align="center">
    <a href="#quick-start">Quick Start</a> •
    <a href="#documentation">Docs</a>
</p>
<p align="center">
    <a href="https://github.com/Jacute/gowntools/actions">
        <img src="https://github.com/Jacute/gowntools/actions/workflows/tests.yml/badge.svg" alt="CI Status">
    </a>
    <a href='https://badge.coveralls.io/github/Jacute/gowntools?branch=main'>
        <img src='https://badge.coveralls.io/repos/github/Jacute/gowntools/badge.svg?branch=main' alt='Coverage Status' />
    </a>
    <a href="https://github.com/Jacute/gowntools/releases">
        <img alt="Release" src="https://img.shields.io/github/v/release/Jacute/gowntools">
    </a>
</p>

## Dependencies

For use debug functions:

- gdb
- terminal like tmux, xterm or gnome-terminal

For finding gadgets:

- nasm

## Quick start

1. Install library

`go get github.com/Jacute/gowntools@latest`

2. Install cli tool

`go install github.com/Jacute/gowntools/cmd/gowncli@latest`

3. Check [examples](./examples/)

## Documentation

> ⚠️ **Now library supports to analyze only ELF binaries**

https://pkg.go.dev/github.com/Jacute/gowntools
