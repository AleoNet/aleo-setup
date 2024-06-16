# Shared structures and functions for Aleo setup 1

## Description

There are some data structures which we reuse in coordinator,
contributor and verifier. For example, public settings of a verifier.
This package is a home of such structures. It may as well help
to specify a communication protocol a bit better, for example
which format of message encoding we are using, and to contain
the encode/decode functions for the shared structures.

## Usage

Check the doc comments provided by the data structures and helper functions.
Must be used with compatible versions of **serde** and **serde_json**.

## Error types

Right now the errors in encode/decode functions are the same as those returned
by **serde_json**
