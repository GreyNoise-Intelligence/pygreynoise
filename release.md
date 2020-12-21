# Release Instructions

The following outlines the process to push a release of this repo to PyPi as a new released version.

### Prereqs

Ensure that you advbumpversion installed.  This is the tool that the repo is configured to use to
officially bump and tag a version.

`pip install advbumpversion`


### Notes

The file `.bumpversion.cfg` contains the information that used by advbumpversion to update version
numbers in all appropriate places.  If the repo version number is added in any new locations,
ensure this config file is updated.

### CHANGELOG Setup

When adding new entries to the CHANGELOG, it is important ensure that the following header is used:

This should be at the top of the file, right under the page header.
```
=========
Changelog
=========

Version `dev`_
================
**Date**: unreleased
```

The file also needs to conclude with the following:
```
.. _`dev`: https://github.com/GreyNoise-Intelligence/pygreynoise/compare/v0.5.0...HEAD
```
Ensure that the end of the line is from the previous version to HEAD

If these are missing, the `reset_changelog.py` script can be used to add them.

## Create a new branch for release

Before running bumpversion, a new branch needs to be created so the changes bumpversion makes can
be pushed to a PR.

### Bumpversion Commands

#### Dry Run

It is recommended that the --dry-run option always be used to confirm changes before the actual
command is run.  This command can be used to validate all places that advbumpversion will make
changes.

Example: `bumpversion --dry-run --verbose patch`

#### Patch Release Command
The following will publish a patch release, for example 0.5.0 to 0.5.1

`bumpversion patch`

#### Minor Release Command
The following will publish a patch release, for example 0.5.0 to 0.6.0

`bumpversion minor`

#### Major Release Command
The following will publish a patch release, for example 0.5.0 to 1.0.0

`bumpversion major`

## Push branch without tags

Once bumpversion is successful, push the branch to Github and create a PR for the version update

## Validation PR and merge

Once the PR is created CircleCI should begin the validation.  Use CircleCI to validate a successful
build then merge the PR into master.

## Push tag and validate release

Once the PR is merged, push the new tag, then use CircleCI to confirm the new tag builds
successfully and pushes to PyPI

## Prep for next version

Run the ``reset_changelog.py`` script to add in the default sections needed in CHANGELOG.rst to
allow for bumpversion to work for the next release.  This can be included in the next PR when
prepping for next version.
