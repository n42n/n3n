# Release Process

## Regular release process
First, ensure that all the changes to be included in the release have been
committed and merged in to the main branch of the public repository.

Next, locally:
- edit `VERSION` file to new version, e.g. `4.0.1`
- `git add VERSION`
- `git commit -m "Bump version file"`
- `git tag -a 4.0.1 # Add the changelog while creating the tag`
- `git push --tags`

Then, on github:
- Wait for CI jobs to run and turn green
- Create new release from the new tag
- Paste in the same changelog as used in the tag
- Automated CI jobs should start
- Once CI is green, the assets will be automatically added to the release

### TODO - improving the process

- The VERSION file is intended to stop foot-gun events for the cases where no
  git checkout is being used.  Is this still useful?
- The changelog is added in two places.  This is not the intent of the
  automation, but github might have changed something
- The CI was intended to automatically run when the tag is uploaded and then
  automatically create the github release.  The github triggers are not
  working for that case and should be investigated/fixed

After the above TODO items are addressed, the process could be as simple as
create the annotated tag, push the tag, wait for the CI to run.

### TODO - dpkg built versions show as dirty

- a skeleton debian changelog is committed to the repository and is
  automatically appended to as part of the dpkg build.  However, this means
  that any dpkg build is going to show up as a dirty build.

## Stable patch release notes

- Semver
- Any release is supposed to be a 0 patchlevel release (eg: 4.1.0) - though any
  issues found during the release process may cause a higher patchlevel to
  be used for the release
- New features or code can immediately start being committed to the main
  branch after a release.  (Any dev code compiled after this will have a
  version number like 4.1.0-n-gZZZZ, clearly marking it as part of a non
  release.
- If a bug is found after significant dev work has been committed, but the
  bugfix should be backported to a previous release, a release branch is
  created (eg: "n3n-4.1.y") the bugfix is committed in that branch and the
  release process with an incremented patchlevel will be done from that branch.
