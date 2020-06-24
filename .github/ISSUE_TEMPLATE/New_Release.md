---
name: New Release
about: Checklist of Release actions
---

<!-- Please only use this issue-type if you are creating a new release. -->

<!-- Set the issue title to 'New release checklist for version X.Y.Z'. -->

# New release checklist

## Before creating a GitHub tag

- [ ] Review the milestone issues, move unfinished to the next release, close the milestone.
- [ ] Update the `CHANGELOG.md`, review and merge the change.
- [ ] Assure testable packages are available for the `#core` channel on Slack.
- [ ] Ask for a volunteer to make a GitHub tag.
- [ ] Assure the ChangeLog shows up in the tag release notes.

## After creating a GitHub tag

- [ ] Create packages and upload to S3 (for download use only).
- [ ] Update the website with the new release and schema.
- [ ] Publish the website changes.
- [ ] Publish the new packages into the hosted repos.
- [ ] Bump or ping the [Homebrew Cask](https://github.com/Homebrew/homebrew-cask/blob/master/Casks/osquery.rb).
- [ ] Advertise the new release. :)
