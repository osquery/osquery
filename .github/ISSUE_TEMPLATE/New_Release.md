---
name: New Release
about: Checklist of Release actions
title: ''
labels: ''
assignees: ''

---

<!-- Please only use this issue-type if you are creating a new release. -->

<!-- Set the issue title to 'New release checklist for version X.Y.Z'. -->

# New release checklist

## Before creating a GitHub tag

- [ ] Review the [milestones](https://github.com/osquery/osquery/milestones), move unfinished issues to the next release, close the milestone.
- [ ] Ask for a Technical Steering Committee member to make a GitHub tag.
- [ ] Assure that testable packages are available on the Releases page, and announce to the `#core` channel on Slack.

## After creating a GitHub tag

- [ ] If the `CHANGELOG.md` hasn't already been updated, update it in a new Pull Request, review and merge it. It should reflect everything done up to the tagged version commit.
- [ ] Assure that the ChangeLog shows up in the [tag release notes](https://github.com/osquery/osquery/tags).
- [ ] Create packages and upload to S3 (for download use only).
- [ ] Update the website with the new release and schema.
- [ ] Publish the website changes.
- [ ] Publish the new packages into the hosted repos.
- [ ] Bump or ping the [Homebrew Cask](https://github.com/Homebrew/homebrew-cask/blob/master/Casks/osquery.rb).
- [ ] Advertise the new release. :)
