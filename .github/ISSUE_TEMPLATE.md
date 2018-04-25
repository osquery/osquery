<!--

Thanks for filing an issue!

If this is a usage or deployment question, and not a bug report,
please asking it in one of our community supported channel.

StackOverflow: https://stackoverflow.com/tags/osquery
Reddit: https://www.reddit.com/r/osquery/

Slack: https://osquery-slack.herokuapp.com/

If this is a feature request or request for comment, just delete everything here and write
out the request, providing as much context as you can.

-->

### What version of `osquery` are you using? What operating system. Be specific.
You can run this query to get the necessary details: 
```
osqueryd -S --line 'SELECT oi.version as osquery_version, os.version AS os_version, os.build AS os_build, os.platform AS os_platform FROM os_version AS os JOIN osquery_info as oi;'
```

### What have you already tried?

### What did you expect to see?

### What did you see instead?
