<!--

Thanks for filing an issue! If this is a question or feature request, just delete
everything here and write out the request, providing as much context as you can.

If this is a usage question and not a bug report, consider asking it in one of our community supported channel. 

Slack: https://osquery-slack.herokuapp.com/
Stack Overflow: https://area51.stackexchange.com/proposals/117450/osquery
Reddit: https://www.reddit.com/r/osquery/

-->

### What version of `osquery` are you using? What operating system. Be specific.
You Can run this query to get the necessary details: 
```
osqueryd -S --line 'SELECT oi.version as osquery_version, os.version AS os_version, os.build AS os_build, os.platform AS os_platform FROM os_version AS os JOIN osquery_info as oi;'
```

### What did you do?

### What did you expect to see?

### What did you see instead?
