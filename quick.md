Add a cli argument for "--auth-count-sample", "-ac". Also add a TUI hotkey to execute the same function. When it is specified, the tool will asynchronously complete the following tasks:
- pull the latest logs matching the log-location that is specified on launch
  - cwl: For each log group in each region, download the latest 10,000 logs with no pagination at all
  - s3: For each s3 bucket used for waf logging, download the just the last s3 json.gzip file
  - waf: For each waf in each region, download 500 log sample set
- save all results into the sqlite db for later use
- make sure that all calculations for showing how many logs with authentications exist in a waf log are properly updated based on the sample data

