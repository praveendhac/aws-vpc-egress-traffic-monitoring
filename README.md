# Egress FlowLogs Monitoring
Service to read AWS egress flow logs which are in the form of netflow logs, add extrainformation 
like instance name/type/role and push it to Sensu client

Configure below ENV variables
```
VPC_LOG_GROUP_NAME
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
START_READING_LOGS_EPOCHTIME
AWS_DEFAULT_REGION
SLEEP
AWS_VPC_ID
```
