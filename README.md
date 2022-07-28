# Coralogix-OCAPI

This application retrieves logs from Open Commerce OrderSearch api and sends them to your **Coralogix** account.

It requires the following parameters:

## Coralogix Configuration
* **CoralogixRegion** - Possible values are `Europe`, `Europe2`, `US`, `Singapore` or `India`. Choose `Europe` if your Coralogix account URL ends with `.com`, `US` if it ends with `.us` and `India` if it ends with `.in`. This is a **Coralogix** parameter and does not relate to your to your AWS region.
* **PrivateKey** - Can be found in your **Coralogix** account under `Settings` -> `Send your logs`. It is located in the upper left corner.
* **ApplicationName** - A mandatory metadata field that is sent with each log and helps to classify it.
* **SubsystemName** - A mandatory metadata field that is sent with each log and helps to classify it.

## OCAPI Configuration

* **OCAPIUsername** - A mandatory field, the OCAPI username. used to get authenticated.
* **OCAPIPassword** - A mandatory field, the OCAPI password. used to get authenticated.
* **OCAPIEndpoints** - A mandatory field, The full endpoint to the orderSearch api
* **SelectStatement** - The select statement to be used in the query. default to `(*)`

## Lambda Configuration

* **FunctionArchitecture** - Lambda function architecture [x86_64, arm64].
* **FunctionMemorySize** - Lambda function memory limit.
* **FunctionTimeout** - Lambda function timeout limit.
* **FunctionSchedule** - Lambda function schedule in minutes, the function will be invoked each X minutes. after deploy first invocation will be after X minutes.
* **NotificationEmail** - Failure notification email address.

## Script Configuration

* **LogsToStdout** - Send logs to stdout/cloudwatch. Possible values are `True`, `False`.



## License

This project is licensed under the Apache-2.0 License.
