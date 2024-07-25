# AWS SAW Monitoring And Automatic Analysis Architecture

This is a sample repository with a monitoring and automatic analysis example architecture using AWS SAW.

## Analysis SSM managed node issue

This is an architecture that automatically detects when an Amazon EC2 instance is not a managed node of AWS Systems Manager, performs problem analysis using SAW, and notifies the results in Slack. This repository is a sample solution included in an AWS support blog.

1.Register SlackWebHookUrl in Secrets Manager.

```
export SLACK_WEB_HOOK_URL="YOUR_SLACK_WEB_HOOK_URL"
export SECRET_NAME="YOUR_SECRET_NAME"

aws secretsmanager create-secret --name ${SECRET_NAME} --secret-string ${SLACK_WEB_HOOK_URL}
```

2. Build the artifact with AWS SAM

```bash
$ sam build
```

3. Deploy the artifact with AWS SAM, adding the `${SECRET_NAME}` for Name in Secrets Manager or SNS topic arn in as parameters.If the SNS topic is encrypted by KMS, the KMS key ARN is also specified as a parameter.

```
$ sam deploy --guided
```

4. Launch EC2 instance without instance profile.This instance cannot be a managed node.

5. Check the analysis results using AWS SAW in Slack after about 10 minutes have passed

6. To clean up the cloudformation stack

```bash
$ sam delete
```

7.To clean up the secrets managers

```
aws secretsmanager delete-secret --secret-id ${SECRET_NAME}
```

8. Terminate the instance launched in step 3