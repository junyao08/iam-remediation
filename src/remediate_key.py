import json
import logging
import os
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Support local Floci endpoint seamlessly when AWS_ENDPOINT_URL is injected
ENDPOINT_URL = os.environ.get("AWS_ENDPOINT_URL")
iam_client = boto3.client("iam", endpoint_url=ENDPOINT_URL)
sns_client = boto3.client("sns", endpoint_url=ENDPOINT_URL)

EXEMPT_USERS = {
    u.strip() for u in os.environ.get("EXEMPT_USERS", "").split(",") if u.strip()
}
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")


def log_structured(level: str, event_type: str, **kwargs) -> None:
    payload = {"event_type": event_type, **kwargs}
    msg = json.dumps(payload, default=str)
    if level == "ERROR":
        logger.error(msg)
    elif level == "WARNING":
        logger.warning(msg)
    else:
        logger.info(msg)


def lambda_handler(event, context):
    detail = event.get("detail") or {}
    event_name = detail.get("eventName")

    if event_name != "CreateAccessKey":
        log_structured("WARNING", "IGNORED_EVENT", event_name=event_name)
        return {"status": "ignored", "reason": "unexpected_event"}

    # Skip failed API attempts (e.g., user got AccessDenied and no key was created)
    if detail.get("errorCode"):
        log_structured(
            "INFO",
            "FAILED_API_CALL_SKIPPED",
            error_code=detail.get("errorCode"),
            actor=(detail.get("userIdentity") or {}).get("arn"),
        )
        return {"status": "skipped", "reason": "upstream_api_error"}

    response_elements = detail.get("responseElements") or {}
    access_key_obj = response_elements.get("accessKey") or {}
    request_params = detail.get("requestParameters") or {}
    user_identity = detail.get("userIdentity") or {}

    access_key_id = access_key_obj.get("accessKeyId")
    # Resolve target username across both admin-issued and self-service calls
    target_user = (
        access_key_obj.get("userName")
        or request_params.get("userName")
        or user_identity.get("userName")
    )
    actor_arn = user_identity.get("arn", "unknown")
    source_ip = detail.get("sourceIPAddress", "unknown")

    if not access_key_id or not target_user:
        log_structured("ERROR", "MALFORMED_PAYLOAD", detail=detail)
        raise ValueError("Missing accessKeyId or target_user in CloudTrail payload")

    # 1. Exempt Allowlist Check (e.g., breakglass-admin)
    if target_user in EXEMPT_USERS:
        log_structured(
            "WARNING",
            "EXEMPT_KEY_ISSUED",
            target_user=target_user,
            access_key_id=access_key_id,
            actor_arn=actor_arn,
            source_ip=source_ip,
            action_taken="ALLOWED_PER_POLICY",
        )
        _publish_alert(
            subject=f"[AUDIT] Exempt IAM Access Key Created: {target_user}",
            message={
                "severity": "MEDIUM",
                "status": "EXEMPT_ALLOWED",
                "target_user": target_user,
                "access_key_id": access_key_id,
                "actor_arn": actor_arn,
                "source_ip": source_ip,
            },
        )
        return {"status": "exempt", "user": target_user, "access_key_id": access_key_id}

    # 2. Immediate Containment for Non-Exempt Users (CIS 1.11 / NIST IR-4 / CSA IAM-08)
    try:
        iam_client.update_access_key(
            UserName=target_user,
            AccessKeyId=access_key_id,
            Status="Inactive",
        )
    except ClientError as exc:
        log_structured(
            "ERROR",
            "REMEDIATION_FAILED",
            target_user=target_user,
            access_key_id=access_key_id,
            error=str(exc),
        )
        raise  # Triggers Lambda/EventBridge retry and routes to SQS DLQ on exhaustion

    log_structured(
        "WARNING",
        "UNAUTHORIZED_KEY_DEACTIVATED",
        target_user=target_user,
        access_key_id=access_key_id,
        actor_arn=actor_arn,
        source_ip=source_ip,
        action_taken="INACTIVATED",
    )

    _publish_alert(
        subject=f"[SECOPS CONTAINED] Unauthorized IAM Key Deactivated: {target_user}",
        message={
            "severity": "HIGH",
            "status": "CONTAINED_INACTIVE",
            "target_user": target_user,
            "access_key_id": access_key_id,
            "actor_arn": actor_arn,
            "source_ip": source_ip,
        },
    )

    return {"status": "remediated", "user": target_user, "access_key_id": access_key_id}


def _publish_alert(subject: str, message: dict) -> None:
    if not SNS_TOPIC_ARN:
        return
    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],
            Message=json.dumps(message, indent=2),
        )
    except ClientError as exc:
        log_structured("ERROR", "SNS_PUBLISH_FAILED", error=str(exc))