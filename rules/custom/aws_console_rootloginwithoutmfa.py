from panther_aws_helpers import aws_rule_context
from panther_ipinfo_helpers import geoinfo_from_ip_formatted


def rule(event):
    """
    Alert when the AWS root account logs into the console without MFA.

    Checks:
    1. Event is a ConsoleLogin
    2. Identity type is Root
    3. Login was successful
    4. MFA was NOT used (field is not "Yes")
    """
    if event.get("eventName") != "ConsoleLogin":
        return False

    if event.deep_get("userIdentity", "type") != "Root":
        return False

    if event.deep_get("responseElements", "ConsoleLogin") != "Success":
        return False

    # MFAUsed is either "Yes" or "No"; absence also means no MFA
    mfa_used = event.deep_get("additionalEventData", "MFAUsed", default="No")
    return mfa_used != "Yes"


def title(event):
    account_id = event.get("recipientAccountId", "Unknown Account")
    geo = geoinfo_from_ip_formatted(event, "sourceIPAddress")
    return f"AWS root account logged in WITHOUT MFA from ({geo}) in account [{account_id}]"


def dedup(event):
    # Each root login without MFA is a unique high-severity event
    return "-".join([
        event.get("recipientAccountId", "unknown"),
        "RootLoginWithoutMFA",
        event.get("eventTime", "unknown"),
    ])


def alert_context(event):
    ctx = aws_rule_context(event)
    ctx.update({
        "mfa_used": event.deep_get("additionalEventData", "MFAUsed", default="No"),
        "login_url": event.deep_get("additionalEventData", "LoginTo", default=""),
        "mobile_version": event.deep_get("additionalEventData", "MobileVersion", default="No"),
        "root_arn": event.deep_get("userIdentity", "arn", default=""),
        "account_id": event.get("recipientAccountId", ""),
        "source_ip": event.get("sourceIPAddress", ""),
        "user_agent": event.get("userAgent", ""),
        "event_time": event.get("eventTime", ""),
        "aws_region": event.get("awsRegion", ""),
    })
    return ctx
