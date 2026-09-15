# OCSF Constants and mappings

OCSF_CLASSES = {
    "Unknown": 0,
    "Process Activity": 1007,
    "Security Finding": 2001,
    "Account Change": 3001,
    "Authentication": 3002,
    "Network Activity": 4001,
    "HTTP Activity": 4002,
    "File Activity": 1001,
}

OCSF_CATEGORIES = {
    "System Activity": "system",
    "Findings": "findings",
    "Identity & Access Management": "iam",
    "Network Activity": "network",
    "Discovery": "discovery",
    "Other": "other"
}

def get_ocsf_class_uid(class_name: str) -> int:
    return OCSF_CLASSES.get(class_name, 0)
