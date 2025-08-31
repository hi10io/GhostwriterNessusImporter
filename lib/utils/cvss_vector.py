from lib.types.cvss_vector import CVSSVectorPrefixes


def vector_prefix(value: str):

    if ":" not in value:
        raise ValueError(f"Invalid CVSS vector: {value}")

    if "#" in value:
        value = value.split("#")[1]

    value = value.replace("CVSS", "")
    value = value.replace("#", "")
    value = value.split(":")[0]

    return value.strip("/").upper()


def vector_value(prefix: str, value: str):
    return ":".join([prefix, value.split(":")[1].upper().strip("/")])

def process_cvss_vector(parts: list[str]):

    # Default values for CVSS 3.1 (Will change if it's CVSS 2)
    attack_vector = "AV:P"
    attack_complexity = "AC:L"
    privileges_required = "PR:N"
    user_interaction = "UI:N"
    scope = "S:U"
    confidentiality_impact = "C:N"
    integrity_impact = "I:N"
    availability_impact = "A:N"

    cvss_version = "CVSS:3.1"  # Default version

    for vector in parts:
        if vector.upper().startswith("CVSS2#"):
            cvss_version = "CVSS2#"  # Mark as CVSS 2.0
            privileges_required = "Au:N"  # Change to CVSS 2 format
            continue
        elif vector.upper().startswith("CVSS:"):
            cvss_version = vector  # Use detected version (CVSS:3.0 or CVSS:3.1)
            continue

        p = vector_prefix(vector)
        match p:
            case CVSSVectorPrefixes.ATTACK_VECTOR:
                attack_vector = vector_value("AV", vector)
            case CVSSVectorPrefixes.ATTACK_COMPLEXITY:
                attack_complexity = vector_value("AC", vector)
            case CVSSVectorPrefixes.PRIVILEGES_REQUIRED | CVSSVectorPrefixes.AUTH_REQUIRED:
                if cvss_version == "CVSS2#":
                    privileges_required = vector_value("Au", vector)  # Use `Au` for CVSS2
                else:
                    privileges_required = vector_value("PR", vector)  # Use `PR` for CVSS3
            case CVSSVectorPrefixes.USER_INTERACTION:
                if cvss_version != "CVSS2#":  # CVSS2 does not have UI
                    user_interaction = vector_value("UI", vector)
            case CVSSVectorPrefixes.SCOPE:
                if cvss_version != "CVSS2#":  # CVSS2 does not have Scope
                    scope = vector_value("S", vector)
            case CVSSVectorPrefixes.CONFIDENTIALITY_IMPACT:
                confidentiality_impact = vector_value("C", vector)
            case CVSSVectorPrefixes.INTEGRITY_IMPACT:
                integrity_impact = vector_value("I", vector)
            case CVSSVectorPrefixes.AVAILABILITY_IMPACT:
                availability_impact = vector_value("A", vector)
            case _:
                raise ValueError(f"Invalid CVSS vector prefix: {p} for vector {vector}")

    # If it's CVSS2, return in CVSS2 format
    if cvss_version == "CVSS2#":
        return "/".join(
            [
                cvss_version,
                attack_vector,
                attack_complexity,
                privileges_required,  # CVSS2 uses `Au`
                confidentiality_impact,
                integrity_impact,
                availability_impact,
            ]
        )
    
    # Otherwise, return in CVSS 3.x format
    return "/".join(
        [
            cvss_version,
            attack_vector,
            attack_complexity,
            privileges_required,
            user_interaction,
            scope,
            confidentiality_impact,
            integrity_impact,
            availability_impact,
        ]
    )
