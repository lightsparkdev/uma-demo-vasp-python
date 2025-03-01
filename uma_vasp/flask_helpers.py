from typing import NoReturn

from uma import ErrorCode, UmaException


def abort_with_error(
    reason: str,
    error_code: ErrorCode,
) -> NoReturn:
    print(f"Aborting with error {error_code.value.http_status_code}: {reason}")
    raise UmaException(reason, error_code)
