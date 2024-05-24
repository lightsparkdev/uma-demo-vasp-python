from typing import NoReturn, Optional

from uma_vasp.uma_exception import UmaException


def abort_with_error(status_code: int, reason: str, code: Optional[str] = None) -> NoReturn:
    print(f"Aborting with error {status_code}: {reason}")
    raise UmaException(reason, status_code, code)