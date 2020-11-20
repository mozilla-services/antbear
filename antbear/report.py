from collections import Counter
from typing import Any, Iterable


def is_exception(result) -> bool:
    return isinstance(result, Exception)


def tally_failed_results(results: Iterable[Any]):
    return Counter(is_exception(result) for result in results)
