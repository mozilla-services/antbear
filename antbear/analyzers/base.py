from typing import Any, Dict


class BaseAnalyzer:
    """
    Base class for analyzing timeline events

    An Analyzer implementation should define the following static methods:

    .filter

    TODO: filter/match (all / any / count) with result e.g. too many errors or first non-exception
    """

    finished = False

    def __init__(self, config: Dict[str, Any]):
        pass

    def can_analyze(self, data) -> bool:
        raise NotImplementedError()

    def analyze(self, data) -> Any:
        raise NotImplementedError()
