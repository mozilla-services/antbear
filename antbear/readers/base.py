import datetime
from typing import Any, Generator, Iterable, Set, Tuple


class BaseReader:
    """
    Base class for reading an input file type

    A Reader implementation should define the following static methods:

    .file_suffixes
    .read_paths
    """

    @staticmethod
    def file_suffixes() -> Set[str]:
        """
        Returns file suffixes the Reader can read (everything after the dot e.g. txt, json, pcap)
        """
        raise NotImplementedError()

    @staticmethod
    def read_path(
        file_path: str,
    ) -> Generator[Tuple[datetime.datetime, Any], None, None]:
        """
        Takes a path to a file and returns loaded data
        """
        raise NotImplementedError()
