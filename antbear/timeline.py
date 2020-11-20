from datetime import datetime
import logging
import pickle
from typing import Any, Dict, Generator, Iterable, Tuple, Optional

import scapy.plist
from sortedcontainers import SortedKeyList

import antbear.read


log = logging.getLogger(__name__)


class Timeline(SortedKeyList):
    """A Timeline stores a sequence of timestamped data from input files

    It provides iterators over data types

    converting the data
    between types where possible.
    """

    def __init__(self, input_files: Iterable[str]) -> None:
        super().__init__(self, key=lambda t: t[0])

        for file_index, (input_filename, reader, data_generator) in enumerate(
            antbear.read.read_files(input_files)
        ):
            for i, (timestamp, packet) in enumerate(data_generator):
                self.add(
                    (
                        timestamp,
                        (reader, input_filename, i, packet),
                    )
                )
            log.info(f"read {i} events from {input_filename}")

    def count_of_type(self, data_type) -> int:
        return len(list(self.iter_type(data_type)))

    def iter_type(
        self, data_type
    ) -> Generator[Tuple[datetime, Tuple[str, int, Any]], None, None]:
        for timestamp, (reader, filename, i, data) in self:
            # log.error(f"have data type {type(data)} (want {data_type})")
            if not isinstance(data, data_type):
                if not reader.can_convert(type(data), data_type):
                    log.debug(f"skipping data type {type(data)} (want {data_type})")
                    continue
                else:
                    converted = reader.convert(data, data_type)
                    if isinstance(converted, Exception):
                        log.warn(
                            f"{reader} failed to convert data type {type(data)} to {data_type}: {converted}"
                        )
                        continue
                    yield timestamp, (filename, i, converted)

            yield timestamp, (filename, i, data)

    def save(self, output_path: str) -> None:
        pickle.dump(list(self), open(output_path, "wb"))

    def load(self, input_path: str) -> None:
        # TODO: test save then load results in the same timeline data
        for event in pickle.load(open(input_path, "rb")):
            self.add(event)
        log.info(f"read {len(self)} events from {input_path}")
