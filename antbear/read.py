import logging
import itertools
import pathlib
from typing import Dict, Iterable

import antbear.readers.har
import antbear.readers.pcap


log = logging.getLogger(__name__)


def get_readers_by_suffix(
    readers: Iterable[antbear.readers.base.BaseReader],
) -> Dict[str, antbear.readers.base.BaseReader]:
    reader_by_suffix = {}
    for reader in readers:
        for suffix in reader.file_suffixes():
            reader_by_suffix[f".{suffix}"] = reader
    return reader_by_suffix


def read_files(input_file_paths: Iterable[str]):
    reader_by_suffix = get_readers_by_suffix(
        [
            antbear.readers.pcap.PCAPReader,
            antbear.readers.har.HARReader,
        ]
    )
    for suffix, reader in reader_by_suffix.items():
        log.debug(f"reading {suffix} files with {reader.__name__}")

    for suffix, files in itertools.groupby(
        input_file_paths, lambda p: pathlib.Path(p).suffix
    ):
        if suffix not in reader_by_suffix:
            for input_file in files:
                log.warn(
                    f"cannot read file extension: {suffix!r}; skipping {input_file!r}"
                )
            continue

        for input_file in files:
            yield input_file, reader_by_suffix[suffix], reader_by_suffix[
                suffix
            ].read_path(input_file)
