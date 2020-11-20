import importlib
import logging
from typing import Any, Dict, Tuple

import toml

from antbear.analyzers.base import BaseAnalyzer


log = logging.getLogger(__name__)


default_timeline_data_file = ".antbear.timeline.pickle"
default_analysis_results_data_file = ".antbear.analysis.pickle"


def read_config_from_path(config_path: str) -> dict:
    with open(config_path, "r") as config_file:
        config = toml.load(config_file)["antbear"]
        if "timeline_data_file" not in config:
            config["timeline_data_file"] = default_timeline_data_file
        if "analysis_data_file" not in config:
            config["analysis_data_file"] = default_analysis_results_data_file
        return config
    # TODO: set/update logging config


def load_analyzers(config: Dict[str, Any]) -> Dict[str, BaseAnalyzer]:
    analyzer_module = importlib.import_module(config["analyzers"]["import_path"])
    analyzers = {
        analyzer_name: getattr(analyzer_module, analyzer_name)(
            config.get(analyzer_name, {})
        )
        for analyzer_name in config["analyzers"]["names"]
    }
    return analyzers
