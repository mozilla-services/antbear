import json

import antbear.report
from antbear.reporters.base import BaseReporter


class JSONReporter(BaseReporter):
    """
    Returns JSON-encoded analyzer aggregate statistics as a str.

    """

    @staticmethod
    def write_report(timeline, data_by_analyzer) -> str:
        return json.dumps(
            {
                "summary": {
                    str(analyzer): data["summary"]
                    for analyzer, data in data_by_analyzer.items()
                }
            }
        )
