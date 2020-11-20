import antbear.report
from antbear.reporters.base import BaseReporter


class TextReporter(BaseReporter):
    """
    Returns a summary of analysis results
    """

    @staticmethod
    def write_report(timeline, data_by_analyzer) -> str:
        s = "Summary:\n\n"
        for analyzer, data in data_by_analyzer.items():
            s += f"{analyzer!s}: {data['summary']['passed']} passed, {data['summary']['failed']} failed; {data['summary']['matched']} matched\n"
        return s
