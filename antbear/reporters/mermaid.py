import base64
import json
import webbrowser
import logging

from antbear.http import Request, Response, get_requst_src_dest
import antbear.report
from antbear.reporters.base import BaseReporter


log = logging.getLogger(__name__)


def is_valid_sequence_diagram_actor(actor: str) -> bool:
    return ":" not in actor


class MermaidJSReporter(BaseReporter):
    """
    Returns a JS string for a mermaid.js sequence diagram

    https://mermaid-js.github.io/mermaid/#/sequenceDiagram
    """

    @staticmethod
    def write_report(timeline, data_by_analyzer) -> str:
        events = []
        for timestamp, (reader, filename, i, data) in timeline:
            if isinstance(data, Request):
                tmp = get_requst_src_dest(data)
                if tmp is None:
                    continue
                src, dest = tmp
                strip_scheme = lambda s: s.rsplit("://", 1)[-1]
                src, dest = strip_scheme(src), strip_scheme(dest)
                if not (
                    is_valid_sequence_diagram_actor(src)
                    and is_valid_sequence_diagram_actor(dest)
                ):
                    log.warn(
                        f"skipping {data} mermaid.js cannot render actor with colon in sequence diagram"
                    )
                    continue

                events.append(f"{src}->>{dest}: {data.method} {data.uri}")
            elif isinstance(data, Response):
                # Alice<<-John: I'm fine
                if not getattr(data, "answers", None):
                    log.warn(f"skipping {data} could not find a request it answers")
                    continue

                tmp = get_requst_src_dest(data.answers)
                if tmp is None:
                    continue
                dest, src = tmp
                src, dest = strip_scheme(src), strip_scheme(dest)
                if not (
                    is_valid_sequence_diagram_actor(src)
                    and is_valid_sequence_diagram_actor(dest)
                ):
                    log.warn(
                        f"skipping {data} mermaid.js cannot render actor with colon in sequence diagram"
                    )
                    continue
                # TODO: handle syntax errors from response lines containing dashes?
                events.append(f"{dest}<<-{src}: {data.status} {data.reason}")

        # NB: - is not allowed in participant (but is allowed in the as field)
        # https://mermaid-js.github.io/mermaid-live-editor/#/edit/eyJjb2RlIjoic2VxdWVuY2VEaWFncmFtXG4gICAgcGFydGljaXBhbnQgYXBpIGFzIFwiYXBpLWFjY291bnRzLnN0YWdlLm1vemF3cy5uZXRcIlxuICAgICUlIGNhdXNlcyBzeW50eCBlcnJvclxuICAgICUlIHBhcnRpY2lwYW50IGFwaS1hY2NvdW50cy5zdGFnZS5tb3phd3MubmV0IiwibWVybWFpZCI6eyJ0aGVtZSI6ImRlZmF1bHQifSwidXBkYXRlRWRpdG9yIjpmYWxzZX0
        # refs: https://github.com/mermaid-js/mermaid/issues/1228
        #
        # hosts = "\n    ".join(f'participant "{host}"' for host in hosts)
        events = "\n    ".join(events)
        return fr"""
sequenceDiagram

    {events}
"""

    @staticmethod
    def display_report(report: str) -> None:
        diagram_json = json.dumps(
            {"code": report, "mermaid": {"theme": "default"}, "updateEditor": False}
        )
        b64_diagram_json = base64.urlsafe_b64encode(
            bytes(diagram_json, "utf-8")
        ).decode("utf-8")
        # breakpoint()
        url = f"https://mermaid-js.github.io/mermaid-live-editor/#/edit/{b64_diagram_json}"
        log.info(f"opening a tab with {url}")
        webbrowser.open_new_tab(url)
