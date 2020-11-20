import os
import io
import logging
import logging.config
import pickle
from typing import AnyStr, Iterable, Optional

import click

import antbear.config
import antbear.timeline
import antbear.report
from antbear.reporters.mermaid import MermaidJSReporter
from antbear.reporters.text import TextReporter
from antbear.reporters.json import JSONReporter


log_level = "DEBUG"
log_level = "INFO"

cfg = {
    "version": 1,
    "formatters": {
        "brief": {
            "format": "%(message)s",
            "datefmt": "",
        },
        "default": {
            "()": "logging.Formatter",
            "format": "%(asctime)s %(levelname)-8s %(name)-15s %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "formatter": "brief",
        },
    },
    "loggers": {
        "antbear.cli": {
            "handlers": ["console"],
            "level": log_level,
        },
        "antbear.http": {
            "handlers": ["console"],
            "level": log_level,
        },
        "antbear.read": {
            "handlers": ["console"],
            "level": log_level,
        },
        "antbear.timeline": {
            "handlers": ["console"],
            "level": log_level,
        },
        "antbear.readers.har": {
            "handlers": ["console"],
            "level": log_level,
        },
        "antbear.readers.pcap": {
            "handlers": ["console"],
            "level": log_level,
        },
        "antbear.reporters.mermaid": {
            "handlers": ["console"],
            "level": log_level,
        },
    },
}
logging.config.dictConfig(cfg)

report_type_to_reporter = {
    "text": TextReporter,
    "json": JSONReporter,
    "mermaid": MermaidJSReporter,
}

log = logging.getLogger(__name__)


@click.group()
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(
        exists=True,
        dir_okay=False,
        writable=False,
        readable=True,
    ),
    default="config.toml",
    show_default=True,
)
@click.pass_context
def cli(ctx: click.Context, config_path: str):
    """"""
    ctx.ensure_object(dict)

    ctx.obj["config"] = antbear.config.read_config_from_path(config_path)
    log.debug(f"loaded config {ctx.obj['config']}")


@cli.command("slurp")
@click.argument(
    "input_filename",
    nargs=-1,
    type=click.Path(
        exists=True,
        dir_okay=False,
        writable=False,
        readable=True,
    ),
)
@click.pass_context
def slurp(ctx: click.Context, input_filename: Iterable[AnyStr]) -> None:
    """
    Slurp events from input files into a unified timeline of events
    """
    log.debug(f"input filenames from CLI: {input_filename}")
    config = ctx.obj["config"]
    config_input_files = config["input_files"]
    log.debug(f"input filenames from config: {config_input_files}")
    inputs = input_filename if input_filename else config_input_files
    timeline_data_file = config["timeline_data_file"]
    timeline = antbear.timeline.Timeline(inputs)
    timeline.save(timeline_data_file)
    log.info(f"serialized {len(timeline)} events to {timeline_data_file}")


@cli.command("analyze")
@click.argument(
    "analyzer_name",
    nargs=-1,
    type=str,
)
@click.pass_context
def analyze(ctx: click.Context, analyzer_name: Iterable[str]) -> None:
    """
    Assess certain properties of captures from input filenames
    """
    config = ctx.obj["config"]
    timeline_data_file = config["timeline_data_file"]
    timeline = antbear.timeline.Timeline([])
    timeline.load(timeline_data_file)
    log.debug(f"analyzer names from CLI: {analyzer_name}")

    analyzers = antbear.config.load_analyzers(config)
    log.debug(f"loaded analyzers from config {analyzers}")
    if analyzer_name:
        log.debug(f"limiting analyzers to {analyzer_name}")
        analyzers = {
            config_analyzer_name: analyzer
            for config_analyzer_name, analyzer in analyzers.items()
            if config_analyzer_name in analyzer_name
        }

    results_by_analyzer = {}
    for analyzer_name, analyzer in analyzers.items():
        results = []
        for timestamp, (filename, i, data) in timeline.iter_type(analyzer.input_type):
            if not analyzer.can_analyze(data):
                log.debug(f"{analyzer} skipping analyzing data")
                continue
            results.append((timestamp, (filename, i, data), analyzer.analyze(data)))
            if analyzer.finished:
                log.debug(f"{analyzer} finished")
                break
        results_by_analyzer[analyzer] = results
    analysis_data_file = config["analysis_data_file"]
    pickle.dump(results_by_analyzer, open(analysis_data_file, "wb"))
    log.info(f"saved analysis results to {analysis_data_file}")


@cli.command("report")
@click.option("-v", "--verbose", count=True)
@click.option("-d", "--display", is_flag=True, default=False)
@click.option("-o", "--output", type=click.File("wb"), default="-")
@click.argument(
    "report_type",
    nargs=1,
    type=click.Choice(list(report_type_to_reporter.keys()), case_sensitive=False),
    default="text",
)
@click.pass_context
def report(
    ctx: click.Context, report_type: str, verbose: int, display: bool, output
) -> None:
    """
    Report traffic properties and analysis results
    """
    config = ctx.obj["config"]
    analysis_data_file = config["analysis_data_file"]
    timeline_data_file = config["timeline_data_file"]

    results_by_analyzer = pickle.load(open(analysis_data_file, "rb"))
    timeline = antbear.timeline.Timeline([])
    timeline.load(timeline_data_file)

    data_by_analyzer = {
        analyzer: {
            "results": results,
            "summary": None,
        }
        for analyzer, results in results_by_analyzer.items()
    }
    for analyzer, results in results_by_analyzer.items():
        exception_counter = antbear.report.tally_failed_results(r[-1] for r in results)
        data_by_analyzer[analyzer]["summary"] = {
            "passed": exception_counter[False],
            "failed": exception_counter[True],
            "matched": len(results),
        }

    # TODO: change reporters to write to an io.StringIO instead of returning a str

    # TODO: use verbosity level to show more detailed reports e.g. to display all failures
    # if True:
    #     log.warn(f"{analyzer} failed got a {type(result).__name__}")
    # else:
    #     log.info(f"verified {analyzer} got {result}")
    # pass

    # TODO: configure reporters
    reporter = report_type_to_reporter[report_type]
    report = reporter.write_report(timeline, data_by_analyzer)
    output.write(bytes(report, "utf-8"))

    if display and hasattr(reporter, "display_report"):
        reporter.display_report(report)


@cli.command("clean")
@click.option("-f", "--force", is_flag=True, default=False)
@click.pass_context
def clean(ctx: click.Context, force: bool) -> None:
    """
    Clean up antbear data and cache files
    """
    config = ctx.obj["config"]
    timeline_data_file = config["timeline_data_file"]
    analysis_data_file = config["analysis_data_file"]
    data_files = [timeline_data_file, analysis_data_file]
    for data_file in data_files:
        if force or click.confirm(f"delete {data_file!r}?", abort=True):
            os.remove(data_file)
            log.info(f"removed {data_file!r}")


if __name__ == "__main__":
    cli()
