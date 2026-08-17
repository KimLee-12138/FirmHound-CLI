"""CLI entry point for FSA."""

import click


@click.group()
@click.option("--config", default="config/dev.yaml", help="Path to YAML config.")
@click.pass_context
def main(ctx: click.Context, config: str) -> None:
    """Firmware Security Agent CLI."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = config


@main.command()
@click.argument("firmware_path")
@click.pass_context
def smoke(ctx: click.Context, firmware_path: str) -> None:
    """Run a smoke test on a firmware sample."""
    click.echo(f"Smoke test: config={ctx.obj['config']}, firmware={firmware_path}")


if __name__ == "__main__":
    main()
