import click
from isis_attack.cli.commands import register_commands


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """ISIS 协议攻击模拟器 -- 支持 13 种 ISIS 攻击类型"""
    pass


register_commands(cli)


if __name__ == "__main__":
    cli()
