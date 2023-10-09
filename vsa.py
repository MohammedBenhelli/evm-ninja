from binaryninja import (
    BackgroundTaskThread,
    BinaryDataNotification,
    BinaryView,
    Function,
    Settings,
    SettingsScope,
    log_debug,
)

from .cfg import CFG
from .classes import _Thread
from .constants import LOGGER_SYMBOL


def run_vsa(thread: _Thread, view: BinaryView, function: Function) -> None:
    cfg: CFG = function.session_data.cfg
    cfg_function = cfg.functions[function.start]
    thread.task.progress = f"[VSA {LOGGER_SYMBOL}] Analyzing function {cfg_function.name} at {function.start}"

    # First run that get obvious JUMPDEST in function's blocks and add a branche
    for block in cfg_function.blocks:
        for edge in block.non_dyn_jumpdests:
            log_debug(f"{cfg_function.name} function have an edge to {edge} block", LOGGER_SYMBOL)
        function.set_auto_indirect_branches(
            source=block.end.location,
            branches=[(view.arch, edge) for edge in block.non_dyn_jumpdests]
        )
        dest_branches = function.get_indirect_branches_at(block.end.location)
        log_debug(f"{cfg_function.name} dest_branches {dest_branches}", LOGGER_SYMBOL)

    if function.start == 0:
        max_function_size, _ = Settings().get_integer_with_scope(
            "analysis.limits.maxFunctionSize",
            scope=SettingsScope.SettingsDefaultScope,
        )
        view.max_function_size_for_analysis = max_function_size if max_function_size else 65536


class VsaTaskThread(BackgroundTaskThread):
    def __init__(self: "VsaTaskThread", view: BinaryView, function: Function) -> None:
        log_debug(f"Running VSA for {function.name}", LOGGER_SYMBOL)
        BackgroundTaskThread.__init__(self, f"Running VSA for {function.name}", False)
        self.view = view
        self.function = function

    def run(self: "VsaTaskThread") -> None:
        run_vsa(self.thread, self.view, self.function)


class VsaNotification(BinaryDataNotification):
    def function_added(self: "VsaNotification", view: BinaryView, function: Function) -> None:
        vsa_task = VsaTaskThread(view, function)
        vsa_task.start()
