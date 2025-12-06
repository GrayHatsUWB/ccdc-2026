import re
from enum import Enum
from typing import Set, List, Dict, Any, cast


class SystemModuleException(Exception):
    pass


class SystemModuleState(Enum):
    INVALID = 0
    LIVE = 1
    LOADING = 2
    UNLOADING = 3

    @staticmethod
    def from_str(value: str):
        value = value.lower()
        if value == "live":
            return SystemModuleState.LIVE
        elif value == "loading":
            return SystemModuleState.LOADING
        elif value == "unloading":
            return SystemModuleState.UNLOADING
        return SystemModuleState.INVALID


class SystemModuleTaintFlag(Enum):
    """
    - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/panic.c#n494
    - https://www.kernel.org/doc/Documentation/sysctl/kernel.txt (section "tainted")

         1 (P): proprietary module was loaded
         2 (F): module was force loaded
         4 (S): SMP kernel oops on an officially SMP incapable processor
         8 (R): module was force unloaded
        16 (M): processor reported a Machine Check Exception (MCE)
        32 (B): bad page referenced or some unexpected page flags
        64 (U): taint requested by userspace application
       128 (D): kernel died recently, i.e. there was an OOPS or BUG
       256 (A): an ACPI table was overridden by user
       512 (W): kernel issued warning
      1024 (C): staging driver was loaded
      2048 (I): workaround for bug in platform firmware applied
      4096 (O): externally-built ("out-of-tree") module was loaded
      8192 (E): unsigned module was loaded
     16384 (L): soft lockup occurred
     32768 (K): kernel has been live patched
     65536 (X): Auxiliary taint, defined and used by for distros
    131072 (T): The kernel was built with the struct randomization plugin
    """
    INVALID = 0
    PROPRIETARY_MODULE = 1
    FORCED_MODULE = 2
    CPU_OUT_OF_SPEC = 4
    FORCED_RMMOD = 8
    MACHINE_CHECK = 16
    BAD_PAGE = 32
    USER = 64
    DIE = 128
    OVERRIDDEN_ACPI_TABLE = 256
    WARN = 512
    CRAP = 1024
    FIRMWARE_WORKAROUND = 2048
    OOT_MODULE = 4096
    UNSIGNED_MODULE = 8192
    SOFTLOCKUP = 16384
    LIVEPATCH = 32768
    AUX = 65536
    RANDSTRUCT = 131072

    @staticmethod
    def from_str(value: str):
        value = value.upper()
        if value == "P":
            return SystemModuleTaintFlag.PROPRIETARY_MODULE
        elif value == "F":
            return SystemModuleTaintFlag.FORCED_MODULE
        elif value == "S":
            return SystemModuleTaintFlag.CPU_OUT_OF_SPEC
        elif value == "R":
            return SystemModuleTaintFlag.FORCED_RMMOD
        elif value == "M":
            return SystemModuleTaintFlag.MACHINE_CHECK
        elif value == "B":
            return SystemModuleTaintFlag.BAD_PAGE
        elif value == "U":
            return SystemModuleTaintFlag.USER
        elif value == "D":
            return SystemModuleTaintFlag.DIE
        elif value == "A":
            return SystemModuleTaintFlag.OVERRIDDEN_ACPI_TABLE
        elif value == "W":
            return SystemModuleTaintFlag.WARN
        elif value == "C":
            return SystemModuleTaintFlag.CRAP
        elif value == "I":
            return SystemModuleTaintFlag.FIRMWARE_WORKAROUND
        elif value == "O":
            return SystemModuleTaintFlag.OOT_MODULE
        elif value == "E":
            return SystemModuleTaintFlag.UNSIGNED_MODULE
        elif value == "L":
            return SystemModuleTaintFlag.SOFTLOCKUP
        elif value == "K":
            return SystemModuleTaintFlag.LIVEPATCH
        elif value == "X":
            return SystemModuleTaintFlag.AUX
        elif value == "T":
            return SystemModuleTaintFlag.RANDSTRUCT
        return SystemModuleTaintFlag.INVALID


class SystemModule:

    def __init__(self,
                 name: str,
                 size: int,
                 reference_count: int,
                 state: SystemModuleState,
                 dependencies: Set[str],
                 taint_flags: Set[SystemModuleTaintFlag]):
        """
        Represents a module from /proc/modules

        @param name: module name
        @param size: size in bytes of the module
        @param reference_count: count of references to this module (documentation says "number of instances",
        but source code says reference count https://elixir.bootlin.com/linux/v6.12.6/source/kernel/module/procfs.c#L107)
        @param state: state of the module
        @param dependencies: name of modules that this module depends on
        @param taint_flags: taint flags for the module
        """
        self._name = name
        self._size = size
        self._reference_count = reference_count
        self._state = state
        self._dependencies = dependencies
        self._taint_flags = taint_flags

    def __eq__(self, other):
        return (hasattr(other, "name")
                and self.name == other.name
                and hasattr(other, "size")
                and self.size == other.size
                and hasattr(other, "reference_count")
                and self.reference_count == other.reference_count
                and hasattr(other, "state")
                and self.state.value == other.state.value
                and hasattr(other, "dependencies")
                and self.dependencies == other.dependencies
                and hasattr(other, "taint_flags")
                and set(map(lambda x: x.value, self.taint_flags)) == set(map(lambda x: x.value, other.taint_flags)))

    def __hash__(self):
        return hash((self.name,
                     self.size,
                     self.reference_count,
                     self.state.value,
                     ",".join(self.dependencies),
                     sum(map(lambda x: x.value, self.taint_flags))))

    def __str__(self):
        return "%s:%d:%d:%s:%s:%s" % (self._name,
                                     self._size,
                                     self._reference_count,
                                     self._state.name,
                                     self._dependencies,
                                     self._taint_flags)

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name,
                "size": self.size,
                "reference_count": self.reference_count,
                "state": self.state.name,
                "dependencies": list(self.dependencies),
                "taint_flags": list(map(lambda x: x.name, self.taint_flags))}

    @staticmethod
    def from_dict(module_dict: Dict[str, Any]):
        return SystemModule(module_dict["name"],
                            module_dict["size"],
                            module_dict["reference_count"],
                            cast(SystemModuleState, SystemModuleState[module_dict["state"]]),
                            module_dict["dependencies"],
                            cast(Set[SystemModuleTaintFlag], set(map(lambda x: SystemModuleTaintFlag[x], module_dict["taint_flags"]))))

    @staticmethod
    def from_proc_modules_line(proc_line: str):
        """
        Parses a line from /proc/modules and creates a module object

        @param proc_line: line from /proc/modules to parse
        @return: module object parsed from argument line
        """

        """
        Examples from Ubuntu 22.04:
        mei_pxp 16384 0 - Live 0x0000000000000000
        irqbypass 12288 1 kvm, Live 0x0000000000000000
        nvidia 56823808 2 nvidia_uvm,nvidia_modeset, Live 0x0000000000000000 (PO)
        vboxnetadp 28672 0 - Live 0x0000000000000000 (OE)
        vboxdrv 696320 2 vboxnetadp,vboxnetflt, Live 0x0000000000000000 (OE)
        rpcsec_gss_krb5 36864 0 - Live 0xffffffffc1611000
        ipv6 450560 32 [permanent], Live 0x7f000000
        """
        proc_line = proc_line.strip()

        match = re.match(r'^(\w+) (\d+) (\d+) ((\w|,|-|\[permanent\])*) (\w+) 0x[0-9a-fA-f]+( \(([A-Z]+)\))?', proc_line)
        if not match:
            raise ValueError("Illegal line: %s" % proc_line)

        name = match.group(1)
        size = int(match.group(2), 10)
        reference_count = int(match.group(3), 10)
        state = SystemModuleState.from_str(match.group(6))

        dependencies = set([])
        dependencies_str = match.group(4)
        if dependencies_str != "-":
            for dependency_str in filter(lambda x: x != "", dependencies_str.split(",")):
                dependencies.add(dependency_str)

        taint_flags = set([])
        taint_flags_str = match.group(8)
        if taint_flags_str:
            for flag in taint_flags_str.strip():
                taint_flags.add(SystemModuleTaintFlag.from_str(flag))

        return SystemModule(name,
                            size,
                            reference_count,
                            state,
                            dependencies,
                            taint_flags)

    @property
    def name(self) -> str:
        return self._name

    @property
    def size(self) -> int:
        return self._size

    @property
    def reference_count(self) -> int:
        return self._reference_count

    @property
    def state(self) -> SystemModuleState:
        return self._state

    @property
    def dependencies(self) -> Set[str]:
        return set(self._dependencies)

    @property
    def taint_flags(self) -> Set[SystemModuleTaintFlag]:
        return set(self._taint_flags)


def get_system_modules(modules_file: str = "/proc/modules") -> List[SystemModule]:
    """
    Gets the modules loaded into the kernel from /proc/modules
    :return:
    """
    module_list = []
    try:
        with open(modules_file, 'rt') as fp:
            for line in fp:
                if line.strip() == "":
                    continue
                module_list.append(SystemModule.from_proc_modules_line(line.strip()))

    except Exception as e:
        raise SystemModuleException(str(e))

    return module_list
