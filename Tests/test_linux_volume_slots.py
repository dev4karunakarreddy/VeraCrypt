#!/usr/bin/env python3
"""Exercise production slot selection with leftover Linux mapper devices.

No mounts or administrator privileges are required. The C++ harness compiles
the production selection/validation methods against scripted mount discovery.
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def method(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


HARNESS = r'''
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <iostream>
using namespace std;
using VolumeSlotNumber = unsigned int;
struct DirectoryPath : string {
    DirectoryPath(const string &path) : string(path) {}
    bool IsEmpty() const { return empty(); }
};
struct VolumeInfo { VolumeSlotNumber SlotNumber; };
struct MountOptions {
    VolumeSlotNumber SlotNumber = 0;
    shared_ptr<DirectoryPath> MountPoint;
    bool NoFilesystem = true;
};
struct VolumeSlotUnavailable : runtime_error {
    VolumeSlotUnavailable(const char *s) : runtime_error(s) {}
};
#define SRC_POS "slot selection"
#define foreach_ref(declaration, container) for (declaration : container)
class CoreBase {
public:
    virtual ~CoreBase() {}
    set<VolumeSlotNumber> Mounted, BusyMountPoints;
    VolumeSlotNumber GetFirstSlotNumber() const { return 1; }
    VolumeSlotNumber GetLastSlotNumber() const { return 4; }
    vector<VolumeInfo> GetMountedVolumes() const {
        vector<VolumeInfo> volumes;
        for (auto slot : Mounted) volumes.push_back({slot});
        return volumes;
    }
    DirectoryPath SlotNumberToMountPoint(VolumeSlotNumber slot) const {
        return to_string(slot);
    }
    VolumeSlotNumber MountPointToSlotNumber(const DirectoryPath &path) const {
        return stoul(path);
    }
    bool IsMountPointAvailable(const DirectoryPath &path) const {
        return !BusyMountPoints.count(stoul(path));
    }
    virtual bool IsSlotNumberAvailable(VolumeSlotNumber slot) const;
    VolumeSlotNumber GetFirstFreeSlotNumber(VolumeSlotNumber startFrom = 0) const;
    void CoalesceSlotNumberAndMountPoint(MountOptions &options) const;
};
using CoreUnix = CoreBase;
class CoreLinux : public CoreUnix {
public:
    set<string> MapperDevices;
    bool IsDeviceMapperDevicePresent(const string &name) const {
        return MapperDevices.count(name);
    }
    bool IsSlotNumberAvailable(VolumeSlotNumber slot) const override;
};
// PRODUCTION_METHODS
void Require(bool condition, const char *message) {
    if (!condition) throw runtime_error(message);
}
int main() {
    CoreLinux core;
    Require(core.GetFirstFreeSlotNumber() == 1, "empty inventory");
    core.MapperDevices.insert("unrelated-device");
    Require(core.GetFirstFreeSlotNumber() == 1, "unrelated mapper");
    core.MapperDevices.insert("veracrypt1");
    Require(!core.IsSlotNumberAvailable(1), "leftover mapper must remain protected");
    Require(core.GetFirstFreeSlotNumber() == 2, "automatic selection must skip leftover mapper");
    MountOptions format;
    core.CoalesceSlotNumberAndMountPoint(format);
    Require(format.SlotNumber == 2 && !format.MountPoint, "temporary formatting mount");
    MountOptions explicitSlot;
    explicitSlot.SlotNumber = 1;
    bool rejected = false;
    try { core.CoalesceSlotNumberAndMountPoint(explicitSlot); }
    catch (const VolumeSlotUnavailable &) { rejected = true; }
    Require(rejected, "explicit occupied slot must fail");
    core.Mounted.insert(2);
    core.BusyMountPoints.insert(3);
    Require(core.GetFirstFreeSlotNumber() == 4, "skip mounted and busy mount point");
    Require(core.GetFirstFreeSlotNumber(3) == 4, "startFrom must be honored");
    MountOptions normal;
    normal.NoFilesystem = false;
    core.CoalesceSlotNumberAndMountPoint(normal);
    Require(normal.SlotNumber == 4 && *normal.MountPoint == "4", "normal mount selection");
    core.MapperDevices.insert("veracrypt4");
    rejected = false;
    try { core.GetFirstFreeSlotNumber(); }
    catch (const VolumeSlotUnavailable &) { rejected = true; }
    Require(rejected, "exhausted slots must fail");
    core.MapperDevices.erase("veracrypt1");
    Require(core.GetFirstFreeSlotNumber() == 1, "released mapper slot can be reused");
    cout << "PASS: automatic formatting/mount slots skip leftover Linux mappings; explicit occupied slots remain blocked\n";
}
'''


def main():
    base = (ROOT / "src/Core/CoreBase.cpp").read_text()
    linux = (ROOT / "src/Core/Unix/Linux/CoreLinux.cpp").read_text()
    methods = "\n".join([
        method(base, "void CoreBase::CoalesceSlotNumberAndMountPoint"),
        method(base, "VolumeSlotNumber CoreBase::GetFirstFreeSlotNumber"),
        method(base, "bool CoreBase::IsSlotNumberAvailable"),
        method(linux, "bool CoreLinux::IsSlotNumberAvailable"),
    ])
    with tempfile.TemporaryDirectory(prefix="veracrypt-slots-") as directory:
        source = Path(directory) / "slots.cpp"
        binary = Path(directory) / "slots"
        source.write_text(HARNESS.replace("// PRODUCTION_METHODS", methods))
        subprocess.run(shlex.split(os.environ.get("CXX", "c++")) +
                       ["-std=c++11", "-Wall", "-Wextra", str(source), "-o", str(binary)],
                       check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
