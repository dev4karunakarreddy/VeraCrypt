#!/usr/bin/env python3
"""Test SOS erasure against production libraries using disposable file volumes.

Run after building the application. No GUI, mounts, sudo, or real devices are
used. Covers primary/backup detection, read-only reopening, failed writes,
password/cache erasure, retained cipher objects and exception serialization.
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include "Volume/Volume.h"
#include "Volume/VolumePasswordCache.h"
#include "Volume/EncryptionModeXTS.h"
#include "Platform/MemoryStream.h"
#include <iostream>
#include <stdexcept>
using namespace VeraCrypt;
void Require(bool passed, const char *message) {
    if (!passed) throw std::runtime_error(message);
}
bool Zero(const uint8 *data, size_t size) {
    for (size_t i = 0; i < size; ++i) if (data[i]) return false;
    return true;
}
shared_ptr<VolumePassword> MakePassword(const char *text) {
    return make_shared<VolumePassword>(reinterpret_cast<const uint8 *>(text), strlen(text));
}
struct InspectHeader : VolumeHeader {
    InspectHeader() : VolumeHeader(TC_VOLUME_HEADER_SIZE) {}
    void Seed(const SecureBuffer &key, shared_ptr<VeraCrypt::EncryptionAlgorithm> algorithm) {
        DataAreaKey.CopyFrom(key);
        EA = algorithm;
        Flags = TC_HEADER_FLAG_SAFEGUARD_VOLUME;
    }
    bool KeyErased() const { return Zero(DataAreaKey.Ptr(), DataAreaKey.Size()); }
};
struct InspectCipher : CipherAES {
    bool ScheduleErased() const { return Zero(ScheduledKey.Ptr(), ScheduledKey.Size()); }
};
void Wipe(const string &directory, const char *name, bool backup, bool readOnly, bool fail) {
    FilePath path(directory + "/" + name);
    auto password = MakePassword("sos-test-password");
    auto protectionPassword = MakePassword("protection-test-password");
    VolumePasswordCache::Store(*MakePassword("cached-test-password"));
    auto file = make_shared<File>();
    file->Open(path, (readOnly || fail) ? File::OpenRead : File::OpenReadWrite, File::ShareNone);
    Volume volume;
    bool detected = false;
    try {
        volume.Open(file, password, 0, make_shared<Pkcs5HmacSha512>(), {}, false,
            readOnly ? VolumeProtection::ReadOnly : VolumeProtection::None,
            protectionPassword, 0, {}, {}, VolumeType::Unknown, backup);
    }
    catch (const SafeguardWipeFailed &) {
        Require(fail, "unexpected wipe failure");
        detected = true;
    }
    catch (const SafeguardWipeTriggered &) {
        Require(!fail, "failed write reported as success");
        detected = true;
    }
    Require(detected, "SOS password was not recognized");
    Require(password->IsEmpty() && Zero(password->DataPtr(), VolumePassword::MaxSize), "SOS password retained");
    Require(protectionPassword->IsEmpty() && Zero(protectionPassword->DataPtr(), VolumePassword::MaxSize), "protection password retained");
    Require(VolumePasswordCache::IsEmpty(), "password cache retained");
    Require(path.IsFile() == fail, "incomplete overwrite must not delete file");
    if (fail) Require(file->Length() == 1048576, "failed overwrite truncated file");
}
int main(int argc, char **argv) {
    Require(argc == 2, "test directory required");
    string directory(argv[1]);
    // Retained references must observe erased keys, not merely released owners.
    auto algorithm = make_shared<VeraCrypt::AES>();
    auto mode = make_shared<EncryptionModeXTS>();
    SecureBuffer key(32);
    memset(key.Ptr(), 0x5a, key.Size());
    algorithm->SetKey(key);
    mode->SetKey(key);
    algorithm->SetMode(mode);
    auto cipher = algorithm->GetCiphers().front();
    algorithm->EraseKey();
    Require(Zero(cipher->GetKey().Ptr(), cipher->GetKey().Size()), "cipher key retained");
    Require(Zero(mode->GetKey().Ptr(), mode->GetKey().Size()) && !mode->IsKeySet(), "XTS key retained");
    uint8 block[16] = {};
    bool invalidated = false;
    try { cipher->EncryptBlock(block); }
    catch (const NotInitialized &) { invalidated = true; }
    Require(invalidated, "erased cipher still accepts encryption");
    InspectCipher inspectCipher;
    inspectCipher.SetKey(key);
    Require(!inspectCipher.ScheduleErased(), "cipher test has no key schedule");
    inspectCipher.EraseKey();
    Require(inspectCipher.ScheduleErased(), "expanded key schedule retained");
    algorithm->SetKey(key);
    mode->SetKey(key);
    InspectHeader header;
    header.Seed(key, algorithm);
    header.EraseSensitiveData();
    Require(header.KeyErased() && !header.GetEncryptionAlgorithm() && !header.IsSafeguard(), "header secrets retained");
    Require(Zero(cipher->GetKey().Ptr(), cipher->GetKey().Size()) && !mode->IsKeySet(), "header cipher references retained keys");

    // A failed-wipe exception must survive transport without becoming success.
    auto stream = make_shared<MemoryStream>();
    SafeguardWipeFailed failure("test");
    failure.Serialize(stream);
    auto restored = Serializable::DeserializeNew<Exception>(stream);
    Require(dynamic_cast<SafeguardWipeFailed *>(restored.get()), "wipe failure lost in serialization");

    Wipe(directory, "primary.hc", false, false, false);
    Wipe(directory, "backup.hc", true, false, false);
    Wipe(directory, "readonly.hc", false, true, false);
    Wipe(directory, "failure.hc", false, false, true);

    FilePath path(directory + "/plain.hc");
    auto ordinary = MakePassword("creation-test-password");
    Volume normal;
    normal.Open(VolumePath(path), false, ordinary, 1, make_shared<Pkcs5HmacSha512>(), {}, false);
    Require(!ordinary->IsEmpty(), "ordinary password erased");
    normal.Close();
    Require(path.IsFile(), "ordinary volume deleted");
    auto wrong = MakePassword("incorrect-password");
    bool rejected = false;
    try { normal.Open(VolumePath(path), false, wrong, 1, make_shared<Pkcs5HmacSha512>(), {}, false); }
    catch (const PasswordIncorrect &) { rejected = true; }
    Require(rejected && !wrong->IsEmpty() && path.IsFile(), "wrong password triggered wipe");
    auto retainedAlgorithm = normal.GetEncryptionAlgorithm();
    auto reusedPassword = MakePassword("sos-test-password");
    bool reusedWiped = false;
    try { normal.Open(VolumePath(FilePath(directory + "/reuse.hc")), false, reusedPassword, 0, make_shared<Pkcs5HmacSha512>(), {}, false); }
    catch (const SafeguardWipeFailed &) { throw; }
    catch (const SafeguardWipeTriggered &) { reusedWiped = true; }
    Require(reusedWiped && !normal.GetHeader(), "reused volume retains header");
    Require(normal.GetPim() == 0, "previous volume PIM retained");
    for (auto retainedCipher : retainedAlgorithm->GetCiphers())
        Require(Zero(retainedCipher->GetKey().Ptr(), retainedCipher->GetKey().Size()), "previous volume key retained");
    cout << "PASS: primary/backup SOS wipes, read-only reopening, honest failures, credential/key cleanup and ordinary mounts\n";
}
'''


def main():
    source_root = ROOT / "src"
    binary = source_root / "Main/veracrypt"
    with tempfile.TemporaryDirectory(prefix="veracrypt-sos-test-") as directory:
        directory = Path(directory)
        source = directory / "wipe.cpp"
        harness = directory / "wipe"
        source.write_text(HARNESS)
        command = shlex.split(os.environ.get("CXX", "c++")) + [
            "-std=c++11", "-DTC_UNIX", "-DTC_LINUX", "-D_FILE_OFFSET_BITS=64",
            "-I" + str(source_root), "-I" + str(source_root / "Crypto"),
            "-I" + str(source_root / "PKCS11"), "-I" + str(source_root / "Crypto/Argon2/include"),
            str(source), "-Wl,--start-group",
            str(source_root / "Volume/Volume.a"), str(source_root / "Platform/Platform.a"),
            "-Wl,--end-group", "-pthread", "-o", str(harness),
        ]
        subprocess.run(command, check=True)
        # Invalid SOS settings must be rejected before an existing host changes.
        for volume_type, password in (("normal", "creation-test-password"),
                                      ("hidden", "sos-test-password")):
            target = directory / ("invalid-" + volume_type + ".hc")
            original = b"existing host must survive validation" * 131072
            target.write_bytes(original)
            args = [str(binary), "-t", "-c", str(target), "--size=1048576",
                    "--password=creation-test-password", "--pim=1", "--hash=sha512",
                    "--encryption=AES", "--filesystem=FAT", "--volume-type=" + volume_type,
                    "--keyfiles=", "--random-source=/dev/urandom", "--non-interactive",
                    "--sos-password=" + password, "--force"]
            result = subprocess.run(args, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 or target.read_bytes() != original:
                raise RuntimeError("invalid SOS settings accepted or changed the host")

        for name in ("primary", "backup", "readonly", "failure", "plain", "reuse"):
            args = [str(binary), "-t", "-c", str(directory / (name + ".hc")),
                    "--size=1048576", "--password=creation-test-password", "--pim=1",
                    "--hash=sha512", "--encryption=AES", "--filesystem=FAT",
                    "--volume-type=normal", "--keyfiles=", "--random-source=/dev/urandom",
                    "--non-interactive"]
            if name != "plain":
                args += ["--sos-password=sos-test-password"]
            result = subprocess.run(args, capture_output=True, text=True, timeout=60)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
        subprocess.run([str(harness), str(directory)], check=True, timeout=60)


if __name__ == "__main__":
    main()
