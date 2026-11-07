// clevr-se-helper: the machine key in the Secure Enclave, for the system
// custody (endpoint-agent/go/chip.go). The custody keeps the key's opaque blob
// in its own folder, 0600, and runs this to make or use the key; the private
// key never leaves the enclave, and the blob is good on this Mac only.
//
//   clevr-se-helper available                         -> "yes", or exit 1
//   clevr-se-helper create                            -> blob, then the SPKI DER public key
//   clevr-se-helper public   < blob                   -> the SPKI DER public key
//   clevr-se-helper sign     < blob, then the message -> the raw r||s signature (64 bytes)
//
// Every value is base64 on a line of its own; the blob comes on stdin, never
// in argv. P-256 ECDSA over SHA-256, as the engine verifies es256
// (brain/src/lib/identity/machine_keys.ts).
//
// The key is usable after the first unlock since boot, by whoever holds the
// blob on this Mac. Measured from a command-line process as an ordinary user;
// never measured from the LaunchDaemon running as _clevr.
import CryptoKit
import Foundation
import Security

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write(Data((msg + "\n").utf8))
    exit(1)
}

func stdinLines() -> [String] {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    return String(decoding: data, as: UTF8.self).split(separator: "\n").map {
        $0.trimmingCharacters(in: .whitespacesAndNewlines)
    }.filter { !$0.isEmpty }
}

func enclaveKey(_ blob: String) -> SecureEnclave.P256.Signing.PrivateKey {
    guard let data = Data(base64Encoded: blob) else { fail("the key blob is not base64") }
    do {
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
    } catch {
        fail("the Secure Enclave refused the key blob: \(error)")
    }
}

let args = CommandLine.arguments
guard args.count == 2 else { fail("usage: clevr-se-helper available|create|public|sign") }

switch args[1] {
case "available":
    guard SecureEnclave.isAvailable else { fail("no Secure Enclave on this Mac") }
    print("yes")
case "create":
    guard SecureEnclave.isAvailable else { fail("no Secure Enclave on this Mac") }
    var err: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &err)
    else { fail("no access control: \(String(describing: err?.takeRetainedValue()))") }
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        print(key.dataRepresentation.base64EncodedString())
        print(key.publicKey.derRepresentation.base64EncodedString())
    } catch {
        fail("the Secure Enclave made no key: \(error)")
    }
case "public":
    let lines = stdinLines()
    guard lines.count == 1 else { fail("public reads one line: the key blob") }
    print(enclaveKey(lines[0]).publicKey.derRepresentation.base64EncodedString())
case "sign":
    let lines = stdinLines()
    guard lines.count == 2, let message = Data(base64Encoded: lines[1]) else {
        fail("sign reads two lines: the key blob and the message, in base64")
    }
    do {
        print(try enclaveKey(lines[0]).signature(for: message).rawRepresentation.base64EncodedString())
    } catch {
        fail("the Secure Enclave did not sign: \(error)")
    }
default:
    fail("unknown command \(args[1]): available, create, public or sign")
}
