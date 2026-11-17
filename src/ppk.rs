//! PuTTY's `.ppk` private keys (file format 2 and 3), turned into the OpenSSH
//! format the rest of flint reads. PuTTY keeps the same SSH wire fields as
//! OpenSSH, so the work is checking the MAC, decrypting, and moving fields.

use aes::Aes256;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PpkError {
    #[error("this PuTTY key is protected by a passphrase")]
    NeedsPassphrase,
    #[error("wrong passphrase for this PuTTY key")]
    WrongPassphrase,
    #[error("{0}")]
    Invalid(String),
}

fn invalid(what: &str) -> PpkError {
    PpkError::Invalid(format!("this PuTTY key file cannot be read: {what}"))
}

pub fn is_ppk(text: &str) -> bool {
    text.trim_start().starts_with("PuTTY-User-Key-File-")
}

/// The key as an unencrypted OpenSSH private key. The vault encrypts it.
pub fn to_openssh(text: &str, passphrase: Option<&str>) -> Result<Zeroizing<String>, PpkError> {
    let ppk = parse(text)?;
    let is_encrypted = match ppk.field("Encryption")? {
        "none" => false,
        "aes256-cbc" => true,
        other => return Err(invalid(&format!("unknown encryption {other}"))),
    };
    let passphrase = passphrase.unwrap_or("");
    if is_encrypted && passphrase.is_empty() {
        return Err(PpkError::NeedsPassphrase);
    }
    let secrets = derive_secrets(&ppk, is_encrypted, passphrase)?;
    let private = if is_encrypted {
        decrypt(&ppk.private, &secrets)?
    } else {
        Zeroizing::new(ppk.private.clone())
    };
    if !is_mac_right(&ppk, &private, &secrets.mac_key)? {
        return Err(if is_encrypted {
            PpkError::WrongPassphrase
        } else {
            invalid("it is damaged")
        });
    }
    let keypair = openssh_keypair(&ppk.algorithm, &ppk.public, &private)?;
    let container = openssh_container(&ppk.public, &keypair, ppk.field("Comment")?);
    ssh_key::PrivateKey::from_bytes(&container)
        .and_then(|key| key.to_openssh(ssh_key::LineEnding::LF))
        .map_err(|e| invalid(&e.to_string()))
}

struct Ppk {
    version: u8,
    algorithm: String,
    fields: Vec<(String, String)>,
    public: Vec<u8>,
    private: Vec<u8>,
}

impl Ppk {
    fn field(&self, name: &str) -> Result<&str, PpkError> {
        self.fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .ok_or_else(|| invalid(&format!("no {name}")))
    }
}

fn parse(text: &str) -> Result<Ppk, PpkError> {
    use base64::Engine as _;
    // Not trimmed: the MAC covers the comment exactly, spaces and all.
    let mut lines = text.trim_start().lines();
    let (key, algorithm) = lines
        .next()
        .and_then(|line| line.split_once(": "))
        .ok_or_else(|| invalid("no header"))?;
    let version = match key {
        "PuTTY-User-Key-File-2" => 2,
        "PuTTY-User-Key-File-3" => 3,
        _ => return Err(invalid("only versions 2 and 3 are known")),
    };
    let mut ppk = Ppk {
        version,
        algorithm: algorithm.to_string(),
        fields: Vec::new(),
        public: Vec::new(),
        private: Vec::new(),
    };
    while let Some(line) = lines.next() {
        if line.trim().is_empty() {
            continue;
        }
        // An empty comment is written as "Comment: ", or by some tools "Comment:".
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("a broken line"))?;
        let value = value.strip_prefix(' ').unwrap_or(value);
        let blob = match name {
            "Public-Lines" => &mut ppk.public,
            "Private-Lines" => &mut ppk.private,
            _ => {
                ppk.fields.push((name.to_string(), value.to_string()));
                continue;
            }
        };
        let count: usize = value.parse().map_err(|_| invalid("a bad line count"))?;
        let text: String = lines.by_ref().take(count).map(str::trim).collect();
        *blob = base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(|_| invalid("bad base64"))?;
    }
    Ok(ppk)
}

struct Secrets {
    cipher_key: Zeroizing<[u8; 32]>,
    iv: [u8; 16],
    mac_key: Zeroizing<Vec<u8>>,
}

fn derive_secrets(ppk: &Ppk, is_encrypted: bool, passphrase: &str) -> Result<Secrets, PpkError> {
    let mut secrets = Secrets {
        cipher_key: Zeroizing::new([0; 32]),
        iv: [0; 16],
        mac_key: Zeroizing::new(Vec::new()),
    };
    if ppk.version == 2 {
        let mut key = Zeroizing::new([0u8; 40]);
        let first = Sha1::new()
            .chain_update([0, 0, 0, 0])
            .chain_update(passphrase);
        let second = Sha1::new()
            .chain_update([0, 0, 0, 1])
            .chain_update(passphrase);
        key[..20].copy_from_slice(&first.finalize());
        key[20..].copy_from_slice(&second.finalize());
        secrets.cipher_key.copy_from_slice(&key[..32]);
        // Version 2 always has a MAC key, made from an empty passphrase when there is none.
        let mac_key = Sha1::new()
            .chain_update("putty-private-key-file-mac-key")
            .chain_update(passphrase)
            .finalize();
        *secrets.mac_key = mac_key.to_vec();
        return Ok(secrets);
    }
    if !is_encrypted {
        return Ok(secrets);
    }
    let mut derived = Zeroizing::new([0u8; 80]);
    let salt = hex(ppk.field("Argon2-Salt")?)?;
    argon2_for(ppk)?
        .hash_password_into(passphrase.as_bytes(), &salt, &mut *derived)
        .map_err(|e| invalid(&e.to_string()))?;
    secrets.cipher_key.copy_from_slice(&derived[..32]);
    secrets.iv.copy_from_slice(&derived[32..48]);
    *secrets.mac_key = derived[48..].to_vec();
    Ok(secrets)
}

fn argon2_for(ppk: &Ppk) -> Result<argon2::Argon2<'static>, PpkError> {
    let algorithm = match ppk.field("Key-Derivation")? {
        "Argon2id" => argon2::Algorithm::Argon2id,
        "Argon2i" => argon2::Algorithm::Argon2i,
        "Argon2d" => argon2::Algorithm::Argon2d,
        other => return Err(invalid(&format!("unknown key derivation {other}"))),
    };
    let number = |name: &str| -> Result<u32, PpkError> {
        ppk.field(name)?
            .parse()
            .map_err(|_| invalid(&format!("a bad {name}")))
    };
    let params = argon2::Params::new(
        number("Argon2-Memory")?,
        number("Argon2-Passes")?,
        number("Argon2-Parallelism")?,
        Some(80),
    )
    .map_err(|e| invalid(&e.to_string()))?;
    Ok(argon2::Argon2::new(
        algorithm,
        argon2::Version::V0x13,
        params,
    ))
}

fn decrypt(private: &[u8], secrets: &Secrets) -> Result<Zeroizing<Vec<u8>>, PpkError> {
    let mut buffer = Zeroizing::new(private.to_vec());
    cbc::Decryptor::<Aes256>::new(secrets.cipher_key.as_ref().into(), &secrets.iv.into())
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|_| invalid("the private part is not whole blocks"))?;
    Ok(buffer)
}

fn is_mac_right(ppk: &Ppk, private: &[u8], mac_key: &[u8]) -> Result<bool, PpkError> {
    let expected = hex(ppk.field("Private-MAC")?)?;
    let mut data = Vec::new();
    for part in [
        ppk.algorithm.as_bytes(),
        ppk.field("Encryption")?.as_bytes(),
        ppk.field("Comment")?.as_bytes(),
        &ppk.public,
        private,
    ] {
        put_string(&mut data, part);
    }
    let is_right = if ppk.version == 2 {
        let mut mac =
            Hmac::<Sha1>::new_from_slice(mac_key).map_err(|_| invalid("a bad MAC key"))?;
        mac.update(&data);
        mac.verify_slice(&expected).is_ok()
    } else {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(mac_key).map_err(|_| invalid("a bad MAC key"))?;
        mac.update(&data);
        mac.verify_slice(&expected).is_ok()
    };
    Ok(is_right)
}

/// The fields OpenSSH keeps for a key pair: its public fields, then the private ones.
fn openssh_keypair(
    algorithm: &str,
    public: &[u8],
    private: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PpkError> {
    let mut public = WireReader(public);
    let mut private = WireReader(private);
    if public.string()? != algorithm.as_bytes() {
        return Err(invalid("the public key is of another type"));
    }
    let mut out = Zeroizing::new(Vec::new());
    put_string(&mut out, algorithm.as_bytes());
    match algorithm {
        "ssh-ed25519" => {
            let public_key = public.string()?;
            // PuTTY stores the private half as a little-endian number, without its high zero bytes.
            let seed = private.string()?;
            if seed.len() > 32 || public_key.len() != 32 {
                return Err(invalid("a bad ed25519 key"));
            }
            let mut both = Zeroizing::new([0u8; 64]);
            both[..seed.len()].copy_from_slice(seed);
            both[32..].copy_from_slice(public_key);
            put_string(&mut out, public_key);
            put_string(&mut out, &*both);
        }
        "ssh-rsa" => {
            let (e, n) = (public.string()?, public.string()?);
            let d = private.string()?;
            let (p, q, iqmp) = (private.string()?, private.string()?, private.string()?);
            for part in [n, e, d, iqmp, p, q] {
                put_string(&mut out, part);
            }
        }
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            let (curve, point) = (public.string()?, public.string()?);
            let size = match curve {
                b"nistp256" => 32,
                b"nistp384" => 48,
                _ => 66,
            };
            put_string(&mut out, curve);
            put_string(&mut out, point);
            put_string(&mut out, &ecdsa_scalar(private.string()?, size)?);
        }
        other => {
            return Err(PpkError::Invalid(format!(
                "{other} keys from PuTTY are not supported"
            )))
        }
    }
    Ok(out)
}

/// PuTTY writes the scalar as short as it goes; OpenSSH wants its full width,
/// with a zero in front when the top bit is set.
fn ecdsa_scalar(mpint: &[u8], size: usize) -> Result<Zeroizing<Vec<u8>>, PpkError> {
    let digits = &mpint[mpint.iter().take_while(|&&byte| byte == 0).count()..];
    if digits.len() > size {
        return Err(invalid("a bad ECDSA key"));
    }
    let mut scalar = Zeroizing::new(vec![0u8; size - digits.len()]);
    scalar.extend_from_slice(digits);
    if scalar[0] >= 0x80 {
        scalar.insert(0, 0);
    }
    Ok(scalar)
}

/// The binary `openssh-key-v1` container, unencrypted.
fn openssh_container(public: &[u8], keypair: &[u8], comment: &str) -> Zeroizing<Vec<u8>> {
    let check: u32 = rand::random();
    let mut section = Zeroizing::new(Vec::new());
    section.extend_from_slice(&check.to_be_bytes());
    section.extend_from_slice(&check.to_be_bytes());
    section.extend_from_slice(keypair);
    put_string(&mut section, comment.as_bytes());
    let mut pad = 1u8;
    while !section.len().is_multiple_of(8) {
        section.push(pad);
        pad += 1;
    }
    let mut out = Zeroizing::new(b"openssh-key-v1\0".to_vec());
    for part in [&b"none"[..], b"none", b""] {
        put_string(&mut out, part);
    }
    out.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut out, public);
    put_string(&mut out, &section);
    out
}

struct WireReader<'a>(&'a [u8]);

impl<'a> WireReader<'a> {
    fn string(&mut self) -> Result<&'a [u8], PpkError> {
        let too_short = || invalid("it ends too early");
        let prefix: [u8; 4] = self
            .0
            .get(..4)
            .and_then(|prefix| prefix.try_into().ok())
            .ok_or_else(too_short)?;
        let length = u32::from_be_bytes(prefix) as usize;
        let end = 4usize.checked_add(length).ok_or_else(too_short)?;
        let value = self.0.get(4..end).ok_or_else(too_short)?;
        self.0 = &self.0[end..];
        Ok(value)
    }
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn hex(text: &str) -> Result<Vec<u8>, PpkError> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return Err(invalid("bad hex"));
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).map_err(|_| invalid("bad hex")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "correct horse";

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/ppk/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(path).unwrap()
    }

    /// The public key blob of what the conversion gives, as russh reads it.
    /// Not its name: russh names an RSA key after its signature, rsa-sha2-512.
    fn public_blob(pem: &str) -> String {
        use russh::keys::PublicKeyBase64 as _;
        let key = russh::keys::decode_secret_key(pem, None).unwrap();
        key.clone_public_key().unwrap().public_key_base64()
    }

    #[test]
    fn every_puttygen_key_becomes_the_same_openssh_key() {
        let cases = [
            ("ed25519-v3.ppk", "ed25519.pub", None),
            ("ed25519-v3-pass.ppk", "ed25519.pub", Some(PASSPHRASE)),
            ("ed25519-v3-argon2i.ppk", "ed25519.pub", Some(PASSPHRASE)),
            ("ed25519-v3-argon2d.ppk", "ed25519.pub", Some(PASSPHRASE)),
            ("ed25519-v2.ppk", "ed25519.pub", None),
            ("ed25519-v2-pass.ppk", "ed25519.pub", Some(PASSPHRASE)),
            ("rsa-v3.ppk", "rsa.pub", None),
            ("rsa-v2-pass.ppk", "rsa.pub", Some(PASSPHRASE)),
            ("p256-v3.ppk", "p256.pub", None),
            ("p384-v3-pass.ppk", "p384.pub", Some(PASSPHRASE)),
            ("p521-v2.ppk", "p521.pub", None),
            ("nocomment-v3.ppk", "nocomment.pub", None),
        ];
        for (ppk, public, passphrase) in cases {
            let text = fixture(ppk);
            assert!(is_ppk(&text), "{ppk}");
            let pem = to_openssh(&text, passphrase).unwrap_or_else(|e| panic!("{ppk}: {e}"));
            assert!(
                pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"),
                "{ppk}"
            );
            // puttygen's own public key: "<type> <blob> <comment>".
            let expected = fixture(public);
            let expected = expected.split_whitespace().nth(1).unwrap();
            assert_eq!(public_blob(&pem), expected, "{ppk}");
            // The private half belongs to it: russh, which signs in with it, makes a
            // signature that the public half checks.
            let key = russh::keys::decode_secret_key(&pem, None).unwrap();
            let signature = key.sign_detached(b"test").unwrap();
            let public = key.clone_public_key().unwrap();
            assert!(public.verify_detached(b"test", signature.as_ref()), "{ppk}");
        }
    }

    #[test]
    fn a_protected_key_asks_for_its_passphrase_and_refuses_a_wrong_one() {
        for ppk in [
            "ed25519-v3-pass.ppk",
            "ed25519-v2-pass.ppk",
            "rsa-v2-pass.ppk",
        ] {
            let text = fixture(ppk);
            assert_eq!(
                to_openssh(&text, None),
                Err(PpkError::NeedsPassphrase),
                "{ppk}"
            );
            assert_eq!(
                to_openssh(&text, Some("")),
                Err(PpkError::NeedsPassphrase),
                "{ppk}"
            );
            assert_eq!(
                to_openssh(&text, Some("wrong")),
                Err(PpkError::WrongPassphrase),
                "{ppk}"
            );
        }
        // A key without one does not care about a passphrase it is given.
        assert!(to_openssh(&fixture("ed25519-v3.ppk"), Some("anything")).is_ok());
    }

    #[test]
    fn a_damaged_or_foreign_file_is_refused() {
        let text = fixture("ed25519-v3.ppk");
        let damaged = text.replace("Comment: flint-test-ed25519", "Comment: someone-else");
        assert!(matches!(
            to_openssh(&damaged, None),
            Err(PpkError::Invalid(_))
        ));
        let old = text.replace("PuTTY-User-Key-File-3", "PuTTY-User-Key-File-1");
        assert!(matches!(to_openssh(&old, None), Err(PpkError::Invalid(_))));
        let cut = "PuTTY-User-Key-File-3: ssh-ed25519\n";
        assert!(matches!(to_openssh(cut, None), Err(PpkError::Invalid(_))));
        assert!(!is_ppk("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn an_ecdsa_scalar_gets_its_full_width() {
        assert_eq!(*ecdsa_scalar(&[0x12], 4).unwrap(), vec![0, 0, 0, 0x12]);
        assert_eq!(
            *ecdsa_scalar(&[0, 0x92, 1, 2, 3], 4).unwrap(),
            vec![0, 0x92, 1, 2, 3]
        );
        assert!(ecdsa_scalar(&[1, 2, 3, 4, 5], 4).is_err());
    }

    #[test]
    fn a_length_past_the_end_is_an_error_not_a_panic() {
        let mut reader = WireReader(&[0xff, 0xff, 0xff, 0xff, 1]);
        assert!(reader.string().is_err());
    }
}
