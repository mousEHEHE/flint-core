# flint-core

The part of [flint](https://github.com/mousEHEHE/flint-gpui) that has no UI:
SSH and SFTP, the terminal emulator, the encrypted vault, and the account
with sync.

The desktop app (flint-gpui) and the mobile app (flint-mobile) both depend
on it, so a vault or a synced host made on one of them opens on the other.

An app must call `flint_core::app::set_version` at start. On iOS and Android
it must also call `flint_core::app::set_data_dir`, because `dirs` does not
know the app folder there.

## License

GPL-3.0. See [LICENSE](LICENSE).
