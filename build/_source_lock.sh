#!/bin/sh
# Sources retrieved from their upstream HTTPS origins on 2026-09-14.
TC_NETBSD4_COMMIT=07a9c83a12c56f1bb6fe0e2ae08c9d2b46dd307c
TC_NETBSD7_COMMIT=c6d30a1d62252652a8c6804f6c18408cbf5ec39c
TC_SAMBA4_COMMIT=a72d4598bf4a2186769f25050663f4779ea581e0
TC_SAMBA4X_COMMIT=b5923e8d9563bcee569eb3f3ecc712a2a3761c1c

tc_checkout_pinned_source() {
    source_dir=$1
    source_url=$2
    source_commit=$3
    case "$source_url" in https://*) ;; *) echo "Source URL must use HTTPS" >&2; return 1 ;; esac
    mkdir -p "$source_dir"
    [ -d "$source_dir/.git" ] || git -C "$source_dir" init
    git -C "$source_dir" fetch --depth 1 "$source_url" "$source_commit" || return 1
    [ "$(git -C "$source_dir" rev-parse FETCH_HEAD)" = "$source_commit" ] || return 1
    # These are dedicated build source trees; remove prior applied patches.
    git -C "$source_dir" checkout --detach --force "$source_commit" || return 1
    git -C "$source_dir" reset --hard "$source_commit" || return 1
    git -C "$source_dir" clean -fd || return 1
}

tc_verify_source_archive() {
    archive_path=$1
    case "$(basename "$archive_path")" in
        gmp-6.3.0.tar.xz) expected=a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898 ;;
        nettle-3.10.2.tar.gz) expected=fe9ff51cb1f2abb5e65a6b8c10a92da0ab5ab6eaf26e7fc2b675c45f1fb519b5 ;;
        libtasn1-4.21.0.tar.gz) expected=1d8a444a223cc5464240777346e125de51d8e6abf0b8bac742ac84609167dc87 ;;
        gnutls-3.8.13.tar.xz) expected=ffed8ec1bf09c2426d4f14aae377de4753b53e537d685e604e99a8b16ca9c97e ;;
        *) echo "Unreviewed source archive: $archive_path" >&2; return 1 ;;
    esac
    if command -v sha256 >/dev/null 2>&1; then
        actual=$(sha256 -q "$archive_path") || return 1
    elif command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$archive_path") || return 1
        actual=${actual%% *}
    else
        actual=$(shasum -a 256 "$archive_path") || return 1
        actual=${actual%% *}
    fi
    [ "$actual" = "$expected" ] || {
        echo "Source checksum mismatch: $archive_path" >&2
        return 1
    }
}
