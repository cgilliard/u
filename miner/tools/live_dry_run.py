#!/usr/bin/env python3
# The steps of docs/LIVE_TEST.md, on the dev network, with six nodes of one
# machine: python3 tools/live_dry_run.py target/release/tabminer /tmp/dry 41000
# (the binary built with --features dev, a directory to make, a first port).
import subprocess, os, sys, time, select, shutil, re
BIN = sys.argv[1]; ROOT = sys.argv[2]; BASE = int(sys.argv[3])
shutil.rmtree(ROOT, ignore_errors=True); os.makedirs(ROOT)
PORT = dict(A=BASE, B=BASE+1, C=BASE+2, H=BASE+4, W1=BASE+5, W2=BASE+6)
at = lambda n: f"127.0.0.1:{PORT[n]}"
COMMON = ["--network","dev","--threads","2","--no-seeds","--seed",at("A"),"--seed",at("B"),"--min-confirmations","1"]
T0 = time.time()
def say(*a): print(f"[{time.time()-T0:7.1f}s]", *a, flush=True)
class Node:
    def __init__(s, name, extra):
        s.name = name; s.dir = f"{ROOT}/{name}"; s.extra = extra; s.start(new=True)
    def start(s, new=False):
        s.err = open(f"{s.dir}.err", "ab")
        s.p = subprocess.Popen([BIN, "--data-dir", s.dir, "--listen", at(s.name)] + COMMON + s.extra,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=s.err)
        if new:
            s.p.stdin.write(b"\n"); s.p.stdin.flush()   # no password, asked of a new wallet
        s.read()
    def read(s, timeout=30):
        buf = b""; end = time.time() + timeout
        while not (buf.endswith(b"> ") and (len(buf) == 2 or buf[-3:-2] == b"\n")):
            r, _, _ = select.select([s.p.stdout], [], [], max(0, end - time.time()))
            if not r: raise RuntimeError(f"{s.name}: no prompt; got {buf[-300:]!r}")
            b = os.read(s.p.stdout.fileno(), 4096)
            if not b: raise RuntimeError(f"{s.name} stopped: {buf[-300:]!r}")
            buf += b
        return buf[:-2].decode()
    def ask(s, cmd, timeout=30):
        s.p.stdin.write((cmd + "\n").encode()); s.p.stdin.flush()
        out = s.read(timeout)
        # (a blank first line leaves a prompt behind: take the last answer)
        return out.split("\n> ")[-1].lstrip("> ")
    def log(s): return open(f"{s.dir}/tabernacle.log", errors="replace").read()
    def stop(s):
        try: s.p.stdin.write(b"quit\n"); s.p.stdin.flush(); s.p.wait(10)
        except Exception: s.p.kill()
    def height(s): return int(s.ask("status").split()[1].replace(",", ""))
    def balance(s): return s.ask("balance").splitlines()[0].replace("spendable", "").strip()
    def coins(s):
        try: return float(s.balance().replace(",", ""))
        except ValueError: return 0.0
RESULTS = []
def step(name, ok, detail=""):
    RESULTS.append((name, ok)); say(("PASS " if ok else "FAIL ") + name + ((" :: " + detail) if detail and not ok else ""))
def wait(cond, timeout, every=0.3):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if cond(): return True
        except Exception as e: pass
        time.sleep(every)
    return False
N = {}
try:
    N["A"] = Node("A", ["--relay"])
    for n, extra in [("B", ["--relay","--no-mine"]), ("C", ["--relay","--no-mine"]), ("H", ["--no-mine"]), ("W1", ["--no-mine"]), ("W2", ["--no-mine"])]:
        N[n] = Node(n, extra)
    A, B, C, H, W1, W2 = (N[k] for k in ["A","B","C","H","W1","W2"])
    ADDR = {k: v.ask("address").strip() for k, v in N.items()}
    say("addresses:", {k: a[:12] for k, a in ADDR.items()})
    ok = wait(lambda: all("reached at: 2 of 2" in N[k].ask("status") for k in N), 90)
    step("init: every wallet is reached at both seeds", ok, "\n".join(k + ": " + [l for l in N[k].ask("status").splitlines() if "reached" in l or "peers" in l].__repr__() for k in N))
    wait(lambda: A.balance() != "0", 120)
    # 1. fund
    r1 = A.ask(f"send 100 {ADDR['H']}"); 
    wait(lambda: H.balance() == "100", 90)
    r2 = A.ask(f"send 100 {ADDR['W1']}")
    ok = wait(lambda: H.balance() == "100" and W1.balance() == "100", 120)
    step("init 1: fund H and W1 from the miner", ok, f"{r1!r} {r2!r} H={H.balance()} W1={W1.balance()} A={A.balance()}")
    def pay(frm, to, amount, expect_in_log, timeout=30):
        t = time.time(); before = frm.log().count(expect_in_log)
        said = frm.ask(f"send {amount} {to}")
        if "begun" not in said: return None, said
        ok = wait(lambda: frm.log().count(expect_in_log) > before, timeout, 0.02)
        return (time.time() - t if ok else None), said
    # (A wallet's change is its to spend again once a block has it: until then it has what else it holds.)
    def settled(node, least=20): return wait(lambda: node.ask("slates").startswith("no payments begun") and node.coins() >= least, 120)
    # 2. by address
    t, said = pay(W1, ADDR["W2"], 5, f"answered by {ADDR['W2']}, signed and pooled")
    ok = t is not None and wait(lambda: W2.balance() == "5", 90)
    step(f"init 2: W1 pays W2 by address ({t and round(t,2)}s)", ok, said)
    settled(W1)
    # 3. to itself
    t, said = pay(W1, ADDR["W1"], 1, f"answered by {ADDR['W1']}, signed and pooled")
    step(f"init 3: W1 pays itself ({t and round(t,2)}s)", t is not None, said); settled(W1)
    # 4. to nobody
    nobody = "tab1" + "q"*0
    said = W1.ask("send 1 tab1nothing")
    fake = ADDR["W2"]  # make an address nobody holds: ask H's wallet for a fresh one is not possible; use a stopped node later
    # (an address nobody holds: C's address after it is told to be a wallet nowhere is not possible either; skip to names)
    # 5. a name
    said = H.ask("name-commit mailhub")
    ok = wait(lambda: H.ask("name-reveal mailhub").startswith("Name mailhub: revealed"), 240)
    ok = ok and wait(lambda: "  owned  " in H.ask("names"), 240)
    upd = H.ask(f"name-update mailhub {ADDR['H']}")
    ok = ok and wait(lambda: W1.ask("name mailhub").startswith("mailhub says") and "0"*64 not in W1.ask("name mailhub"), 240)
    step("init 5a: H registers mailhub and has it say its address", ok, f"{said!r} {upd!r} {W1.ask('name mailhub')!r}")
    t, said = pay(W1, "@mailhub", 2, f"answered by {ADDR['H']}, signed and pooled")
    step(f"init 5b: W1 pays @mailhub ({t and round(t,2)}s)", t is not None and wait(lambda: H.balance() not in ("0",), 90), said); settled(W1)
    # 6. a name under it
    said = H.ask(f"subname set alice@mailhub {ADDR['W2']}")
    ok = wait(lambda: "reached by it at 2 nodes" in W2.ask("subnames"), 60)
    step("init 6a: H gives alice@mailhub to W2, which is reached by it at both seeds", ok, f"{said!r} {W2.ask('subnames')!r}")
    b = W2.balance()
    t, said = pay(W1, "alice@mailhub", 3, f"answered by {ADDR['W2']}, signed and pooled")
    step(f"init 6b: W1 pays alice@mailhub ({t and round(t,2)}s)", t is not None and f"alice@mailhub is {ADDR['W2']}" in W1.log(), said); settled(W1)
    # 7. a name nobody was given
    said = W1.ask("send 1 bob@mailhub")
    ok = wait(lambda: "to bob@mailhub was not delivered (that wallet is not there): given up" in W1.log(), 90)
    step("init 7: a payment to bob@mailhub is an error and is given up", ok and W1.ask("slates").startswith("no payments begun"), said + W1.ask("slates"))
    # 8. another key signs
    word = f"{ROOT}/mailhub.word"
    s1 = H.ask(f"subname delegate mailhub {ADDR['W1']} 10 {word}")
    s2 = W1.ask(f"subname signer {word}")
    s3 = W1.ask(f"subname set desk@mailhub {ADDR['H']}")
    ok = wait(lambda: "this wallet is desk@mailhub" in H.ask("subnames") and "reached by it at 2 nodes" in H.ask("subnames"), 60)
    step("init 8a: W1 signs for mailhub by H's word and gives desk@mailhub to H", ok, f"{s1!r}\n{s2!r}\n{s3!r}\n{H.ask('subnames')!r}")
    settled(W2, 2)
    t, said = pay(W2, "desk@mailhub", 1, f"answered by {ADDR['H']}, signed and pooled")
    step(f"init 8b: W2 pays desk@mailhub ({t and round(t,2)}s)", t is not None, said); settled(W2, 2)
    # 9. one seed stopped
    B.stop(); time.sleep(1)
    times = []
    for i in range(4):
        t, said = pay(W1, ADDR["W2"], 1, f"answered by {ADDR['W2']}, signed and pooled", 60); times.append(t and round(t,2)); settled(W1)
    step(f"init 9: with seed B stopped, four payments still go ({times})", all(x is not None for x in times), said)
    B.start(); 
    ok = wait(lambda: "reached at: 2 of 2" in W1.ask("status") and "reached at: 2 of 2" in W2.ask("status"), 120)
    step("init 9b: B started again, wallets are reached at both again", ok, W1.ask("status"))
    # 4 (late): to a wallet that is not there — C's wallet with C stopped is still relayless here; use a made-up but valid address: H stopped.
    # ---------------- onion ----------------
    relays = f"{ROOT}/relays.txt"
    open(relays, "w").write("mode onion\n" + "".join(f"relay {ADDR[k]} {at(k)}\n" for k in "ABC"))
    said = A.ask(f"set-leaf 0 {relays}")
    say("set-leaf:", said.strip()[:200]); say("consensus:", A.ask("consensus").strip().replace("\n", " | ")[:400])
    ok = wait(lambda: "onion mode" in W1.log() and "onion mode" in W2.log() and "onion mode" in H.log(), 900, 2)
    step(f"onion 3a: the file is voted in and every wallet's node says onion mode (block {A.height()})", ok, A.ask("consensus"))
    ok = wait(lambda: all("reached at: 3 of 3" in N[k].ask("status") for k in ["H","W1","W2"]), 120)
    step("onion 3b: wallets are reached at 3 of 3 relays", ok, "\n".join(k + ": " + N[k].ask("status") for k in N))
    settled(W1)
    t, said = pay(W1, ADDR["W2"], 5, f"answered by {ADDR['W2']}, signed and pooled")
    step(f"onion 4a: W1 pays W2 by address ({t and round(t,2)}s)", t is not None, said); settled(W1)
    t, said = pay(W1, ADDR["W1"], 1, f"answered by {ADDR['W1']}, signed and pooled")
    step(f"onion 4b: W1 pays itself ({t and round(t,2)}s)", t is not None, said); settled(W1)
    t, said = pay(W1, "@mailhub", 2, f"answered by {ADDR['H']}, signed and pooled")
    step(f"onion 4c: W1 pays @mailhub ({t and round(t,2)}s)", t is not None, said); settled(W1)
    ok = wait(lambda: "reached by it at 3 nodes" in W2.ask("subnames"), 120)
    step("onion 4d: W2 is reached by alice@mailhub at 3 relays", ok, W2.ask("subnames"))
    t, said = pay(W1, "alice@mailhub", 3, f"answered by {ADDR['W2']}, signed and pooled")
    step(f"onion 4e: W1 pays alice@mailhub ({t and round(t,2)}s)", t is not None, said); settled(W1)
    said = W1.ask("send 1 bob@mailhub")
    n0 = W1.log().count("to bob@mailhub was not delivered")
    ok = wait(lambda: W1.log().count("to bob@mailhub was not delivered") > n0 - 0 and W1.ask("slates").startswith("no payments begun"), 90)
    step("onion 4f: a payment to bob@mailhub is an error and is given up", ok, said + W1.ask("slates"))
    wait(lambda: "reached by it at 3 nodes" in H.ask("subnames"), 120); settled(W2, 2)
    t, said = pay(W2, "desk@mailhub", 1, f"answered by {ADDR['H']}, signed and pooled")
    step(f"onion 4g: W2 pays desk@mailhub, signed for by word ({t and round(t,2)}s)", t is not None, said + H.ask("subnames")); settled(W2, 2)
    # 5. a relay stopped
    C.stop(); time.sleep(1)
    times = []
    for i in range(4):
        t, said = pay(W1, ADDR["W2"], 1, f"answered by {ADDR['W2']}, signed and pooled", 75); times.append(t and round(t,2)); settled(W1)
        if t is None: say("  no answer:", said.strip()[:80], "|", [l for l in W1.ask("status").splitlines() if "reached" in l], [l for l in W2.ask("status").splitlines() if "reached" in l], "| A:", [l for l in A.ask("status").splitlines() if "sessions" in l or "reached" in l])
    step(f"onion 5: with relay C stopped, payments go again ({times})", times[-1] is not None and times[-2] is not None, said + "\n" + W1.ask("status") + W2.ask("status") + "\n".join(W1.log().splitlines()[-12:]))
    C.start()
    ok = wait(lambda: "reached at: 3 of 3" in W1.ask("status") and "reached at: 3 of 3" in W2.ask("status"), 240)
    step("onion 5b: C started again, wallets are reached at 3 of 3 again", ok, W1.ask("status") + W2.ask("status"))
    # 6. over the next boundary, paying all the while
    h = A.height(); nxt = (h // 144 + 1) * 144
    say(f"at block {h}; paying across block {nxt}")
    seen, fails, count = set(), [], 0
    while A.height() < nxt + 5:
        hh = A.height()
        st = [l for l in W2.ask("status").splitlines() if l.startswith("reached at")]
        if abs(hh - nxt) <= 4: seen.add((hh, st[0] if st else "?"))
        if hh >= nxt - 6:
            t, said = pay(W1, ADDR["W2"], 1, f"answered by {ADDR['W2']}, signed and pooled", 40); count += 1
            if t is None: fails.append((hh, said.strip()[:120]))
            settled(W1)
        else: time.sleep(2)
    say("around the boundary W2 said:", sorted(seen))
    step(f"onion 6: {count} payments across the boundary at block {nxt}, {len(fails)} failed", not fails, repr(fails))
    ok = wait(lambda: "reached at: 3 of 3" in W2.ask("status"), 120)
    step("onion 6b: after the boundary W2 is reached at 3 of 3", ok, W2.ask("status"))
    t, said = pay(W1, "alice@mailhub", 1, f"answered by {ADDR['W2']}, signed and pooled", 60)
    step(f"onion 6c: alice@mailhub is paid in the new epoch ({t and round(t,2)}s)", t is not None, said + W2.ask("subnames"))
except Exception as e:
    import traceback; traceback.print_exc(); step("the run itself", False, repr(e))
finally:
    for n in N.values(): n.stop()
    say("SUMMARY:", sum(1 for _, ok in RESULTS if ok), "passed,", sum(1 for _, ok in RESULTS if not ok), "failed")
    for name, ok in RESULTS:
        if not ok: say("  FAILED:", name)
