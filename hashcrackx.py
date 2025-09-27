#!/usr/bin/env python3

import base64, binascii, codecs, string, urllib.parse, html, re, sys, os
from termcolor import cprint
import pyfiglet
import time

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("="*80)
    title = pyfiglet.figlet_format("HashCrackerX", font="slant")
    author = pyfiglet.figlet_format("Developed by Zencrypt", font="digital")
    colors = ["red","yellow","green","cyan","white","magenta"]
    for i, line in enumerate(title.splitlines()):
        if line.strip(): cprint(line, colors[i % len(colors)], attrs=["bold"])
    for i, line in enumerate(author.splitlines()):
        if line.strip(): cprint(line, colors[(i+4) % len(colors)], attrs=["bold"])
    cprint("="*80, "yellow", attrs=["bold"])


COMMON_WORDS = ["the","and","that","this","flag","ctf","is","are","you","hello","password"]
def english_score(s):
    s_low = s.lower()
    score = sum(s_low.count(w) for w in COMMON_WORDS)
    letter_score = sum(s_low.count(ch) for ch in " etaoinshrdlu") / max(1, len(s))
    return score + letter_score*2

def printable_ratio(s):
    if not s: return 0.0
    return sum(1 for ch in s if ch.isprintable())/len(s)

def is_hash(s):
    hex_only = all(c in string.hexdigits for c in s)
    L = len(s)
    if hex_only:
        if L==32: return ("MD5",1.0)
        if L==40: return ("SHA1",1.0)
        if L==56: return ("SHA224",1.0)
        if L==64: return ("SHA256",1.0)
        if L==96: return ("SHA384",1.0)
        if L==128: return ("SHA512",1.0)
    return (None,0.0)


def try_base64(s):
    
    try:
        out = base64.b64decode(s, validate=True)
        text = out.decode('utf-8', errors='ignore')
        return text, 0.95
    except Exception:
        pass
    try:
        out = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
        text = out.decode('utf-8', errors='ignore')
        return text, 0.9
    except Exception:
        return None, 0.0

def try_base32(s):
    try:
        out = base64.b32decode(s, casefold=True)
        text = out.decode('utf-8', errors='ignore')
        return text, 0.9
    except Exception:
        return None, 0.0

def try_base85(s):
    for fn in (base64.a85decode, base64.b85decode):
        try:
            out = fn(s)
            text = out.decode('utf-8', errors='ignore')
            return text, 0.85
        except Exception:
            continue
    return None, 0.0

def try_base58(s):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if any(ch not in alphabet for ch in s): return None, 0.0
    try:
        num = 0
        for ch in s:
            num = num*58 + alphabet.index(ch)
        combined = num.to_bytes((num.bit_length()+7)//8, 'big') or b'\x00'
       
        npad = len(s) - len(s.lstrip('1'))
        out = (b'\x00'*npad + combined).decode('utf-8', errors='ignore')
        return out, 0.8 if printable_ratio(out) > 0.6 else (out, 0.5)
    except Exception:
        return None, 0.0

def try_hex(s):
    s_clean = s.replace(" ", "")
    if not s_clean: return None, 0.0
    if all(c in string.hexdigits for c in s_clean) and len(s_clean) % 2 == 0:
        try:
            out = bytes.fromhex(s_clean).decode('utf-8', errors='ignore')
            return out, 0.9 if printable_ratio(out) > 0.6 else (out, 0.6)
        except Exception:
            return None, 0.0
    return None, 0.0

def try_binary(s):
    s_clean = s.replace(" ", "")
    if not s_clean or any(c not in "01" for c in s_clean): return None, 0.0
    if len(s_clean) % 8 != 0: return None, 0.0
    try:
        out = bytes(int(s_clean[i:i+8], 2) for i in range(0, len(s_clean), 8)).decode('utf-8', errors='ignore')
        return out, 0.9 if printable_ratio(out) > 0.6 else (out, 0.6)
    except Exception:
        return None, 0.0

def try_url(s):
    if "%" in s:
        out = urllib.parse.unquote(s)
        return out, 0.8
    return None, 0.0

def try_html_entities(s):
    if "&#" in s or "&amp;" in s or "&lt;" in s:
        out = html.unescape(s)
        return out, 0.8
    return None, 0.0

def try_uudecode(s):
    try:
        out = binascii.a2b_uu(s).decode('utf-8', errors='ignore')
        return out, 0.75
    except Exception:
        return None, 0.0

def try_rot13(s):
    out = codecs.decode(s, 'rot_13')
    score = 0.6 + 0.4*bool(sum(out.lower().count(w) for w in COMMON_WORDS))
    return out, score if out!=s else (None, 0.0)

def try_rot5(s):
    if not any(ch.isdigit() for ch in s): return None, 0.0
    table = str.maketrans("0123456789","5678901234")
    out = s.translate(table)
    return out, 0.6

def try_rot18(s):
  
    if not any(ch.isalpha() for ch in s) and not any(ch.isdigit() for ch in s):
        return None, 0.0
  
    out = []
    for ch in s:
        if ch.isalpha():
            out.append(codecs.decode(ch, 'rot_13'))
        elif ch.isdigit():
            out.append(str((int(ch)+5)%10))
        else:
            out.append(ch)
    out = ''.join(out)
    score = 0.6 + 0.3*bool(sum(out.lower().count(w) for w in COMMON_WORDS))
    return out, score

def try_atbash(s):
    def at(c):
        if c.isupper(): return chr(65 + (25-(ord(c)-65)))
        if c.islower(): return chr(97 + (25-(ord(c)-97)))
        return c
    out = ''.join(at(c) for c in s)
    score = 0.5 + 0.4*bool(sum(out.lower().count(w) for w in COMMON_WORDS))
    return out, score if out!=s else (None, 0.0)

def try_reverse(s):
    out = s[::-1]
    return out, 0.5 + 0.4*bool(sum(out.lower().count(w) for w in COMMON_WORDS)) if out!=s else (None, 0.0)

MORSE = {
    '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I',
    '.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R',
    '...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z',
    '-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9','/':' '
}
def try_morse(s):
    if not all(ch in ".- /" for ch in s.strip()): return None, 0.0
    parts = s.strip().split()
    out = ''.join(MORSE.get(p, '') for p in parts)
    return out, 0.75 if out else (None, 0.0)


ENGLISH_FREQ = {'E':12.0,'T':9.1,'A':8.12,'O':7.68,'I':7.31,'N':6.95,' ':13.0}
def score_text_for_english(txt):
    s = txt.upper()
    return sum(s.count(ch) * ENGLISH_FREQ.get(ch, 0) for ch in ENGLISH_FREQ)

def single_byte_xor_candidates(s, max_candidates=3):
 
    data = None
    try:
        hex_clean = s.replace(" ","")
        if all(c in string.hexdigits for c in hex_clean) and len(hex_clean)%2==0:
            data = bytes.fromhex(hex_clean)
        else:
            data = s.encode('latin-1', errors='ignore')
    except Exception:
        data = s.encode('latin-1', errors='ignore')

    candidates = []
    for key in range(256):
        out = bytes(b ^ key for b in data)
        try:
            txt = out.decode('utf-8')
        except:
            txt = out.decode('latin-1', errors='ignore')
        pr = printable_ratio(txt)
        if pr < 0.85: 
            continue
        score = score_text_for_english(txt)
        if score < 15: 
            continue
        candidates.append((key, score, txt))
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[:max_candidates]


COMMON_KEYS = ["secret","password","key","ctf","flag","admin","hello"]
def vigenere_try(s):
    results = []
    if not any(ch.isalpha() for ch in s): return results
    for k in COMMON_KEYS:
        out = []
        ki = 0
        for ch in s:
            if ch.isalpha():
                base = 65 if ch.isupper() else 97
                shift = ord(k[ki % len(k)].lower()) - 97
                out.append(chr((ord(ch) - base - shift) % 26 + base))
                ki += 1
            else:
                out.append(ch)
        txt = ''.join(out)
        if any(w in txt.lower() for w in COMMON_WORDS):
            results.append((k, txt))
    return results


def detect_single(text):
    
    results = []
 
    hname, hconf = is_hash(text)
    if hname:
        results.append({'method': hname, 'confidence': 1.0, 'decoded': None, 'note': 'Hash (one-way)'} )
        return results  

  
    checks = [
        ("Base64", try_base64),
        ("Base32", try_base32),
        ("Base85", try_base85),
        ("Base58", try_base58),
        ("Hex", try_hex),
        ("Binary", try_binary),
        ("URL", try_url),
        ("HTML Entities", try_html_entities),
        ("UUDecode", try_uudecode),
        ("ROT13", try_rot13),
        ("ROT5", try_rot5),
        ("ROT18", try_rot18),
        ("Atbash", try_atbash),
        ("Reverse", try_reverse),
        ("Morse", try_morse),
    ]

    for name, fn in checks:
        try:
            out, conf = fn(text)
        except Exception:
            out, conf = None, 0.0
        if out is not None and conf > 0.0:
          
            esc = english_score(out)
            if esc > 0:
                conf = min(1.0, conf + 0.15)
          
            if printable_ratio(out) > 0.4 or any(w in out.lower() for w in COMMON_WORDS):
                results.append({'method': name, 'confidence': round(conf,2), 'decoded': out, 'note': None})

    xor_cands = single_byte_xor_candidates(text, max_candidates=2)
    for key, score, txt in xor_cands:
        results.append({'method': f"SingleByteXOR (key={key})", 'confidence': 0.9, 'decoded': txt, 'note': f"english_score={int(score)}"})

    
    vig = vigenere_try(text)
    for k, dec in vig:
        results.append({'method': f"Vigenere (key='{k}')", 'confidence': 0.8, 'decoded': dec, 'note': None})

   
    results.sort(key=lambda r: (r['confidence'], english_score(r['decoded'] or "")), reverse=True)
    return results


def peel(text, depth=2, limit_per_layer=3):
  
    steps = []
    queue = [(text, 0)]
    seen = {text}
    while queue:
        cur, d = queue.pop(0)
        if d >= depth: continue
        out_list = detect_single(cur)
        for out in out_list[:limit_per_layer]:
            dec = out['decoded']
            if dec and dec not in seen and dec.strip() and dec != cur:
                seen.add(dec)
                steps.append({'from': cur, 'method': out['method'], 'confidence': out['confidence'], 'to': dec})
                queue.append((dec, d+1))
    return steps


def main():
    banner()
    text = input("🔹 Paste the encoded/obfuscated text: ").strip()
    print("\n🔎 Detecting best guesses (this will avoid noisy low-confidence outputs)...\n")
    time.sleep(0.25)
    results = detect_single(text)
    if not results:
        cprint("No likely method detected. It might be a custom or binary blob.", "yellow")
        return
    cprint(f"Likely methods (top {min(5,len(results))}):","green", attrs=["bold"])
    for i, r in enumerate(results[:5], start=1):
        method = r['method']
        conf = r['confidence']
        decoded = r['decoded']
        note = r['note']
        cprint(f"{i}. {method}  (confidence {conf*100:.0f}%)", "cyan", attrs=["bold"])
        if decoded:
  
            snippet = decoded if len(decoded) <= 300 else decoded[:300] + " ... [truncated]"
            cprint(f"   → {snippet}", "white")
        if note:
            cprint(f"   note: {note}", "yellow")


    steps = peel(text, depth=2, limit_per_layer=2)
    if steps:
        cprint("\nMulti-layer peel (limited):", "green")
        for st in steps:
            cprint(f"[{st['method']}] -> {st['to'][:200]}{' ...' if len(st['to'])>200 else ''}", "magenta")

if __name__ == "__main__":
    main()
