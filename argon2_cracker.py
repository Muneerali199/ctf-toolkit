#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
import time
import base64
import argparse
import urllib.request
import itertools
import string

# ============================================================================
# AUTO DEPENDENCY INSTALLER
# ============================================================================
def install_if_missing(package, import_name=None):
    if import_name is None:
        import_name = package
    try:
        __import__(import_name)
    except ImportError:
        print(f"[*] Missing dependency: {package}. Auto-installing...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package, "-q"])
            print(f"[+] Successfully installed {package}")
        except Exception as e:
            print(f"[-] Failed to install {package}: {e}")
            sys.exit(1)

install_if_missing("argon2-cffi", "argon2")
install_if_missing("colorama")
install_if_missing("pyperclip")

try:
    from argon2 import PasswordHasher
    from argon2.low_level import hash_secret, Type
    import colorama
    from colorama import Fore, Back, Style
    import pyperclip
except ImportError as e:
    print(f"[-] Error importing modules after installation: {e}")
    sys.exit(1)

colorama.init(autoreset=True)

# ============================================================================
# GLOBALS & CONSTANTS
# ============================================================================
BANNER = r"""
    ___                    ____   ____                _             
   /   |  _________ ___  __|_  | / __ \_____________ | | __ _____  
  / /| | / ___/ __ `__ \/ /_/ / / / / / ___/ __ `__\| |/ // ___/  
 / ___ |/ /  / / / / / /\__, / / /_/ / /__/ / / / / |   <\__ \   
/_/  |_/_/  /_/ /_/ /_//____/  \____/\___/_/ /_/ /_/|_|\_\____/  
        CTF Argon2 Hash Cracker | By Muneer Ali | picoCTF Tool
"""

# ============================================================================
# FIX 1: MANUAL LOW-LEVEL ARGON2 VERIFICATION (SUPPORTS 16-BYTE TRUNCATED)
# ============================================================================
def manual_argon2_verify(hash_str, password):
    """
    Manual verification that works with truncated hashes.
    Instead of verifying, we RE-HASH the password with 
    same params and compare outputs directly.
    """
    try:
        parts = hash_str.strip().split('$')
        
        variant = parts[1]
        version = int(parts[2].split('=')[1])
        
        params = {}
        for param in parts[3].split(','):
            k, v = param.split('=')
            params[k] = int(v)
            
        memory_cost = params['m']
        time_cost = params['t']
        parallelism = params['p']
        
        def decode_b64(s):
            s = s.replace('-', '+').replace('_', '/')
            padding = 4 - (len(s) % 4)
            if padding != 4:
                s += '=' * padding
            return base64.b64decode(s)
            
        salt = decode_b64(parts[4])
        stored_hash = decode_b64(parts[5])
        hash_len = len(stored_hash) # Use ACTUAL length (16 or 32)
        
        if variant == 'argon2id':
            hash_type = Type.ID
        elif variant == 'argon2i':
            hash_type = Type.I
        else:
            hash_type = Type.D
            
        computed = hash_secret(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=hash_type,
            version=version
        )
        
        computed_parts = computed.decode('utf-8').split('$')
        computed_hash = computed_parts[-1]
        stored_hash_b64 = parts[5]
        
        def normalize_b64(s):
            s = s.rstrip('=')
            return s.replace('+', '-').replace('/', '_')
            
        return normalize_b64(computed_hash) == normalize_b64(stored_hash_b64)
        
    except Exception as e:
        return False

def test_manual_verify():
    print(Fore.CYAN + "[*] Testing manual verification...")
    # Create a known hash with 16 byte length
    test_ph = PasswordHasher(
        memory_cost=65536, time_cost=3, 
        parallelism=4, hash_len=16
    )
    test_hash = test_ph.hash("moon")
    
    if manual_argon2_verify(test_hash, "moon"):
        print(Fore.GREEN + "[+] Manual verify works correctly!")
        return True
    else:
        print(Fore.RED + "[-] Manual verify failed!")
        return False

# ============================================================================
# FIX 2: HASHCAT / JOHN THE RIPPER INTEGRATION
# ============================================================================
def hashcat_crack(hash_str, wordlist_file=None):
    """
    Try cracking with Hashcat or John The Ripper
    """
    print(Fore.YELLOW + "\n[*] Trying Hashcat...")
    
    if not shutil.which('hashcat'):
        print(Fore.RED + "[!] Hashcat not found!")
        if sys.platform == 'darwin':
            print(Fore.CYAN + "[*] Installing via brew...")
            subprocess.run(['brew', 'install', 'hashcat'], capture_output=True)
    
    with open('temp_hash.txt', 'w') as f:
        f.write(hash_str + '\n')
    
    if not wordlist_file:
        wordlist_file = 'words4.txt'
        if os.path.exists('/usr/share/dict/words'):
            subprocess.run('grep -E "^[a-z]{4}$" /usr/share/dict/words > words4.txt', shell=True)
        else:
            with open('words4.txt', 'w') as f:
                f.write("moon\nflag\nhack\nroot\n")
    
    if shutil.which('hashcat'):
        cmd = [
            'hashcat',
            '-m', '13400',
            'temp_hash.txt',
            wordlist_file,
            '--force',
            '--quiet',
            '-O',
        ]
        
        print(Fore.CYAN + f"[*] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            output = result.stdout + result.stderr
            for line in output.splitlines():
                if ':' in line and 'argon2' in line.lower():
                    return line.split(':')[-1].strip()

    print(Fore.YELLOW + "[*] Trying John the Ripper...")
    if shutil.which('john'):
        john_cmd = ['john', '--format=argon2', '--wordlist=' + wordlist_file, 'temp_hash.txt']
        result = subprocess.run(john_cmd, capture_output=True, text=True)
        if 'password hash cracked' in result.stdout.lower() or 'Loaded 1 password' in result.stdout:
            show_cmd = ['john', '--show', 'temp_hash.txt']
            show = subprocess.run(show_cmd, capture_output=True, text=True)
            for line in show.stdout.splitlines():
                if ':' in line and not line.startswith('0 password'):
                    return line.split(':')[1]
    else:
        print(Fore.RED + "[-] John the Ripper not found. Skipping.")
        
    return None

# ============================================================================
# WORDLIST GENERATOR
# ============================================================================
def build_complete_wordlist(length=4):
    all_words = []
    seen = set()
    
    def add(word):
        w = word.strip()
        if w and w not in seen:
            seen.add(w)
            all_words.append(w)
    
    tier1 = [
        "flag","hack","code","root","pass","test","ctf","pico",
        "pwnd","vuln","admin","user","sudo","bash","salt","hash",
        "wolf","bear","lion","fish","bird","frog","duck","deer",
        "cat","dog","bat","rat","pig","cow","fox","owl","elk",
        "fire","dark","moon","star","rain","snow","wind","rock",
        "gold","blue","time","life","cave","gate","path","wave",
        "sand","tree","leaf","seed","rose","lake","hill","jade",
        "love","hate","king","hero","zero","ship","boat","door",
        "wall","road","book","milk","beer","wine","cake","ruby",
        "iron","rust","data","byte","word","find","curl","make",
        "free","safe","lost","warm","cool","high","deep","wide",
        "true","evil","good","fake","real","dead","born","void",
        "null","meat","meal","deal","heal","seal","teal","able",
        "army","base","bath","bell","belt","bill","bind","bite",
        "bond","bone","boss","bowl","burn","busy","grid","kill",
        "land","lava","lazy","lead","lean","leap","lend","lens",
        "lime","line","link","list","live","load","lock","logo",
        "loom","loop","lore","luck","maze","melt","mesa","mesh",
        "mild","mill","mind","mine","mint","mist","mock","mode",
        "mold","mole","mood","moor","moth","muse","musk","mute",
        "myth","name","navy","near","neck","nest","news","nice",
        "nick","node","norm","nose","note","numb","odds","once",
        "open","oral","orca","oven","pace","pack","page","pain",
        "pair","pale","palm","pane","park","part","peak","peel",
        "peer","pick","pile","pine","pink","pipe","plan","plot",
        "plow","plug","poem","pole","poll","pond","pool","pore",
        "port","pour","prey","prod","prop","pull","pump","push",
        "quit","race","rack","raid","rail","rake","rank","rare",
        "rash","rate","rave","rays","read","ream","reap","rear",
        "reed","reef","reek","reel","rely","rend","rent","rest",
        "rice","rich","ride","rift","ring","riot","ripe","rise",
        "risk","rite","roam","roar","robe","role","roll","roof",
        "room","rope","rout","rove","ruin","rule","ruse","rush",
        "saga","sage","sake","sale","sane","save","scan","scar",
        "seam","sear","self","sell","send","shed","shin","show",
        "shun","shut","sick","side","sift","sigh","silk","sill",
        "silo","sing","sink","site","size","skin","skip","slab",
        "slam","slap","slay","slim","slip","slot","slow","slug",
        "slum","slur","smug","snag","snap","snip","soak","soar",
        "sock","soft","soil","sole","some","song","soon","sore",
        "sort","soul","span","spar","spin","spit","spun","stab",
        "stem","step","stir","stun","such","suit","sulk","sung",
        "sunk","sure","surf","swan","swap","swat","sway","tack",
        "tale","tall","tame","tang","tape","tarn","tart","task",
        "team","tear","teem","tell","tend","tent","term","thin",
        "tick","tide","tilt","toad","toil","toll","tome","tone",
        "tore","torn","toss","town","trap","tray","trek","trim",
        "trio","trip","trod","tuck","tuft","tuna","tune","turf",
        "tusk","twin","type","ugly","unit","urge","vain","vale",
        "vane","vary","vast","veil","vein","verb","vest","vibe",
        "vile","vine","vise","vole","volt","vote","wail","wake",
        "wane","warp","wart","wash","wasp","weak","wean","weep",
        "weld","welt","whet","whim","whip","whom","wick","wilt",
        "wimp","wink","wire","wise","wish","wisp","woke","womb",
        "wore","worm","wort","wove","writ","yawn","yell","yoga",
        "yore","zeal","zest","zinc","zone","zoom","atom","axis",
        "blur","bold","bulk","cell","chip","clan","clap","clay",
        "clip","clue","coal","coil","coin","colt","cone","cook",
        "cork","corn","coup","crew","crop","crow","cull","cult",
        "curb","cure","curl","cyst","damp","daze","deft","dent",
        "dew","dial","dice","dime","dine","dire","disk","dusk",
        "dust","dyed","edge","emit","envy","epic","exam","fawn",
        "feat","fern","feud","flaw","flea","flew","flex","flip",
        "flit","flog","flow","foam","foes","fold","fond","font",
        "ford","fore","fork","form","fort","foul","fowl","fray",
        "fume","fund","furl","fury","fuse","fuzz","gale","gall",
        "gash","gaze","gear","germ","gild","gill","gird","gist",
        "glen","glib","glob","glow","glue","glyph","gnaw","goad",
        "gore","gory","gust","guts","hack","hail","hale","halt",
        "harp","haze","heed","helm","hemp","herb","herd","hewn",
        "hike","hilt","hive","hoax","hone","hood","hoop","hose",
        "hulk","hull","hump","hung","hunk","hunt","hurl","hymn",
        "ibis","inch","iris","isle","itch","jab","jail","jest",
        "jolt","jot","jowl","junk","just","keen","kelp","kern",
        "knit","knob","knot","lace","lard","lark","lash","latch",
        "laud","lax","laze","lilt","lisp","lob","loch","loft",
        "loin","loll","lope","lour","lox","lube","lug","lunge",
        "lurk","lust","mace","malt","mar","mare","mars","mart",
        "mast","maul","meek","mire","mob","mock","molt","moat",
        "mop","mote","moue","mourn","mow","mucus","mud","mug",
        "mulch","mull","murk","narc","nark","nett","newt","nip",
        "nit","notch","nook","nova","nub","nun","nuns","oaf",
        "oar","oat","oboe","okra","omen","omit","orb","ore",
        "pact","pare","parr","pave","pawn","peat","peck","peg",
        "pelt","perch","pest","phase","plop","plow","ploy","plum",
        "plop","pock","pod","pomp","pore","pose","posh","pot",
        "pouch","pout","pox","prank","preen","prow","prude","pry",
        "puck","pug","pulp","pun","punt","purr","quad","quay",
        "rave","raze","razz","ream","riff","rile","rind","rink",
        "romp","rook","rot","roux","ruffle","rue","rug","rum",
        "rump","rune","rung","rut","sag","sap","sass","sate",
        "scalp","scam","scone","scoop","scope","scorn","scour",
        "scowl","scrap","shag","sham","shank","shard","skit",
        "skulk","skunk","slab","slew","sloe","slop","sloth",
        "slug","smear","smelt","snare","snob","snore","snub",
        "spade","spank","spar","spawn","speck","spew","spite",
        "spoil","spook","spore","sprat","sprig","sprout","spry",
        "spur","stag","stale","stalk","stall","stave","stew",
        "stint","stomp","stoop","store","stork","storm","stout",
        "stub","stump","stung","sty","suds","swab","swag",
        "swam","swamp","swear","swill","swoop","swore","swum",
        "taint","tally","talon","tamp","tang","tangle","taunt",
        "tawny","text","thaw","thud","thug","thump","tier",
        "tiff","tilt","timid","tinge","tint","tip","toad",
        "tog","tong","top","topple","torch","tore","totem",
        "tow","toxic","tract","tramp","trash","trawl","tread",
        "tremble","trench","tress","tripe","tromp","trope",
        "troth","trounce","trout","trove","truant","trudge",
        "trump","trunk","truss","tuber","tuck","tug","tumble",
        "tunic","turban","turf","twig","twill","twinge","twirl",
        "twit","ulcer","umber","undo","unrest","unwrap","urn",
        "uvula","vapor","vault","veer","verge","vigor","viper",
        "virus","visor","vista","vomit","vouch","waft","wager",
        "waif","wallow","waltz","warble","wards","wares","wrath",
        "wring","wrist","xenon","yoke","zeal",
    ]
    for w in tier1:
        if len(w) == length:
            add(w)
            
    try:
        result = subprocess.run(
            ['grep', '-E', f'^[a-z]{{{length}}}$', '/usr/share/dict/words'],
            capture_output=True, text=True
        )
        for w in result.stdout.splitlines():
            add(w)
    except:
        pass
    
    if os.path.exists('rockyou.txt'):
        with open('rockyou.txt', encoding='utf-8', errors='ignore') as f:
            for line in f:
                w = line.strip()
                if len(w) == length:
                    try:
                        w.encode('ascii')
                        add(w)
                    except:
                        pass
                        
    for combo in itertools.product(string.ascii_lowercase, repeat=length):
        add(''.join(combo))
        
    return all_words

def show_flag(password):
    print(Fore.GREEN + f"""
╔══════════════════════════════════════╗
║  PASSWORD CRACKED!                   ║
║  Password : {password:<26} ║
║  Flag     : picoCTF{{{password}}}{' '*(22-len(password))} ║
╚══════════════════════════════════════╝
""")
    with open('ctf_flags.txt', 'a') as f:
        f.write(f"picoCTF{{{password}}}\n")
    try:
        pyperclip.copy(f"picoCTF{{{password}}}")
        print(Fore.CYAN + "[+] Copied to clipboard!")
    except:
        pass

def read_hash_from_file(filepath):
    try:
        with open(filepath, 'r') as f:
            hash_str = f.read().strip()
        hash_str = hash_str.strip()
        if not hash_str.startswith('$argon2'):
            raise ValueError(f"Invalid hash format: {hash_str[:20]}")
        return hash_str
    except Exception as e:
        print(Fore.RED + f"[-] Error reading hash file: {e}")
        sys.exit(1)

# ============================================================================
# MAIN EXECUTION
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description="Argon2 Cracker for CTFs")
    parser.add_argument("--hashfile", help="File containing Argon2 hash")
    parser.add_argument("--length", type=int, default=4, help="Password length filter (default: 4)")
    args = parser.parse_args()

    print(Fore.GREEN + Style.BRIGHT + BANNER)
    
    if not args.hashfile:
        print(Fore.RED + "[-] Missing --hashfile argument!")
        sys.exit(1)

    hash_str = read_hash_from_file(args.hashfile)
    
    print(Fore.CYAN + f"[*] Hash: {hash_str}")
    print(Fore.CYAN + f"[*] Hash length: {len(hash_str)}")
    
    parts = hash_str.split('$')
    hash_bytes_b64 = parts[-1]
    
    padding = 4 - len(hash_bytes_b64) % 4
    if padding != 4:
        hash_bytes_b64 += '=' * padding
        
    hash_bytes = base64.b64decode(hash_bytes_b64)
    print(Fore.CYAN + f"[*] Hash size: {len(hash_bytes)} bytes", end=" ")
    if len(hash_bytes) == 16:
        print(Fore.YELLOW + "(TRUNCATED - using manual verification)")
    else:
        print(Fore.GREEN + "(COMPLETE)")
        
    if not test_manual_verify():
        sys.exit(1)
    
    print(Fore.MAGENTA + "\n[>>>] ATTACK 1: HASHCAT <<<")
    result = hashcat_crack(hash_str)
    if result:
        show_flag(result)
        return
    
    print(Fore.MAGENTA + "\n[>>>] ATTACK 2: MANUAL ARGON2 VERIFICATION <<<")
    wordlist = build_complete_wordlist(length=args.length)
    
    start = time.time()
    for i, word in enumerate(wordlist):
        if not word.strip():
            continue
        try:
            word.encode('ascii')
        except:
            continue
            
        if i % 5 == 0:
            elapsed = time.time() - start
            rate = i / elapsed if elapsed > 0 else 0
            eta = (len(wordlist) - i) / rate / 60 if rate > 0 else 0
            sys.stdout.write(f"\r{Fore.CYAN}  [{i}/{len(wordlist)}] {word:<15} Rate:{rate:.1f}/s ETA:{eta:.1f}min{Style.RESET_ALL} ")
            sys.stdout.flush()
        
        if manual_argon2_verify(hash_str, word):
            sys.stdout.write("\n")
            show_flag(word)
            return
            
    print(Fore.RED + "\n[-] Not cracked")

if __name__ == "__main__":
    main()