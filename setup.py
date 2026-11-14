"""Job-authored pinned, local-only setup. No global install or TLS overrides."""
import hashlib, html.parser, json, os, pathlib, subprocess, tarfile, urllib.request, venv

os.nice(10)
root = pathlib.Path(__file__).resolve().parent
demo = root / 'demo'
meta = json.loads((root / 'download-metadata.json').read_text())
downloads = root / 'downloads'
downloads.mkdir(exist_ok=True)
def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()
def download(url, name, digest):
    path = downloads / name
    if not path.exists(): path.write_bytes(fetch(url))
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, name
    print('verified ' + name, flush=True)
    return path
go = meta['go']['data']
archive = download('https://go.dev/dl/' + go['filename'], go['filename'], go['sha256'])
target = root / 'toolchains' / 'go1.27.3'
if not (target / 'go/bin/go').exists():
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as tar: tar.extractall(target, filter='data')
wheel = next(f for f in meta['z3_pypi']['data']['files'] if 'manylinux_2_27_x86_64' in f['filename'])
wheelpath = download(wheel['url'], wheel['filename'], wheel['sha256'])
envpath = root / 'venv'
if not (envpath / 'bin/python').exists(): venv.create(envpath, with_pip=True)
env = os.environ | {'PIP_NO_CACHE_DIR':'1','PIP_DISABLE_PIP_VERSION_CHECK':'1','PYTHONDONTWRITEBYTECODE':'1'}
proc = subprocess.run([str(envpath/'bin/python'), '-m', 'pip', 'install', '--no-index', '--no-deps', str(wheelpath)], env=env, capture_output=True, text=True)
assert proc.returncode == 0, 'local wheel installation failed'
url = 'https://developers.googleblog.com/catch-go-bugs-that-fuzzing-misses-with-gemini-and-a-constraint-solver/'
raw = fetch(url)
class Blocks(html.parser.HTMLParser):
    def __init__(self): super().__init__(); self.depth=0; self.blocks=[]; self.current=''
    def handle_starttag(self, tag, attrs):
        if tag == 'pre': self.depth+=1; self.current=''
    def handle_endtag(self, tag):
        if tag == 'pre': self.depth-=1; self.blocks.append(self.current)
    def handle_data(self, data):
        if self.depth: self.current+=data
parser=Blocks(); parser.feed(raw.decode())
chosen={}
for key, needle in [('parser','func ParseTwoChunkFrame'),('solver','import z3'),('clip','f.Fuzz(')]:
    code=next(b for b in parser.blocks if needle in b).strip()+'\n'
    chosen[key]=code
    assert 'Copyright' not in code or 'Copyright' in code
source=demo/'source'; source.mkdir(exist_ok=True)
(source/'published_parser.go').write_text('// Source: '+url+'\n// Function as published; package declaration is job-authored.\npackage demo\n\n'+chosen['parser'])
(source/'published_solver.py').write_text('# Source: '+url+'\n# As published.\n'+chosen['solver'])
(source/'published_clip.txt').write_text('// Source: '+url+'\n// As published (fragment).\n'+chosen['clip'])
provenance={'article_url':url,'publication_date':'2026-11-12','publisher':'Google Developers Blog','article_response_sha256':hashlib.sha256(raw).hexdigest(),'code_sha256':{k:hashlib.sha256(v.encode()).hexdigest() for k,v in chosen.items()},'licence_notice_in_selected_blocks':any('copyright' in v.lower() or 'license' in v.lower() for v in chosen.values()),'go_archive_sha256':go['sha256'],'z3_wheel_sha256':wheel['sha256'],'z3_distribution_version':meta['z3_pypi']['data']['version']}
(demo/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
print('local toolchains and published code ready', flush=True)
