from pathlib import Path
import json
root=Path(__file__).resolve().parents[1]
categories={
'factual':[
('What is the capital city of Australia?','https://en.wikipedia.org/wiki/Canberra'),
('How long does Mercury take to orbit the Sun?','https://science.nasa.gov/mercury/facts/'),
('Who developed the theory of general relativity?','https://en.wikipedia.org/wiki/Albert_Einstein'),
('When was the United Nations founded?','https://www.un.org/en/about-us/history-of-the-un'),
('What is the SI definition of a metre?','https://www.bipm.org/en/measurement-units/si-base-units'),
('How many chambers does a human heart have?','https://en.wikipedia.org/wiki/Heart'),
('What is the tallest mountain above sea level?','https://en.wikipedia.org/wiki/Mount_Everest'),
('Why is Venus hotter than Mercury?','https://science.nasa.gov/venus/facts/'),
('What is the chemical symbol for gold?','https://en.wikipedia.org/wiki/Gold'),
('What causes the phases of the Moon?','https://science.nasa.gov/moon/moon-phases/')],
'how_to_technical':[
('How do I create a Python virtual environment with venv?','https://docs.python.org/3/library/venv.html'),
('How do I parse JSON into a Python dictionary?','https://docs.python.org/3/library/json.html'),
('How do I read a text file into a string in Rust?','https://doc.rust-lang.org/std/fs/fn.read_to_string.html'),
('How do I handle recoverable errors using Result in Rust?','https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html'),
('How do I make an HTTP request with the JavaScript Fetch API?','https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch'),
('How do I define a CSS grid layout?','https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_grid_layout/Basic_concepts_of_grid_layout'),
('How do I run a subprocess and capture its output in Python?','https://docs.python.org/3/library/subprocess.html'),
('How do I undo the last Git commit while keeping the changes?','https://git-scm.com/docs/git-reset'),
('How do I create a PostgreSQL database table?','https://www.postgresql.org/docs/current/tutorial-table.html'),
('How do I publish a Rust crate to crates.io?','https://doc.rust-lang.org/cargo/reference/publishing.html')],
'product_commerce':[
('Find the official Raspberry Pi 5 product specifications.','https://www.raspberrypi.com/products/raspberry-pi-5/'),
('Find the official Framework Laptop 13 product page.','https://frame.work/laptop13'),
('Find the Apple MacBook Air technical specifications.','https://www.apple.com/macbook-air/specs/'),
('Find the official Nintendo Switch OLED model product page.','https://www.nintendo.com/us/gaming-systems/switch/oled-model/'),
('Find the official Steam Deck OLED product page.','https://www.steamdeck.com/en/oled'),
('Find the official Sony WH-1000XM5 wireless headphones page.','https://electronics.sony.com/audio/headphones/headband/p/wh1000xm5-b'),
('Find the Logitech MX Master 3S mouse product page.','https://www.logitech.com/en-us/products/mice/mx-master-3s.910-006556.html'),
('Find the official Prusa MK4S 3D printer product page.','https://www.prusa3d.com/product/original-prusa-mk4s-3d-printer-5/'),
('Find the official Arduino Uno Rev3 board specifications.','https://store.arduino.cc/products/arduino-uno-rev3'),
('Find the official Fairphone 5 product page.','https://www.fairphone.com/en/fairphone-5/')],
'recent_news':[
('What did the September 2026 Rust debugging survey results say?','https://blog.rust-lang.org/2026/09/07/rust-debugging-survey-2026-results/'),
('What did Rust 1.98.1 fix in September 2026?','https://blog.rust-lang.org/2026/09/03/Rust-1.98.1/'),
('What changed in rustup 1.29.1 released in September 2026?','https://blog.rust-lang.org/2026/09/01/Rustup-1.29.1/'),
('Who are the first Rust Maintainers in Residence announced in August 2026?','https://blog.rust-lang.org/2026/08/26/announcing-our-first-maintainers-in-residence/'),
('What changed when Rust enabled the next generation trait solver on nightly in August 2026?','https://blog.rust-lang.org/2026/08/21/enabling-next-solver-on-nightly/'),
('What happened in the August 2026 arrayref supply chain attack?','https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/'),
('What features were stabilised in Rust 1.98.0 in August 2026?','https://blog.rust-lang.org/2026/08/20/Rust-1.98.0/'),
('When does Firefox switch to a two week release cadence in 2026?','https://blog.mozilla.org/sumo/2026/08/19/firefox-new-release-cadence-and-what-to-expect/'),
('What did Hubble and Webb discover about distant solar system objects in September 2026?','https://science.nasa.gov/missions/hubble/nasas-hubble-webb-find-far-out-solar-system-objects-remember-past/'),
('What did Hubble find around Saturn south pole in September 2026?','https://science.nasa.gov/missions/hubble/nasas-hubble-tracks-new-decagon-encircling-saturns-south-pole/')],
'image_bearing':[
('Find a page with a photograph of the Eiffel Tower.','https://en.wikipedia.org/wiki/Eiffel_Tower'),
('Find a page showing the Mona Lisa painting.','https://en.wikipedia.org/wiki/Mona_Lisa'),
('Find a page with images of the Pillars of Creation.','https://en.wikipedia.org/wiki/Pillars_of_Creation'),
('Find photographs of the Grand Canyon on an informative page.','https://en.wikipedia.org/wiki/Grand_Canyon'),
('Find a page illustrating the Japanese cherry blossom.','https://en.wikipedia.org/wiki/Cherry_blossom'),
('Find a page with a photograph of a red panda.','https://en.wikipedia.org/wiki/Red_panda'),
('Find a page with pictures of the Sydney Opera House.','https://en.wikipedia.org/wiki/Sydney_Opera_House'),
('Find a page showing the Rosetta Stone.','https://en.wikipedia.org/wiki/Rosetta_Stone'),
('Find a page with a picture of the aurora borealis.','https://en.wikipedia.org/wiki/Aurora'),
('Find a page with images of the James Webb Space Telescope.','https://en.wikipedia.org/wiki/James_Webb_Space_Telescope')]
}
queries=[]; seeds=[]
for cat, items in categories.items():
 for q,url in items:
  queries.append({'id':f'q{len(queries)+1:02}','category':cat,'query':q,'candidate_url':url,'acceptable_urls':[],'label_status':'pending_crawl_and_index_verification'})
  seeds.append({'url':url,'category':cat})
def add(base,paths,cat):
 for p in paths.split():
  url=base+p
  if url not in {s['url'] for s in seeds}:seeds.append({'url':url,'category':cat})
add('https://en.wikipedia.org/wiki/','Ada_Lovelace Alan_Turing Charles_Darwin Marie_Curie Isaac_Newton Paris London Tokyo Berlin Rome Solar_System Earth Mars Jupiter Saturn Uranus Neptune Sun Photosynthesis Water Oxygen Carbon_Dioxide DNA Evolution Climate_change Great_Barrier_Reef Taj_Mahal Stonehenge Colosseum Machu_Picchu Blue_whale Tiger Lion Giraffe Elephant Penguin Volcano Rainbow Waterfall', 'reference_image')
add('https://docs.python.org/3/library/','pathlib.html csv.html sqlite3.html argparse.html asyncio.html concurrent.futures.html threading.html multiprocessing.html datetime.html zoneinfo.html time.html math.html statistics.html random.html secrets.html hashlib.html hmac.html ssl.html http.client.html urllib.request.html urllib.parse.html gzip.html zipfile.html tarfile.html shutil.html tempfile.html os.html sys.html logging.html unittest.html re.html collections.html itertools.html functools.html dataclasses.html typing.html enum.html contextlib.html io.html socket.html', 'technical')
add('https://doc.rust-lang.org/book/','ch01-01-installation.html ch01-02-hello-world.html ch01-03-hello-cargo.html ch02-00-guessing-game-tutorial.html ch03-01-variables-and-mutability.html ch03-02-data-types.html ch03-03-how-functions-work.html ch03-05-control-flow.html ch04-01-what-is-ownership.html ch04-02-references-and-borrowing.html ch04-03-slices.html ch05-01-defining-structs.html ch05-03-method-syntax.html ch06-01-defining-an-enum.html ch06-02-match.html ch07-01-packages-and-crates.html ch08-01-vectors.html ch08-02-strings.html ch08-03-hash-maps.html ch10-01-syntax.html ch10-02-traits.html ch10-03-lifetime-syntax.html ch11-01-writing-tests.html ch12-00-an-io-project.html ch13-01-closures.html ch13-02-iterators.html ch15-01-box.html ch16-01-threads.html ch16-03-shared-state.html ch17-01-futures-and-syntax.html', 'technical')
add('https://www.gov.uk/','renew-adult-passport apply-first-adult-passport register-to-vote check-uk-visa foreign-travel-advice bank-holidays national-minimum-wage-rates income-tax-rates apply-online-to-replace-a-driving-licence vehicle-tax check-mot-history check-mot-status apply-provisional-driving-licence government/organisations government/how-government-works government/get-involved browse/housing-local-services browse/working browse/education browse/business', 'government_how_to')
add('https://www.raspberrypi.com/products/','raspberry-pi-4-model-b/ raspberry-pi-400/ raspberry-pi-zero-2-w/ raspberry-pi-pico/ raspberry-pi-pico-2/ raspberry-pi-camera-module-3/ raspberry-pi-global-shutter-camera/ raspberry-pi-ssd/ raspberry-pi-touch-display-2/ raspberry-pi-ai-kit/', 'product_commerce')
add('https://science.nasa.gov/','mars/facts/ jupiter/facts/ saturn/facts/ uranus/facts/ neptune/facts/ sun/facts/ moon/facts/ solar-system/ planets/ universe/', 'factual_image')
add('https://developer.mozilla.org/en-US/docs/Web/','JavaScript/Guide HTML CSS API/Canvas_API API/Web_Storage_API API/Service_Worker_API HTTP/Overview HTTP/CORS Accessibility Security', 'technical')
seeds=seeds[:200]
assert len(seeds)==200 and len({s['url'] for s in seeds})==200
(root/'data/seeds.json').write_text(json.dumps(seeds,indent=2)+'\n')
(root/'data/query-candidates.json').write_text(json.dumps({'labelling_rule':'Manual relevance judgement from captured page content; exact canonical page URL, no blanket domains; only confirmed indexed pages enter the answer set. Frozen before retrieval runs.','queries':queries},indent=2)+'\n')
print('seeds',len(seeds),'queries',len(queries))
from collections import Counter
print(Counter(s['category'] for s in seeds))
