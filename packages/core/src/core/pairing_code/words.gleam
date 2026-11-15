//// The BIP-39 English word list, as data, with an index in each direction
//// (ADR-016).
////
//// A pairing code's secret is three words, and a word is an index into this
//// list: 2048 words, so eleven bits each and thirty-three bits for three.
//// The list is the one published with BIP-0039 (`bip-0039/english.txt` in
//// the `bitcoin/bips` repository), used unchanged and in its published
//// order, whose SHA-256 is
////
//// ```text
//// 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
//// ```
////
//// Only the words are used. The mnemonic checksum and the seed derivation
//// that BIP-39 builds on the list are not: these are words a person reads
//// to another person, not a wallet seed, and a mistyped word is caught by
//// `index_of` refusing it. The list is chosen for speech because its first
//// four letters identify a word, and it is sorted, which is what lets
//// `index_of` search it in logarithmic time.
////
//// ## Representation
////
//// The list is one binary constant, `table`, with every word padded with
//// spaces to nine bytes (the longest word has eight letters, so a space
//// always follows it). Word `i` is therefore the nine bytes at offset
//// `9 * i`: `word_at` is a sub-binary slice, no list is walked, and the
//// BEAM keeps the constant once in the module's literal pool. One alternative
//// is a pattern match with 2048 string arms, which compiles to a large
//// decision tree for no gain; another is a `List(String)`, which is a linear
//// scan to look up and a linked list to hold. The table is generated from the
//// published file by a script that is not part of the repository, so that no
//// word is typed by hand, and `words_are_sorted_and_distinct_test` in
//// `test/core/pairing_code_test.gleam` checks the properties the search
//// relies on.
////
//// ## Flow
////
//// `index_of` → `search` → `word_at`
////
//// 1. `index_of` starts a `search` over the whole list.
//// 2. `search` asks `word_at` for the middle word and compares it with the
////    candidate, keeping the half that can still hold it until the range is
////    empty.
//// 3. `word_at` slices the word's slot out of the table and trims the padding.

import gleam/bit_array
import gleam/bool
import gleam/order
import gleam/result
import gleam/string

/// How many words the list holds. A power of two, so a uniform index is a
/// slice of random bits with no modulo bias.
pub const word_count = 2048

/// How many bits select one word: `word_count` is two to this power.
pub const index_bits = 11

/// The bytes one word occupies in `table`: the longest word and a space.
const slot_bytes = 9

/// The words in order, each space-padded to `slot_bytes`.
const table = <<
  "abandon  ability  able     about    above    absent   absorb   abstract ":utf8,
  "absurd   abuse    access   accident account  accuse   achieve  acid     ":utf8,
  "acoustic acquire  across   act      action   actor    actress  actual   ":utf8,
  "adapt    add      addict   address  adjust   admit    adult    advance  ":utf8,
  "advice   aerobic  affair   afford   afraid   again    age      agent    ":utf8,
  "agree    ahead    aim      air      airport  aisle    alarm    album    ":utf8,
  "alcohol  alert    alien    all      alley    allow    almost   alone    ":utf8,
  "alpha    already  also     alter    always   amateur  amazing  among    ":utf8,
  "amount   amused   analyst  anchor   ancient  anger    angle    angry    ":utf8,
  "animal   ankle    announce annual   another  answer   antenna  antique  ":utf8,
  "anxiety  any      apart    apology  appear   apple    approve  april    ":utf8,
  "arch     arctic   area     arena    argue    arm      armed    armor    ":utf8,
  "army     around   arrange  arrest   arrive   arrow    art      artefact ":utf8,
  "artist   artwork  ask      aspect   assault  asset    assist   assume   ":utf8,
  "asthma   athlete  atom     attack   attend   attitude attract  auction  ":utf8,
  "audit    august   aunt     author   auto     autumn   average  avocado  ":utf8,
  "avoid    awake    aware    away     awesome  awful    awkward  axis     ":utf8,
  "baby     bachelor bacon    badge    bag      balance  balcony  ball     ":utf8,
  "bamboo   banana   banner   bar      barely   bargain  barrel   base     ":utf8,
  "basic    basket   battle   beach    bean     beauty   because  become   ":utf8,
  "beef     before   begin    behave   behind   believe  below    belt     ":utf8,
  "bench    benefit  best     betray   better   between  beyond   bicycle  ":utf8,
  "bid      bike     bind     biology  bird     birth    bitter   black    ":utf8,
  "blade    blame    blanket  blast    bleak    bless    blind    blood    ":utf8,
  "blossom  blouse   blue     blur     blush    board    boat     body     ":utf8,
  "boil     bomb     bone     bonus    book     boost    border   boring   ":utf8,
  "borrow   boss     bottom   bounce   box      boy      bracket  brain    ":utf8,
  "brand    brass    brave    bread    breeze   brick    bridge   brief    ":utf8,
  "bright   bring    brisk    broccoli broken   bronze   broom    brother  ":utf8,
  "brown    brush    bubble   buddy    budget   buffalo  build    bulb     ":utf8,
  "bulk     bullet   bundle   bunker   burden   burger   burst    bus      ":utf8,
  "business busy     butter   buyer    buzz     cabbage  cabin    cable    ":utf8,
  "cactus   cage     cake     call     calm     camera   camp     can      ":utf8,
  "canal    cancel   candy    cannon   canoe    canvas   canyon   capable  ":utf8,
  "capital  captain  car      carbon   card     cargo    carpet   carry    ":utf8,
  "cart     case     cash     casino   castle   casual   cat      catalog  ":utf8,
  "catch    category cattle   caught   cause    caution  cave     ceiling  ":utf8,
  "celery   cement   census   century  cereal   certain  chair    chalk    ":utf8,
  "champion change   chaos    chapter  charge   chase    chat     cheap    ":utf8,
  "check    cheese   chef     cherry   chest    chicken  chief    child    ":utf8,
  "chimney  choice   choose   chronic  chuckle  chunk    churn    cigar    ":utf8,
  "cinnamon circle   citizen  city     civil    claim    clap     clarify  ":utf8,
  "claw     clay     clean    clerk    clever   click    client   cliff    ":utf8,
  "climb    clinic   clip     clock    clog     close    cloth    cloud    ":utf8,
  "clown    club     clump    cluster  clutch   coach    coast    coconut  ":utf8,
  "code     coffee   coil     coin     collect  color    column   combine  ":utf8,
  "come     comfort  comic    common   company  concert  conduct  confirm  ":utf8,
  "congress connect  consider control  convince cook     cool     copper   ":utf8,
  "copy     coral    core     corn     correct  cost     cotton   couch    ":utf8,
  "country  couple   course   cousin   cover    coyote   crack    cradle   ":utf8,
  "craft    cram     crane    crash    crater   crawl    crazy    cream    ":utf8,
  "credit   creek    crew     cricket  crime    crisp    critic   crop     ":utf8,
  "cross    crouch   crowd    crucial  cruel    cruise   crumble  crunch   ":utf8,
  "crush    cry      crystal  cube     culture  cup      cupboard curious  ":utf8,
  "current  curtain  curve    cushion  custom   cute     cycle    dad      ":utf8,
  "damage   damp     dance    danger   daring   dash     daughter dawn     ":utf8,
  "day      deal     debate   debris   decade   december decide   decline  ":utf8,
  "decorate decrease deer     defense  define   defy     degree   delay    ":utf8,
  "deliver  demand   demise   denial   dentist  deny     depart   depend   ":utf8,
  "deposit  depth    deputy   derive   describe desert   design   desk     ":utf8,
  "despair  destroy  detail   detect   develop  device   devote   diagram  ":utf8,
  "dial     diamond  diary    dice     diesel   diet     differ   digital  ":utf8,
  "dignity  dilemma  dinner   dinosaur direct   dirt     disagree discover ":utf8,
  "disease  dish     dismiss  disorder display  distance divert   divide   ":utf8,
  "divorce  dizzy    doctor   document dog      doll     dolphin  domain   ":utf8,
  "donate   donkey   donor    door     dose     double   dove     draft    ":utf8,
  "dragon   drama    drastic  draw     dream    dress    drift    drill    ":utf8,
  "drink    drip     drive    drop     drum     dry      duck     dumb     ":utf8,
  "dune     during   dust     dutch    duty     dwarf    dynamic  eager    ":utf8,
  "eagle    early    earn     earth    easily   east     easy     echo     ":utf8,
  "ecology  economy  edge     edit     educate  effort   egg      eight    ":utf8,
  "either   elbow    elder    electric elegant  element  elephant elevator ":utf8,
  "elite    else     embark   embody   embrace  emerge   emotion  employ   ":utf8,
  "empower  empty    enable   enact    end      endless  endorse  enemy    ":utf8,
  "energy   enforce  engage   engine   enhance  enjoy    enlist   enough   ":utf8,
  "enrich   enroll   ensure   enter    entire   entry    envelope episode  ":utf8,
  "equal    equip    era      erase    erode    erosion  error    erupt    ":utf8,
  "escape   essay    essence  estate   eternal  ethics   evidence evil     ":utf8,
  "evoke    evolve   exact    example  excess   exchange excite   exclude  ":utf8,
  "excuse   execute  exercise exhaust  exhibit  exile    exist    exit     ":utf8,
  "exotic   expand   expect   expire   explain  expose   express  extend   ":utf8,
  "extra    eye      eyebrow  fabric   face     faculty  fade     faint    ":utf8,
  "faith    fall     false    fame     family   famous   fan      fancy    ":utf8,
  "fantasy  farm     fashion  fat      fatal    father   fatigue  fault    ":utf8,
  "favorite feature  february federal  fee      feed     feel     female   ":utf8,
  "fence    festival fetch    fever    few      fiber    fiction  field    ":utf8,
  "figure   file     film     filter   final    find     fine     finger   ":utf8,
  "finish   fire     firm     first    fiscal   fish     fit      fitness  ":utf8,
  "fix      flag     flame    flash    flat     flavor   flee     flight   ":utf8,
  "flip     float    flock    floor    flower   fluid    flush    fly      ":utf8,
  "foam     focus    fog      foil     fold     follow   food     foot     ":utf8,
  "force    forest   forget   fork     fortune  forum    forward  fossil   ":utf8,
  "foster   found    fox      fragile  frame    frequent fresh    friend   ":utf8,
  "fringe   frog     front    frost    frown    frozen   fruit    fuel     ":utf8,
  "fun      funny    furnace  fury     future   gadget   gain     galaxy   ":utf8,
  "gallery  game     gap      garage   garbage  garden   garlic   garment  ":utf8,
  "gas      gasp     gate     gather   gauge    gaze     general  genius   ":utf8,
  "genre    gentle   genuine  gesture  ghost    giant    gift     giggle   ":utf8,
  "ginger   giraffe  girl     give     glad     glance   glare    glass    ":utf8,
  "glide    glimpse  globe    gloom    glory    glove    glow     glue     ":utf8,
  "goat     goddess  gold     good     goose    gorilla  gospel   gossip   ":utf8,
  "govern   gown     grab     grace    grain    grant    grape    grass    ":utf8,
  "gravity  great    green    grid     grief    grit     grocery  group    ":utf8,
  "grow     grunt    guard    guess    guide    guilt    guitar   gun      ":utf8,
  "gym      habit    hair     half     hammer   hamster  hand     happy    ":utf8,
  "harbor   hard     harsh    harvest  hat      have     hawk     hazard   ":utf8,
  "head     health   heart    heavy    hedgehog height   hello    helmet   ":utf8,
  "help     hen      hero     hidden   high     hill     hint     hip      ":utf8,
  "hire     history  hobby    hockey   hold     hole     holiday  hollow   ":utf8,
  "home     honey    hood     hope     horn     horror   horse    hospital ":utf8,
  "host     hotel    hour     hover    hub      huge     human    humble   ":utf8,
  "humor    hundred  hungry   hunt     hurdle   hurry    hurt     husband  ":utf8,
  "hybrid   ice      icon     idea     identify idle     ignore   ill      ":utf8,
  "illegal  illness  image    imitate  immense  immune   impact   impose   ":utf8,
  "improve  impulse  inch     include  income   increase index    indicate ":utf8,
  "indoor   industry infant   inflict  inform   inhale   inherit  initial  ":utf8,
  "inject   injury   inmate   inner    innocent input    inquiry  insane   ":utf8,
  "insect   inside   inspire  install  intact   interest into     invest   ":utf8,
  "invite   involve  iron     island   isolate  issue    item     ivory    ":utf8,
  "jacket   jaguar   jar      jazz     jealous  jeans    jelly    jewel    ":utf8,
  "job      join     joke     journey  joy      judge    juice    jump     ":utf8,
  "jungle   junior   junk     just     kangaroo keen     keep     ketchup  ":utf8,
  "key      kick     kid      kidney   kind     kingdom  kiss     kit      ":utf8,
  "kitchen  kite     kitten   kiwi     knee     knife    knock    know     ":utf8,
  "lab      label    labor    ladder   lady     lake     lamp     language ":utf8,
  "laptop   large    later    latin    laugh    laundry  lava     law      ":utf8,
  "lawn     lawsuit  layer    lazy     leader   leaf     learn    leave    ":utf8,
  "lecture  left     leg      legal    legend   leisure  lemon    lend     ":utf8,
  "length   lens     leopard  lesson   letter   level    liar     liberty  ":utf8,
  "library  license  life     lift     light    like     limb     limit    ":utf8,
  "link     lion     liquid   list     little   live     lizard   load     ":utf8,
  "loan     lobster  local    lock     logic    lonely   long     loop     ":utf8,
  "lottery  loud     lounge   love     loyal    lucky    luggage  lumber   ":utf8,
  "lunar    lunch    luxury   lyrics   machine  mad      magic    magnet   ":utf8,
  "maid     mail     main     major    make     mammal   man      manage   ":utf8,
  "mandate  mango    mansion  manual   maple    marble   march    margin   ":utf8,
  "marine   market   marriage mask     mass     master   match    material ":utf8,
  "math     matrix   matter   maximum  maze     meadow   mean     measure  ":utf8,
  "meat     mechanic medal    media    melody   melt     member   memory   ":utf8,
  "mention  menu     mercy    merge    merit    merry    mesh     message  ":utf8,
  "metal    method   middle   midnight milk     million  mimic    mind     ":utf8,
  "minimum  minor    minute   miracle  mirror   misery   miss     mistake  ":utf8,
  "mix      mixed    mixture  mobile   model    modify   mom      moment   ":utf8,
  "monitor  monkey   monster  month    moon     moral    more     morning  ":utf8,
  "mosquito mother   motion   motor    mountain mouse    move     movie    ":utf8,
  "much     muffin   mule     multiply muscle   museum   mushroom music    ":utf8,
  "must     mutual   myself   mystery  myth     naive    name     napkin   ":utf8,
  "narrow   nasty    nation   nature   near     neck     need     negative ":utf8,
  "neglect  neither  nephew   nerve    nest     net      network  neutral  ":utf8,
  "never    news     next     nice     night    noble    noise    nominee  ":utf8,
  "noodle   normal   north    nose     notable  note     nothing  notice   ":utf8,
  "novel    now      nuclear  number   nurse    nut      oak      obey     ":utf8,
  "object   oblige   obscure  observe  obtain   obvious  occur    ocean    ":utf8,
  "october  odor     off      offer    office   often    oil      okay     ":utf8,
  "old      olive    olympic  omit     once     one      onion    online   ":utf8,
  "only     open     opera    opinion  oppose   option   orange   orbit    ":utf8,
  "orchard  order    ordinary organ    orient   original orphan   ostrich  ":utf8,
  "other    outdoor  outer    output   outside  oval     oven     over     ":utf8,
  "own      owner    oxygen   oyster   ozone    pact     paddle   page     ":utf8,
  "pair     palace   palm     panda    panel    panic    panther  paper    ":utf8,
  "parade   parent   park     parrot   party    pass     patch    path     ":utf8,
  "patient  patrol   pattern  pause    pave     payment  peace    peanut   ":utf8,
  "pear     peasant  pelican  pen      penalty  pencil   people   pepper   ":utf8,
  "perfect  permit   person   pet      phone    photo    phrase   physical ":utf8,
  "piano    picnic   picture  piece    pig      pigeon   pill     pilot    ":utf8,
  "pink     pioneer  pipe     pistol   pitch    pizza    place    planet   ":utf8,
  "plastic  plate    play     please   pledge   pluck    plug     plunge   ":utf8,
  "poem     poet     point    polar    pole     police   pond     pony     ":utf8,
  "pool     popular  portion  position possible post     potato   pottery  ":utf8,
  "poverty  powder   power    practice praise   predict  prefer   prepare  ":utf8,
  "present  pretty   prevent  price    pride    primary  print    priority ":utf8,
  "prison   private  prize    problem  process  produce  profit   program  ":utf8,
  "project  promote  proof    property prosper  protect  proud    provide  ":utf8,
  "public   pudding  pull     pulp     pulse    pumpkin  punch    pupil    ":utf8,
  "puppy    purchase purity   purpose  purse    push     put      puzzle   ":utf8,
  "pyramid  quality  quantum  quarter  question quick    quit     quiz     ":utf8,
  "quote    rabbit   raccoon  race     rack     radar    radio    rail     ":utf8,
  "rain     raise    rally    ramp     ranch    random   range    rapid    ":utf8,
  "rare     rate     rather   raven    raw      razor    ready    real     ":utf8,
  "reason   rebel    rebuild  recall   receive  recipe   record   recycle  ":utf8,
  "reduce   reflect  reform   refuse   region   regret   regular  reject   ":utf8,
  "relax    release  relief   rely     remain   remember remind   remove   ":utf8,
  "render   renew    rent     reopen   repair   repeat   replace  report   ":utf8,
  "require  rescue   resemble resist   resource response result   retire   ":utf8,
  "retreat  return   reunion  reveal   review   reward   rhythm   rib      ":utf8,
  "ribbon   rice     rich     ride     ridge    rifle    right    rigid    ":utf8,
  "ring     riot     ripple   risk     ritual   rival    river    road     ":utf8,
  "roast    robot    robust   rocket   romance  roof     rookie   room     ":utf8,
  "rose     rotate   rough    round    route    royal    rubber   rude     ":utf8,
  "rug      rule     run      runway   rural    sad      saddle   sadness  ":utf8,
  "safe     sail     salad    salmon   salon    salt     salute   same     ":utf8,
  "sample   sand     satisfy  satoshi  sauce    sausage  save     say      ":utf8,
  "scale    scan     scare    scatter  scene    scheme   school   science  ":utf8,
  "scissors scorpion scout    scrap    screen   script   scrub    sea      ":utf8,
  "search   season   seat     second   secret   section  security seed     ":utf8,
  "seek     segment  select   sell     seminar  senior   sense    sentence ":utf8,
  "series   service  session  settle   setup    seven    shadow   shaft    ":utf8,
  "shallow  share    shed     shell    sheriff  shield   shift    shine    ":utf8,
  "ship     shiver   shock    shoe     shoot    shop     short    shoulder ":utf8,
  "shove    shrimp   shrug    shuffle  shy      sibling  sick     side     ":utf8,
  "siege    sight    sign     silent   silk     silly    silver   similar  ":utf8,
  "simple   since    sing     siren    sister   situate  six      size     ":utf8,
  "skate    sketch   ski      skill    skin     skirt    skull    slab     ":utf8,
  "slam     sleep    slender  slice    slide    slight   slim     slogan   ":utf8,
  "slot     slow     slush    small    smart    smile    smoke    smooth   ":utf8,
  "snack    snake    snap     sniff    snow     soap     soccer   social   ":utf8,
  "sock     soda     soft     solar    soldier  solid    solution solve    ":utf8,
  "someone  song     soon     sorry    sort     soul     sound    soup     ":utf8,
  "source   south    space    spare    spatial  spawn    speak    special  ":utf8,
  "speed    spell    spend    sphere   spice    spider   spike    spin     ":utf8,
  "spirit   split    spoil    sponsor  spoon    sport    spot     spray    ":utf8,
  "spread   spring   spy      square   squeeze  squirrel stable   stadium  ":utf8,
  "staff    stage    stairs   stamp    stand    start    state    stay     ":utf8,
  "steak    steel    stem     step     stereo   stick    still    sting    ":utf8,
  "stock    stomach  stone    stool    story    stove    strategy street   ":utf8,
  "strike   strong   struggle student  stuff    stumble  style    subject  ":utf8,
  "submit   subway   success  such     sudden   suffer   sugar    suggest  ":utf8,
  "suit     summer   sun      sunny    sunset   super    supply   supreme  ":utf8,
  "sure     surface  surge    surprise surround survey   suspect  sustain  ":utf8,
  "swallow  swamp    swap     swarm    swear    sweet    swift    swim     ":utf8,
  "swing    switch   sword    symbol   symptom  syrup    system   table    ":utf8,
  "tackle   tag      tail     talent   talk     tank     tape     target   ":utf8,
  "task     taste    tattoo   taxi     teach    team     tell     ten      ":utf8,
  "tenant   tennis   tent     term     test     text     thank    that     ":utf8,
  "theme    then     theory   there    they     thing    this     thought  ":utf8,
  "three    thrive   throw    thumb    thunder  ticket   tide     tiger    ":utf8,
  "tilt     timber   time     tiny     tip      tired    tissue   title    ":utf8,
  "toast    tobacco  today    toddler  toe      together toilet   token    ":utf8,
  "tomato   tomorrow tone     tongue   tonight  tool     tooth    top      ":utf8,
  "topic    topple   torch    tornado  tortoise toss     total    tourist  ":utf8,
  "toward   tower    town     toy      track    trade    traffic  tragic   ":utf8,
  "train    transfer trap     trash    travel   tray     treat    tree     ":utf8,
  "trend    trial    tribe    trick    trigger  trim     trip     trophy   ":utf8,
  "trouble  truck    true     truly    trumpet  trust    truth    try      ":utf8,
  "tube     tuition  tumble   tuna     tunnel   turkey   turn     turtle   ":utf8,
  "twelve   twenty   twice    twin     twist    two      type     typical  ":utf8,
  "ugly     umbrella unable   unaware  uncle    uncover  under    undo     ":utf8,
  "unfair   unfold   unhappy  uniform  unique   unit     universe unknown  ":utf8,
  "unlock   until    unusual  unveil   update   upgrade  uphold   upon     ":utf8,
  "upper    upset    urban    urge     usage    use      used     useful   ":utf8,
  "useless  usual    utility  vacant   vacuum   vague    valid    valley   ":utf8,
  "valve    van      vanish   vapor    various  vast     vault    vehicle  ":utf8,
  "velvet   vendor   venture  venue    verb     verify   version  very     ":utf8,
  "vessel   veteran  viable   vibrant  vicious  victory  video    view     ":utf8,
  "village  vintage  violin   virtual  virus    visa     visit    visual   ":utf8,
  "vital    vivid    vocal    voice    void     volcano  volume   vote     ":utf8,
  "voyage   wage     wagon    wait     walk     wall     walnut   want     ":utf8,
  "warfare  warm     warrior  wash     wasp     waste    water    wave     ":utf8,
  "way      wealth   weapon   wear     weasel   weather  web      wedding  ":utf8,
  "weekend  weird    welcome  west     wet      whale    what     wheat    ":utf8,
  "wheel    when     where    whip     whisper  wide     width    wife     ":utf8,
  "wild     will     win      window   wine     wing     wink     winner   ":utf8,
  "winter   wire     wisdom   wise     wish     witness  wolf     woman    ":utf8,
  "wonder   wood     wool     word     work     world    worry    worth    ":utf8,
  "wrap     wreck    wrestle  wrist    write    wrong    yard     year     ":utf8,
  "yellow   you      young    youth    zebra    zero     zone     zoo      ":utf8,
>>

/// The word at an index, or `Error(Nil)` outside `0..word_count - 1`. Takes
/// constant time: the word is a slice of `table` at a fixed offset.
///
/// ## Examples
///
/// ```gleam
/// assert words.word_at(0) == Ok("abandon")
/// ```
///
/// ```gleam
/// assert words.word_at(2047) == Ok("zoo")
/// ```
///
/// ```gleam
/// assert words.word_at(2048) == Error(Nil)
/// ```
pub fn word_at(index: Int) -> Result(String, Nil) {
  use <- bool.guard(index < 0 || index >= word_count, Error(Nil))

  // The slot is padded to a fixed width, so it is cut at a computed offset
  // and the padding is trimmed; no word contains a space.
  use slot <- result.try(bit_array.slice(table, index * slot_bytes, slot_bytes))
  use padded <- result.map(bit_array.to_string(slot))
  string.trim_end(padded)
}

/// The index of a word, or `Error(Nil)` when it is not on the list. The
/// match is exact: no case folding, no trimming, no prefix. Takes
/// logarithmic time, eleven comparisons at most.
///
/// ## Examples
///
/// ```gleam
/// assert words.index_of("abandon") == Ok(0)
/// ```
///
/// ```gleam
/// assert words.index_of("Abandon") == Error(Nil)
/// ```
pub fn index_of(word: String) -> Result(Int, Nil) {
  search(word, 0, word_count)
}

/// Looks for `word` among the indices `low` up to, not including, `high`.
/// Each step halves the range, which is sound because the list is sorted in
/// the byte order `string.compare` uses.
fn search(word: String, low: Int, high: Int) -> Result(Int, Nil) {
  use <- bool.guard(low >= high, Error(Nil))
  let middle = low + { high - low } / 2
  use candidate <- result.try(word_at(middle))

  // The word sorts before, after or at the middle: keep the half that can
  // still hold it.
  case string.compare(word, candidate) {
    order.Eq -> Ok(middle)
    order.Lt -> search(word, low, middle)
    order.Gt -> search(word, middle + 1, high)
  }
}
