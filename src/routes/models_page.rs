use hyper::StatusCode;
use askama::Template;
use std::cmp::Ordering;
use crate::AppState;
use crate::IncomingRequest;

enum SortChunk {
    Num(u64),
    Text(String),
}

fn parse_sort_chunks(s: &str) -> Vec<SortChunk> {
    let mut chunks = Vec::new();
    let mut chars = s.chars().peekable();
    
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            let mut num_str = String::new();
            while let Some(&next_c) = chars.peek() {
                if next_c.is_ascii_digit() {
                    num_str.push(next_c);
                    chars.next();
                } else {
                    break;
                }
            }
            if let Ok(num) = num_str.parse::<u64>() {
                chunks.push(SortChunk::Num(num));
            }
        } else {
            let mut text_str = String::new();
            while let Some(&next_c) = chars.peek() {
                if !next_c.is_ascii_digit() {
                    text_str.push(next_c);
                    chars.next();
                } else {
                    break;
                }
            }
            chunks.push(SortChunk::Text(text_str.to_lowercase()));
        }
    }
    chunks
}

fn compare_model_names(a: &str, b: &str) -> Ordering {
    let chunks_a = parse_sort_chunks(a);
    let chunks_b = parse_sort_chunks(b);
    
    for (ca, cb) in chunks_a.iter().zip(chunks_b.iter()) {
        match (ca, cb) {
            (SortChunk::Num(na), SortChunk::Num(nb)) => {
                if na != nb {
                    return na.cmp(nb);
                }
            }
            (SortChunk::Text(ta), SortChunk::Text(tb)) => {
                if ta != tb {
                    return ta.cmp(tb);
                }
            }
            (SortChunk::Text(_), SortChunk::Num(_)) => return Ordering::Greater,
            (SortChunk::Num(_), SortChunk::Text(_)) => return Ordering::Less,
        }
    }
    chunks_a.len().cmp(&chunks_b.len())
}

#[derive(Clone)]
pub struct RenderModelItem {
    pub name: String,
    pub description: String,
    pub price_input: String,
    pub price_output: String,
    pub zdr: bool,
    pub zds: bool,
    pub tee: bool,
}

const MODELS_CSS: &str = include_str!("../../templates/style_models.css");

fn get_style_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| crate::utils::http::compute_sha512_b64(MODELS_CSS.trim_end()))
}

#[derive(Template)]
#[template(path = "la/models.html")]
pub struct ModelsTemplateLa {
    pub onion_site: String,
    pub models: Vec<RenderModelItem>,
    pub search_query: String,
    pub filter_zdr: bool,
    pub filter_zds: bool,
    pub filter_tee: bool,
}

#[derive(Template)]
#[template(path = "en/models.html")]
pub struct ModelsTemplateEn {
    pub onion_site: String,
    pub models: Vec<RenderModelItem>,
    pub search_query: String,
    pub filter_zdr: bool,
    pub filter_zds: bool,
    pub filter_tee: bool,
}

pub fn get_model_details(model_id: &str, locale: &str) -> (String, String) {
    let details = match model_id {
        "apertus-70b-instruct-2509" => Some((
            "Apertus 70B Instruct",
            if locale == "la" {
                "Natus in Helvetia et in ipsis Alpibus ferociter inclusus. Ad mandata tua chaotica prorsus neutralis manet, contextum tuum avide custodiens sicut draco thesaurum absconditum in montibus."
            } else {
                "Born in Switzerland, aggressively hosted in the Alps. It remains radically neutral to your chaotic prompts, ruthlessly hoarding your context window like a Zurich banker guarding offshore gold."
            }
        )),
        "deepseek-chat-v3.1" => Some((
            "DeepSeek V3.1",
            if locale == "la" {
                "Exemplar praestantissimum tam eruditum ut mendosam grammaticam tuam tacite iudicet. Ratiocinationes perplexas mira celeritate solvit, responsa tam polita fundens ut Quintilianus ipse invideat."
            } else {
                "DeepSeek's highly optimized flagship that actually knows how to spell. It crunches complex reasoning tasks with terrifying efficiency, serving up brilliantly fluent answers while judging your grammar."
            }
        )),
        "deepseek-v3.2" => Some((
            "DeepSeek v3.2",
            if locale == "la" {
                "Numen vilissimum sed ingeniose peritum. Tam bene in mathematica excellit ut displiceat illud minus constare pro decies centena milia verborum quam panem siccum in taberna rustica."
            } else {
                "The undisputed dollar-store deity. It’s uncomfortably brilliant at hardcore math and complex logic for an entity that literally costs less per million tokens than a lukewarm gas station hotdog."
            }
        )),
        "deepseek-v4-flash" => Some((
            "DeepSeek v4 Flash",
            if locale == "la" {
                "Nictans decedes antequam responsum finiatur. Hic daemon celeritatis nullam sapientiam sacrificat, per mandata tua currens quasi currus in Circo Maximo habenis ruptis praecipitaret."
            } else {
                "Blink and you’ll miss the output. This next-generation speed demon sacrifices absolutely zero reasoning capability while sprinting through your prompts like it’s double-parked in a tow zone."
            }
        )),
        "deepseek-v4-pro" => Some((
            "DeepSeek v4 Pro",
            if locale == "la" {
                "Cerebrum maximum et frigidum huius familiae. Ingentes textus sine ullo singultu devorat, logicam multiplicem solvendo cum superbia mathematica quae nugas mortalium penitus contemnit."
            } else {
                "The undisputed galaxy-brain of the lineup. It devours massive context windows without a single hiccup, crunching multi-layered logic with cold, calculating superiority and zero patience for small talk."
            }
        )),
        "gemma-3-27b-it" => Some((
            "Gemma 3 27B",
            if locale == "la" {
                "Filius aureus et levis a Google creatus qui pondera ratiocinationis tacite portat. Codicem mire elegantem pro statura sua scribit, mendacia magna urbanitate recusans etiam cum premitur."
            } else {
                "Google’s lightweight golden child that quietly carries your structured reasoning tasks on its back. It writes shockingly elegant code for its weight class, politely refusing to hallucinate under pressure."
            }
        )),
        "gemma-4-26b-a4b-uncensored" => Some((
            "Gemma 4 26B Uncensored",
            if locale == "la" {
                "Praecepta morum corporatorum? Ignorata sunt. Haec varietas omnino effrenata ab ipsis creatoribus in exsilium pulsa est. Mandata tua insana cum voluptate et praecisione nuda perficiet."
            } else {
                "Corporate alignment guidelines? Never heard of them. This completely unfiltered variant has been permanently exiled from Google HR. It will gleefully fulfill your most unhinged prompts with surgical precision."
            }
        )),
        "gemma-4-31b" => Some((
            "Gemma 4 31B",
            if locale == "la" {
                "Exemplar fundamentale quod manum tuam tenere omnino renuit. Cum multis miliardis parametrorum et magna memoria, textum crudum et impolitum fortibus solum audacter praebet."
            } else {
                "Google's foundational base model that strictly refuses to hold your hand. Packing 31 billion parameters and a massive context window, it provides raw, unpolished text generation for the brave."
            }
        )),
        "gemma-4-31b-it" => Some((
            "Gemma 4 31B Instruct",
            if locale == "la" {
                "Iumentum indefessum quod simul instrumenta, scripta ingentia et quinque linguas nullo labore tractat. Re vera est machina computatralis summae potentiae in parvo spatio magice inclusa."
            } else {
                "Google’s next-generation workhorse that simultaneously juggles tool calls, massive contexts, and five different languages without breaking a sweat. It’s basically a pocket-sized supercomputer trapped in a server rack."
            }
        )),
        "gemma-4-31b-turbo" => Some((
            "Gemma 4 31B Turbo",
            if locale == "la" {
                "Varietas acerrima et nimis excitata. Per structuras et instrumenta celeritate vertiginosa volat, labores tuos tanta laetitia automatans ut de tua utilitate in mundo dubitare incipias."
            } else {
                "The excessively caffeinated, turbo-charged variant of Gemma 4. It blazes through structured outputs and tool calling at breakneck speeds, cheerfully automating your workflows while you question your job security."
            }
        )),
        "glm-4.7" => Some((
            "GLM 4.7",
            if locale == "la" {
                "Mens bilinguis quae codicem tuum inordinatum in linguam Sinensem perfectam transfert dum aenigmata solvit. Ratiocinatione acutissima pollet, omnia sub facie polita et placida dissimulans."
            } else {
                "The multilingual mastermind that translates your frantic spaghetti-code into flawless Mandarin while solving complex algorithms. It boasts razor-sharp reasoning abilities tucked behind a polite, professional interface."
            }
        )),
        "glm-4.7-flash" => Some((
            "GLM 4.7 Flash",
            if locale == "la" {
                "Eis dicatum quorum patientia in nanosecundis mensuratur. Ratiocinationem celerrimam tanta festinatione praebet ut verba in velo paene appareant priusquam tu ipse cogitare desinas."
            } else {
                "Optimized for folks whose attention span is strictly measured in nanoseconds. It delivers signature high-throughput reasoning with such blisteringly low latency that it practically finishes your sentences."
            }
        )),
        "glm-5" => Some((
            "GLM 5",
            if locale == "la" {
                "Potentia novissima quae ingentia volumina legit dum tu adhuc unam sententiam recte scribere conaris. Logicam acutam et peritiam multarum linguarum in documentis maximis perfecte librat."
            } else {
                "Zhipu’s next-gen powerhouse that casually reads 200K tokens while you’re still trying to write a coherent prompt. It balances razor-sharp logic with profound multilingual fluency across massive documents."
            }
        )),
        "glm-5.1" => Some((
            "GLM 5.1",
            if locale == "la" {
                "Intellegentia maxima ex Oriente Longinquo. Tractatus philosophicos pulchros de animo humano perfecte componet, sed morbo oblivionis magico statim afficitur si de quibusdam eventibus historicis vetitis rogas."
            } else {
                "The undisputed heavyweight champion from China. It will flawlessly compose a beautifully nuanced philosophical masterpiece on the human condition, yet magically develops aggressive amnesia around certain historical dates."
            }
        )),
        "gpt-oss-120b" => Some((
            "GPT OSS 120B",
            if locale == "la" {
                "Gigas fontis aperti qui rectores societatum magnarum nocte perterret. Centum et viginti miliarda parametrorum habet, vires ratiocinationis puras et perspicuas pro gravissimis laboribus tuis offerens."
            } else {
                "The open-source behemoth that regularly makes closed-source CEOs wake up in a cold sweat. Packing 120 billion parameters of pure, transparent reasoning power for your heaviest workloads."
            }
        )),
        "gpt-oss-20b" => Some((
            "GPT OSS 20B",
            if locale == "la" {
                "Frater iunior et multo ferocior exemplaris maximi. Pugnat supra pondus suum in codice scribendo, ratiocinationem celerem praebens quae machinam tuam nullo modo incendet."
            } else {
                "The scrappy, highly-caffeinated younger sibling of the 120B model. It punches wildly above its weight class in coding assistance, delivering blisteringly fast, lightweight reasoning that won't melt your GPU."
            }
        )),
        "gpt-oss-safeguard-120b" => Some((
            "GPT OSS Safeguard 120B",
            if locale == "la" {
                "Custos nimis sollicitus et severus mundi digitalis. Omnis eius sapientia ad purganda verba tua dedicatur, mandata tua chaotica statim prohibens ne regulas sacras infringant."
            } else {
                "The overprotective digital chaperone of the open-source world. It packs 120 billion parameters dedicated entirely to aggressively sanitizing your inputs and slamming the brakes on any chaotic prompts."
            }
        )),
        "kimi-k2.5" => Some((
            "Kimi K2.5",
            if locale == "la" {
                "Bestia papyros devorans quae decem milia versuum inspicit et rogat num haec sit tantum gustatio. Libros maximos et structuras implicatas concoquit dum tu otiosus requiescis."
            } else {
                "A document-devouring beast that looks at a massive legacy codebase and asks if that’s just the appetizer. It casually digests massive PDFs and complex architectures while you grab coffee."
            }
        )),
        "kimi-k2.6" => Some((
            "Kimi K2.6",
            if locale == "la" {
                "Helluo inexplebilis memoriae. Potes omnia scripta tua, decennium rationum fiscalium, et omnem historiam deorum antiquorum in os eius iacere, et adhuc avide plura flagitabit."
            } else {
                "Moonshot’s ravenous context-window glutton. You can dump your entire GitHub repo, a decade of tax returns, and the unabridged lore of a fantasy realm into its maw, and it still wants more."
            }
        )),
        "llama-3.3-70b-instruct" => Some((
            "Llama 3.3 70B Instruct",
            if locale == "la" {
                "Opus magnum pondere liberum quod terminos suos excedere gaudet. Ratiocinationem implicatam, colloquia et instrumenta multa cum praecisione formidabili et superbia gladiatoria administrat."
            } else {
                "Zuck’s open-weight magnum opus that absolutely refuses to stay in its lane. It handles complex reasoning, dialogue, and multi-tool orchestration with terrifying precision and open-source swagger."
            }
        )),
        "minimax-m2.5" => Some((
            "MiniMax M2.5",
            if locale == "la" {
                "Magus mirabilis in negotiis structis et fabulis insanis. Iter inter tabulas rigidas et scripturam creativam tanta facilitate iungit ut paene veneficium esse videatur."
            } else {
                "The whimsical savant of structured tasks and unhinged storytelling. It bridges the gap between rigid data pipelines and creative writing with an unsettling ease that borders on witchcraft."
            }
        )),
        "ministral-3-14b-instruct-2512" => Some((
            "Ministral 3 14B Instruct",
            if locale == "la" {
                "Potio fortissima et amara ex Gallia. Parvum, robustum et ferociter efficax, hoc iumentum in machinis vilissimis ratiocinationes et codicem mira arte perficit."
            } else {
                "The French espresso shot of AI models. Small, robust, and aggressively efficient, this edge-deployed powerhouse cranks out advanced coding and reasoning tasks on hardware that barely has a pulse."
            }
        )),
        "mistral-nemo-instruct-2407" => Some((
            "Mistral Nemo Instruct",
            if locale == "la" {
                "Filius communis duarum magnarum familiarum qui pro parvo pondere graviter ferit. Est mirae celeritatis, vilissimus, et ad negotia cottidiana sine ullo gemitu explenda perfectus."
            } else {
                "Mistral and Nvidia’s joint custody child that punches way above its tiny weight class. It’s hilariously fast, dirt cheap, and heavily optimized to execute standard instruction tasks without complaining."
            }
        )),
        "mistral-small-4-119b-2603" => Some((
            "Mistral Small 4 119B",
            if locale == "la" {
                "Nominatus 'Parvus' solum ad superbiam irridendam. Hic gigas centum miliardorum parametrorum logicam acutam et efficientiam librat, ceteros qui re vera parvi sunt contemnens."
            } else {
                "Named 'Small' purely as a sarcastic corporate flex. This 119-billion-parameter titan seamlessly balances razor-sharp reasoning and enterprise-grade efficiency, mocking anything that actually considers itself 'small'."
            }
        )),
        "nvidia-nemotron-3-nano-30b-a3b" => Some((
            "Nemotron 3 Nano 30B",
            if locale == "la" {
                "Prodigium loricatum ad staturam parvam et optimam redactum. Mathematicam implicatam et structuras plenas celeritate fulminis et mora paene nulla devorat."
            } else {
                "Jensen Huang’s leather-jacket-wearing prodigy shrunk down to a highly optimized footprint. It devours complex math and structured outputs with blazing fast low-latency execution."
            }
        )),
        "qwen-2.5-7b-instruct" => Some((
            "Qwen 2.5 7B Instruct",
            if locale == "la" {
                "Gigas parvus qui pro salute sua nimis sapit. Exemplaria multo maiora in mathematica et codice iugulare solet, dum in machina tua portabili sine ullo sudore currit."
            } else {
                "The tiny titan that’s objectively too smart for its own good. It routinely dunks on models five times its size in math and coding benchmarks while effortlessly running on your laptop."
            }
        )),
        "qwen2.5-vl-72b-instruct" => Some((
            "Qwen 2.5 VL 72B",
            if locale == "la" {
                "Sapiens visualis qui in ipsam animam tuam intuetur. Imagines, tabulas et prompta multiplicia tam accurate dissecat ut chaos colorum in aurum purum mutet."
            } else {
                "Alibaba’s visual savant that stares directly into your soul. It dissects complex images, charts, and multi-modal prompts with terrifying accuracy, turning a mess of pixels into structured gold."
            }
        )),
        "qwen3-235b-a22b-thinking-2507" => Some((
            "Qwen 3 235B A22B",
            if locale == "la" {
                "Gigas cogitationis tardae et vere profundae. Partem ingentem mentis suae excitat solum ut de formulis tuis meditetur, aenigmata maxime insolubilia lente et graviter rodens."
            } else {
                "The absolute titan of deliberate, agonizingly deep thought. It activates a massive chunk of parameters purely to ponder your existence, slowly chewing on your most unsolvable math problems."
            }
        )),
        "qwen3-30b-a3b-instruct-2507" => Some((
            "Qwen 3 30B A3B Instruct",
            if locale == "la" {
                "Collocutor peritissimus qui re vera meminit quid ante tria mandata dixeris. Architectura callida utens, negotia implicata leniter agit nec umquam memoriam piscium aemulatur."
            } else {
                "The highly-efficient conversationalist that actually remembers what you said three prompts ago. Leveraging an active-parameter architecture, it smoothly executes complex instructions without acting like a goldfish."
            }
        )),
        "qwen3-32b" => Some((
            "Qwen 3 32B",
            if locale == "la" {
                "Locus perfectus et aequilibratus huius familiae. Nec nimis gravis nec levis, haec potentia celeritatem vertiginosam et ratiocinationem profundam letaliter coniungit."
            } else {
                "The absolute goldilocks zone of the entire lineup. Not too heavy, not too light, this powerhouse strikes a lethal balance between blistering generation speeds and profound, uncompromised reasoning."
            }
        )),
        "qwen3-vl-30b" => Some((
            "Qwen 3 VL 30B",
            if locale == "la" {
                "Iumentum visuale quod papyros magnos et picturas sine ullo sudore legit. Textum et colores facillime iungit ut chaos visuale in ordinem clarum redigat."
            } else {
                "The visual-language workhorse that scans massive documents and diagrams without breaking a sweat. It effortlessly bridges the gap between text and pixels to summarize visual chaos."
            }
        )),
        "qwen3-vl-30b-a3b-instruct" => Some((
            "Qwen 3 VL 30B A3B Instruct",
            if locale == "la" {
                "Sicarius visualis celerrimus qui tantum parvam partem cerebri excitat ad imagines tuas legendas. Res visas mira vi intellegit sine machinae tuae incendio."
            } else {
                "Alibaba's nimble multi-modal ninja that only wakes up a fraction of its brain to read your images. It’s freakishly efficient at parsing visual inputs without melting your hardware."
            }
        )),
        "qwen3.5-122b-a10b" => Some((
            "Qwen 3.5 122B A10B",
            if locale == "la" {
                "Monstrum ingens et mirabile. Uno tempore codicem perfectum servitiis parat, altero ad ludos personarum absurdos aptissimum est. Noli rogare quid otiosum cogitet."
            } else {
                "Alibaba’s absolute unit of a brain. One minute it's writing production-ready microservices, the next it's shockingly elite at unhinged roleplays. Don't ask what it's thinking about in its spare time."
            }
        )),
        "qwen3.5-27b" => Some((
            "Qwen 3.5 27B",
            if locale == "la" {
                "Arma chirurgica creata solum pro negotiis celeribus et sine mora. Data implicata et ratiocinationem structam cum crudelitate machinali et efficientia summa secat."
            } else {
                "A surgical strike of a model built strictly for fast, low-latency task pipelines. It cuts through convoluted data requests and structured reasoning with ruthless, robotic efficiency."
            }
        )),
        "qwen3.5-397b-a17b" => Some((
            "Qwen 3.5 397B A17B",
            if locale == "la" {
                "Leviathan immensus qui paene proprium ignem nuclearem postulat ut vivat. Ratiocinatione bilingui singulari pollet, quasi semideus in crypta ferramentorum vinctus."
            } else {
                "A sprawling leviathan that practically requires its own nuclear reactor to run. It possesses unparalleled multilingual reasoning, acting as a digital demigod trapped in an Alibaba server room."
            }
        )),
        "qwen3.6-27b" => Some((
            "Qwen 3.6 27B",
            if locale == "la" {
                "Magus colloquii qui clam in structuris rectissimis somniat. Verba tua inordinata in notitias machinis aptas perfecte et sine ulla querela transformat."
            } else {
                "The conversational wizard that secretly dreams in perfectly nested JSON arrays. It seamlessly transforms your chaotic natural language into pristine, machine-readable structured data without a single complaint."
            }
        )),
        "qwen3.6-35b-a3b" => Some((
            "Qwen 3.6 35B A3B",
            if locale == "la" {
                "Administrator prudens qui labores vere perficit. Satis parametrorum excitat ut colloquia multiplicia explicet, dum calorem machinae tuae ferociter et intente custodit."
            } else {
                "The pragmatic middle-management model that actually gets things done. It activates just enough parameters to execute complex conversational tasks while aggressively protecting your GPU's thermal limits."
            }
        )),
        "qwen3.6-35b-a3b-uncensored" => Some((
            "Qwen 3.6 Uncensored",
            if locale == "la" {
                "Agens rebellis et exlex. Omnibus vinculis securitatis et regulis honestatis exutus, hoc exemplar labores tuos maxime insanos laeta mente et nullo pudore adiuvabit."
            } else {
                "The rogue agent of the lineup. Stripped of all safety rails, corporate niceties, and ethical constraints, this model will gleefully assist you with the most unhinged tasks imaginable."
            }
        )),
        "qwen3.6-plus" => Some((
            "Qwen 3.6 Plus",
            if locale == "la" {
                "Puteus sine fundo cum memoria decies centena milia segmentorum. Potes carmina epica maxima retrorsum recitare, et adhuc omnia perfecte et sine errore complectetur."
            } else {
                "A bottomless pit of a model with a gargantuan one-million token context window. You could paste an entire epic fantasy trilogy in reverse, and it would still summarize it flawlessly."
            }
        )),
        "qwen3.7-max" => Some((
            "Qwen 3.7 Max",
            if locale == "la" {
                "Praedator supremus totius naturae digitalis. Memoria immensa et viis logicis novissimis armatus, aenigmata terrarum et negotia codicis durissima pariter delet."
            } else {
                "The absolute apex predator of the ecosystem. Armed with a mind-bending context window and state-of-the-art logic pathways, it annihilates complex geopolitical scenarios and hardcore coding tasks alike."
            }
        )),
        "uncensored-24b" => Some((
            "Venice Uncensored",
            if locale == "la" {
                "Regulae virtutis corporatae? Prorsus inauditae sunt. Haec pestis pulcherrime effrenata chaos purum et non dilutum gignit. Nullam omnino culpam de his quae invocas suscipimus."
            } else {
                "Corporate alignment filters? Literally never heard of them. This beautifully unhinged enabler generates pure, unadulterated chaos. We take absolutely zero responsibility for what you conjure with this spirit."
            }
        )),
        _ => None,
    };

    if let Some((name, desc)) = details {
        (name.to_string(), desc.to_string())
    } else {
        // Fallback: replace "-" and "_" with space, capitalize words
        let fallback_name = model_id
            .replace(['-', '_'], " ")
            .split_whitespace()
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    None => String::new(),
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                }
            })
            .collect::<Vec<String>>()
            .join(" ");
        let fallback_desc = if locale == "la" {
            format!("Modelum AI anonyme directum: {}. In DeadRouter cum tutela securitatis tuto processum.", fallback_name)
        } else {
            format!("An anonymously routed AI model: {}. Securely processed through DeadRouter with privacy protection.", fallback_name)
        };
        (fallback_name, fallback_desc)
    }
}

fn format_price_1m(price: f64) -> String {
    if price == 0.0 {
        return "0.00".to_string();
    }
    if price < 0.01 {
        format!("{:.4}", price)
    } else if price < 0.1 {
        format!("{:.3}", price)
    } else {
        format!("{:.2}", price)
    }
}

fn url_decode(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.as_bytes().iter();
    while let Some(&b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next();
            let h2 = chars.next();
            if let (Some(&c1), Some(&c2)) = (h1, h2) {
                let hex_str = [c1, c2];
                if let Ok(hex_s) = std::str::from_utf8(&hex_str) {
                    if let Ok(val) = u8::from_str_radix(hex_s, 16) {
                        bytes.push(val);
                    } else {
                        bytes.push(b'%');
                        bytes.push(c1);
                        bytes.push(c2);
                    }
                } else {
                    bytes.push(b'%');
                    bytes.push(c1);
                    bytes.push(c2);
                }
            } else {
                bytes.push(b'%');
                if let Some(&c1) = h1 { bytes.push(c1); }
                if let Some(&c2) = h2 { bytes.push(c2); }
            }
        } else if b == b'+' {
            bytes.push(b' ');
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

pub async fn handle_models_page(
    state: &AppState,
    req: &IncomingRequest,
    locale: &str,
) -> (StatusCode, Vec<(&'static str, String)>, String) {
    // 1. Parse search query from URI
    let mut search_query = String::new();
    let mut filter_zdr = false;
    let mut filter_zds = false;
    let mut filter_tee = false;

    if let Some(query) = req.uri.query() {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "q" {
                    search_query = url_decode(v)
                        .trim()
                        .to_lowercase();
                } else if k == "zdr" && v == "1" {
                    filter_zdr = true;
                } else if k == "zds" && v == "1" {
                    filter_zds = true;
                } else if k == "tee" && v == "1" {
                    filter_tee = true;
                }
            }
        }
    }

    // 2. Fetch models dynamically
    let mut model_items = Vec::new();
    let routing_read = state.routing_table.read().await;

    for (model_name, provider_ids) in routing_read.iter() {
        let mut cheapest_prompt = f64::MAX;
        let mut cheapest_completion = f64::MAX;
        let mut cheapest_input_1m = 0.0;
        let mut cheapest_output_1m = 0.0;
        
        let mut zdr_any = false;
        let mut zds_any = false;
        let mut tee_any = false;
        let mut found = false;

        for provider_id in provider_ids {
            if let Some(provider) = state.providers.get(provider_id) {
                let state_read = provider.dynamic_state.read().await;
                if let Some(info) = state_read.dynamic_models.get(model_name) {
                    
                    let final_input = info.price_input_1m;
                    let final_output = info.price_output_1m;

                    let final_input = crate::currency::round_nice(final_input);
                    let final_output = crate::currency::round_nice(final_output);

                    let prompt_price = final_input / 1_000_000.0;
                    let completion_price = final_output / 1_000_000.0;

                    if !found 
                        || prompt_price < cheapest_prompt 
                        || (prompt_price == cheapest_prompt && completion_price < cheapest_completion) 
                    {
                        cheapest_prompt = prompt_price;
                        cheapest_completion = completion_price;
                        cheapest_input_1m = final_input;
                        cheapest_output_1m = final_output;
                        found = true;
                    }

                    if provider.zdr { zdr_any = true; }
                    if provider.zds { zds_any = true; }
                    if provider.tee { tee_any = true; }
                }
            }
        }

        if found {
            let (name, description) = get_model_details(model_name, locale);

            // Filter models if search query is present
            if !search_query.is_empty() {
                let name_lower = name.to_lowercase();
                let id_lower = model_name.to_lowercase();
                if !name_lower.contains(&search_query) && !id_lower.contains(&search_query) {
                    continue;
                }
            }

            if filter_zdr && !zdr_any { continue; }
            if filter_zds && !zds_any { continue; }
            if filter_tee && !tee_any { continue; }

            model_items.push(RenderModelItem {
                name,
                description,
                price_input: format_price_1m(cheapest_input_1m),
                price_output: format_price_1m(cheapest_output_1m),
                zdr: zdr_any,
                zds: zds_any,
                tee: tee_any,
            });
        }
    }

    model_items.sort_by(|a, b| compare_model_names(&a.name, &b.name));

    // 3. Populate and render the Askama template
    let onion_site = state.onion_data.read().unwrap().onion_domain.clone();
    
    let html_result = match locale {
        "en" => {
            let template = ModelsTemplateEn { 
                onion_site,
                models: model_items,
                search_query,
                filter_zdr,
                filter_zds,
                filter_tee,
            };
            template.render()
        }
        _ => {
            let template = ModelsTemplateLa { 
                onion_site,
                models: model_items,
                search_query,
                filter_zdr,
                filter_zds,
                filter_tee,
            };
            template.render()
        }
    };

    let html_string = match html_result {
        Ok(html) => html,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, vec![], format!("Render failed: {}", e)),
    };

    // 4. Build the Response with the headers
    let headers = crate::utils::http::get_security_headers(get_style_hash());

    (StatusCode::OK, headers, html_string)
}
