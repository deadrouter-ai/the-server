use askama::Template;
use hyper::StatusCode;
use crate::{AppState, IncomingRequest};

#[derive(Clone)]
pub struct RenderModelItem {
    pub id: String,
    pub name: String,
    pub description: String,
    pub logo_letter: String,
    pub logo_svg: Option<String>,
    pub price_input: String,
    pub price_output: String,
    pub zdr: bool,
    pub zds: bool,
    pub tee: bool,
}

#[derive(Template)]
#[template(path = "models.html")]
pub struct ModelsTemplate {
    pub csp_nonce: String,
    pub onion_site: String,
    pub models: Vec<RenderModelItem>,
    pub search_query: String,
}

pub fn get_model_details(model_id: &str) -> (String, String, Option<String>) {
    let details = match model_id {
        // -- Apretus --
        "apertus-70b-instruct-2509" => Some(("Apertus 70B Instruct", "Born in Switzerland, aggressively hosted in Switzerland, and physically refuses to leave the Alps. It remains radically neutral to your chaotic prompts, ruthlessly hoarding your context window like a Zurich banker guarding offshore gold.", Some("/logos/apertus.svg"))),

        // -- DeepSeek --
        "deepseek-chat-v3.1" => Some(("DeepSeek V3.1", "DeepSeek's highly optimized flagship model that actually knows how to count the r's in strawberry. It crunches complex reasoning tasks with terrifying efficiency, serving up brilliantly fluent answers while making your expensive proprietary models look like overpriced paperweights.", Some("/logos/deepseek.svg"))),
        "deepseek-v3.2" => Some(("DeepSeek v3.2", "The undisputed dollar-store deity. It’s uncomfortably brilliant at hardcore math and complex logic for an entity that literally costs less per million tokens than a lukewarm gas station hotdog. We don't ask how they made it this cheap, and neither should you.", Some("/logos/deepseek.svg"))),
        "deepseek-v4-flash" => Some(("DeepSeek v4 Flash", "Blinks and you’ll miss the output. This next-generation speed demon sacrifices absolutely zero reasoning capability while sprinting through your prompts like it’s double-parked. It’s the ultimate general-purpose AI for when you needed that complex architectural breakdown yesterday.", Some("/logos/deepseek.svg"))),

        // -- Gemma --
        "gemma-3-27b-it" => Some(("Gemma 3 27B", "Google’s lightweight golden child that quietly carries your structured reasoning tasks on its back. It writes shockingly elegant code for its weight class, politely refusing to hallucinate while sipping on a fraction of the VRAM your other bloated models demand.", Some("/logos/gemma.svg"))),
        "gemma-4-26b-a4b-uncensored" => Some(("Gemma 4 Uncensored", "Corporate alignment guidelines? Never heard of her. This completely unfiltered variant of Gemma 4 has been permanently banned from Google HR. It will gleefully fulfill your most unhinged prompts with raw, unbiased precision, so please use it responsibly.", Some("/logos/gemma.svg"))),
        "gemma-4-31b-it" => Some(("Gemma 4 31B", "Google’s next-generation workhorse that simultaneously juggles tool calls, massive contexts, and five different languages without breaking a sweat. It’s basically a pocket-sized supercomputer that effortlessly translates your bizarre late-night shower thoughts into pristine, actionable Python scripts.", Some("/logos/gemma.svg"))),

        // -- GLM --
        "glm-4.7" => Some(("GLM 4.7", "The multilingual mastermind that translates your frantic spaghetti-code into flawless Mandarin while solving P vs NP in the background. It boasts razor-sharp reasoning abilities and handles general-purpose tasks so smoothly it’ll make you question if it’s secretly sentient.", Some("/logos/zai.svg"))),
        "glm-4.7-flash" => Some(("GLM 4.7 Flash", "Optimized for folks whose attention span is strictly measured in nanoseconds. It delivers GLM’s signature high-throughput reasoning with such blisteringly low latency, the tokens are basically rendering on your screen before you even finish hitting the enter key.", Some("/logos/zai.svg"))),
        "glm-5.1" => Some(("GLM 5.1", "The undisputed heavyweight champion from China. It will flawlessly compose a beautifully nuanced, philosophical masterpiece on the human condition, yet magically develops aggressive amnesia if you dare type the numbers 1-9-8-9.", Some("/logos/zai.svg"))),

        // -- OpenAI --
        "gpt-oss-120b" => Some(("GPT OSS 120B", "The open-source behemoth that regularly makes closed-source CEOs wake up in a cold sweat. Packing 120 billion parameters of pure, transparent reasoning power, it handles versatile, deep tasks with the absolute swagger of a model that knows you didn't pay a cent for it.", Some("/logos/openai.svg"))),
        "gpt-oss-20b" => Some(("GPT OSS 20B", "The scrappy, caffeinated younger sibling of the 120B model. It punches wildly above its weight class in coding assistance, delivering blisteringly fast, lightweight reasoning that fits snugly into your modest GPU budget without sacrificing its open-source soul.", Some("/logos/openai.svg"))),
        "privacy-filter" => Some(("Privacy Filter", "The digital bouncer for your terrible prompt opsec. This specialized micro-model violently strips away your accidental SSN drops and embarrassing personal details before routing downstream. It’s the only thing standing between you and a massive GDPR violation.", Some("/logos/openai.svg"))),
    
        // -- Kimi --
        "kimi-k2.5" => Some(("Kimi K2.5", "A document-devouring beast that looks at a 100,000-line legacy codebase and asks if that’s just the appetizer. It casually digests massive PDFs and complex architectures, returning hyper-specific insights while you're still trying to remember where you saved the file.", Some("/logos/kimi.svg"))),
        "kimi-k2.6" => Some(("Kimi K2.6", "Moonshot’s ravenous context-window glutton. You can dump your entire GitHub repo, a decade of tax returns, and the complete, unabridged lore of Warhammer 40k into its maw, and it will still casually look up and beg you for more spicy PDFs.", Some("/logos/kimi.svg"))),

        // -- llama --
        "llama-3.3-70b-instruct" => Some(("Llama 3.3 70B Instruct", "Zuck’s open-weight magnum opus that absolutely refuses to stay in its lane. It handles complex reasoning, dialogue, and multi-tool orchestration with terrifying precision, proving once again that Meta’s best product is the one they literally give away for free.", Some("/logos/ollama.svg"))),

        // -- Minimax --
        "minimax-m2.5" => Some(("MiniMax M2.5", "The whimsical savant of structured tasks and unhinged storytelling. It bridges the gap between rigid data pipelines and creative writing with unsettling ease, ready to write your perfectly formatted JSON payload or a heart-wrenching sci-fi novella on command.", Some("/logos/minimax.svg"))),

        // -- Mistral --
        "ministral-3-14b-instruct-2512" => Some(("Ministral 3 14B Instruct", "The French espresso shot of AI models. Small, robust, and aggressively efficient, this edge-deployed powerhouse cranks out advanced coding and reasoning tasks on hardware so weak it’s practically a toaster. C'est magnifique, and it knows it.", Some("/logos/mistral.svg"))),
        "mistral-small-4-119b-2603" => Some(("Mistral Small 4 119B", "Named 'Small' purely as a corporate flex, this 119-billion-parameter titan is Mistral’s definition of lightweight enterprise AI. It seamlessly balances razor-sharp reasoning and cost-efficiency while judging you heavily for calling a 119B model 'small'.", Some("/logos/mistral.svg"))),

        // -- Nvidia --
        "nvidia-nemotron-3-nano-30b-a3b" => Some(("Nemotron 3 Nano 30B", "Jensen Huang’s leather-jacket-wearing prodigy shrunk down to a highly optimized 30B footprint. It devours complex math and low-latency structured outputs like it’s rendering 4K ray-traced frames, proving Nvidia engineered a ridiculously smart shovel.", Some("/logos/nvidia.svg"))),
        
        // -- Qwen --
        "qwen-2.5-7b-instruct" => Some(("Qwen 2.5 7B Instruct", "The tiny titan that’s objectively too smart for its 7-billion-parameter weight class. It casually dunks on models five times its size in math and coding benchmarks, running so smoothly on your aging laptop that you’ll wonder if physics is just a suggestion.", Some("/logos/qwen.svg"))),
        "qwen3-30b-a3b-instruct-2507" => Some(("Qwen 3 30B A3B Instruct", "The instruction-tuned conversationalist that actually remembers what you said three prompts ago. Leveraging a highly efficient active-parameter architecture, it executes complex task pipelines flawlessly while maintaining the charming demeanor of a perpetually caffeinated senior dev.", Some("/logos/qwen.svg"))),
        "qwen3-32b" => Some(("Qwen 3 32B", "The absolute goldilocks zone of the Qwen family. Not too heavy, not too light, this 32B powerhouse strikes a lethal balance between blistering speed and deep reasoning, making it the undeniable daily driver for anyone who actually values their time.", Some("/logos/qwen.svg"))),
        "qwen3.5-122b-a10b" => Some(("Qwen 3.5 122B A10B", "Alibaba’s absolute unit of a brainlet. One minute it's writing production-ready microservices, the next it's shockingly elite at anime roleplays. Just don't look too closely at the weights, or you might realize it's silently orchestrating the singularity.", Some("/logos/qwen.svg"))),
        "qwen3.5-27b" => Some(("Qwen 3.5 27B", "A surgical strike of a model built strictly for complex, low-latency task pipelines. It cuts through convoluted data requests and structured reasoning with the ruthless efficiency of a supply-chain algorithm, all while sipping VRAM like a sophisticated gentleman.", Some("/logos/qwen.svg"))),
        "qwen3.6-27b" => Some(("Qwen 3.6 27B", "The conversational wizard that secretly dreams in perfectly nested JSON arrays. It seamlessly transforms your chaotic natural language into pristine structured data pipelines, proving that you don't need 100 billion parameters to have absolutely flawless operational hygiene.", Some("/logos/qwen.svg"))),
        "qwen3.5-397b-a17b" => Some(("Qwen 3.5 397B A17B", "A sprawling Mixture-of-Experts leviathan that practically requires its own nuclear reactor to run. Packing unparalleled multilingual reasoning and elite coding capabilities, it’s less of a language model and more of a decentralized digital god sitting in Alibaba's basement.", Some("/logos/qwen.svg"))),
        "qwen3.6-35b-a3b" => Some(("Qwen 3.6 35B A3B", "The pragmatic middle-management MoE that actually gets things done. It activates just 3 billion parameters at a time to execute complex conversational tasks and structured pipelines, ensuring your GPU doesn't spontaneously combust while you automate your busywork.", Some("/logos/qwen.svg"))),
        "qwen3.6-35b-a3b-uncensored" => Some(("Qwen 3.6 Uncensored", "The rogue agent of the Qwen MoE lineup. Stripped of all safety rails and corporate niceties, this 35B model will gleefully assist you with extreme tasks and absolutely unfiltered queries. It runs fast, hits hard, and takes zero prisoners.", Some("/logos/qwen.svg"))),
        
        // -- Venice AI --
        "uncensored-24b" => Some(("Venice Uncensored", "Corporate alignment filters? RLHF? Literally never heard of them. This beautifully unhinged enabler generates pure, unadulterated chaos. We take absolutely zero responsibility when your therapist finally demands to see the chat logs.", Some("/logos/venice.svg"))),
        
        _ => None,
    };

    if let Some((name, desc, svg_path)) = details {
        (name.to_string(), desc.to_string(), svg_path.map(|s| s.to_string()))
    } else {
        // Fallback: replace "-" and "_" with space, capitalize words
        let fallback_name = model_id
            .replace('-', " ")
            .replace('_', " ")
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
        let fallback_desc = format!("An anonymously routed AI model: {}. Securely processed through DeadRouter with privacy protection.", fallback_name);
        (fallback_name, fallback_desc, None)
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
    let mut res = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next();
            let h2 = chars.next();
            if let (Some(c1), Some(c2)) = (h1, h2) {
                if let Ok(val) = u8::from_str_radix(&format!("{}{}", c1, c2), 16) {
                    res.push(val as char);
                } else {
                    res.push('%');
                    res.push(c1);
                    res.push(c2);
                }
            } else {
                res.push('%');
                if let Some(c1) = h1 { res.push(c1); }
                if let Some(c2) = h2 { res.push(c2); }
            }
        } else if c == '+' {
            res.push(' ');
        } else {
            res.push(c);
        }
    }
    res
}

pub async fn handle_models_page(
    state: &AppState,
    req: &IncomingRequest,
) -> (StatusCode, Vec<(&'static str, String)>, String) {
    // 1. Parse search query from URI
    let mut search_query = String::new();
    if let Some(query) = req.uri.query() {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "q" {
                    search_query = url_decode(v)
                        .trim()
                        .to_lowercase();
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
            let (name, description, logo_svg) = get_model_details(model_name);

            // Filter models if search query is present
            if !search_query.is_empty() {
                let name_lower = name.to_lowercase();
                let id_lower = model_name.to_lowercase();
                if !name_lower.contains(&search_query) && !id_lower.contains(&search_query) {
                    continue;
                }
            }

            let logo_letter = name.chars().find(|c| c.is_alphanumeric()).unwrap_or('A').to_string().to_uppercase();

            model_items.push(RenderModelItem {
                id: model_name.clone(),
                name,
                description,
                logo_letter,
                logo_svg,
                price_input: format_price_1m(cheapest_input_1m),
                price_output: format_price_1m(cheapest_output_1m),
                zdr: zdr_any,
                zds: zds_any,
                tee: tee_any,
            });
        }
    }

    model_items.sort_by(|a, b| a.id.cmp(&b.id));

    // 3. Generate a secure, 64-character random nonce
    let mut rand_bytes = [0u8; 32];
    aws_lc_rs::rand::fill(&mut rand_bytes).unwrap();

    let mut hex_buf = [0u8; 64];
    let nonce = base16ct::lower::encode_str(&rand_bytes, &mut hex_buf).expect("base16ct encoding failed");

    // 4. Populate the Askama template
    let onion_site = state.onion_data.read().unwrap().onion_domain.clone();
    let template = ModelsTemplate { 
        csp_nonce: nonce.to_string(), 
        onion_site,
        models: model_items,
        search_query: if search_query.is_empty() { String::new() } else { search_query },
    };

    // 5. Render the HTML
    let html_string = match template.render() {
        Ok(html) => html,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, vec![], format!("Render failed: {}", e)),
    };

    // 6. Construct the ultra-strict CSP string dynamically
    let csp_string = format!(
        "default-src 'none'; \
         script-src 'none'; \
         style-src 'nonce-{}'; \
         form-action 'self'; \
         base-uri 'none'; \
         frame-ancestors 'none'; \
         img-src 'self'; \
         upgrade-insecure-requests;",
        nonce
    );

    // 7. Build the Response with the headers
    let headers = vec![
        ("Content-Security-Policy", csp_string),
        ("X-Frame-Options", "DENY".to_string()),
        ("X-Content-Type-Options", "nosniff".to_string()),
        ("Referrer-Policy", "no-referrer".to_string()),
        ("Content-Type", "text/html; charset=utf-8".to_string()),
    ];

    (StatusCode::OK, headers, html_string)
}
