use std::cmp::Ordering;

#[derive(PartialEq, PartialOrd, Debug)]
enum SortChunk {
    Text(String),
    Num(f64),
}

fn extract_sort_chunks(s: &str) -> Vec<SortChunk> {
    let mut chunks = Vec::new();
    let mut chars = s.chars().peekable();
    
    while chars.peek().is_some() {
        if chars.peek().unwrap().is_ascii_digit() {
            let mut num_str = String::new();
            let mut has_dot = false;
            while let Some(&nc) = chars.peek() {
                if nc.is_ascii_digit() {
                    num_str.push(nc);
                    chars.next();
                } else if nc == '.' && !has_dot {
                    let mut clone_iter = chars.clone();
                    clone_iter.next();
                    if let Some(&nnc) = clone_iter.peek() {
                        if nnc.is_ascii_digit() {
                            num_str.push(nc);
                            has_dot = true;
                            chars.next();
                            continue;
                        }
                    }
                    break;
                } else {
                    break;
                }
            }
            if let Ok(n) = num_str.parse::<f64>() {
                chunks.push(SortChunk::Num(n));
            } else {
                chunks.push(SortChunk::Text(num_str));
            }
        } else {
            let mut text_str = String::new();
            while let Some(&nc) = chars.peek() {
                if !nc.is_ascii_digit() {
                    text_str.push(nc.to_ascii_lowercase());
                    chars.next();
                } else {
                    break;
                }
            }
            chunks.push(SortChunk::Text(text_str));
        }
    }
    chunks
}

fn compare_model_names(a: &str, b: &str) -> std::cmp::Ordering {
    let chunks_a = extract_sort_chunks(a);
    let chunks_b = extract_sort_chunks(b);
    
    let len = chunks_a.len().min(chunks_b.len());
    for i in 0..len {
        match (&chunks_a[i], &chunks_b[i]) {
            (SortChunk::Text(t1), SortChunk::Text(t2)) => {
                match t1.cmp(t2) {
                    Ordering::Equal => continue,
                    other => return other,
                }
            }
            (SortChunk::Num(n1), SortChunk::Num(n2)) => {
                match n2.partial_cmp(n1).unwrap_or(Ordering::Equal) {
                    Ordering::Equal => continue,
                    other => return other,
                }
            }
            (SortChunk::Text(_), SortChunk::Num(_)) => return Ordering::Greater,
            (SortChunk::Num(_), SortChunk::Text(_)) => return Ordering::Less,
        }
    }
    chunks_a.len().cmp(&chunks_b.len())
}

fn main() {
    let mut names = vec![
        "GLM 4.7",
        "GLM 5.1",
        "DeepSeek v3.2",
        "DeepSeek v4 Flash",
        "Qwen 3.5 27B",
        "Qwen 3.5 122B A10B",
        "Qwen 3.6 35B A3B Uncensored",
        "Qwen 3.6 27B",
    ];
    
    names.sort_by(|a, b| compare_model_names(a, b));
    
    for n in names {
        println!("{}", n);
    }
}
