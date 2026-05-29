//! Prompt handling: inline / file / directory.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crate::repo::find_dom_repo_root;

type R<T> = Result<T, Box<dyn Error>>;

/// Load a prompt either from inline text or a file path.
pub fn load(inline: Option<&str>, file: Option<&Path>) -> R<LoadedPrompt> {
    if let Some(text) = inline {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err("inline prompt is empty".into());
        }
        return Ok(LoadedPrompt {
            text: text.to_string(),
            source: PromptSource::Inline,
        });
    }
    let path = file.ok_or("no prompt source provided")?;
    let resolved = path
        .canonicalize()
        .map_err(|e| format!("cannot resolve prompt path {}: {e}", path.display()))?;
    let bytes = fs::read(&resolved)
        .map_err(|e| format!("cannot read prompt file {}: {e}", resolved.display()))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| format!("prompt file is not valid UTF-8: {}", resolved.display()))?;
    if text.trim().is_empty() {
        return Err(format!("prompt file is empty: {}", resolved.display()).into());
    }
    Ok(LoadedPrompt {
        text,
        source: PromptSource::File(resolved),
    })
}

#[derive(Debug, Clone)]
pub struct LoadedPrompt {
    pub text: String,
    pub source: PromptSource,
}

#[derive(Debug, Clone)]
pub enum PromptSource {
    Inline,
    File(PathBuf),
}

impl PromptSource {
    pub fn display(&self) -> String {
        match self {
            PromptSource::Inline => "(inline)".to_string(),
            PromptSource::File(p) => p.display().to_string(),
        }
    }
}

/// `list-prompts`
pub fn cmd_list() -> R<()> {
    let cwd = std::env::current_dir()?;
    let root = find_dom_repo_root(&cwd)?;
    let dir = root.path.join("prompts");
    if !dir.is_dir() {
        println!(
            "[dom-agent-runner] no prompts/ directory at {}",
            dir.display()
        );
        return Ok(());
    }
    let mut entries: Vec<_> = fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.eq_ignore_ascii_case("txt"))
        })
        .map(|e| e.path())
        .collect();
    entries.sort();
    if entries.is_empty() {
        println!("[dom-agent-runner] no prompts/*.txt files");
        return Ok(());
    }
    println!("[dom-agent-runner] prompts ({}):", entries.len());
    for p in entries {
        if let Ok(rel) = p.strip_prefix(&root.path) {
            println!("  {}", rel.display());
        } else {
            println!("  {}", p.display());
        }
    }
    Ok(())
}

/// `show-prompt <path>`
pub fn cmd_show(path: &Path) -> R<()> {
    let resolved = path
        .canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", path.display()))?;
    let text = fs::read_to_string(&resolved)?;
    println!("--- prompt: {}", resolved.display());
    println!("{text}");
    println!("--- end");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_prompt_loads() {
        let p = load(Some("hello"), None).unwrap();
        assert_eq!(p.text, "hello");
        assert!(matches!(p.source, PromptSource::Inline));
    }

    #[test]
    fn empty_inline_rejected() {
        assert!(load(Some(""), None).is_err());
        assert!(load(Some("   \n"), None).is_err());
    }

    #[test]
    fn file_prompt_loads_and_preserves_multiline() {
        let pid = std::process::id();
        let tmp = std::env::temp_dir().join(format!("dar-prompt-{pid}.txt"));
        fs::write(&tmp, "line1\nline2\n\nline4\n").unwrap();
        let p = load(None, Some(&tmp)).unwrap();
        assert_eq!(p.text, "line1\nline2\n\nline4\n");
        match p.source {
            PromptSource::File(_) => {}
            _ => panic!("expected file source"),
        }
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn empty_file_rejected() {
        let pid = std::process::id();
        let tmp = std::env::temp_dir().join(format!("dar-empty-{pid}.txt"));
        fs::write(&tmp, "").unwrap();
        assert!(load(None, Some(&tmp)).is_err());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn missing_file_rejected() {
        let path = PathBuf::from("/this/path/definitely/does/not/exist/xyz.txt");
        assert!(load(None, Some(&path)).is_err());
    }
}
